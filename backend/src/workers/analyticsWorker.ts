import { snapshotNetworkDailyStats } from './timescaleSnapshot';
import { queryTimescale } from '../db/timescale';
import { logger } from '../logger/logger';

const SNAPSHOT_INTERVAL = parseInt(process.env.ANALYTICS_SNAPSHOT_INTERVAL_MS || '3600000', 10);
const WATCHDOG_INTERVAL = 5 * 60 * 1000; // 5 minutes

export const MANAGED_CONTINUOUS_AGGREGATES = [
  'reputation_snapshots_daily',
  'mv_daily_fulfillment_rates_cagg',
  'mv_weekly_fulfillment_rates_cagg',
  'mv_monthly_fulfillment_rates_cagg',
  'mv_trust_score_trends_cagg',
  'cagg_commitment_events_1h',
  'cagg_commitment_events_1d',
  'cagg_commitment_events_1w',
  'cagg_attestor_votes_1h',
  'cagg_attestor_votes_1d',
  'cagg_attestor_votes_1w',
] as const;

export type ManagedContinuousAggregate = (typeof MANAGED_CONTINUOUS_AGGREGATES)[number];

const MANAGED_VIEW_SET = new Set<string>(MANAGED_CONTINUOUS_AGGREGATES);

export const HYPERTABLE_RETENTION_TARGETS: ReadonlyArray<{
  table: string;
  retentionInterval: string;
}> = [
  { table: 'commitment_events', retentionInterval: '180 days' },
  { table: 'attestor_votes', retentionInterval: '180 days' },
  { table: 'commitment_outcomes', retentionInterval: '90 days' },
  { table: 'trust_score_snapshots', retentionInterval: '90 days' },
];

export type CacheInvalidationListener = (refreshedViews: string[]) => void;

export class AnalyticsWorker {
  private snapshotTimer: NodeJS.Timeout | null = null;
  private watchdogTimer: NodeJS.Timeout | null = null;
  private readonly invalidationListeners = new Set<CacheInvalidationListener>();

  start() {
    console.log('[Analytics Worker] Starting analytics worker...');

    // Schedule periodic snapshots
    this.snapshotTimer = setInterval(() => {
      this.runSnapshot();
    }, SNAPSHOT_INTERVAL);

    // Schedule periodic CAGG health watchdog
    this.watchdogTimer = setInterval(() => {
      this.watchCAAGHealth();
    }, WATCHDOG_INTERVAL);

    // Run initial snapshot and watchdog check
    this.runSnapshot().catch(console.error);
    this.watchCAAGHealth().catch(console.error);

    console.log('[Analytics Worker] Analytics worker started');
    console.log(`[Analytics Worker] Snapshot interval: ${SNAPSHOT_INTERVAL}ms`);
    console.log(`[Analytics Worker] CAGG Watchdog interval: ${WATCHDOG_INTERVAL}ms`);
  }

  stop() {
    console.log('[Analytics Worker] Stopping analytics worker...');

    if (this.snapshotTimer) {
      clearInterval(this.snapshotTimer);
      this.snapshotTimer = null;
    }

    if (this.watchdogTimer) {
      clearInterval(this.watchdogTimer);
      this.watchdogTimer = null;
    }

    console.log('[Analytics Worker] Analytics worker stopped');
  }

  /**
   * Registers a callback invoked whenever continuous aggregates are refreshed
   * so downstream in-memory or Redis caches can invalidate stale entries.
   */
  onCacheInvalidate(listener: CacheInvalidationListener): () => void {
    this.invalidationListeners.add(listener);
    return () => {
      this.invalidationListeners.delete(listener);
    };
  }

  /**
   * Emits cache invalidation for the given continuous aggregate view names.
   */
  invalidateCaches(refreshedViews: string[]): void {
    if (refreshedViews.length === 0) return;
    for (const listener of this.invalidationListeners) {
      try {
        listener(refreshedViews);
      } catch (err) {
        logger.error('Cache invalidation listener threw error', err);
      }
    }
  }

  /**
   * Refreshes the specified continuous aggregates over `windowInterval` and triggers
   * cache invalidation for all refreshed views.
   */
  async refreshContinuousAggregates(
    views: readonly string[] = MANAGED_CONTINUOUS_AGGREGATES,
    windowInterval = '3 days',
  ): Promise<string[]> {
    const refreshed: string[] = [];
    for (const viewName of views) {
      if (!MANAGED_VIEW_SET.has(viewName)) {
        logger.warn('Skipping unmanaged continuous aggregate name', { viewName });
        continue;
      }
      await queryTimescale(
        `CALL refresh_continuous_aggregate($1, NOW() - $2::interval, NOW())`,
        [viewName, windowInterval],
      );
      refreshed.push(viewName);
      logger.info('Refreshed continuous aggregate', { viewName, windowInterval });
    }
    this.invalidateCaches(refreshed);
    return refreshed;
  }

  /**
   * Coordinates hypertable retention cleanup across managed hypertables.
   */
  async enforceRetentionAndCompression(): Promise<{ droppedTables: string[] }> {
    const droppedTables: string[] = [];
    for (const { table, retentionInterval } of HYPERTABLE_RETENTION_TARGETS) {
      try {
        await queryTimescale(
          `SELECT drop_chunks($1::regclass, older_than => $2::interval)`,
          [table, retentionInterval],
        );
        droppedTables.push(table);
      } catch (error) {
        logger.warn('Hypertable retention drop_chunks skipped', { table, error });
      }
    }
    return { droppedTables };
  }

  private async runSnapshot() {
    console.log('[Analytics Worker] Running network stats snapshot...');
    try {
      await snapshotNetworkDailyStats();
      await this.enforceRetentionAndCompression();
      console.log('[Analytics Worker] Daily stats snapshot completed');
    } catch (error) {
      console.error('[Analytics Worker] Snapshot failed:', error);
    }
  }

  // Watchdog: checks CAAG health every 5 minutes
  async watchCAAGHealth(): Promise<void> {
    try {
      const stale = await queryTimescale(`
        SELECT view_name, next_scheduled_run AS next_run
        FROM timescaledb_information.continuous_aggregate_stats
        WHERE next_scheduled_run < NOW() - INTERVAL '10 minutes'
      `);

      if (stale.rows.length > 0) {
        logger.warn('CAGG background jobs appear stalled', { staleViews: stale.rows });

        if (process.env.CAGG_MANUAL_REFRESH === 'true') {
          const staleNames = stale.rows.map((r: { view_name: string }) => r.view_name);
          await this.refreshContinuousAggregates(staleNames, '3 days');
        }
      }
    } catch (error) {
      logger.error('Failed to check CAGG health', error);
    }
  }
}

// Export singleton instance
export const analyticsWorker = new AnalyticsWorker();

// Auto-start if this file is run directly
if (require.main === module) {
  analyticsWorker.start();

  // Graceful shutdown
  process.on('SIGINT', () => {
    console.log('[Analytics Worker] Received SIGINT, shutting down...');
    analyticsWorker.stop();
    process.exit(0);
  });

  process.on('SIGTERM', () => {
    console.log('[Analytics Worker] Received SIGTERM, shutting down...');
    analyticsWorker.stop();
    process.exit(0);
  });
}
