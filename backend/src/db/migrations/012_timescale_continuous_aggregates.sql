-- Migration 012: TimescaleDB Continuous Aggregates & Real-Time Hypertable Ingestion (Issue #303)
--
-- 1. Creates the `commitment_events` hypertable and converts `attestor_votes` into a hypertable.
-- 2. Enables real-time aggregation (`timescaledb.materialized_only = false`) across all
--    continuous aggregates so queries seamlessly merge materialized chunks with live unaggregated rows.
-- 3. Defines 1-hour, 1-day, and 1-week continuous aggregates over `commitment_events` and `attestor_votes`.
-- 4. Registers automated refresh and retention policies.

-- ---------------------------------------------------------------------------
-- 1. Hypertable setup for commitment_events and attestor_votes
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS commitment_events (
  time                        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  commitment_id               VARCHAR(255) NOT NULL,
  event_type                  VARCHAR(64) NOT NULL,
  issuer                      VARCHAR(255) NOT NULL,
  counterparty                VARCHAR(255),
  amount                      DECIMAL(20, 8) NOT NULL DEFAULT 0,
  resolution_duration_seconds BIGINT,
  ledger_sequence             BIGINT NOT NULL DEFAULT 0
);

SELECT create_hypertable('commitment_events', 'time', if_not_exists => TRUE);

CREATE INDEX IF NOT EXISTS idx_commitment_events_issuer_time
  ON commitment_events (issuer, time DESC);
CREATE INDEX IF NOT EXISTS idx_commitment_events_type_time
  ON commitment_events (event_type, time DESC);
CREATE INDEX IF NOT EXISTS idx_commitment_events_commitment_id
  ON commitment_events (commitment_id, time DESC);

-- Adjust attestor_votes primary key to include the partitioning column `voted_at`
ALTER TABLE attestor_votes DROP CONSTRAINT IF EXISTS attestor_votes_pkey;
ALTER TABLE attestor_votes ADD PRIMARY KEY (commitment_id, attestor, voted_at);

SELECT create_hypertable(
  'attestor_votes',
  'voted_at',
  if_not_exists => TRUE,
  migrate_data  => TRUE
);

CREATE INDEX IF NOT EXISTS idx_attestor_votes_attestor_time
  ON attestor_votes (attestor, voted_at DESC);

-- Enable real-time aggregation on existing continuous aggregates from migration 010
ALTER MATERIALIZED VIEW reputation_snapshots_daily
  SET (timescaledb.materialized_only = false);
ALTER MATERIALIZED VIEW mv_daily_fulfillment_rates_cagg
  SET (timescaledb.materialized_only = false);
ALTER MATERIALIZED VIEW mv_weekly_fulfillment_rates_cagg
  SET (timescaledb.materialized_only = false);
ALTER MATERIALIZED VIEW mv_monthly_fulfillment_rates_cagg
  SET (timescaledb.materialized_only = false);
ALTER MATERIALIZED VIEW mv_trust_score_trends_cagg
  SET (timescaledb.materialized_only = false);

-- ---------------------------------------------------------------------------
-- 2. Continuous Aggregates over commitment_events (1h, 1d, 1w)
-- ---------------------------------------------------------------------------

CREATE MATERIALIZED VIEW IF NOT EXISTS cagg_commitment_events_1h
WITH (timescaledb.continuous, timescaledb.materialized_only = false) AS
SELECT
  time_bucket('1 hour', time)                                    AS bucket,
  issuer,
  COUNT(*)                                                       AS total_events,
  COUNT(*) FILTER (WHERE event_type = 'fulfilled')               AS fulfilled_count,
  COUNT(*) FILTER (WHERE event_type = 'late')                    AS late_count,
  COUNT(*) FILTER (WHERE event_type = 'breached')                AS breached_count,
  COUNT(*) FILTER (WHERE event_type = 'disputed')                AS disputed_count,
  COALESCE(SUM(amount), 0)                                       AS total_volume,
  AVG(resolution_duration_seconds)                               AS avg_resolution_duration_seconds,
  MAX(ledger_sequence)                                           AS max_ledger_sequence
FROM commitment_events
GROUP BY bucket, issuer
WITH NO DATA;

CREATE MATERIALIZED VIEW IF NOT EXISTS cagg_commitment_events_1d
WITH (timescaledb.continuous, timescaledb.materialized_only = false) AS
SELECT
  time_bucket('1 day', time)                                     AS bucket,
  issuer,
  COUNT(*)                                                       AS total_events,
  COUNT(*) FILTER (WHERE event_type = 'fulfilled')               AS fulfilled_count,
  COUNT(*) FILTER (WHERE event_type = 'late')                    AS late_count,
  COUNT(*) FILTER (WHERE event_type = 'breached')                AS breached_count,
  COUNT(*) FILTER (WHERE event_type = 'disputed')                AS disputed_count,
  COALESCE(SUM(amount), 0)                                       AS total_volume,
  AVG(resolution_duration_seconds)                               AS avg_resolution_duration_seconds,
  MAX(ledger_sequence)                                           AS max_ledger_sequence
FROM commitment_events
GROUP BY bucket, issuer
WITH NO DATA;

CREATE MATERIALIZED VIEW IF NOT EXISTS cagg_commitment_events_1w
WITH (timescaledb.continuous, timescaledb.materialized_only = false) AS
SELECT
  time_bucket('1 week', time)                                    AS bucket,
  issuer,
  COUNT(*)                                                       AS total_events,
  COUNT(*) FILTER (WHERE event_type = 'fulfilled')               AS fulfilled_count,
  COUNT(*) FILTER (WHERE event_type = 'late')                    AS late_count,
  COUNT(*) FILTER (WHERE event_type = 'breached')                AS breached_count,
  COUNT(*) FILTER (WHERE event_type = 'disputed')                AS disputed_count,
  COALESCE(SUM(amount), 0)                                       AS total_volume,
  AVG(resolution_duration_seconds)                               AS avg_resolution_duration_seconds,
  MAX(ledger_sequence)                                           AS max_ledger_sequence
FROM commitment_events
GROUP BY bucket, issuer
WITH NO DATA;

-- ---------------------------------------------------------------------------
-- 3. Continuous Aggregates over attestor_votes (1h, 1d, 1w)
-- ---------------------------------------------------------------------------

CREATE MATERIALIZED VIEW IF NOT EXISTS cagg_attestor_votes_1h
WITH (timescaledb.continuous, timescaledb.materialized_only = false) AS
SELECT
  time_bucket('1 hour', voted_at)                                AS bucket,
  attestor,
  COUNT(*)                                                       AS votes_cast,
  COUNT(*) FILTER (WHERE outcome = 'fulfilled')                  AS fulfilled_votes,
  COUNT(*) FILTER (WHERE outcome = 'late')                       AS late_votes,
  COUNT(*) FILTER (WHERE outcome = 'breached')                   AS breached_votes,
  MIN(voted_at)                                                  AS first_voted_at,
  MAX(voted_at)                                                  AS last_voted_at,
  MAX(ledger_sequence)                                           AS max_ledger_sequence
FROM attestor_votes
GROUP BY bucket, attestor
WITH NO DATA;

CREATE MATERIALIZED VIEW IF NOT EXISTS cagg_attestor_votes_1d
WITH (timescaledb.continuous, timescaledb.materialized_only = false) AS
SELECT
  time_bucket('1 day', voted_at)                                 AS bucket,
  attestor,
  COUNT(*)                                                       AS votes_cast,
  COUNT(*) FILTER (WHERE outcome = 'fulfilled')                  AS fulfilled_votes,
  COUNT(*) FILTER (WHERE outcome = 'late')                       AS late_votes,
  COUNT(*) FILTER (WHERE outcome = 'breached')                   AS breached_votes,
  MIN(voted_at)                                                  AS first_voted_at,
  MAX(voted_at)                                                  AS last_voted_at,
  MAX(ledger_sequence)                                           AS max_ledger_sequence
FROM attestor_votes
GROUP BY bucket, attestor
WITH NO DATA;

CREATE MATERIALIZED VIEW IF NOT EXISTS cagg_attestor_votes_1w
WITH (timescaledb.continuous, timescaledb.materialized_only = false) AS
SELECT
  time_bucket('1 week', voted_at)                                AS bucket,
  attestor,
  COUNT(*)                                                       AS votes_cast,
  COUNT(*) FILTER (WHERE outcome = 'fulfilled')                  AS fulfilled_votes,
  COUNT(*) FILTER (WHERE outcome = 'late')                       AS late_votes,
  COUNT(*) FILTER (WHERE outcome = 'breached')                   AS breached_votes,
  MIN(voted_at)                                                  AS first_voted_at,
  MAX(voted_at)                                                  AS last_voted_at,
  MAX(ledger_sequence)                                           AS max_ledger_sequence
FROM attestor_votes
GROUP BY bucket, attestor
WITH NO DATA;

-- ---------------------------------------------------------------------------
-- 4. Continuous Aggregate Refresh & Retention Policies
-- ---------------------------------------------------------------------------

SELECT add_continuous_aggregate_policy('cagg_commitment_events_1h',
  start_offset      => INTERVAL '7 days',
  end_offset        => INTERVAL '1 minute',
  schedule_interval => INTERVAL '5 minutes',
  if_not_exists     => TRUE);

SELECT add_continuous_aggregate_policy('cagg_commitment_events_1d',
  start_offset      => INTERVAL '30 days',
  end_offset        => INTERVAL '5 minutes',
  schedule_interval => INTERVAL '15 minutes',
  if_not_exists     => TRUE);

SELECT add_continuous_aggregate_policy('cagg_commitment_events_1w',
  start_offset      => INTERVAL '180 days',
  end_offset        => INTERVAL '1 hour',
  schedule_interval => INTERVAL '1 hour',
  if_not_exists     => TRUE);

SELECT add_continuous_aggregate_policy('cagg_attestor_votes_1h',
  start_offset      => INTERVAL '7 days',
  end_offset        => INTERVAL '1 minute',
  schedule_interval => INTERVAL '5 minutes',
  if_not_exists     => TRUE);

SELECT add_continuous_aggregate_policy('cagg_attestor_votes_1d',
  start_offset      => INTERVAL '30 days',
  end_offset        => INTERVAL '5 minutes',
  schedule_interval => INTERVAL '15 minutes',
  if_not_exists     => TRUE);

SELECT add_continuous_aggregate_policy('cagg_attestor_votes_1w',
  start_offset      => INTERVAL '180 days',
  end_offset        => INTERVAL '1 hour',
  schedule_interval => INTERVAL '1 hour',
  if_not_exists     => TRUE);

SELECT add_retention_policy('commitment_events', INTERVAL '180 days', if_not_exists => TRUE);
SELECT add_retention_policy('attestor_votes',    INTERVAL '180 days', if_not_exists => TRUE);
