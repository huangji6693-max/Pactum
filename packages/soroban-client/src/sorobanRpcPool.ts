import { Account, FeeBumpTransaction, Keypair, Transaction, rpc, xdr } from '@stellar/stellar-sdk';

export interface SorobanRpcNodeConfig {
  url: string;
  headers?: Record<string, string>;
}

export interface SorobanRpcPoolOptions {
  allowHttp?: boolean;
  timeout?: number;
  headers?: Record<string, string>;
  maxAttempts?: number;
  cooldownMs?: number;
  successBonus?: number;
  failurePenalty?: number;
  maxScore?: number;
  minScore?: number;
  onFallback?: (info: {
    url: string;
    error: unknown;
    attempt: number;
    remaining: number;
  }) => void;
  onNodeSuccess?: (stats: SorobanRpcNodeStats) => void;
  onNodeFailure?: (stats: SorobanRpcNodeStats, error: unknown) => void;
  onExhausted?: (error: unknown, context: Record<string, unknown>) => void;
  serverFactory?: (url: string, options: rpc.Server.Options) => rpc.Server;
}

export interface SorobanRpcNodeStats {
  url: string;
  score: number;
  latencyMs: number;
  totalSuccesses: number;
  totalFailures: number;
  consecutiveFailures: number;
  lastError?: string;
  lastAttemptAt?: number;
  cooldownUntil?: number;
}

export class RetryableRpcError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'RetryableRpcError';
  }
}

export class RpcPoolExhaustedError extends Error {
  readonly lastError: unknown;
  readonly nodeStats: SorobanRpcNodeStats[];
  readonly attempts: number;

  constructor(lastError: unknown, nodeStats: SorobanRpcNodeStats[], attempts: number) {
    const reason = lastError instanceof Error ? lastError.message : String(lastError);
    super(
      `All ${nodeStats.length} configured Soroban RPC node(s) failed after ${attempts} ` +
        `attempt(s). Last error: ${reason}`,
    );
    this.name = 'RpcPoolExhaustedError';
    this.lastError = lastError;
    this.nodeStats = nodeStats;
    this.attempts = attempts;
  }
}

const NETWORK_ERROR_HINTS = [
  'fetch failed',
  'failed to fetch',
  'network error',
  'econnrefused',
  'econnreset',
  'enotfound',
  'etimedout',
  'timeout of ',
  'socket hang up',
  'getaddrinfo',
  'load failed',
  'request timed out',
];

export function isRetryableError(error: unknown): boolean {
  if (error instanceof RetryableRpcError) return true;
  if (!error || typeof error !== 'object') return false;

  const candidate = error as {
    response?: { status?: unknown };
    status?: unknown;
    code?: unknown;
    name?: unknown;
    message?: unknown;
  };

  const status =
    typeof candidate.response?.status === 'number'
      ? candidate.response.status
      : typeof candidate.status === 'number' && candidate.status >= 100 && candidate.status <= 599
        ? candidate.status
        : undefined;
  if (status !== undefined) {
    return status === 429 || (status >= 500 && status <= 599);
  }

  if (typeof candidate.code === 'number') {
    return candidate.code === -32603 || (candidate.code <= -32000 && candidate.code >= -32099);
  }

  const name = typeof candidate.name === 'string' ? candidate.name.toLowerCase() : '';
  const message = typeof candidate.message === 'string' ? candidate.message.toLowerCase() : '';
  if (name === 'fetcherror' || name === 'networkerror' || name === 'timeouterror') return true;
  if (name === 'typeerror' && NETWORK_ERROR_HINTS.some((hint) => message.includes(hint))) {
    return true;
  }
  return NETWORK_ERROR_HINTS.some((hint) => message.includes(hint));
}

interface RpcNodeState extends SorobanRpcNodeStats {
  server: rpc.Server;
}

const EWMA_ALPHA = 0.7;
const DEFAULT_OPTIONS: Required<
  Pick<
    SorobanRpcPoolOptions,
    | 'allowHttp'
    | 'timeout'
    | 'cooldownMs'
    | 'successBonus'
    | 'failurePenalty'
    | 'maxScore'
    | 'minScore'
  >
> = {
  allowHttp: true,
  timeout: 15_000,
  cooldownMs: 30_000,
  successBonus: 2,
  failurePenalty: 25,
  maxScore: 100,
  minScore: 0,
};

export class SorobanRpcPool {
  private readonly nodes: RpcNodeState[];
  private readonly options: SorobanRpcPoolOptions;
  private readonly nodeOrder = new Map<string, number>();

  constructor(urls: Array<string | SorobanRpcNodeConfig>, options: SorobanRpcPoolOptions = {}) {
    if (!urls || urls.length === 0) {
      throw new Error('SorobanRpcPool requires at least one RPC endpoint URL');
    }
    this.options = { ...DEFAULT_OPTIONS, ...options };

    this.nodes = urls.map((entry, index) => {
      const config = typeof entry === 'string' ? { url: entry } : entry;
      const url = config.url.trim();
      if (!url) {
        throw new Error('SorobanRpcPool received an empty RPC endpoint URL');
      }
      const serverOptions: rpc.Server.Options = {
        allowHttp: this.options.allowHttp,
        timeout: this.options.timeout,
        headers: { ...this.options.headers, ...config.headers },
      };
      const server = this.options.serverFactory
        ? this.options.serverFactory(url, serverOptions)
        : new rpc.Server(url, serverOptions);
      this.nodeOrder.set(url, index);
      return {
        url,
        server,
        score: this.options.maxScore ?? DEFAULT_OPTIONS.maxScore,
        latencyMs: 0,
        totalSuccesses: 0,
        totalFailures: 0,
        consecutiveFailures: 0,
      };
    });
  }

  get size(): number {
    return this.nodes.length;
  }

  get preferredUrl(): string | undefined {
    return this.rankNodes()[0]?.url;
  }

  getStats(): SorobanRpcNodeStats[] {
    return this.rankNodes().map((node) => this.toStats(node));
  }

  async checkHealth(): Promise<SorobanRpcNodeStats[]> {
    await Promise.all(
      this.nodes.map(async (node) => {
        const startedAt = Date.now();
        try {
          await node.server.getHealth();
          this.recordSuccess(node, startedAt);
        } catch (error) {
          this.recordFailure(node, error, startedAt, true);
        }
      }),
    );
    return this.getStats();
  }

  async execute<T>(
    operation: (server: rpc.Server) => Promise<T>,
    options: { isRetryable?: (error: unknown) => boolean } = {},
  ): Promise<T> {
    const candidates = this.rankNodes();
    const maxAttempts = Math.min(
      Math.max(1, this.options.maxAttempts ?? candidates.length),
      candidates.length,
    );
    let lastError: unknown;

    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      const node = candidates[attempt];
      if (!node) break;
      const startedAt = Date.now();
      node.lastAttemptAt = startedAt;

      try {
        const result = await operation(node.server);
        this.recordSuccess(node, startedAt);
        return result;
      } catch (error) {
        lastError = error;
        const retryable =
          error instanceof RetryableRpcError ||
          (options.isRetryable ? options.isRetryable(error) : isRetryableError(error));
        this.recordFailure(node, error, startedAt, retryable);

        const remaining = maxAttempts - attempt - 1;
        if (retryable && remaining > 0) {
          this.options.onFallback?.({ url: node.url, error, attempt: attempt + 1, remaining });
        } else if (retryable) {
          this.options.onExhausted?.(error, {
            rpcNode: node.url,
            attempts: maxAttempts,
            errorType: error instanceof Error ? error.name : typeof error,
          });
          throw new RpcPoolExhaustedError(lastError, this.getStats(), maxAttempts);
        } else {
          throw error;
        }
      }
    }

    throw new RpcPoolExhaustedError(lastError, this.getStats(), maxAttempts);
  }

  async getAccount(address: string): Promise<Account> {
    return this.execute(async (server) => {
      const ledgerKey = xdr.LedgerKey.account(
        new xdr.LedgerKeyAccount({
          accountId: Keypair.fromPublicKey(address).xdrPublicKey(),
        }),
      );
      const response = await server.getLedgerEntries(ledgerKey);
      if (!response.entries.length) {
        throw new Error(`Account not found: ${address}`);
      }
      const entry = response.entries[0].val.account();
      return new Account(address, entry.seqNum().toString());
    });
  }

  getHealth(): Promise<rpc.Api.GetHealthResponse> {
    return this.execute((server) => server.getHealth());
  }

  getNetwork(): Promise<rpc.Api.GetNetworkResponse> {
    return this.execute((server) => server.getNetwork());
  }

  getLatestLedger(): Promise<rpc.Api.GetLatestLedgerResponse> {
    return this.execute((server) => server.getLatestLedger());
  }

  getTransaction(hash: string): Promise<rpc.Api.GetTransactionResponse> {
    return this.execute((server) => server.getTransaction(hash));
  }

  simulateTransaction(
    tx: Transaction | FeeBumpTransaction,
    addlResources?: rpc.Server.ResourceLeeway,
    authMode?: rpc.Api.SimulationAuthMode,
    useUpgradedAuth?: boolean,
  ): Promise<rpc.Api.SimulateTransactionResponse> {
    return this.execute((server) =>
      server.simulateTransaction(tx, addlResources, authMode, useUpgradedAuth),
    );
  }

  prepareTransaction(tx: Transaction | FeeBumpTransaction): Promise<Transaction> {
    return this.execute((server) => server.prepareTransaction(tx));
  }

  async sendTransaction(
    transaction: Transaction | FeeBumpTransaction,
  ): Promise<rpc.Api.SendTransactionResponse> {
    return this.execute(async (server) => {
      const response = await server.sendTransaction(transaction);
      if (response.status === 'TRY_AGAIN_LATER') {
        throw new RetryableRpcError(
          'Soroban RPC node is overloaded (sendTransaction returned TRY_AGAIN_LATER); retrying on another node',
        );
      }
      return response;
    });
  }

  private rankNodes(): RpcNodeState[] {
    const now = Date.now();
    return [...this.nodes].sort((a, b) => {
      const aCoolingDown = a.cooldownUntil !== undefined && a.cooldownUntil > now;
      const bCoolingDown = b.cooldownUntil !== undefined && b.cooldownUntil > now;
      if (aCoolingDown !== bCoolingDown) return aCoolingDown ? 1 : -1;
      if (b.score !== a.score) return b.score - a.score;
      if (a.latencyMs !== b.latencyMs) return a.latencyMs - b.latencyMs;
      return (this.nodeOrder.get(a.url) ?? 0) - (this.nodeOrder.get(b.url) ?? 0);
    });
  }

  private recordSuccess(node: RpcNodeState, startedAt: number): void {
    const latency = Date.now() - startedAt;
    node.latencyMs =
      node.latencyMs === 0 ? latency : node.latencyMs * EWMA_ALPHA + latency * (1 - EWMA_ALPHA);
    node.totalSuccesses += 1;
    node.consecutiveFailures = 0;
    node.cooldownUntil = undefined;
    node.lastError = undefined;
    node.score = Math.min(
      this.options.maxScore ?? DEFAULT_OPTIONS.maxScore,
      node.score + (this.options.successBonus ?? DEFAULT_OPTIONS.successBonus),
    );
    this.options.onNodeSuccess?.(this.toStats(node));
  }

  private recordFailure(
    node: RpcNodeState,
    error: unknown,
    startedAt: number,
    retryable: boolean,
  ): void {
    const latency = Date.now() - startedAt;
    node.latencyMs =
      node.latencyMs === 0 ? latency : node.latencyMs * EWMA_ALPHA + latency * (1 - EWMA_ALPHA);
    node.totalFailures += 1;
    node.lastError = error instanceof Error ? error.message : String(error);

    if (retryable) {
      node.consecutiveFailures += 1;
      node.cooldownUntil = Date.now() + (this.options.cooldownMs ?? DEFAULT_OPTIONS.cooldownMs);
      node.score = Math.max(
        this.options.minScore ?? DEFAULT_OPTIONS.minScore,
        node.score - (this.options.failurePenalty ?? DEFAULT_OPTIONS.failurePenalty),
      );
    } else {
      node.consecutiveFailures = 0;
    }
    this.options.onNodeFailure?.(this.toStats(node), error);
  }

  private toStats(node: RpcNodeState): SorobanRpcNodeStats {
    return {
      url: node.url,
      score: node.score,
      latencyMs: node.latencyMs,
      totalSuccesses: node.totalSuccesses,
      totalFailures: node.totalFailures,
      consecutiveFailures: node.consecutiveFailures,
      lastError: node.lastError,
      lastAttemptAt: node.lastAttemptAt,
      cooldownUntil: node.cooldownUntil,
    };
  }
}
