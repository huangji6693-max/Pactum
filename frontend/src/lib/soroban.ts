import {
  Account,
  Contract,
  rpc,
  TransactionBuilder,
  Networks,
  BASE_FEE,
  xdr,
  Address,
  Keypair,
  nativeToScVal,
  scValToNative,
} from '@stellar/stellar-sdk';
import type { Reputation } from './api';
import { Buffer } from 'buffer';
import { signTransaction } from '@stellar/freighter-api';
import { signTransactionWithLedger } from './wallet-adapters/ledger-adapter';
import type { WalletProvider } from './wallet';
import { decodeSimulationError, isSorobanXdrError } from './xdrDecode';
import type { DecodedXdrError } from './xdrDecode';
import { SorobanRpcPool } from './sorobanRpcPool';

/**
 * Default pool of Soroban RPC endpoints, ordered by preference.
 *
 * Every endpoint in a pool must be on the **same Stellar network** so that a
 * transaction prepared or submitted through any of them is valid on all of
 * them. Operators can override/extend the pool at build time with the
 * `VITE_SOROBAN_RPC_URLS` env var (comma-separated list) — the legacy single
 * `VITE_SOROBAN_RPC_URL` is still honoured as a one-node pool.
 */
export const DEFAULT_SOROBAN_RPC_URLS: string[] = ['https://soroban-testnet.stellar.org'];

/** @deprecated Use {@link DEFAULT_SOROBAN_RPC_URLS} / {@link resolveSorobanRpcUrls}. */
export const DEFAULT_SOROBAN_RPC_URL = DEFAULT_SOROBAN_RPC_URLS[0];
export const DEFAULT_CONTRACT_ID = 'CBADTVTJ6IN332HIKZ7LWUYMYTLPZYCEBV3X2HS47VHR5UDBHQ3GAA7E';
export const DEFAULT_NETWORK_PASSPHRASE = Networks.TESTNET;

/**
 * Enhanced error class that carries decoded Soroban XDR information.
 *
 * When a simulation fails, this error wraps the raw RPC response alongside
 * decoded diagnostic events, the attempted operation, and resolution guidance.
 * UI components can extract these fields to render a rich error modal.
 */
export class SorobanSimulationError extends Error {
  public readonly diagnosticEventBlobs: string[];
  public readonly attemptedFunction: string | null;
  public readonly decodedXdrError: DecodedXdrError;

  constructor(
    message: string,
    rawError: string,
    diagnosticEventBlobs: string[] = [],
    attemptedFunction: string | null = null,
  ) {
    super(message);
    this.name = 'SorobanSimulationError';
    this.diagnosticEventBlobs = diagnosticEventBlobs;
    this.attemptedFunction = attemptedFunction;
    this.decodedXdrError = decodeSimulationError(rawError, diagnosticEventBlobs, attemptedFunction);
  }
}

/**
 * Extract base64-encoded diagnostic event XDR blobs from a raw simulation
 * error response. These are often embedded in the error string or returned
 * as a separate `events` array.
 */
export function extractDiagnosticEventBlobs(
  simulationResult: rpc.Api.SimulateTransactionErrorResponse | any,
): string[] {
  const blobs: string[] = [];

  if (!simulationResult || typeof simulationResult !== 'object') {
    return blobs;
  }

  // Path 1: `events` array on the simulation response (parsed DiagnosticEvent[])
  if (Array.isArray(simulationResult.events)) {
    for (const event of simulationResult.events) {
      try {
        const base64 = (event as any).toXDR?.('base64');
        if (base64) blobs.push(base64);
      } catch {
        // skip
      }
    }
  }

  // Path 2: Base64 strings embedded in the error message
  if (typeof simulationResult.error === 'string') {
    const matches = simulationResult.error.match(/[A-Za-z0-9+/]{40,}={0,2}/g);
    if (matches) {
      for (const m of matches) {
        if (isSorobanXdrError(m)) {
          blobs.push(m);
        }
      }
    }
  }

  return blobs;
}

/**
 * Resolves the ordered list of Soroban RPC endpoints the caller wants, in
 * priority order:
 *
 * 1. Explicit `rpcUrls` array (most specific),
 * 2. explicit legacy single `rpcUrl`,
 * 3. `VITE_SOROBAN_RPC_URLS` (comma-separated) from the environment,
 * 4. legacy `VITE_SOROBAN_RPC_URL` from the environment,
 * 5. {@link DEFAULT_SOROBAN_RPC_URLS}.
 *
 * Duplicate/empty entries are removed.
 */
export function resolveSorobanRpcUrls(rpcUrls?: string[], rpcUrl?: string): string[] {
  if (rpcUrls && rpcUrls.length > 0) {
    const deduped = dedupeRpcUrls(rpcUrls);
    if (deduped.length > 0) return deduped;
    // Explicit list had only blank entries — fall through to env / defaults.
  }
  if (rpcUrl && rpcUrl.trim()) {
    return [rpcUrl.trim()];
  }
  const envList = import.meta.env.VITE_SOROBAN_RPC_URLS;
  if (typeof envList === 'string' && envList.trim()) {
    return dedupeRpcUrls(
      envList
        .split(',')
        .map((u) => u.trim())
        .filter(Boolean),
    );
  }
  const envSingle = import.meta.env.VITE_SOROBAN_RPC_URL;
  if (typeof envSingle === 'string' && envSingle.trim()) {
    return [envSingle.trim()];
  }
  return [...DEFAULT_SOROBAN_RPC_URLS];
}

function dedupeRpcUrls(urls: string[]): string[] {
  const seen = new Set<string>();
  const result: string[] = [];
  for (const raw of urls) {
    const url = raw?.trim();
    if (!url) continue;
    const normalized = url.replace(/\/+$/, '').toLowerCase();
    if (!seen.has(normalized)) {
      seen.add(normalized);
      result.push(url);
    }
  }
  return result;
}

/**
 * Module-level pool cache keyed by a stable sort-join of the resolved URLs.
 *
 * Because every RPC entry point (`submitCreateCommitment`,
 * `fetchReputationFromRpc`, `fetchLatestLedgerAnchor`) previously
 * constructed a fresh {@link SorobanRpcPool} per invocation, health scores,
 * EWMA latencies and cooldowns were lost between calls — a node that
 * returned 429 on the last call was ranked first again on the next call.
 * In-call retry worked; cross-call routing to the healthiest node did not.
 *
 * Caching reuses the same pool instance for the same set of URLs so that
 * scores degrade and recover naturally as real traffic flows through.
 */
const poolCache = new Map<string, SorobanRpcPool>();

/**
 * Per-pool set of live status listeners. The pool-wide `onFallback` closure
 * is fixed at construction time, so it consults this set on every fallback
 * and notifies each registered listener. This lets per-call callers pass
 * their own `onStatusUpdate` and receive failover messages in the UI without
 * binding the callback into the (long-lived, cached) pool instance.
 */
const statusListeners = new Map<string, Set<(statusMessage: string) => void>>();

/** Upper bound on registered status listeners per pool (see {@link getOrCreatePool}). */
const MAX_STATUS_LISTENERS = 8;

/**
 * Returns a {@link SorobanRpcPool} for the given URL set, creating it on
 * first use and reusing it on subsequent calls so health scores, EWMA
 * latencies and cooldowns persist across invocations.
 *
 * @param urls Ordered list of RPC endpoints for the pool.
 * @param onStatusUpdate Optional per-call callback invoked with a
 * user-facing message whenever the pool fails over to a backup node.
 * Callbacks are stored in a listener set keyed by the pool and invoked by the
 * pool's fallback handler — they are never bound into the cached pool itself.
 */
export function getOrCreatePool(
  urls: string[],
  onStatusUpdate?: (statusMessage: string) => void,
): SorobanRpcPool {
  const key = [...urls].sort().join('|');
  let pool = poolCache.get(key);
  if (!pool) {
    pool = new SorobanRpcPool(urls, {
      allowHttp: true,
      timeout: 15_000,
      onFallback: ({ url, error, attempt, remaining }) => {
        const reason = error instanceof Error ? error.message : String(error);
        console.warn(
          `[SorobanRpcPool] RPC node ${url} failed (${reason}); retrying on another node ` +
            `(attempt ${attempt}/${attempt + remaining}).`,
        );
        // Notify every live status listener registered for this pool.
        for (const listener of statusListeners.get(key) ?? []) {
          try {
            listener(`RPC node unavailable (${reason}). Retrying on a backup node...`);
          } catch {
            // A misbehaving listener must not break the failover path.
          }
        }
      },
    });
    poolCache.set(key, pool);
  }
  if (onStatusUpdate) {
    let listeners = statusListeners.get(key);
    if (!listeners) {
      listeners = new Set();
      statusListeners.set(key, listeners);
    }
    listeners.add(onStatusUpdate);
    // Keep the set bounded. Listeners are per-invocation UI callbacks that are
    // never explicitly unregistered, so without a cap a long-lived session
    // would retain every stale React state setter it ever registered.
    while (listeners.size > MAX_STATUS_LISTENERS) {
      const oldest = listeners.values().next().value;
      if (oldest === undefined) break;
      listeners.delete(oldest);
    }
  }
  return pool;
}

/**
 * Builds a pool wired up with sensible production defaults.
 *
 * @deprecated Prefer {@link getOrCreatePool} which caches the pool instance
 * so that health scores persist across calls.
 */
function createSorobanRpcPool(
  urls: string[],
  onStatusUpdate?: (statusMessage: string) => void,
): SorobanRpcPool {
  return getOrCreatePool(urls, onStatusUpdate);
}

export interface CreateCommitmentParams {
  issuerAddress: string;
  counterpartyAddress: string;
  termsHashHex: string;
  dueAtSeconds: number;
  /**
   * Optional M-of-N attestor panel addresses (`Vec<Address>`) and quorum threshold (`u32`).
   * When omitted or empty, defaults to single-resolver dispute resolution (`[]`, `0`).
   */
  attestors?: string[];
  voteThreshold?: number;
  /**
   * Ordered list of Soroban RPC endpoints (connection pool). When omitted,
   * `VITE_SOROBAN_RPC_URLS` / `VITE_SOROBAN_RPC_URL` / defaults are used.
   */
  rpcUrls?: string[];
  /** @deprecated Use {@link CreateCommitmentParams.rpcUrls}. */
  rpcUrl?: string;
  contractId?: string;
  networkPassphrase?: string;
  onStatusUpdate?: (statusMessage: string) => void;
  walletProvider?: WalletProvider;
}

export interface CreateCommitmentResult {
  hash: string;
  commitmentId?: number | bigint;
  status: 'SUCCESS';
}

export interface SimulationCost {
  /** Estimated fee in stroops (1 XLM = 10,000,000 stroops). */
  feeStroops: string;
  /** Estimated fee formatted as XLM string for display. */
  feeXlm: string;
  /** CPU instructions consumed. */
  cpuInsns: string;
  /** Memory bytes consumed. */
  memBytes: string;
}

export interface SimulationPreview {
  /** True if simulation succeeded. */
  success: boolean;
  /** Decoded error message if simulation failed. */
  error?: string;
  /** Cost metrics if simulation succeeded. */
  cost?: SimulationCost;
  /** List of required authorizations as human-readable strings. */
  requiredAuths: string[];
  /** Raw simulation result for downstream use (prepareTransaction). */
  rawSimulation: rpc.Api.SimulateTransactionResponse;
}

export interface TrustedLedgerAnchor {
  hash: string;
  sequence: number;
}

export interface SorobanReadOptions {
  /**
   * Ordered list of Soroban RPC endpoints (connection pool). When omitted,
   * `VITE_SOROBAN_RPC_URLS` / `VITE_SOROBAN_RPC_URL` / defaults are used.
   */
  rpcUrls?: string[];
  /** @deprecated Use {@link SorobanReadOptions.rpcUrls}. */
  rpcUrl?: string;
}

export interface ReputationQueryOptions extends SorobanReadOptions {
  contractId?: string;
  networkPassphrase?: string;
}

export async function fetchLatestLedgerAnchor(
  options: SorobanReadOptions = {},
): Promise<TrustedLedgerAnchor> {
  const pool = createSorobanRpcPool(resolveSorobanRpcUrls(options.rpcUrls, options.rpcUrl));
  const ledger = await pool.getLatestLedger();

  if (!ledger.id || !ledger.sequence) {
    throw new Error('Soroban RPC returned an incomplete latest-ledger response');
  }

  return { hash: ledger.id, sequence: ledger.sequence };
}

/**
 * Runs simulateTransaction against the Soroban RPC and returns a parsed
 * SimulationPreview without modifying any state or prompting the wallet.
 */
export async function preflightSimulate(
  tx: ReturnType<TransactionBuilder['build']>,
  rpcUrl = import.meta.env.VITE_SOROBAN_RPC_URL || DEFAULT_SOROBAN_RPC_URL,
): Promise<SimulationPreview> {
  const server = new rpc.Server(rpcUrl, { allowHttp: true });
  const simulation = await server.simulateTransaction(tx);

  if (rpc.Api.isSimulationError(simulation)) {
    return {
      success: false,
      error: simulation.error ?? 'Simulation failed with unknown error.',
      requiredAuths: [],
      rawSimulation: simulation,
    };
  }

  // Parse cost metrics
  const feeStroops = simulation.minResourceFee ?? '0';
  const feeXlm = (Number(feeStroops) / 10_000_000).toFixed(7);

  const cost: SimulationCost = {
    feeStroops,
    feeXlm,
    cpuInsns: (simulation as any).cost?.cpuInsns ?? '0',
    memBytes: (simulation as any).cost?.memBytes ?? '0',
  };

  // Parse required auths as readable strings
  const requiredAuths: string[] = [];
  if (simulation.result?.auth) {
    for (const auth of simulation.result.auth) {
      try {
        const decoded: xdr.SorobanAuthorizationEntry =
          typeof auth === 'string'
            ? xdr.SorobanAuthorizationEntry.fromXDR(auth, 'base64')
            : (auth as xdr.SorobanAuthorizationEntry);
        const credentials = decoded.credentials();
        if (credentials.switch().name === 'sorobanCredentialsAddress') {
          const addrCreds = credentials.address();
          requiredAuths.push(
            addrCreds.address().accountId().ed25519().toString('hex').slice(0, 8) + '...',
          );
        } else {
          requiredAuths.push('Source account authorization');
        }
      } catch {
        requiredAuths.push('Unknown authorization');
      }
    }
  }

  return {
    success: true,
    cost,
    requiredAuths,
    rawSimulation: simulation,
  };
}

/**
 * Reads the registry's current arbitrator address. `create_commitment` requires a
 * `resolver_address`, and this is the standard, no-custom-resolver value to pass for it: naming a
 * current arbitrator routes disputes through the registry's committee majority vote instead of
 * single-delegate resolution. Never default `resolver_address` to the issuer or counterparty --
 * `resolve_dispute`'s only guard is `caller == resolver_address`, so that would let a party
 * unilaterally resolve their own dispute.
 */
export async function fetchArbitrator(
  rpcUrls?: string[],
  rpcUrl?: string,
  contractId = import.meta.env.VITE_PACTUM_CONTRACT_ID || DEFAULT_CONTRACT_ID,
  networkPassphrase = import.meta.env.VITE_STELLAR_NETWORK_PASSPHRASE || DEFAULT_NETWORK_PASSPHRASE,
): Promise<string> {
  const pool = getOrCreatePool(resolveSorobanRpcUrls(rpcUrls, rpcUrl));
  const contract = new Contract(contractId);
  const source = new Account(Keypair.random().publicKey(), '0');
  const transaction = new TransactionBuilder(source, {
    fee: BASE_FEE,
    networkPassphrase,
  })
    .addOperation(contract.call('get_arbitrator'))
    .setTimeout(30)
    .build();

  const simulation = await pool.simulateTransaction(transaction);
  if (rpc.Api.isSimulationError(simulation)) {
    const diagBlobs = extractDiagnosticEventBlobs(simulation);
    const decoded = decodeSimulationError(simulation.error, diagBlobs, 'get_arbitrator');
    throw new SorobanSimulationError(
      decoded.message ?? `Failed to read registry arbitrator: ${simulation.error}`,
      simulation.error,
      diagBlobs,
      'get_arbitrator',
    );
  }
  if (!simulation.result) {
    throw new Error('Direct Soroban query returned no arbitrator value');
  }

  return String(scValToNative(simulation.result.retval));
}

export async function fetchReputationFromRpc(
  address: string,
  options: ReputationQueryOptions = {},
): Promise<Reputation> {
  const contractId =
    options.contractId || import.meta.env.VITE_PACTUM_CONTRACT_ID || DEFAULT_CONTRACT_ID;
  const networkPassphrase =
    options.networkPassphrase ||
    import.meta.env.VITE_STELLAR_NETWORK_PASSPHRASE ||
    DEFAULT_NETWORK_PASSPHRASE;
  const pool = getOrCreatePool(resolveSorobanRpcUrls(options.rpcUrls, options.rpcUrl));
  const contract = new Contract(contractId);
  const source = new Account(Keypair.random().publicKey(), '0');
  const transaction = new TransactionBuilder(source, {
    fee: BASE_FEE,
    networkPassphrase,
  })
    .addOperation(contract.call('get_reputation', nativeToScVal(address, { type: 'address' })))
    .setTimeout(30)
    .build();

  const simulation = await pool.simulateTransaction(transaction);
  if (rpc.Api.isSimulationError(simulation)) {
    const diagnosticBlobs = extractDiagnosticEventBlobs(simulation);
    const decoded = decodeSimulationError(simulation.error, diagnosticBlobs, 'get_reputation');
    throw new SorobanSimulationError(
      decoded.message ?? `Direct Soroban query failed: ${simulation.error}`,
      simulation.error,
      diagnosticBlobs,
      'get_reputation',
    );
  }
  if (!simulation.result) {
    throw new Error('Direct Soroban query returned no reputation value');
  }

  const value = scValToNative(simulation.result.retval) as Record<string, number | bigint>;
  const fulfilled = Number(value.fulfilled_count ?? value.fulfilledCount ?? 0);
  const late = Number(value.late_count ?? value.lateCount ?? 0);
  const breached = Number(value.breached_count ?? value.breachedCount ?? 0);

  return {
    address,
    fulfilled,
    late,
    breached,
    total: fulfilled + late + breached,
  };
}

/**
 * Converts a 64-character hex string (32 bytes SHA-256) into a Uint8Array
 */
export function hexToBytes(hexStr: string): Uint8Array {
  const cleanHex = hexStr.replace(/^0x/i, '');
  if (cleanHex.length !== 64) {
    throw new Error(
      `Invalid terms hash hex length: expected 64 hex characters (32 bytes), got ${cleanHex.length}`,
    );
  }
  const bytes = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    bytes[i] = parseInt(cleanHex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/**
 * Helper to auto-fund a new unfunded Testnet account via Stellar Friendbot
 */
export async function fundTestnetAccount(address: string): Promise<boolean> {
  try {
    const response = await fetch(
      `https://friendbot.stellar.org/?addr=${encodeURIComponent(address)}`,
    );
    return response.ok;
  } catch (e) {
    console.warn(`[Friendbot] Could not auto-fund ${address}:`, e);
    return false;
  }
}

/**
 * Builds, simulates, signs via Freighter, and submits a `create_commitment` Soroban transaction.
 *
 * Every RPC interaction goes through a {@link SorobanRpcPool}: if the active
 * node rate-limits (HTTP 429), returns a 5xx, or drops the connection, the
 * request is transparently retried on the next-healthiest node.
 */
export async function submitCreateCommitment({
  issuerAddress,
  counterpartyAddress,
  termsHashHex,
  dueAtSeconds,
  attestors,
  voteThreshold,
  rpcUrls,
  rpcUrl,
  contractId = import.meta.env.VITE_PACTUM_CONTRACT_ID || DEFAULT_CONTRACT_ID,
  networkPassphrase = import.meta.env.VITE_STELLAR_NETWORK_PASSPHRASE || DEFAULT_NETWORK_PASSPHRASE,
  onStatusUpdate,
  walletProvider = 'freighter',
}: CreateCommitmentParams): Promise<CreateCommitmentResult> {
  // 1. Parameter Validation
  if (!issuerAddress || !issuerAddress.startsWith('G')) {
    throw new Error('Connected wallet issuer address must be a valid Stellar public key (G...)');
  }
  if (!counterpartyAddress || !counterpartyAddress.startsWith('G')) {
    throw new Error('Counterparty address must be a valid Stellar public key (G...)');
  }
  if (issuerAddress.trim().toUpperCase() === counterpartyAddress.trim().toUpperCase()) {
    throw new Error('Issuer and Counterparty addresses cannot be identical.');
  }

  const nowSeconds = Math.floor(Date.now() / 1000);
  if (dueAtSeconds <= nowSeconds) {
    throw new Error(
      `Due date must be in the future. Selected timestamp (${dueAtSeconds}) is not > current timestamp (${nowSeconds}).`,
    );
  }

  const normalizedAttestors = (attestors ?? []).map((a) => a.trim()).filter(Boolean);
  const resolvedThreshold =
    normalizedAttestors.length > 0 ? Math.max(1, Number(voteThreshold ?? 1)) : 0;
  if (normalizedAttestors.length > 0 && resolvedThreshold > normalizedAttestors.length) {
    throw new Error(
      `Vote threshold (${resolvedThreshold}) cannot exceed attestor panel size (${normalizedAttestors.length}).`,
    );
  }

  onStatusUpdate?.('Initializing Soroban RPC connection pool...');
  const pool = createSorobanRpcPool(resolveSorobanRpcUrls(rpcUrls, rpcUrl), onStatusUpdate);

  // 2. Convert Arguments to ScVal
  onStatusUpdate?.('Encoding contract parameters...');
  const issuerScVal = Address.fromString(issuerAddress).toScVal();
  const counterpartyScVal = Address.fromString(counterpartyAddress).toScVal();
  const termsHashBytes = hexToBytes(termsHashHex);
  const termsHashScVal = xdr.ScVal.scvBytes(Buffer.from(termsHashBytes));
  const dueAtScVal = xdr.ScVal.scvU64(xdr.Uint64.fromString(dueAtSeconds.toString()));

  // create_commitment requires a resolver_address; the wizard's UI has no concept of a custom
  // dispute resolver yet, so read the registry's own arbitrator and use that (see
  // fetchArbitrator's doc comment for why this -- NOT issuerScVal/counterpartyScVal -- is the
  // safe default: resolve_dispute's only guard is `caller == resolver_address`, so defaulting to
  // the issuer would let them unilaterally resolve their own dispute).
  onStatusUpdate?.('Fetching registry arbitrator...');
  const arbitratorAddress = await fetchArbitrator(rpcUrls, rpcUrl, contractId, networkPassphrase);
  const resolverScVal = Address.fromString(arbitratorAddress).toScVal();
  // oracle and schema_id are both genuinely optional (Option<Address>/Option<u32>) with no
  // downstream code assuming they're populated; the wizard doesn't collect either yet.
  const oracleScVal = xdr.ScVal.scvVoid();
  const schemaIdScVal = xdr.ScVal.scvVoid();
  // Empty attestors + a 0 threshold is the contract's explicitly-designed "no voting panel, use
  // the single-resolver dispute path" state (contracts/registry/src/commitments.rs::create).
  // When an M-of-N attestor panel is configured, encode the panel addresses and quorum threshold.
  const attestorsScVal = xdr.ScVal.scvVec(
    normalizedAttestors.map((addr) => Address.fromString(addr).toScVal()),
  );
  const voteThresholdScVal = xdr.ScVal.scvU32(resolvedThreshold);

  // 3. Build Transaction Envelope
  onStatusUpdate?.('Fetching sequence number for issuer account...');
  let account: any = null;
  try {
    account = await pool.getAccount(issuerAddress);
  } catch (err: any) {
    const errStr = String(err?.message || err).toLowerCase();
    if (errStr.includes('not found') || errStr.includes('404') || errStr.includes('account')) {
      onStatusUpdate?.('Issuer account unfunded on Testnet. Auto-funding via Stellar Friendbot...');
      const funded = await fundTestnetAccount(issuerAddress);
      if (funded) {
        onStatusUpdate?.('Account funded! Re-fetching sequence number...');
        await new Promise((resolve) => setTimeout(resolve, 1500));
        try {
          account = await pool.getAccount(issuerAddress);
        } catch (e2) {
          console.warn('Re-fetch account error:', e2);
        }
      }
    }

    if (!account) {
      throw new Error(
        `Connected account (${issuerAddress.substring(0, 8)}...) is not funded on Stellar Testnet yet. Please fund it with Testnet XLM in your Freighter extension or via Stellar Friendbot.`,
      );
    }
  }

  const contract = new Contract(contractId);

  const tx = new TransactionBuilder(account, {
    fee: BASE_FEE,
    networkPassphrase,
  })
    .addOperation(
      contract.call(
        'create_commitment',
        issuerScVal,
        counterpartyScVal,
        termsHashScVal,
        dueAtScVal,
        resolverScVal,
        oracleScVal,
        schemaIdScVal,
        attestorsScVal,
        voteThresholdScVal,
      ),
    )
    .setTimeout(60)
    .build();

  // 4. Simulate & Prepare Transaction Envelope (Soroban footprint & fees)
  onStatusUpdate?.('Simulating transaction on Soroban RPC...');
  let preparedTx: Awaited<ReturnType<typeof pool.prepareTransaction>>;
  try {
    preparedTx = await pool.prepareTransaction(tx);
  } catch (prepareErr: unknown) {
    const errMsg = prepareErr instanceof Error ? prepareErr.message : String(prepareErr);
    const diagBlobs = extractDiagnosticEventBlobs({ error: errMsg });
    const decoded = decodeSimulationError(errMsg, diagBlobs, 'create_commitment');
    throw new SorobanSimulationError(
      decoded.message ?? `Transaction simulation failed: ${errMsg}`,
      errMsg,
      diagBlobs,
      'create_commitment',
    );
  }

  const unsignedXdr = preparedTx.toXDR();

  // NOTE: preflightSimulate is called earlier in the UI layer before
  // reaching this point. This prepareTransaction call is still required
  // to get the final prepared XDR with correct footprint for signing.

  // 5. Prompt the connected wallet for a signature
  let signedXdr = '';

  if (walletProvider === 'ledger') {
    onStatusUpdate?.('Awaiting signature on Ledger device (confirm on-screen)...');
    signedXdr = await signTransactionWithLedger(unsignedXdr, networkPassphrase);
  } else if (walletProvider === 'web3auth') {
    onStatusUpdate?.('Signing with your social-login Stellar key...');
    const { signTransactionWithWeb3Auth } = await import('./web3auth');
    signedXdr = signTransactionWithWeb3Auth(unsignedXdr, networkPassphrase);
  } else {
    onStatusUpdate?.('Awaiting signature in Freighter wallet...');
    const signResult = await signTransaction(unsignedXdr, {
      networkPassphrase,
      address: issuerAddress,
    });

    if (typeof signResult === 'string') {
      signedXdr = signResult;
    } else if (signResult && typeof signResult === 'object') {
      if ((signResult as any).error) {
        throw new Error(`Freighter signing rejected: ${(signResult as any).error}`);
      }
      signedXdr =
        (signResult as any).signedTxXdr ||
        (signResult as any).signedXdr ||
        (signResult as any).signedTransaction ||
        '';
    }
  }

  if (!signedXdr) {
    throw new Error('Transaction signing was cancelled or denied.');
  }

  // 6. Submit Signed Transaction Envelope to RPC
  onStatusUpdate?.('Submitting transaction to Stellar Testnet...');
  const signedTx = TransactionBuilder.fromXDR(signedXdr, networkPassphrase);
  const sendResult = await pool.sendTransaction(signedTx);

  if (sendResult.status === 'ERROR' || sendResult.errorResult) {
    throw new Error(`RPC submission error: ${sendResult.errorResult || sendResult.status}`);
  }

  const txHash = sendResult.hash;
  onStatusUpdate?.(`Transaction submitted! Confirming hash ${txHash.substring(0, 10)}...`);

  // 7. Poll RPC for Final On-Chain Ledger Status
  let txStatus: rpc.Api.GetTransactionStatus = rpc.Api.GetTransactionStatus.NOT_FOUND;
  let txResult: rpc.Api.GetTransactionResponse | null = null;
  let attempts = 0;

  // 25 attempts (30s) was too tight against a freshly-booted local sandbox
  // under CI load, where ledger close + RPC round-trip time can eat most of
  // that budget before the tx is even included -- bumped to give real
  // confirmation latency enough headroom.
  while (attempts < 45) {
    attempts++;
    await new Promise((resolve) => setTimeout(resolve, 1200));
    txResult = await pool.getTransaction(txHash);
    txStatus = txResult.status;

    if (txStatus === rpc.Api.GetTransactionStatus.SUCCESS) {
      break;
    } else if (txStatus === rpc.Api.GetTransactionStatus.FAILED) {
      // Enrich the FAILED result with XDR decoding if available
      const failedTx = txResult as rpc.Api.GetFailedTransactionResponse | null;
      let diagBlobs: string[] = [];
      if (failedTx?.diagnosticEventsXdr) {
        diagBlobs = failedTx.diagnosticEventsXdr
          .map((e: any) => {
            try {
              return (e as any).toXDR?.('base64') ?? String(e);
            } catch {
              return null;
            }
          })
          .filter((b: string | null): b is string => b !== null);
      }
      const resultXdr = (failedTx as any)?.resultXdr;
      const enrichedMessage = resultXdr
        ? `Transaction execution failed on Stellar Testnet. Hash: ${txHash}`
        : `Transaction execution failed on Stellar Testnet. Hash: ${txHash}`;
      throw new SorobanSimulationError(
        enrichedMessage,
        enrichedMessage,
        diagBlobs,
        'create_commitment',
      );
    }
  }

  if (txStatus !== rpc.Api.GetTransactionStatus.SUCCESS) {
    throw new Error(`Transaction confirmation timed out. Hash: ${txHash}`);
  }

  let commitmentId: number | bigint | undefined = undefined;
  const successTx = txResult as any;
  if (successTx && successTx.returnValue) {
    try {
      const nativeVal = scValToNative(successTx.returnValue);
      if (typeof nativeVal === 'number' || typeof nativeVal === 'bigint') {
        commitmentId = nativeVal;
      }
    } catch (e) {
      console.warn('Could not parse commitmentId from retval:', e);
    }
  }

  onStatusUpdate?.('Transaction confirmed successfully on-chain!');

  return {
    hash: txHash,
    commitmentId,
    status: 'SUCCESS',
  };
}

// ---------------------------------------------------------------------------
// Attestor Staking, Unbonding, Slashing & Dispute Committee Helpers (#296)
// ---------------------------------------------------------------------------

/** 14-day unbonding period in seconds (`14 * 24 * 60 * 60 = 1_209_600`). */
export const UNBONDING_PERIOD_SECONDS = 14 * 24 * 60 * 60;

/** 7-day voting window for disputed M-of-N commitments (`7 * 24 * 60 * 60 = 604_800`). */
export const ATTESTOR_VOTE_TIMEOUT_SECONDS = 7 * 24 * 60 * 60;

/** 10% stake slashing rate applied to dissenting panel voters when quorum resolves. */
export const SLASH_PERCENT = 10;

export type DisputeVoteOutcome = 'Fulfilled' | 'Late' | 'Breached';

export interface AttestorStakeInfo {
  attestor: string;
  staked: bigint;
  unbondingUntil: number | null;
  locked: boolean;
  canFinalizeUnstake: boolean;
  remainingUnbondingSeconds: number;
}

export interface ActiveDisputeAssignment {
  commitmentId: number;
  issuer: string;
  counterparty: string;
  attestors: string[];
  voteThreshold: number;
  votesCast: {
    fulfilled: number;
    late: number;
    breached: number;
  };
  deadlineSeconds: number;
  hasVoted?: boolean;
  votedOutcome?: DisputeVoteOutcome;
}

export function formatUnbondingCountdown(
  unbondingUntilSeconds: number | null,
  nowSeconds = Math.floor(Date.now() / 1000),
): {
  remainingSeconds: number;
  canFinalize: boolean;
  progressPercent: number;
  label: string;
} {
  if (unbondingUntilSeconds === null || unbondingUntilSeconds <= 0) {
    return {
      remainingSeconds: 0,
      canFinalize: false,
      progressPercent: 0,
      label: 'No active unbonding request',
    };
  }

  const remaining = Math.max(0, unbondingUntilSeconds - nowSeconds);
  if (remaining === 0) {
    return {
      remainingSeconds: 0,
      canFinalize: true,
      progressPercent: 100,
      label: 'Unbonding complete — Ready to withdraw',
    };
  }

  const days = Math.floor(remaining / 86_400);
  const hours = Math.floor((remaining % 86_400) / 3_600);
  const minutes = Math.floor((remaining % 3_600) / 60);
  const elapsed = Math.max(0, UNBONDING_PERIOD_SECONDS - remaining);
  const progressPercent = Math.min(99, Math.round((elapsed / UNBONDING_PERIOD_SECONDS) * 100));

  return {
    remainingSeconds: remaining,
    canFinalize: false,
    progressPercent,
    label: `${days}d ${hours}h ${minutes}m remaining`,
  };
}

export function calculateSlashedBalance(
  stakedAmount: bigint,
  slashPercent = SLASH_PERCENT,
): {
  slashedCut: bigint;
  remainingStake: bigint;
} {
  if (stakedAmount <= 0n || slashPercent <= 0) {
    return { slashedCut: 0n, remainingStake: stakedAmount > 0n ? stakedAmount : 0n };
  }
  const pct = BigInt(Math.min(100, Math.max(0, slashPercent)));
  const slashedCut = (stakedAmount * pct) / 100n;
  const remainingStake = stakedAmount - slashedCut;
  return { slashedCut, remainingStake };
}

export async function fetchAttestorStakeInfo(
  attestorAddress: string,
  options: ReputationQueryOptions & { nowSeconds?: number } = {},
): Promise<AttestorStakeInfo> {
  const contractId =
    options.contractId || import.meta.env.VITE_PACTUM_CONTRACT_ID || DEFAULT_CONTRACT_ID;
  const networkPassphrase =
    options.networkPassphrase ||
    import.meta.env.VITE_STELLAR_NETWORK_PASSPHRASE ||
    DEFAULT_NETWORK_PASSPHRASE;
  const pool = getOrCreatePool(resolveSorobanRpcUrls(options.rpcUrls, options.rpcUrl));
  const contract = new Contract(contractId);
  const source = new Account(Keypair.random().publicKey(), '0');

  const transaction = new TransactionBuilder(source, {
    fee: BASE_FEE,
    networkPassphrase,
  })
    .addOperation(
      contract.call('get_stake_info', nativeToScVal(attestorAddress, { type: 'address' })),
    )
    .setTimeout(30)
    .build();

  const simulation = await pool.simulateTransaction(transaction);
  if (rpc.Api.isSimulationError(simulation)) {
    const diagnosticBlobs = extractDiagnosticEventBlobs(simulation);
    const decoded = decodeSimulationError(simulation.error, diagnosticBlobs, 'get_stake_info');
    throw new SorobanSimulationError(
      decoded.message ?? `Failed to read attestor stake info: ${simulation.error}`,
      simulation.error,
      diagnosticBlobs,
      'get_stake_info',
    );
  }
  if (!simulation.result) {
    throw new Error('Direct Soroban query returned no stake info');
  }

  const raw = (scValToNative(simulation.result.retval) ?? {}) as Record<string, unknown>;
  const stakedRaw = raw.staked ?? 0;
  const staked = typeof stakedRaw === 'bigint' ? stakedRaw : BigInt(String(stakedRaw));
  const unbondingRaw = raw.unbonding_until ?? raw.unbondingUntil ?? null;
  const unbondingUntil =
    unbondingRaw === null || unbondingRaw === undefined ? null : Number(unbondingRaw);
  const locked = Boolean(raw.locked);

  const countdown = formatUnbondingCountdown(unbondingUntil, options.nowSeconds);

  return {
    attestor: attestorAddress,
    staked,
    unbondingUntil,
    locked,
    canFinalizeUnstake: countdown.canFinalize && !locked && staked > 0n,
    remainingUnbondingSeconds: countdown.remainingSeconds,
  };
}

async function executeAttestorContractTx({
  methodName,
  args,
  signerAddress,
  walletProvider = 'freighter',
  rpcUrls,
  rpcUrl,
  contractId = import.meta.env.VITE_PACTUM_CONTRACT_ID || DEFAULT_CONTRACT_ID,
  networkPassphrase = import.meta.env.VITE_STELLAR_NETWORK_PASSPHRASE || DEFAULT_NETWORK_PASSPHRASE,
  onStatusUpdate,
}: {
  methodName: string;
  args: xdr.ScVal[];
  signerAddress: string;
  walletProvider?: WalletProvider;
  rpcUrls?: string[];
  rpcUrl?: string;
  contractId?: string;
  networkPassphrase?: string;
  onStatusUpdate?: (msg: string) => void;
}): Promise<{ hash: string; status: 'SUCCESS' }> {
  onStatusUpdate?.(`Preparing ${methodName} transaction...`);
  const pool = getOrCreatePool(resolveSorobanRpcUrls(rpcUrls, rpcUrl), onStatusUpdate);
  const account = await pool.getAccount(signerAddress);
  const contract = new Contract(contractId);

  const tx = new TransactionBuilder(account, {
    fee: BASE_FEE,
    networkPassphrase,
  })
    .addOperation(contract.call(methodName, ...args))
    .setTimeout(60)
    .build();

  const preparedTx = await pool.prepareTransaction(tx);
  const unsignedXdr = preparedTx.toXDR();

  let signedXdr = '';
  if (walletProvider === 'ledger') {
    onStatusUpdate?.('Awaiting signature on Ledger device...');
    signedXdr = await signTransactionWithLedger(unsignedXdr, networkPassphrase);
  } else if (walletProvider === 'web3auth') {
    onStatusUpdate?.('Signing with social-login Stellar key...');
    const { signTransactionWithWeb3Auth } = await import('./web3auth');
    signedXdr = signTransactionWithWeb3Auth(unsignedXdr, networkPassphrase);
  } else {
    onStatusUpdate?.('Awaiting signature in Freighter wallet...');
    const signResult = await signTransaction(unsignedXdr, {
      networkPassphrase,
      address: signerAddress,
    });
    if (typeof signResult === 'string') {
      signedXdr = signResult;
    } else if (signResult && typeof signResult === 'object') {
      if ((signResult as any).error) {
        throw new Error(`Freighter signing rejected: ${(signResult as any).error}`);
      }
      signedXdr =
        (signResult as any).signedTxXdr ||
        (signResult as any).signedXdr ||
        (signResult as any).signedTransaction ||
        '';
    }
  }

  if (!signedXdr) {
    throw new Error('Transaction signing was cancelled or denied.');
  }

  onStatusUpdate?.('Submitting transaction to Stellar Testnet...');
  const signedTx = TransactionBuilder.fromXDR(signedXdr, networkPassphrase);
  const sendResult = await pool.sendTransaction(signedTx);
  if (sendResult.status === 'ERROR' || sendResult.errorResult) {
    throw new Error(`RPC submission error: ${sendResult.errorResult || sendResult.status}`);
  }

  const txHash = sendResult.hash;
  let attempts = 0;
  while (attempts < 25) {
    attempts++;
    const txResult = await pool.getTransaction(txHash);
    if (txResult.status === rpc.Api.GetTransactionStatus.SUCCESS) {
      return { hash: txHash, status: 'SUCCESS' };
    }
    if (txResult.status === rpc.Api.GetTransactionStatus.FAILED) {
      throw new Error(`Transaction execution failed on Stellar Testnet. Hash: ${txHash}`);
    }
    await new Promise((r) => setTimeout(r, 500));
  }

  throw new Error(`Transaction confirmation timed out. Hash: ${txHash}`);
}

export async function submitStakeAttestor({
  attestorAddress,
  amountStroops,
  walletProvider = 'freighter',
  rpcUrls,
  rpcUrl,
  contractId,
  networkPassphrase,
  onStatusUpdate,
}: {
  attestorAddress: string;
  amountStroops: bigint | number | string;
  walletProvider?: WalletProvider;
  rpcUrls?: string[];
  rpcUrl?: string;
  contractId?: string;
  networkPassphrase?: string;
  onStatusUpdate?: (msg: string) => void;
}): Promise<{ hash: string; status: 'SUCCESS' }> {
  const amountBigInt =
    typeof amountStroops === 'bigint' ? amountStroops : BigInt(String(amountStroops));
  if (amountBigInt <= 0n) {
    throw new Error('Stake amount must be strictly greater than zero.');
  }

  return executeAttestorContractTx({
    methodName: 'stake_attestor',
    args: [
      Address.fromString(attestorAddress).toScVal(),
      nativeToScVal(amountBigInt, { type: 'i128' }),
    ],
    signerAddress: attestorAddress,
    walletProvider,
    rpcUrls,
    rpcUrl,
    contractId,
    networkPassphrase,
    onStatusUpdate,
  });
}

export async function submitRequestUnstake({
  attestorAddress,
  walletProvider = 'freighter',
  rpcUrls,
  rpcUrl,
  contractId,
  networkPassphrase,
  onStatusUpdate,
}: {
  attestorAddress: string;
  walletProvider?: WalletProvider;
  rpcUrls?: string[];
  rpcUrl?: string;
  contractId?: string;
  networkPassphrase?: string;
  onStatusUpdate?: (msg: string) => void;
}): Promise<{ hash: string; unbondingUntil: number; status: 'SUCCESS' }> {
  const res = await executeAttestorContractTx({
    methodName: 'request_unstake',
    args: [Address.fromString(attestorAddress).toScVal()],
    signerAddress: attestorAddress,
    walletProvider,
    rpcUrls,
    rpcUrl,
    contractId,
    networkPassphrase,
    onStatusUpdate,
  });
  const unbondingUntil = Math.floor(Date.now() / 1000) + UNBONDING_PERIOD_SECONDS;
  return { ...res, unbondingUntil };
}

export async function submitFinalizeUnstake({
  attestorAddress,
  walletProvider = 'freighter',
  rpcUrls,
  rpcUrl,
  contractId,
  networkPassphrase,
  onStatusUpdate,
}: {
  attestorAddress: string;
  walletProvider?: WalletProvider;
  rpcUrls?: string[];
  rpcUrl?: string;
  contractId?: string;
  networkPassphrase?: string;
  onStatusUpdate?: (msg: string) => void;
}): Promise<{ hash: string; status: 'SUCCESS' }> {
  return executeAttestorContractTx({
    methodName: 'finalize_unstake',
    args: [Address.fromString(attestorAddress).toScVal()],
    signerAddress: attestorAddress,
    walletProvider,
    rpcUrls,
    rpcUrl,
    contractId,
    networkPassphrase,
    onStatusUpdate,
  });
}

export async function submitCastDisputeVote({
  attestorAddress,
  commitmentId,
  outcome,
  walletProvider = 'freighter',
  rpcUrls,
  rpcUrl,
  contractId,
  networkPassphrase,
  onStatusUpdate,
}: {
  attestorAddress: string;
  commitmentId: number | bigint;
  outcome: DisputeVoteOutcome;
  walletProvider?: WalletProvider;
  rpcUrls?: string[];
  rpcUrl?: string;
  contractId?: string;
  networkPassphrase?: string;
  onStatusUpdate?: (msg: string) => void;
}): Promise<{ hash: string; status: 'SUCCESS' }> {
  return executeAttestorContractTx({
    methodName: 'cast_dispute_vote',
    args: [
      Address.fromString(attestorAddress).toScVal(),
      xdr.ScVal.scvU64(xdr.Uint64.fromString(String(commitmentId))),
      xdr.ScVal.scvVec([xdr.ScVal.scvSymbol(outcome)]),
    ],
    signerAddress: attestorAddress,
    walletProvider,
    rpcUrls,
    rpcUrl,
    contractId,
    networkPassphrase,
    onStatusUpdate,
  });
}

export async function submitCheckDisputeTimeout({
  callerAddress,
  commitmentId,
  walletProvider = 'freighter',
  rpcUrls,
  rpcUrl,
  contractId,
  networkPassphrase,
  onStatusUpdate,
}: {
  callerAddress: string;
  commitmentId: number | bigint;
  walletProvider?: WalletProvider;
  rpcUrls?: string[];
  rpcUrl?: string;
  contractId?: string;
  networkPassphrase?: string;
  onStatusUpdate?: (msg: string) => void;
}): Promise<{ hash: string; status: 'SUCCESS' }> {
  return executeAttestorContractTx({
    methodName: 'check_dispute_timeout',
    args: [xdr.ScVal.scvU64(xdr.Uint64.fromString(String(commitmentId)))],
    signerAddress: callerAddress,
    walletProvider,
    rpcUrls,
    rpcUrl,
    contractId,
    networkPassphrase,
    onStatusUpdate,
  });
}
