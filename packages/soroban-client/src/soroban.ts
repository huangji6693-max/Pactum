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
import {
  signTransactionWithFreighter,
  signTransactionWithLedger,
  signTransactionWithAlbedo,
  signTransactionWithWeb3AuthAdapter,
  type WalletProvider,
} from './walletAdapters';
import { decodeSimulationError, isSorobanXdrError, type DecodedXdrError } from './xdrDecode';
import { SorobanRpcPool } from './sorobanRpcPool';

function getEnv(key: string): string | undefined {
  try {
    const metaEnv = (import.meta as unknown as { env?: Record<string, string | undefined> })?.env;
    if (metaEnv && typeof metaEnv[key] === 'string' && metaEnv[key]!.trim()) {
      return metaEnv[key]!.trim();
    }
  } catch {
    // ignore
  }
  if (
    typeof process !== 'undefined' &&
    process.env &&
    typeof process.env[key] === 'string' &&
    process.env[key]!.trim()
  ) {
    return process.env[key]!.trim();
  }
  return undefined;
}

export const DEFAULT_SOROBAN_RPC_URLS: string[] = ['https://soroban-testnet.stellar.org'];
export const DEFAULT_SOROBAN_RPC_URL = DEFAULT_SOROBAN_RPC_URLS[0];
export const DEFAULT_CONTRACT_ID = 'CBADTVTJ6IN332HIKZ7LWUYMYTLPZYCEBV3X2HS47VHR5UDBHQ3GAA7E';
export const DEFAULT_NETWORK_PASSPHRASE = Networks.TESTNET;

export interface Reputation {
  address: string;
  fulfilled: number;
  late: number;
  breached: number;
  total: number;
}

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

export function extractDiagnosticEventBlobs(
  simulationResult: rpc.Api.SimulateTransactionErrorResponse | any,
): string[] {
  const blobs: string[] = [];

  if (!simulationResult || typeof simulationResult !== 'object') {
    return blobs;
  }

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

export function resolveSorobanRpcUrls(rpcUrls?: string[], rpcUrl?: string): string[] {
  if (rpcUrls && rpcUrls.length > 0) {
    const deduped = dedupeRpcUrls(rpcUrls);
    if (deduped.length > 0) return deduped;
  }
  if (rpcUrl && rpcUrl.trim()) {
    return [rpcUrl.trim()];
  }
  const envList = getEnv('VITE_SOROBAN_RPC_URLS');
  if (envList) {
    return dedupeRpcUrls(
      envList
        .split(',')
        .map((u) => u.trim())
        .filter(Boolean),
    );
  }
  const envSingle = getEnv('VITE_SOROBAN_RPC_URL');
  if (envSingle) {
    return [envSingle];
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

const poolCache = new Map<string, SorobanRpcPool>();
const statusListeners = new Map<string, Set<(statusMessage: string) => void>>();
const MAX_STATUS_LISTENERS = 8;

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
        for (const listener of statusListeners.get(key) ?? []) {
          try {
            listener(`RPC node unavailable (${reason}). Retrying on a backup node...`);
          } catch {
            // ignore
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
    while (listeners.size > MAX_STATUS_LISTENERS) {
      const oldest = listeners.values().next().value;
      if (oldest === undefined) break;
      listeners.delete(oldest);
    }
  }
  return pool;
}

export interface CreateCommitmentParams {
  issuerAddress: string;
  counterpartyAddress: string;
  termsHashHex: string;
  dueAtSeconds: number;
  rpcUrls?: string[];
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
  feeStroops: string;
  feeXlm: string;
  cpuInsns: string;
  memBytes: string;
}

export interface SimulationPreview {
  success: boolean;
  error?: string;
  cost?: SimulationCost;
  requiredAuths: string[];
  rawSimulation: rpc.Api.SimulateTransactionResponse;
}

export interface TrustedLedgerAnchor {
  hash: string;
  sequence: number;
}

export interface SorobanReadOptions {
  rpcUrls?: string[];
  rpcUrl?: string;
}

export interface ReputationQueryOptions extends SorobanReadOptions {
  contractId?: string;
  networkPassphrase?: string;
}

export async function fetchLatestLedgerAnchor(
  optionsOrRpcUrl: SorobanReadOptions | string = {},
): Promise<TrustedLedgerAnchor> {
  const options: SorobanReadOptions =
    typeof optionsOrRpcUrl === 'string' ? { rpcUrl: optionsOrRpcUrl } : optionsOrRpcUrl;
  const pool = getOrCreatePool(resolveSorobanRpcUrls(options.rpcUrls, options.rpcUrl));
  const ledger = await pool.getLatestLedger();

  if (!ledger.id || !ledger.sequence) {
    throw new Error('Soroban RPC returned an incomplete latest-ledger response');
  }

  return { hash: ledger.id, sequence: ledger.sequence };
}

export async function preflightSimulate(
  tx: ReturnType<TransactionBuilder['build']>,
  rpcUrl = getEnv('VITE_SOROBAN_RPC_URL') || DEFAULT_SOROBAN_RPC_URL,
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

  const feeStroops = simulation.minResourceFee ?? '0';
  const feeXlm = (Number(feeStroops) / 10_000_000).toFixed(7);

  const cost: SimulationCost = {
    feeStroops,
    feeXlm,
    cpuInsns: (simulation as any).cost?.cpuInsns ?? '0',
    memBytes: (simulation as any).cost?.memBytes ?? '0',
  };

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
          const pubKeyBytes = addrCreds.address().accountId().ed25519();
          const hexPrefix = Array.from(pubKeyBytes as Uint8Array)
            .slice(0, 4)
            .map((b) => b.toString(16).padStart(2, '0'))
            .join('');
          requiredAuths.push(`${hexPrefix}...`);
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

export async function fetchArbitrator(
  rpcUrlsOrUrl?: string[] | string,
  rpcUrlOrContractId?: string,
  contractIdArg?: string,
  networkPassphraseArg?: string,
): Promise<string> {
  let rpcUrls: string[] | undefined;
  let rpcUrl: string | undefined;
  let contractId: string;
  let networkPassphrase: string;

  if (Array.isArray(rpcUrlsOrUrl)) {
    rpcUrls = rpcUrlsOrUrl;
    rpcUrl = rpcUrlOrContractId;
    contractId = contractIdArg || getEnv('VITE_PACTUM_CONTRACT_ID') || DEFAULT_CONTRACT_ID;
    networkPassphrase =
      networkPassphraseArg ||
      getEnv('VITE_STELLAR_NETWORK_PASSPHRASE') ||
      DEFAULT_NETWORK_PASSPHRASE;
  } else if (typeof rpcUrlsOrUrl === 'string') {
    rpcUrl = rpcUrlsOrUrl;
    contractId = rpcUrlOrContractId || getEnv('VITE_PACTUM_CONTRACT_ID') || DEFAULT_CONTRACT_ID;
    networkPassphrase =
      contractIdArg || getEnv('VITE_STELLAR_NETWORK_PASSPHRASE') || DEFAULT_NETWORK_PASSPHRASE;
  } else {
    rpcUrls = undefined;
    rpcUrl = rpcUrlOrContractId;
    contractId = contractIdArg || getEnv('VITE_PACTUM_CONTRACT_ID') || DEFAULT_CONTRACT_ID;
    networkPassphrase =
      networkPassphraseArg ||
      getEnv('VITE_STELLAR_NETWORK_PASSPHRASE') ||
      DEFAULT_NETWORK_PASSPHRASE;
  }

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
  optionsOrRpcUrl: ReputationQueryOptions | string = {},
  contractIdArg?: string,
  networkPassphraseArg?: string,
): Promise<Reputation> {
  const options: ReputationQueryOptions =
    typeof optionsOrRpcUrl === 'string'
      ? {
          rpcUrl: optionsOrRpcUrl,
          contractId: contractIdArg,
          networkPassphrase: networkPassphraseArg,
        }
      : optionsOrRpcUrl;

  const contractId =
    options.contractId || getEnv('VITE_PACTUM_CONTRACT_ID') || DEFAULT_CONTRACT_ID;
  const networkPassphrase =
    options.networkPassphrase ||
    getEnv('VITE_STELLAR_NETWORK_PASSPHRASE') ||
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

export async function submitCreateCommitment({
  issuerAddress,
  counterpartyAddress,
  termsHashHex,
  dueAtSeconds,
  rpcUrls,
  rpcUrl,
  contractId = getEnv('VITE_PACTUM_CONTRACT_ID') || DEFAULT_CONTRACT_ID,
  networkPassphrase = getEnv('VITE_STELLAR_NETWORK_PASSPHRASE') || DEFAULT_NETWORK_PASSPHRASE,
  onStatusUpdate,
  walletProvider = 'freighter',
}: CreateCommitmentParams): Promise<CreateCommitmentResult> {
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

  onStatusUpdate?.('Initializing Soroban RPC connection pool...');
  const pool = getOrCreatePool(resolveSorobanRpcUrls(rpcUrls, rpcUrl), onStatusUpdate);

  onStatusUpdate?.('Encoding contract parameters...');
  const issuerScVal = Address.fromString(issuerAddress).toScVal();
  const counterpartyScVal = Address.fromString(counterpartyAddress).toScVal();
  const termsHashBytes = hexToBytes(termsHashHex);
  const termsHashScVal = xdr.ScVal.scvBytes(termsHashBytes as unknown as Buffer);
  const dueAtScVal = xdr.ScVal.scvU64(xdr.Uint64.fromString(dueAtSeconds.toString()));

  onStatusUpdate?.('Fetching registry arbitrator...');
  const arbitratorAddress = await fetchArbitrator(rpcUrls, rpcUrl, contractId, networkPassphrase);
  const resolverScVal = Address.fromString(arbitratorAddress).toScVal();
  const oracleScVal = xdr.ScVal.scvVoid();
  const schemaIdScVal = xdr.ScVal.scvVoid();
  const attestorsScVal = xdr.ScVal.scvVec([]);
  const voteThresholdScVal = xdr.ScVal.scvU32(0);

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

  let signedXdr = '';

  if (walletProvider === 'ledger') {
    onStatusUpdate?.('Awaiting signature on Ledger device (confirm on-screen)...');
    signedXdr = await signTransactionWithLedger(unsignedXdr, networkPassphrase);
  } else if (walletProvider === 'web3auth') {
    onStatusUpdate?.('Signing with your social-login Stellar key...');
    signedXdr = await signTransactionWithWeb3AuthAdapter(unsignedXdr, networkPassphrase);
  } else if (walletProvider === 'albedo') {
    onStatusUpdate?.('Awaiting signature in Albedo wallet...');
    signedXdr = await signTransactionWithAlbedo(unsignedXdr, networkPassphrase);
  } else {
    onStatusUpdate?.('Awaiting signature in Freighter wallet...');
    signedXdr = await signTransactionWithFreighter(unsignedXdr, networkPassphrase, issuerAddress);
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
  onStatusUpdate?.(`Transaction submitted! Confirming hash ${txHash.substring(0, 10)}...`);

  let txStatus: rpc.Api.GetTransactionStatus = rpc.Api.GetTransactionStatus.NOT_FOUND;
  let txResult: rpc.Api.GetTransactionResponse | null = null;
  let attempts = 0;

  while (attempts < 45) {
    attempts++;
    await new Promise((resolve) => setTimeout(resolve, 1200));
    txResult = await pool.getTransaction(txHash);
    txStatus = txResult.status;

    if (txStatus === rpc.Api.GetTransactionStatus.SUCCESS) {
      break;
    } else if (txStatus === rpc.Api.GetTransactionStatus.FAILED) {
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
      const enrichedMessage = `Transaction execution failed on Stellar Testnet. Hash: ${txHash}`;
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
