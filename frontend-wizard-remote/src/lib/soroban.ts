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
import { signTransaction } from '@stellar/freighter-api';
import { signTransactionWithLedger } from './wallet-adapters/ledger-adapter';
import type { WalletProvider } from './wallet';
import { decodeSimulationError, isSorobanXdrError } from './xdrDecode';
import type { DecodedXdrError } from './xdrDecode';

export const DEFAULT_SOROBAN_RPC_URL = 'https://soroban-testnet.stellar.org';
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

export interface CreateCommitmentParams {
  issuerAddress: string;
  counterpartyAddress: string;
  termsHashHex: string;
  dueAtSeconds: number;
  attestors?: string[];
  voteThreshold?: number;
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

export interface TrustedLedgerAnchor {
  hash: string;
  sequence: number;
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

export async function fetchLatestLedgerAnchor(
  rpcUrl = import.meta.env.VITE_SOROBAN_RPC_URL || DEFAULT_SOROBAN_RPC_URL,
): Promise<TrustedLedgerAnchor> {
  const server = new rpc.Server(rpcUrl, { allowHttp: true });
  const ledger = await server.getLatestLedger();

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
  rpcUrl = import.meta.env.VITE_SOROBAN_RPC_URL || DEFAULT_SOROBAN_RPC_URL,
  contractId = import.meta.env.VITE_PACTUM_CONTRACT_ID || DEFAULT_CONTRACT_ID,
  networkPassphrase = import.meta.env.VITE_STELLAR_NETWORK_PASSPHRASE || DEFAULT_NETWORK_PASSPHRASE,
): Promise<string> {
  const server = new rpc.Server(rpcUrl, { allowHttp: true });
  const contract = new Contract(contractId);
  const source = new Account(Keypair.random().publicKey(), '0');
  const transaction = new TransactionBuilder(source, {
    fee: BASE_FEE,
    networkPassphrase,
  })
    .addOperation(contract.call('get_arbitrator'))
    .setTimeout(30)
    .build();

  const simulation = await server.simulateTransaction(transaction);
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
  rpcUrl = import.meta.env.VITE_SOROBAN_RPC_URL || DEFAULT_SOROBAN_RPC_URL,
  contractId = import.meta.env.VITE_PACTUM_CONTRACT_ID || DEFAULT_CONTRACT_ID,
  networkPassphrase = import.meta.env.VITE_STELLAR_NETWORK_PASSPHRASE || DEFAULT_NETWORK_PASSPHRASE,
): Promise<Reputation> {
  const server = new rpc.Server(rpcUrl, { allowHttp: true });
  const contract = new Contract(contractId);
  const source = new Account(Keypair.random().publicKey(), '0');
  const transaction = new TransactionBuilder(source, {
    fee: BASE_FEE,
    networkPassphrase,
  })
    .addOperation(contract.call('get_reputation', nativeToScVal(address, { type: 'address' })))
    .setTimeout(30)
    .build();

  const simulation = await server.simulateTransaction(transaction);
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
 */
export async function submitCreateCommitment({
  issuerAddress,
  counterpartyAddress,
  termsHashHex,
  dueAtSeconds,
  attestors,
  voteThreshold,
  rpcUrl = import.meta.env.VITE_SOROBAN_RPC_URL || DEFAULT_SOROBAN_RPC_URL,
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

  onStatusUpdate?.('Initializing Soroban RPC connection...');
  const server = new rpc.Server(rpcUrl, { allowHttp: true });

  // 2. Convert Arguments to ScVal
  onStatusUpdate?.('Encoding contract parameters...');
  const issuerScVal = Address.fromString(issuerAddress).toScVal();
  const counterpartyScVal = Address.fromString(counterpartyAddress).toScVal();
  const termsHashBytes = hexToBytes(termsHashHex);
  // `scvBytes` accepts any Uint8Array at runtime — the `Buffer` param type is just its TS
  // signature (same pattern as lib/crdt/signing.ts's verifyMessage cast in the host).
  const termsHashScVal = xdr.ScVal.scvBytes(termsHashBytes as unknown as Buffer);
  const dueAtScVal = xdr.ScVal.scvU64(xdr.Uint64.fromString(dueAtSeconds.toString()));

  // create_commitment requires a resolver_address; the wizard's UI has no concept of a custom
  // dispute resolver yet, so read the registry's own arbitrator and use that (see
  // fetchArbitrator's doc comment for why this -- not issuer/counterparty -- is the safe default).
  onStatusUpdate?.('Fetching registry arbitrator...');
  const arbitratorAddress = await fetchArbitrator(rpcUrl, contractId, networkPassphrase);
  const resolverScVal = Address.fromString(arbitratorAddress).toScVal();
  // oracle and schema_id are both genuinely optional (Option<Address>/Option<u32>) with no
  // downstream code assuming they're populated; the wizard doesn't collect either yet.
  const oracleScVal = xdr.ScVal.scvVoid();
  const schemaIdScVal = xdr.ScVal.scvVoid();
  // Empty attestors + a 0 threshold is the contract's explicitly-designed "no voting panel, use
  // the single-resolver dispute path" state (contracts/registry/src/commitments.rs::create).
  const normalizedAttestors = (attestors ?? []).map((a) => a.trim()).filter(Boolean);
  const resolvedThreshold =
    normalizedAttestors.length > 0 ? Math.max(1, Number(voteThreshold ?? 1)) : 0;
  if (normalizedAttestors.length > 0 && resolvedThreshold > normalizedAttestors.length) {
    throw new Error(
      `Vote threshold (${resolvedThreshold}) cannot exceed attestor panel size (${normalizedAttestors.length}).`,
    );
  }
  const attestorsScVal = xdr.ScVal.scvVec(
    normalizedAttestors.map((addr) => Address.fromString(addr).toScVal()),
  );
  const voteThresholdScVal = xdr.ScVal.scvU32(resolvedThreshold);

  // 3. Build Transaction Envelope
  onStatusUpdate?.('Fetching sequence number for issuer account...');
  let account: any = null;
  try {
    account = await server.getAccount(issuerAddress);
  } catch (err: any) {
    const errStr = String(err?.message || err).toLowerCase();
    if (errStr.includes('not found') || errStr.includes('404') || errStr.includes('account')) {
      onStatusUpdate?.('Issuer account unfunded on Testnet. Auto-funding via Stellar Friendbot...');
      const funded = await fundTestnetAccount(issuerAddress);
      if (funded) {
        onStatusUpdate?.('Account funded! Re-fetching sequence number...');
        await new Promise((resolve) => setTimeout(resolve, 1500));
        try {
          account = await server.getAccount(issuerAddress);
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
  let preparedTx: Awaited<ReturnType<typeof server.prepareTransaction>>;
  try {
    preparedTx = await server.prepareTransaction(tx);
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

  // 5. Prompt the connected wallet for a signature
  let signedXdr = '';

  if (walletProvider === 'ledger') {
    onStatusUpdate?.('Awaiting signature on Ledger device (confirm on-screen)...');
    signedXdr = await signTransactionWithLedger(unsignedXdr, networkPassphrase);
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
  const sendResult = await server.sendTransaction(signedTx);

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
    txResult = await server.getTransaction(txHash);
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
