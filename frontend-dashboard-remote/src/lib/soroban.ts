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

export const DEFAULT_SOROBAN_RPC_URL = 'https://soroban-testnet.stellar.org';
export const DEFAULT_CONTRACT_ID = 'CBADTVTJ6IN332HIKZ7LWUYMYTLPZYCEBV3X2HS47VHR5UDBHQ3GAA7E';
export const DEFAULT_NETWORK_PASSPHRASE = Networks.TESTNET;

export interface CreateCommitmentParams {
  issuerAddress: string;
  counterpartyAddress: string;
  termsHashHex: string;
  dueAtSeconds: number;
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
    throw new Error(`Failed to read registry arbitrator: ${simulation.error}`);
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
    throw new Error(`Direct Soroban query failed: ${simulation.error}`);
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
  const attestorsScVal = xdr.ScVal.scvVec([]);
  const voteThresholdScVal = xdr.ScVal.scvU32(0);

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
  const preparedTx = await server.prepareTransaction(tx);

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
      signedXdr = (signResult as any).signedTxXdr || (signResult as any).signedXdr || '';
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

  while (attempts < 25) {
    attempts++;
    await new Promise((resolve) => setTimeout(resolve, 1200));
    txResult = await server.getTransaction(txHash);
    txStatus = txResult.status;

    if (txStatus === rpc.Api.GetTransactionStatus.SUCCESS) {
      break;
    } else if (txStatus === rpc.Api.GetTransactionStatus.FAILED) {
      throw new Error(`Transaction execution failed on Stellar Testnet. Hash: ${txHash}`);
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

export const UNBONDING_PERIOD_SECONDS = 14 * 24 * 60 * 60;
export const ATTESTOR_VOTE_TIMEOUT_SECONDS = 7 * 24 * 60 * 60;
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
  options: {
    rpcUrl?: string;
    contractId?: string;
    networkPassphrase?: string;
    nowSeconds?: number;
  } = {},
): Promise<AttestorStakeInfo> {
  const rpcUrl = options.rpcUrl || import.meta.env.VITE_SOROBAN_RPC_URL || DEFAULT_SOROBAN_RPC_URL;
  const contractId =
    options.contractId || import.meta.env.VITE_PACTUM_CONTRACT_ID || DEFAULT_CONTRACT_ID;
  const networkPassphrase =
    options.networkPassphrase ||
    import.meta.env.VITE_STELLAR_NETWORK_PASSPHRASE ||
    DEFAULT_NETWORK_PASSPHRASE;
  const server = new rpc.Server(rpcUrl, { allowHttp: true });
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

  const simulation = await server.simulateTransaction(transaction);
  if (rpc.Api.isSimulationError(simulation)) {
    throw new Error(`Failed to read attestor stake info: ${simulation.error}`);
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
  rpcUrl = import.meta.env.VITE_SOROBAN_RPC_URL || DEFAULT_SOROBAN_RPC_URL,
  contractId = import.meta.env.VITE_PACTUM_CONTRACT_ID || DEFAULT_CONTRACT_ID,
  networkPassphrase = import.meta.env.VITE_STELLAR_NETWORK_PASSPHRASE || DEFAULT_NETWORK_PASSPHRASE,
  onStatusUpdate,
}: {
  methodName: string;
  args: xdr.ScVal[];
  signerAddress: string;
  walletProvider?: WalletProvider;
  rpcUrl?: string;
  contractId?: string;
  networkPassphrase?: string;
  onStatusUpdate?: (msg: string) => void;
}): Promise<{ hash: string; status: 'SUCCESS' }> {
  onStatusUpdate?.(`Preparing ${methodName} transaction...`);
  const server = new rpc.Server(rpcUrl, { allowHttp: true });
  const account = await server.getAccount(signerAddress);
  const contract = new Contract(contractId);

  const tx = new TransactionBuilder(account, {
    fee: BASE_FEE,
    networkPassphrase,
  })
    .addOperation(contract.call(methodName, ...args))
    .setTimeout(60)
    .build();

  const preparedTx = await server.prepareTransaction(tx);
  const unsignedXdr = preparedTx.toXDR();

  let signedXdr = '';
  if (walletProvider === 'ledger') {
    onStatusUpdate?.('Awaiting signature on Ledger device...');
    signedXdr = await signTransactionWithLedger(unsignedXdr, networkPassphrase);
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
  const sendResult = await server.sendTransaction(signedTx);
  if (sendResult.status === 'ERROR' || sendResult.errorResult) {
    throw new Error(`RPC submission error: ${sendResult.errorResult || sendResult.status}`);
  }

  const txHash = sendResult.hash;
  let attempts = 0;
  while (attempts < 25) {
    attempts++;
    const txResult = await server.getTransaction(txHash);
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
  rpcUrl,
  contractId,
  networkPassphrase,
  onStatusUpdate,
}: {
  attestorAddress: string;
  amountStroops: bigint | number | string;
  walletProvider?: WalletProvider;
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
    rpcUrl,
    contractId,
    networkPassphrase,
    onStatusUpdate,
  });
}

export async function submitRequestUnstake({
  attestorAddress,
  walletProvider = 'freighter',
  rpcUrl,
  contractId,
  networkPassphrase,
  onStatusUpdate,
}: {
  attestorAddress: string;
  walletProvider?: WalletProvider;
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
  rpcUrl,
  contractId,
  networkPassphrase,
  onStatusUpdate,
}: {
  attestorAddress: string;
  walletProvider?: WalletProvider;
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
  rpcUrl,
  contractId,
  networkPassphrase,
  onStatusUpdate,
}: {
  attestorAddress: string;
  commitmentId: number | bigint;
  outcome: DisputeVoteOutcome;
  walletProvider?: WalletProvider;
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
    rpcUrl,
    contractId,
    networkPassphrase,
    onStatusUpdate,
  });
}
