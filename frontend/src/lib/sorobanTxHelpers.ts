import { Contract, rpc, TransactionBuilder, xdr } from '@stellar/stellar-sdk';
import { signTransaction } from '@stellar/freighter-api';
import type { WalletProvider } from './wallet';
import { signTransactionWithLedger } from './wallet-adapters/ledger-adapter';
import {
  SorobanSimulationError,
  extractDiagnosticEventBlobs,
  resolveSorobanRpcUrls,
  DEFAULT_NETWORK_PASSPHRASE,
  DEFAULT_CONTRACT_ID,
  getOrCreatePool,
} from './soroban';
import {
  decodeSimulationError,
  decodePartialTransactionEnvelope,
  type ConfiguredSignerWeight,
  type DecodedPartialEnvelope,
} from './xdrDecode';

const BASE_FEE = '100000';

export async function submitGenericSorobanTx({
  methodName,
  args,
  signerAddress,
  walletProvider = 'freighter',
  onStatusUpdate,
  rpcUrls,
  rpcUrl,
  contractId = import.meta.env.VITE_PACTUM_CONTRACT_ID || DEFAULT_CONTRACT_ID,
  networkPassphrase = import.meta.env.VITE_STELLAR_NETWORK_PASSPHRASE || DEFAULT_NETWORK_PASSPHRASE,
}: {
  methodName: string;
  args: xdr.ScVal[];
  signerAddress: string;
  walletProvider?: WalletProvider;
  onStatusUpdate?: (msg: string) => void;
  /** Ordered list of Soroban RPC endpoints (connection pool). */
  rpcUrls?: string[];
  /** @deprecated Use `rpcUrls`. */
  rpcUrl?: string;
  contractId?: string;
  networkPassphrase?: string;
}) {
  onStatusUpdate?.('Initializing Soroban RPC connection pool...');
  const pool = getOrCreatePool(resolveSorobanRpcUrls(rpcUrls, rpcUrl), onStatusUpdate);

  onStatusUpdate?.('Fetching sequence number for account...');
  let account: any = null;
  try {
    account = await pool.getAccount(signerAddress);
  } catch {
    throw new Error(
      `Connected account (${signerAddress.substring(0, 8)}...) is not funded on Stellar Testnet.`,
    );
  }

  const contract = new Contract(contractId);
  const tx = new TransactionBuilder(account, { fee: BASE_FEE, networkPassphrase })
    .addOperation(contract.call(methodName, ...args))
    .setTimeout(60)
    .build();

  onStatusUpdate?.('Simulating transaction on Soroban RPC...');
  let preparedTx: Awaited<ReturnType<typeof pool.prepareTransaction>>;
  try {
    preparedTx = await pool.prepareTransaction(tx);
  } catch (prepareErr: unknown) {
    const errMsg = prepareErr instanceof Error ? prepareErr.message : String(prepareErr);
    const diagBlobs = extractDiagnosticEventBlobs({ error: errMsg });
    const decoded = decodeSimulationError(errMsg, diagBlobs, methodName);
    throw new SorobanSimulationError(
      decoded.message ?? `Transaction simulation failed: ${errMsg}`,
      errMsg,
      diagBlobs,
      methodName,
    );
  }
  const unsignedXdr = preparedTx.toXDR();

  let signedXdr = '';
  if (walletProvider === 'ledger') {
    onStatusUpdate?.('Awaiting signature on Ledger device...');
    signedXdr = await signTransactionWithLedger(unsignedXdr, networkPassphrase);
  } else if (walletProvider === 'web3auth') {
    onStatusUpdate?.('Signing with your social-login Stellar key...');
    const { signTransactionWithWeb3Auth } = await import('./web3auth');
    signedXdr = signTransactionWithWeb3Auth(unsignedXdr, networkPassphrase);
  } else {
    onStatusUpdate?.('Awaiting signature in Freighter wallet...');
    const signResult = await signTransaction(unsignedXdr, {
      networkPassphrase,
      address: signerAddress,
    });
    if (typeof signResult === 'string') signedXdr = signResult;
    else if (signResult && typeof signResult === 'object') {
      if ((signResult as any).error)
        throw new Error(`Freighter signing rejected: ${(signResult as any).error}`);
      signedXdr = (signResult as any).signedTxXdr || (signResult as any).signedXdr || '';
    }
  }

  if (!signedXdr) throw new Error('Transaction signing was cancelled.');

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
  while (attempts < 25) {
    attempts++;
    await new Promise((resolve) => setTimeout(resolve, 1200));
    txResult = await pool.getTransaction(txHash);
    txStatus = txResult.status;
    if (txStatus === rpc.Api.GetTransactionStatus.SUCCESS) break;
    else if (txStatus === rpc.Api.GetTransactionStatus.FAILED) {
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
      throw new SorobanSimulationError(
        `Transaction execution failed on Stellar Testnet. Hash: ${txHash}`,
        `Transaction execution failed on Stellar Testnet. Hash: ${txHash}`,
        diagBlobs,
        methodName,
      );
    }
  }

  if (txStatus !== rpc.Api.GetTransactionStatus.SUCCESS) {
    throw new Error(`Transaction confirmation timed out. Hash: ${txHash}`);
  }

  onStatusUpdate?.('Transaction confirmed successfully on-chain!');
  return { hash: txHash, status: 'SUCCESS' };
}

export async function submitAttest(
  id: number,
  outcome: string,
  signer: string,
  provider: WalletProvider,
  onStatusUpdate?: (msg: string) => void,
) {
  const args = [
    xdr.ScVal.scvU64(xdr.Uint64.fromString(id.toString())),
    xdr.ScVal.scvSymbol(outcome),
  ];
  return submitGenericSorobanTx({
    methodName: 'attest',
    args,
    signerAddress: signer,
    walletProvider: provider,
    onStatusUpdate,
  });
}

export async function submitDispute(
  id: number,
  reason: string,
  signer: string,
  provider: WalletProvider,
  onStatusUpdate?: (msg: string) => void,
) {
  const args = [
    xdr.ScVal.scvU64(xdr.Uint64.fromString(id.toString())),
    xdr.ScVal.scvString(reason),
  ];
  return submitGenericSorobanTx({
    methodName: 'dispute',
    args,
    signerAddress: signer,
    walletProvider: provider,
    onStatusUpdate,
  });
}

export async function submitResolve(
  id: number,
  outcome: string,
  signer: string,
  provider: WalletProvider,
  onStatusUpdate?: (msg: string) => void,
) {
  const args = [
    xdr.ScVal.scvU64(xdr.Uint64.fromString(id.toString())),
    xdr.ScVal.scvSymbol(outcome),
  ];
  return submitGenericSorobanTx({
    methodName: 'resolve_dispute',
    args,
    signerAddress: signer,
    walletProvider: provider,
    onStatusUpdate,
  });
}

export async function submitInitRegistry(
  signer: string,
  provider: WalletProvider,
  onStatusUpdate?: (msg: string) => void,
) {
  return submitGenericSorobanTx({
    methodName: 'init',
    args: [],
    signerAddress: signer,
    walletProvider: provider,
    onStatusUpdate,
  });
}

// ---------------------------------------------------------------------------
// Multi-Signature Partial XDR Coordination & Sharing Helpers (#300)
// ---------------------------------------------------------------------------

export interface MultiSigCoordinationBundle {
  version: 1;
  envelopeXdr: string;
  networkPassphrase: string;
  requiredThreshold: number;
  knownSigners: ConfiguredSignerWeight[];
  description?: string;
  createdAt: number;
}

/**
 * Merges signatures from a newly signed TransactionEnvelope XDR (or single
 * DecoratedSignature base64 XDR) into an existing partial TransactionEnvelope XDR,
 * deduplicating by signature bytes.
 */
export function appendSignatureToEnvelope(
  baseEnvelopeXdr: string,
  signedEnvelopeOrSignatureXdr: string,
  networkPassphrase = import.meta.env.VITE_STELLAR_NETWORK_PASSPHRASE || DEFAULT_NETWORK_PASSPHRASE,
): string {
  const baseTx = TransactionBuilder.fromXDR(baseEnvelopeXdr.trim(), networkPassphrase);
  const existingSigs = new Set(
    (baseTx.signatures ?? []).map((s) => Buffer.from(s.signature()).toString('base64')),
  );

  let incomingSigs: xdr.DecoratedSignature[] = [];
  try {
    const incomingTx = TransactionBuilder.fromXDR(
      signedEnvelopeOrSignatureXdr.trim(),
      networkPassphrase,
    );
    incomingSigs = incomingTx.signatures ?? [];
  } catch {
    const singleSig = xdr.DecoratedSignature.fromXDR(signedEnvelopeOrSignatureXdr.trim(), 'base64');
    incomingSigs = [singleSig];
  }

  for (const sig of incomingSigs) {
    const sigKey = Buffer.from(sig.signature()).toString('base64');
    if (!existingSigs.has(sigKey)) {
      baseTx.signatures.push(sig);
      existingSigs.add(sigKey);
    }
  }

  return baseTx.toXDR();
}

/**
 * Prompts the active wallet (Freighter, Ledger, or Web3Auth) to sign a partial
 * transaction envelope XDR and appends the resulting signature to the envelope.
 */
export async function signPartialTransactionEnvelope({
  envelopeXdr,
  signerAddress,
  walletProvider = 'freighter',
  networkPassphrase = import.meta.env.VITE_STELLAR_NETWORK_PASSPHRASE || DEFAULT_NETWORK_PASSPHRASE,
  onStatusUpdate,
}: {
  envelopeXdr: string;
  signerAddress: string;
  walletProvider?: WalletProvider;
  networkPassphrase?: string;
  onStatusUpdate?: (msg: string) => void;
}): Promise<string> {
  let signedXdr = '';
  if (walletProvider === 'ledger') {
    onStatusUpdate?.('Awaiting partial signature on Ledger device...');
    signedXdr = await signTransactionWithLedger(envelopeXdr, networkPassphrase);
  } else if (walletProvider === 'web3auth') {
    onStatusUpdate?.('Signing partial transaction with social-login Stellar key...');
    const { signTransactionWithWeb3Auth } = await import('./web3auth');
    signedXdr = signTransactionWithWeb3Auth(envelopeXdr, networkPassphrase);
  } else {
    onStatusUpdate?.('Awaiting partial signature in Freighter wallet...');
    const signResult = await signTransaction(envelopeXdr, {
      networkPassphrase,
      address: signerAddress,
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
    throw new Error('Partial transaction signing was cancelled.');
  }

  return appendSignatureToEnvelope(envelopeXdr, signedXdr, networkPassphrase);
}

/**
 * Compact URL-safe LZ-style dictionary + base64url encoder for shareable multi-sig coordination links.
 */
export function encodeShareableMultiSigPayload(bundle: MultiSigCoordinationBundle): string {
  const json = JSON.stringify(bundle);
  const bytes = new TextEncoder().encode(json);
  const b64 = Buffer.from(bytes).toString('base64');
  const b64Url = b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  return `msig1.${b64Url}`;
}

/**
 * Decodes a shareable multi-sig coordination payload or full URL (`?multisig=...`)
 * back into a `MultiSigCoordinationBundle`.
 */
export function decodeShareableMultiSigPayload(payloadOrUrl: string): MultiSigCoordinationBundle {
  let token = payloadOrUrl.trim();
  if (token.includes('multisig=')) {
    try {
      const url = new URL(token, 'https://pactum.app');
      token = url.searchParams.get('multisig') ?? token;
    } catch {
      const match = token.match(/[?&]multisig=([^&#]+)/);
      if (match) token = decodeURIComponent(match[1]);
    }
  }

  if (token.startsWith('msig1.')) {
    token = token.slice('msig1.'.length);
  }

  const normalizedB64 = token.replace(/-/g, '+').replace(/_/g, '/');
  const paddedB64 = normalizedB64.padEnd(
    normalizedB64.length + ((4 - (normalizedB64.length % 4)) % 4),
    '=',
  );
  const decodedJson = Buffer.from(paddedB64, 'base64').toString('utf-8');
  const parsed = JSON.parse(decodedJson) as MultiSigCoordinationBundle;
  if (!parsed || typeof parsed.envelopeXdr !== 'string' || !parsed.envelopeXdr.trim()) {
    throw new Error('Invalid multi-signature coordination payload');
  }
  return parsed;
}

export function buildMultiSigShareUrl(
  bundle: MultiSigCoordinationBundle,
  baseUrl: string = typeof window !== 'undefined'
    ? window.location.origin + window.location.pathname
    : 'https://pactum.app/',
): string {
  const token = encodeShareableMultiSigPayload(bundle);
  const separator = baseUrl.includes('?') ? '&' : '?';
  return `${baseUrl}${separator}multisig=${encodeURIComponent(token)}`;
}

export interface MultiSigSubmissionResult {
  submitted: boolean;
  decoded: DecodedPartialEnvelope;
  hash?: string;
  explorerUrl?: string;
}

/**
 * Checks whether the required signature weight threshold is met on `envelopeXdr`
 * and, if satisfied, immediately submits the final transaction to the Soroban RPC pool.
 */
export async function submitMultiSigEnvelopeIfReady(
  envelopeXdr: string,
  options: {
    knownSigners?: ConfiguredSignerWeight[];
    requiredThreshold?: number;
    networkPassphrase?: string;
    rpcUrls?: string[];
    rpcUrl?: string;
    onStatusUpdate?: (msg: string) => void;
    pollConfirmation?: boolean;
  } = {},
): Promise<MultiSigSubmissionResult> {
  const networkPassphrase =
    options.networkPassphrase ||
    import.meta.env.VITE_STELLAR_NETWORK_PASSPHRASE ||
    DEFAULT_NETWORK_PASSPHRASE;

  const decoded = decodePartialTransactionEnvelope(envelopeXdr, {
    networkPassphrase,
    knownSigners: options.knownSigners,
    requiredThreshold: options.requiredThreshold,
  });

  if (!decoded.thresholdMet) {
    return {
      submitted: false,
      decoded,
    };
  }

  options.onStatusUpdate?.(
    `${decoded.thresholdLabel} — threshold satisfied! Submitting to Soroban RPC...`,
  );
  const pool = getOrCreatePool(
    resolveSorobanRpcUrls(options.rpcUrls, options.rpcUrl),
    options.onStatusUpdate,
  );
  const finalTx = TransactionBuilder.fromXDR(envelopeXdr.trim(), networkPassphrase);
  const sendResult = await pool.sendTransaction(finalTx);
  if (sendResult.status === 'ERROR' || sendResult.errorResult) {
    throw new Error(
      `Multi-sig RPC submission error: ${sendResult.errorResult || sendResult.status}`,
    );
  }

  const txHash = sendResult.hash;
  const explorerUrl = `https://stellar.expert/explorer/testnet/tx/${txHash}`;

  if (options.pollConfirmation !== false) {
    let attempts = 0;
    while (attempts < 15) {
      attempts++;
      const txResp = await pool.getTransaction(txHash);
      if (txResp.status === rpc.Api.GetTransactionStatus.SUCCESS) {
        break;
      }
      if (txResp.status === rpc.Api.GetTransactionStatus.FAILED) {
        throw new Error(`Multi-sig transaction failed on-chain. Hash: ${txHash}`);
      }
      await new Promise((r) => setTimeout(r, 500));
    }
  }

  options.onStatusUpdate?.(`Multi-signature transaction confirmed! Hash: ${txHash}`);
  return {
    submitted: true,
    decoded,
    hash: txHash,
    explorerUrl,
  };
}
