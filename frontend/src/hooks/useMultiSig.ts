import { useCallback, useMemo, useState } from 'react';
import { Networks } from '@stellar/stellar-sdk';
import {
  type ConfiguredSignerWeight,
  type DecodedPartialEnvelope,
  decodePartialTransactionEnvelope,
} from '../lib/xdrDecode';
import type { WalletProvider } from '../lib/wallet';
import {
  type MultiSigCoordinationBundle,
  appendSignatureToEnvelope,
  buildMultiSigShareUrl,
  decodeShareableMultiSigPayload,
  encodeShareableMultiSigPayload,
  signPartialTransactionEnvelope,
  submitMultiSigEnvelopeIfReady,
} from '../lib/sorobanTxHelpers';

export interface InitializeMultiSigInput {
  envelopeXdr: string;
  knownSigners: ConfiguredSignerWeight[];
  requiredThreshold: number;
  networkPassphrase?: string;
  description?: string;
}

export interface UseMultiSigOptions {
  autoSubmit?: boolean;
  pollConfirmation?: boolean;
  rpcUrl?: string;
  rpcUrls?: string[];
  baseUrl?: string;
}

export interface UseMultiSigResult {
  bundle: MultiSigCoordinationBundle | null;
  decoded: DecodedPartialEnvelope | null;
  shareToken: string;
  shareUrl: string;
  qrPayload: string;
  isSigning: boolean;
  isSubmitting: boolean;
  submittedHash: string | null;
  explorerUrl: string | null;
  statusMessage: string | null;
  error: string | null;
  initializeEnvelope: (input: InitializeMultiSigInput) => DecodedPartialEnvelope;
  importFromSharePayload: (payloadOrUrl: string) => DecodedPartialEnvelope;
  signWithWallet: (
    signerAddress: string,
    walletProvider?: WalletProvider,
  ) => Promise<DecodedPartialEnvelope>;
  appendExternalSignature: (signedEnvelopeOrSigXdr: string) => Promise<DecodedPartialEnvelope>;
  submitTransaction: () => Promise<{
    submitted: boolean;
    hash?: string;
    explorerUrl?: string;
  }>;
  exportXdrDownload: () => { filename: string; content: string } | null;
  reset: () => void;
}

/**
 * Pure state-machine coordinator used by `useMultiSig` and deterministic unit tests.
 */
export function createMultiSigCoordinator(options: UseMultiSigOptions = {}): UseMultiSigResult {
  const { autoSubmit = true, pollConfirmation = false, rpcUrl, rpcUrls, baseUrl } = options;

  let bundle: MultiSigCoordinationBundle | null = null;
  let decoded: DecodedPartialEnvelope | null = null;
  let isSigning = false;
  let isSubmitting = false;
  let submittedHash: string | null = null;
  let explorerUrl: string | null = null;
  let statusMessage: string | null = null;
  let error: string | null = null;

  const maybeAutoSubmit = async (
    nextBundle: MultiSigCoordinationBundle,
    nextDecoded: DecodedPartialEnvelope,
  ): Promise<void> => {
    if (!autoSubmit || !nextDecoded.thresholdMet || submittedHash) {
      return;
    }
    isSubmitting = true;
    try {
      const result = await submitMultiSigEnvelopeIfReady(nextBundle.envelopeXdr, {
        knownSigners: nextBundle.knownSigners,
        requiredThreshold: nextBundle.requiredThreshold,
        networkPassphrase: nextBundle.networkPassphrase,
        rpcUrl,
        rpcUrls,
        pollConfirmation,
        onStatusUpdate: (msg) => {
          statusMessage = msg;
        },
      });
      if (result.submitted && result.hash) {
        submittedHash = result.hash;
        explorerUrl = result.explorerUrl ?? null;
      }
    } catch (err) {
      error = err instanceof Error ? err.message : String(err);
    } finally {
      isSubmitting = false;
    }
  };

  const api: UseMultiSigResult = {
    get bundle() {
      return bundle;
    },
    get decoded() {
      return decoded;
    },
    get shareToken() {
      return bundle ? encodeShareableMultiSigPayload(bundle) : '';
    },
    get shareUrl() {
      return bundle ? buildMultiSigShareUrl(bundle, baseUrl) : '';
    },
    get qrPayload() {
      return bundle ? `stellar+multisig:${encodeShareableMultiSigPayload(bundle)}` : '';
    },
    get isSigning() {
      return isSigning;
    },
    get isSubmitting() {
      return isSubmitting;
    },
    get submittedHash() {
      return submittedHash;
    },
    get explorerUrl() {
      return explorerUrl;
    },
    get statusMessage() {
      return statusMessage;
    },
    get error() {
      return error;
    },
    initializeEnvelope(input: InitializeMultiSigInput): DecodedPartialEnvelope {
      error = null;
      submittedHash = null;
      explorerUrl = null;
      const networkPassphrase = input.networkPassphrase || Networks.TESTNET;
      const nextDecoded = decodePartialTransactionEnvelope(input.envelopeXdr, {
        networkPassphrase,
        knownSigners: input.knownSigners,
        requiredThreshold: input.requiredThreshold,
      });
      bundle = {
        version: 1,
        envelopeXdr: nextDecoded.envelopeXdr,
        networkPassphrase,
        requiredThreshold: nextDecoded.requiredThreshold,
        knownSigners: input.knownSigners,
        description: input.description,
        createdAt: Date.now(),
      };
      decoded = nextDecoded;
      statusMessage = nextDecoded.thresholdLabel;
      return nextDecoded;
    },
    importFromSharePayload(payloadOrUrl: string): DecodedPartialEnvelope {
      error = null;
      const parsedBundle = decodeShareableMultiSigPayload(payloadOrUrl);
      const nextDecoded = decodePartialTransactionEnvelope(parsedBundle.envelopeXdr, {
        networkPassphrase: parsedBundle.networkPassphrase,
        knownSigners: parsedBundle.knownSigners,
        requiredThreshold: parsedBundle.requiredThreshold,
      });
      bundle = parsedBundle;
      decoded = nextDecoded;
      statusMessage = `Imported multi-sig bundle — ${nextDecoded.thresholdLabel}`;
      return nextDecoded;
    },
    async signWithWallet(
      signerAddress: string,
      walletProvider: WalletProvider = 'freighter',
    ): Promise<DecodedPartialEnvelope> {
      if (!bundle) {
        throw new Error('No multi-signature transaction envelope initialized.');
      }
      error = null;
      isSigning = true;
      try {
        const updatedXdr = await signPartialTransactionEnvelope({
          envelopeXdr: bundle.envelopeXdr,
          signerAddress,
          walletProvider,
          networkPassphrase: bundle.networkPassphrase,
          onStatusUpdate: (msg) => {
            statusMessage = msg;
          },
        });
        const nextDecoded = decodePartialTransactionEnvelope(updatedXdr, {
          networkPassphrase: bundle.networkPassphrase,
          knownSigners: bundle.knownSigners,
          requiredThreshold: bundle.requiredThreshold,
        });
        bundle = {
          ...bundle,
          envelopeXdr: updatedXdr,
        };
        decoded = nextDecoded;
        statusMessage = nextDecoded.thresholdLabel;
        await maybeAutoSubmit(bundle, nextDecoded);
        return nextDecoded;
      } catch (err) {
        error = err instanceof Error ? err.message : String(err);
        throw err;
      } finally {
        isSigning = false;
      }
    },
    async appendExternalSignature(signedEnvelopeOrSigXdr: string): Promise<DecodedPartialEnvelope> {
      if (!bundle) {
        throw new Error('No multi-signature transaction envelope initialized.');
      }
      error = null;
      const updatedXdr = appendSignatureToEnvelope(
        bundle.envelopeXdr,
        signedEnvelopeOrSigXdr,
        bundle.networkPassphrase,
      );
      const nextDecoded = decodePartialTransactionEnvelope(updatedXdr, {
        networkPassphrase: bundle.networkPassphrase,
        knownSigners: bundle.knownSigners,
        requiredThreshold: bundle.requiredThreshold,
      });
      bundle = {
        ...bundle,
        envelopeXdr: updatedXdr,
      };
      decoded = nextDecoded;
      statusMessage = nextDecoded.thresholdLabel;
      await maybeAutoSubmit(bundle, nextDecoded);
      return nextDecoded;
    },
    async submitTransaction() {
      if (!bundle) {
        throw new Error('No multi-signature transaction envelope initialized.');
      }
      error = null;
      isSubmitting = true;
      try {
        const result = await submitMultiSigEnvelopeIfReady(bundle.envelopeXdr, {
          knownSigners: bundle.knownSigners,
          requiredThreshold: bundle.requiredThreshold,
          networkPassphrase: bundle.networkPassphrase,
          rpcUrl,
          rpcUrls,
          pollConfirmation,
          onStatusUpdate: (msg) => {
            statusMessage = msg;
          },
        });
        decoded = result.decoded;
        if (result.submitted && result.hash) {
          submittedHash = result.hash;
          explorerUrl = result.explorerUrl ?? null;
        }
        return {
          submitted: result.submitted,
          hash: result.hash,
          explorerUrl: result.explorerUrl,
        };
      } catch (err) {
        error = err instanceof Error ? err.message : String(err);
        throw err;
      } finally {
        isSubmitting = false;
      }
    },
    exportXdrDownload() {
      if (!bundle || !decoded) return null;
      return {
        filename: `pactum-multisig-${decoded.txHashHex.slice(0, 10)}.xdr`,
        content: bundle.envelopeXdr,
      };
    },
    reset() {
      bundle = null;
      decoded = null;
      isSigning = false;
      isSubmitting = false;
      submittedHash = null;
      explorerUrl = null;
      statusMessage = null;
      error = null;
    },
  };

  return api;
}

export function useMultiSig(options: UseMultiSigOptions = {}): UseMultiSigResult {
  const { autoSubmit = true, pollConfirmation = false, rpcUrl, rpcUrls, baseUrl } = options;

  const [bundle, setBundle] = useState<MultiSigCoordinationBundle | null>(null);
  const [decoded, setDecoded] = useState<DecodedPartialEnvelope | null>(null);
  const [isSigning, setIsSigning] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [submittedHash, setSubmittedHash] = useState<string | null>(null);
  const [explorerUrl, setExplorerUrl] = useState<string | null>(null);
  const [statusMessage, setStatusMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const maybeAutoSubmit = useCallback(
    async (
      nextBundle: MultiSigCoordinationBundle,
      nextDecoded: DecodedPartialEnvelope,
    ): Promise<void> => {
      if (!autoSubmit || !nextDecoded.thresholdMet || submittedHash) {
        return;
      }
      setIsSubmitting(true);
      try {
        const result = await submitMultiSigEnvelopeIfReady(nextBundle.envelopeXdr, {
          knownSigners: nextBundle.knownSigners,
          requiredThreshold: nextBundle.requiredThreshold,
          networkPassphrase: nextBundle.networkPassphrase,
          rpcUrl,
          rpcUrls,
          pollConfirmation,
          onStatusUpdate: (msg) => setStatusMessage(msg),
        });
        if (result.submitted && result.hash) {
          setSubmittedHash(result.hash);
          setExplorerUrl(result.explorerUrl ?? null);
        }
      } catch (err) {
        setError(err instanceof Error ? err.message : String(err));
      } finally {
        setIsSubmitting(false);
      }
    },
    [autoSubmit, pollConfirmation, rpcUrl, rpcUrls, submittedHash],
  );

  const initializeEnvelope = useCallback(
    (input: InitializeMultiSigInput): DecodedPartialEnvelope => {
      setError(null);
      setSubmittedHash(null);
      setExplorerUrl(null);
      const networkPassphrase = input.networkPassphrase || Networks.TESTNET;
      const nextDecoded = decodePartialTransactionEnvelope(input.envelopeXdr, {
        networkPassphrase,
        knownSigners: input.knownSigners,
        requiredThreshold: input.requiredThreshold,
      });
      const nextBundle: MultiSigCoordinationBundle = {
        version: 1,
        envelopeXdr: nextDecoded.envelopeXdr,
        networkPassphrase,
        requiredThreshold: nextDecoded.requiredThreshold,
        knownSigners: input.knownSigners,
        description: input.description,
        createdAt: Date.now(),
      };
      setBundle(nextBundle);
      setDecoded(nextDecoded);
      setStatusMessage(nextDecoded.thresholdLabel);
      return nextDecoded;
    },
    [],
  );

  const importFromSharePayload = useCallback((payloadOrUrl: string): DecodedPartialEnvelope => {
    setError(null);
    const parsedBundle = decodeShareableMultiSigPayload(payloadOrUrl);
    const nextDecoded = decodePartialTransactionEnvelope(parsedBundle.envelopeXdr, {
      networkPassphrase: parsedBundle.networkPassphrase,
      knownSigners: parsedBundle.knownSigners,
      requiredThreshold: parsedBundle.requiredThreshold,
    });
    setBundle(parsedBundle);
    setDecoded(nextDecoded);
    setStatusMessage(`Imported multi-sig bundle — ${nextDecoded.thresholdLabel}`);
    return nextDecoded;
  }, []);

  const signWithWallet = useCallback(
    async (
      signerAddress: string,
      walletProvider: WalletProvider = 'freighter',
    ): Promise<DecodedPartialEnvelope> => {
      if (!bundle) {
        throw new Error('No multi-signature transaction envelope initialized.');
      }
      setError(null);
      setIsSigning(true);
      try {
        const updatedXdr = await signPartialTransactionEnvelope({
          envelopeXdr: bundle.envelopeXdr,
          signerAddress,
          walletProvider,
          networkPassphrase: bundle.networkPassphrase,
          onStatusUpdate: (msg) => setStatusMessage(msg),
        });

        const nextDecoded = decodePartialTransactionEnvelope(updatedXdr, {
          networkPassphrase: bundle.networkPassphrase,
          knownSigners: bundle.knownSigners,
          requiredThreshold: bundle.requiredThreshold,
        });

        const nextBundle: MultiSigCoordinationBundle = {
          ...bundle,
          envelopeXdr: updatedXdr,
        };
        setBundle(nextBundle);
        setDecoded(nextDecoded);
        setStatusMessage(nextDecoded.thresholdLabel);

        await maybeAutoSubmit(nextBundle, nextDecoded);
        return nextDecoded;
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        setError(message);
        throw err;
      } finally {
        setIsSigning(false);
      }
    },
    [bundle, maybeAutoSubmit],
  );

  const appendExternalSignature = useCallback(
    async (signedEnvelopeOrSigXdr: string): Promise<DecodedPartialEnvelope> => {
      if (!bundle) {
        throw new Error('No multi-signature transaction envelope initialized.');
      }
      setError(null);
      try {
        const updatedXdr = appendSignatureToEnvelope(
          bundle.envelopeXdr,
          signedEnvelopeOrSigXdr,
          bundle.networkPassphrase,
        );
        const nextDecoded = decodePartialTransactionEnvelope(updatedXdr, {
          networkPassphrase: bundle.networkPassphrase,
          knownSigners: bundle.knownSigners,
          requiredThreshold: bundle.requiredThreshold,
        });
        const nextBundle: MultiSigCoordinationBundle = {
          ...bundle,
          envelopeXdr: updatedXdr,
        };
        setBundle(nextBundle);
        setDecoded(nextDecoded);
        setStatusMessage(nextDecoded.thresholdLabel);

        await maybeAutoSubmit(nextBundle, nextDecoded);
        return nextDecoded;
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        setError(message);
        throw err;
      }
    },
    [bundle, maybeAutoSubmit],
  );

  const submitTransaction = useCallback(async () => {
    if (!bundle) {
      throw new Error('No multi-signature transaction envelope initialized.');
    }
    setError(null);
    setIsSubmitting(true);
    try {
      const result = await submitMultiSigEnvelopeIfReady(bundle.envelopeXdr, {
        knownSigners: bundle.knownSigners,
        requiredThreshold: bundle.requiredThreshold,
        networkPassphrase: bundle.networkPassphrase,
        rpcUrl,
        rpcUrls,
        pollConfirmation,
        onStatusUpdate: (msg) => setStatusMessage(msg),
      });
      setDecoded(result.decoded);
      if (result.submitted && result.hash) {
        setSubmittedHash(result.hash);
        setExplorerUrl(result.explorerUrl ?? null);
      }
      return {
        submitted: result.submitted,
        hash: result.hash,
        explorerUrl: result.explorerUrl,
      };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      setError(message);
      throw err;
    } finally {
      setIsSubmitting(false);
    }
  }, [bundle, pollConfirmation, rpcUrl, rpcUrls]);

  const exportXdrDownload = useCallback(() => {
    if (!bundle || !decoded) return null;
    return {
      filename: `pactum-multisig-${decoded.txHashHex.slice(0, 10)}.xdr`,
      content: bundle.envelopeXdr,
    };
  }, [bundle, decoded]);

  const reset = useCallback(() => {
    setBundle(null);
    setDecoded(null);
    setIsSigning(false);
    setIsSubmitting(false);
    setSubmittedHash(null);
    setExplorerUrl(null);
    setStatusMessage(null);
    setError(null);
  }, []);

  const shareToken = useMemo(
    () => (bundle ? encodeShareableMultiSigPayload(bundle) : ''),
    [bundle],
  );
  const shareUrl = useMemo(
    () => (bundle ? buildMultiSigShareUrl(bundle, baseUrl) : ''),
    [bundle, baseUrl],
  );
  const qrPayload = useMemo(
    () => (bundle ? `stellar+multisig:${shareToken}` : ''),
    [bundle, shareToken],
  );

  return {
    bundle,
    decoded,
    shareToken,
    shareUrl,
    qrPayload,
    isSigning,
    isSubmitting,
    submittedHash,
    explorerUrl,
    statusMessage,
    error,
    initializeEnvelope,
    importFromSharePayload,
    signWithWallet,
    appendExternalSignature,
    submitTransaction,
    exportXdrDownload,
    reset,
  };
}
