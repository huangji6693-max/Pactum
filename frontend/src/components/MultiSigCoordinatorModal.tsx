import React, { useState } from 'react';
import type { WalletProvider } from '../lib/wallet';
import type { UseMultiSigResult } from '../hooks/useMultiSig';

export interface MultiSigCoordinatorModalProps {
  isOpen: boolean;
  onClose: () => void;
  multiSig: UseMultiSigResult;
  activeWalletAddress?: string;
  activeWalletProvider?: WalletProvider;
}

export const MultiSigCoordinatorModal: React.FC<MultiSigCoordinatorModalProps> = ({
  isOpen,
  onClose,
  multiSig,
  activeWalletAddress,
  activeWalletProvider = 'freighter',
}) => {
  const [importInput, setImportInput] = useState('');
  const [externalSigInput, setExternalSigInput] = useState('');
  const [copiedLink, setCopiedLink] = useState(false);

  if (!isOpen) return null;

  const {
    bundle,
    decoded,
    shareUrl,
    qrPayload,
    isSigning,
    isSubmitting,
    submittedHash,
    explorerUrl,
    statusMessage,
    error,
    importFromSharePayload,
    signWithWallet,
    appendExternalSignature,
    submitTransaction,
    exportXdrDownload,
  } = multiSig;

  const progressPercent = decoded
    ? Math.min(
        100,
        Math.round((decoded.collectedWeight / Math.max(1, decoded.requiredThreshold)) * 100),
      )
    : 0;

  const handleCopyShareUrl = async () => {
    if (!shareUrl) return;
    if (typeof navigator !== 'undefined' && navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(shareUrl);
    }
    setCopiedLink(true);
    setTimeout(() => setCopiedLink(false), 2000);
  };

  const handleDownloadXdr = () => {
    const fileData = exportXdrDownload();
    if (!fileData || typeof document === 'undefined') return;
    const blob = new Blob([fileData.content], { type: 'application/x-xdr;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = fileData.filename;
    link.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="multisig-coordinator-title"
      data-testid="multisig-coordinator-modal"
      className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/80 p-4 backdrop-blur-sm"
    >
      <div className="w-full max-w-3xl rounded-2xl border border-slate-800 bg-slate-900 p-6 text-slate-100 shadow-2xl">
        <div className="flex items-start justify-between border-b border-slate-800 pb-4">
          <div>
            <span className="inline-block rounded-full bg-indigo-500/10 px-2.5 py-0.5 text-xs font-medium text-indigo-400">
              Stellar / Soroban Multi-Sig Coordinator
            </span>
            <h2 id="multisig-coordinator-title" className="mt-1 text-lg font-semibold text-white">
              Partially-Signed XDR Transaction Coordinator
            </h2>
            {bundle?.description && (
              <p className="mt-0.5 text-xs text-slate-400">{bundle.description}</p>
            )}
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close Multi-Sig Coordinator"
            className="rounded-lg border border-slate-700 px-3 py-1 text-xs text-slate-300 hover:bg-slate-800"
          >
            Close
          </button>
        </div>

        {/* Import / Load Shareable Link or Partial XDR */}
        <div className="mt-4 rounded-xl border border-slate-800 bg-slate-950/60 p-3">
          <label
            htmlFor="multisig-import-input"
            className="block text-xs font-medium text-slate-300"
          >
            Import Shareable Coordination Link (`?multisig=...`) or Bundle Token
          </label>
          <div className="mt-2 flex gap-2">
            <input
              id="multisig-import-input"
              data-testid="multisig-import-input"
              type="text"
              value={importInput}
              onChange={(e) => setImportInput(e.target.value)}
              placeholder="Paste ?multisig=msig1... link or token"
              className="flex-1 rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 font-mono text-xs text-slate-200"
            />
            <button
              type="button"
              data-testid="multisig-import-btn"
              onClick={() => {
                if (importInput.trim()) {
                  importFromSharePayload(importInput.trim());
                  setImportInput('');
                }
              }}
              className="rounded-lg bg-slate-800 px-3 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-700"
            >
              Load Bundle
            </button>
          </div>
        </div>

        {decoded && (
          <div className="mt-4 space-y-4">
            {/* Threshold Progress Banner */}
            <div className="rounded-xl border border-slate-800 bg-slate-950/70 p-4">
              <div className="flex items-center justify-between">
                <span
                  data-testid="multisig-threshold-label"
                  className="text-sm font-semibold text-white"
                >
                  {decoded.thresholdLabel}
                </span>
                <span
                  data-testid="multisig-threshold-status"
                  className={`rounded-full px-2.5 py-0.5 text-xs font-medium ${
                    decoded.thresholdMet
                      ? 'bg-emerald-500/15 text-emerald-400'
                      : 'bg-amber-500/15 text-amber-300'
                  }`}
                >
                  {decoded.thresholdMet
                    ? 'Threshold Met — Ready for Submission'
                    : `${decoded.remainingWeight} more weight required`}
                </span>
              </div>
              <div className="mt-2 h-2 w-full overflow-hidden rounded-full bg-slate-800">
                <div
                  data-testid="multisig-progress-bar"
                  style={{ width: `${progressPercent}%` }}
                  className={`h-full transition-all duration-300 ${
                    decoded.thresholdMet ? 'bg-emerald-500' : 'bg-indigo-500'
                  }`}
                />
              </div>
              <div className="mt-2 flex flex-wrap gap-4 text-[11px] text-slate-400">
                <span>
                  Tx Hash: <code className="text-slate-300">{decoded.txHashHex.slice(0, 16)}…</code>
                </span>
                <span>
                  Source:{' '}
                  <code className="text-slate-300">{decoded.sourceAccount.slice(0, 10)}…</code>
                </span>
                <span>
                  Fee: <code className="text-slate-300">{decoded.feeStroops} stroops</code>
                </span>
              </div>
            </div>

            {/* Decoded Operations Inspection */}
            <div className="rounded-xl border border-slate-800 bg-slate-950/50 p-3">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                Decoded Transaction Operations ({decoded.operations.length})
              </h3>
              <ul className="mt-2 space-y-1.5" data-testid="multisig-operations-list">
                {decoded.operations.map((op) => (
                  <li
                    key={op.index}
                    className="rounded-lg border border-slate-800/80 bg-slate-900/70 px-3 py-2 font-mono text-xs text-slate-200"
                  >
                    <div className="font-semibold text-indigo-300">{op.summary}</div>
                    {op.contractId && (
                      <div className="mt-0.5 text-[11px] text-slate-400">
                        Contract: {op.contractId}
                      </div>
                    )}
                  </li>
                ))}
              </ul>
            </div>

            {/* Signer Checklist */}
            <div className="rounded-xl border border-slate-800 bg-slate-950/50 p-3">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                Co-Signer Status & Weights
              </h3>
              <ul className="mt-2 divide-y divide-slate-800/70" data-testid="multisig-signers-list">
                {decoded.signers.map((signer, idx) => (
                  <li
                    key={signer.publicKey || `${signer.hintHex}-${idx}`}
                    className="flex items-center justify-between py-2 text-xs"
                  >
                    <div>
                      <span className="font-medium text-slate-200">
                        {signer.label || signer.publicKey || `Hint ${signer.hintHex}`}
                      </span>
                      {signer.publicKey && (
                        <span className="ml-2 font-mono text-[11px] text-slate-400">
                          ({signer.publicKey.slice(0, 6)}…{signer.publicKey.slice(-4)})
                        </span>
                      )}
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="rounded bg-slate-800 px-2 py-0.5 font-mono text-[11px] text-slate-300">
                        Weight: {signer.weight}
                      </span>
                      <span
                        className={`rounded-full px-2 py-0.5 text-[11px] font-medium ${
                          signer.signed
                            ? 'bg-emerald-500/15 text-emerald-400'
                            : 'bg-slate-800 text-slate-400'
                        }`}
                      >
                        {signer.signed ? 'Signed' : 'Pending'}
                      </span>
                    </div>
                  </li>
                ))}
              </ul>
            </div>

            {/* Co-Sign & External Signature Append Controls */}
            <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
              <div className="rounded-xl border border-slate-800 bg-slate-950/50 p-3">
                <h4 className="text-xs font-semibold text-slate-300">
                  1. Sign with Connected Wallet
                </h4>
                <p className="mt-1 text-[11px] text-slate-400">
                  Appends your signature to the partial XDR envelope via Freighter or Ledger.
                </p>
                <button
                  type="button"
                  data-testid="multisig-sign-wallet-btn"
                  disabled={isSigning || !activeWalletAddress}
                  onClick={() => {
                    if (activeWalletAddress) {
                      void signWithWallet(activeWalletAddress, activeWalletProvider);
                    }
                  }}
                  className="mt-2.5 w-full rounded-lg bg-indigo-600 px-3 py-2 text-xs font-semibold text-white hover:bg-indigo-500 disabled:opacity-50"
                >
                  {isSigning
                    ? 'Awaiting Signature...'
                    : `Sign Partial XDR (${activeWalletProvider})`}
                </button>
              </div>

              <div className="rounded-xl border border-slate-800 bg-slate-950/50 p-3">
                <h4 className="text-xs font-semibold text-slate-300">
                  2. Merge Co-Signer Signed XDR
                </h4>
                <div className="mt-2 flex gap-2">
                  <input
                    type="text"
                    data-testid="multisig-append-xdr-input"
                    value={externalSigInput}
                    onChange={(e) => setExternalSigInput(e.target.value)}
                    placeholder="Paste co-signer signed XDR"
                    className="flex-1 rounded-lg border border-slate-700 bg-slate-900 px-2.5 py-1.5 font-mono text-xs text-slate-200"
                  />
                  <button
                    type="button"
                    data-testid="multisig-append-xdr-btn"
                    onClick={() => {
                      if (externalSigInput.trim()) {
                        void appendExternalSignature(externalSigInput.trim());
                        setExternalSigInput('');
                      }
                    }}
                    className="rounded-lg bg-slate-800 px-3 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-700"
                  >
                    Merge
                  </button>
                </div>
              </div>
            </div>

            {/* Shareable Coordination Link, QR Payload & .xdr File Export */}
            <div className="rounded-xl border border-slate-800 bg-slate-950/50 p-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <h4 className="text-xs font-semibold text-slate-300">
                  Share Partially-Signed Envelope with Next Co-Signer
                </h4>
                <div className="flex gap-2">
                  <button
                    type="button"
                    data-testid="multisig-copy-link-btn"
                    onClick={() => void handleCopyShareUrl()}
                    className="rounded-lg border border-indigo-500/40 bg-indigo-500/10 px-3 py-1 text-xs font-medium text-indigo-300 hover:bg-indigo-500/20"
                  >
                    {copiedLink ? 'Copied Share Link!' : 'Copy Shareable Link'}
                  </button>
                  <button
                    type="button"
                    data-testid="multisig-download-xdr-btn"
                    onClick={handleDownloadXdr}
                    className="rounded-lg border border-slate-700 bg-slate-800 px-3 py-1 text-xs font-medium text-slate-200 hover:bg-slate-700"
                  >
                    Download .xdr
                  </button>
                  <button
                    type="button"
                    data-testid="multisig-submit-rpc-btn"
                    disabled={!decoded.thresholdMet || isSubmitting}
                    onClick={() => void submitTransaction()}
                    className="rounded-lg bg-emerald-600 px-3 py-1 text-xs font-semibold text-white hover:bg-emerald-500 disabled:opacity-40"
                  >
                    {isSubmitting ? 'Submitting...' : 'Submit to RPC'}
                  </button>
                </div>
              </div>
              <div className="mt-2 grid grid-cols-1 gap-2 md:grid-cols-2">
                <div className=" truncate rounded border border-slate-800 bg-slate-900 p-2 font-mono text-[11px] text-slate-400">
                  <span className="text-slate-500">URL: </span>
                  <span data-testid="multisig-share-url">{shareUrl}</span>
                </div>
                <div className="truncate rounded border border-slate-800 bg-slate-900 p-2 font-mono text-[11px] text-slate-400">
                  <span className="text-slate-500">QR Payload: </span>
                  <span data-testid="multisig-qr-payload">{qrPayload}</span>
                </div>
              </div>
            </div>

            {/* Submission Confirmation & Explorer Link */}
            {submittedHash && (
              <div
                data-testid="multisig-submitted-banner"
                className="rounded-xl border border-emerald-500/40 bg-emerald-500/10 p-3 text-xs text-emerald-200"
              >
                <div className="font-semibold">
                  Multi-Signature Transaction Submitted to Stellar Testnet!
                </div>
                <div className="mt-1 flex flex-wrap items-center justify-between gap-2 font-mono text-[11px]">
                  <span>Hash: {submittedHash}</span>
                  {explorerUrl && (
                    <a
                      href={explorerUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      data-testid="multisig-explorer-link"
                      className="font-semibold text-emerald-300 underline hover:text-emerald-200"
                    >
                      View on Stellar Expert
                    </a>
                  )}
                </div>
              </div>
            )}
          </div>
        )}

        {statusMessage && !error && (
          <p data-testid="multisig-status-msg" className="mt-3 text-xs text-slate-400">
            {statusMessage}
          </p>
        )}
        {error && (
          <p
            role="alert"
            data-testid="multisig-error-msg"
            className="mt-3 rounded-lg border border-rose-500/40 bg-rose-500/10 px-3 py-2 text-xs text-rose-300"
          >
            {error}
          </p>
        )}
      </div>
    </div>
  );
};
