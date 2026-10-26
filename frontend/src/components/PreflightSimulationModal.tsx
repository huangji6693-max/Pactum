import {
  Loader2,
  X,
  AlertTriangle,
  CheckCircle2,
  Cpu,
  Database,
  Coins,
  Layers,
  ShieldAlert,
  ArrowRight,
} from 'lucide-react';
import type { SimulationPreview } from '../lib/soroban';
import {
  analyzePreflightSimulation,
  type PreflightSimulationReport,
} from '../hooks/usePreflightSimulation';

export interface PreflightSimulationModalProps {
  preview: PreflightSimulationReport | SimulationPreview | null;
  onConfirm: () => void;
  onCancel: () => void;
  isOpen: boolean;
}

function isFullReport(
  preview: PreflightSimulationReport | SimulationPreview,
): preview is PreflightSimulationReport {
  return (
    'fees' in preview &&
    'resources' in preview &&
    'footprint' in preview &&
    'canSubmit' in preview
  );
}

function formatNumber(val: string | number): string {
  const num = Number(val);
  if (!Number.isFinite(num)) return String(val);
  return num.toLocaleString('en-US');
}

export default function PreflightSimulationModal({
  preview,
  onConfirm,
  onCancel,
  isOpen,
}: PreflightSimulationModalProps) {
  if (!isOpen) return null;

  const isLoading = preview === null;
  const report: PreflightSimulationReport | null =
    preview === null
      ? null
      : isFullReport(preview)
        ? preview
        : analyzePreflightSimulation(
            preview.rawSimulation ?? {
              error: preview.error,
              minResourceFee: preview.cost?.feeStroops ?? '0',
              cost: preview.cost
                ? {
                    cpuInsns: preview.cost.cpuInsns,
                    memBytes: preview.cost.memBytes,
                  }
                : undefined,
            },
          );

  const isSuccess = report?.success === true;
  const canSubmit = report?.canSubmit === true;
  const blockingReason = report?.blockingReason ?? null;
  const fees = report?.fees;
  const resources = report?.resources;
  const footprint = report?.footprint;
  const stateChanges = report?.stateChanges ?? [];
  const balanceChanges = report?.balanceChanges ?? [];
  const warnings = report?.warnings ?? [];

  const headerGradient = isLoading
    ? 'linear-gradient(135deg, #1e1b4b, #4338ca)'
    : isSuccess && canSubmit
      ? 'linear-gradient(135deg, #0f172a, #1e3a8a)'
      : 'linear-gradient(135deg, #7f1d1d, #dc2626)';

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="sim-modal-title"
      style={{
        position: 'fixed',
        inset: 0,
        zIndex: 1000,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '16px',
        background: 'rgba(2, 6, 23, 0.74)',
        backdropFilter: 'blur(6px)',
      }}
      onClick={(e) => {
        if (e.target === e.currentTarget) onCancel();
      }}
    >
      <div
        style={{
          background: '#ffffff',
          borderRadius: '20px',
          boxShadow: '0 32px 80px rgba(0, 0, 0, 0.32)',
          width: '100%',
          maxWidth: '560px',
          maxHeight: '90vh',
          display: 'flex',
          flexDirection: 'column',
          overflow: 'hidden',
          animation: 'slideUp 0.22s cubic-bezier(0.34, 1.56, 0.64, 1)',
        }}
      >
        {/* Header */}
        <div
          style={{
            background: headerGradient,
            padding: '22px 24px 18px',
            position: 'relative',
            flexShrink: 0,
          }}
        >
          <button
            type="button"
            onClick={onCancel}
            aria-label="Close preview modal"
            style={{
              position: 'absolute',
              top: '16px',
              right: '16px',
              background: 'rgba(255, 255, 255, 0.15)',
              border: 'none',
              borderRadius: '8px',
              color: '#ffffff',
              width: '30px',
              height: '30px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              cursor: 'pointer',
            }}
          >
            <X size={15} />
          </button>

          <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
            <div
              style={{
                width: '44px',
                height: '44px',
                borderRadius: '12px',
                background: 'rgba(255, 255, 255, 0.16)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                flexShrink: 0,
              }}
            >
              {isLoading ? (
                <Loader2
                  size={22}
                  color="#ffffff"
                  style={{ animation: 'spin 1s linear infinite' }}
                />
              ) : isSuccess && canSubmit ? (
                <CheckCircle2 size={22} color="#4ade80" />
              ) : (
                <AlertTriangle size={22} color="#fca5a5" />
              )}
            </div>
            <div>
              <h2
                id="sim-modal-title"
                style={{
                  margin: 0,
                  fontSize: '17px',
                  fontWeight: 800,
                  color: '#ffffff',
                }}
              >
                {isLoading
                  ? 'Simulating Transaction'
                  : !isSuccess
                    ? 'Transaction Would Fail'
                    : !canSubmit
                      ? 'Submission Blocked: Insufficient Balance'
                      : 'Preflight Simulation & Gas Estimation'}
              </h2>
              <p
                style={{
                  margin: '4px 0 0 0',
                  fontSize: '12.5px',
                  color: 'rgba(255, 255, 255, 0.82)',
                }}
              >
                {isLoading
                  ? 'Evaluating multi-operation contract execution on Soroban RPC...'
                  : !isSuccess
                    ? 'Simulation detected a contract revert. Submission is blocked to protect your funds.'
                    : !canSubmit
                      ? 'Your XLM balance is insufficient to cover predicted network and storage fees.'
                      : 'Preflight simulation succeeded. Review predicted resources, storage footprint, and state diff.'}
              </p>
            </div>
          </div>
        </div>

        {/* Scrollable Body */}
        <div
          style={{
            padding: '18px 24px 20px',
            overflowY: 'auto',
            display: 'flex',
            flexDirection: 'column',
            gap: '14px',
          }}
        >
          {isLoading && (
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: '10px',
                padding: '28px 0',
                color: '#4338ca',
                fontSize: '14px',
                fontWeight: 600,
              }}
            >
              <Loader2 size={20} style={{ animation: 'spin 1s linear infinite' }} />{' '}
              Simulating transaction...
            </div>
          )}

          {/* Risk Warnings & Revert Diagnostics */}
          {!isLoading && warnings.length > 0 && (
            <div
              data-testid="preflight-warnings"
              style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}
            >
              {warnings.map((w) => {
                const isCritical = w.severity === 'critical';
                const isWarn = w.severity === 'warning';
                return (
                  <div
                    key={w.code}
                    data-testid={`preflight-warning-${w.code}`}
                    style={{
                      background: isCritical
                        ? '#fef2f2'
                        : isWarn
                          ? '#fffbeb'
                          : '#f0f9ff',
                      border: `1px solid ${
                        isCritical ? '#fecaca' : isWarn ? '#fde68a' : '#bae6fd'
                      }`,
                      borderRadius: '10px',
                      padding: '10px 12px',
                      display: 'flex',
                      alignItems: 'flex-start',
                      gap: '10px',
                    }}
                  >
                    <ShieldAlert
                      size={16}
                      color={isCritical ? '#dc2626' : isWarn ? '#d97706' : '#0284c7'}
                      style={{ marginTop: '2px', flexShrink: 0 }}
                    />
                    <div style={{ flex: 1 }}>
                      <div
                        style={{
                          fontSize: '12.5px',
                          fontWeight: 700,
                          color: isCritical
                            ? '#991b1b'
                            : isWarn
                              ? '#92400e'
                              : '#075985',
                        }}
                      >
                        {w.title}
                      </div>
                      <div
                        style={{
                          fontSize: '11.5px',
                          color: isCritical
                            ? '#b91c1c'
                            : isWarn
                              ? '#b45309'
                              : '#0369a1',
                          marginTop: '2px',
                          wordBreak: 'break-word',
                        }}
                      >
                        {w.message}
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}

          {/* Error Code Block on Failure */}
          {!isLoading && !isSuccess && (
            <div>
              <div
                style={{
                  fontSize: '12px',
                  fontWeight: 700,
                  color: '#991b1b',
                  marginBottom: '6px',
                }}
              >
                Raw RPC Diagnostic Error:
              </div>
              <code
                style={{
                  display: 'block',
                  background: '#fef2f2',
                  border: '1px solid #fecaca',
                  borderRadius: '8px',
                  padding: '10px 12px',
                  fontSize: '11.5px',
                  color: '#b91c1c',
                  wordBreak: 'break-all',
                  whiteSpace: 'pre-wrap',
                  maxHeight: '140px',
                  overflowY: 'auto',
                }}
              >
                {report?.error || 'Simulation failed with unknown error.'}
              </code>
            </div>
          )}

          {/* Detailed Estimation Sections on Success */}
          {!isLoading && isSuccess && fees && resources && footprint && (
            <>
              {/* 1. Fee Component Breakdown */}
              <div
                data-testid="preflight-fee-breakdown"
                style={{
                  background: '#f8fafc',
                  border: '1px solid #e2e8f0',
                  borderRadius: '12px',
                  padding: '12px 14px',
                }}
              >
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    marginBottom: '8px',
                  }}
                >
                  <div
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '6px',
                      fontSize: '11px',
                      fontWeight: 800,
                      color: '#475569',
                      textTransform: 'uppercase',
                      letterSpacing: '0.04em',
                    }}
                  >
                    <Coins size={13} color="#2563eb" /> Predictive Fee Breakdown
                  </div>
                  <div
                    style={{
                      fontSize: '13px',
                      fontWeight: 800,
                      color: '#0f172a',
                    }}
                  >
                    Total: {fees.totalFeeXlm} XLM ({formatNumber(fees.totalFeeStroops)} stroops)
                  </div>
                </div>

                <div
                  style={{
                    display: 'grid',
                    gridTemplateColumns: 'repeat(2, minmax(0, 1fr))',
                    gap: '6px 12px',
                    fontSize: '11.5px',
                    color: '#334155',
                    borderTop: '1px solid #e2e8f0',
                    paddingTop: '8px',
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span style={{ color: '#64748b' }}>Base Network Fee:</span>
                    <span style={{ fontWeight: 600 }}>{fees.baseFeeXlm} XLM</span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span style={{ color: '#64748b' }}>Soroban Resource Fee:</span>
                    <span style={{ fontWeight: 600 }}>{fees.resourceFeeXlm} XLM</span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span style={{ color: '#64748b' }}>Non-Refundable Execution:</span>
                    <span style={{ fontWeight: 600 }}>{fees.nonRefundableFeeXlm} XLM</span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span style={{ color: '#64748b' }}>Refundable Rent / Events:</span>
                    <span style={{ fontWeight: 600, color: '#15803d' }}>
                      {fees.refundableFeeXlm} XLM
                    </span>
                  </div>
                </div>
              </div>

              {/* 2. CPU & Memory Resource Utilization */}
              <div
                data-testid="preflight-resource-metrics"
                style={{
                  background: '#f8fafc',
                  border: '1px solid #e2e8f0',
                  borderRadius: '12px',
                  padding: '12px 14px',
                }}
              >
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px',
                    fontSize: '11px',
                    fontWeight: 800,
                    color: '#475569',
                    textTransform: 'uppercase',
                    letterSpacing: '0.04em',
                    marginBottom: '8px',
                  }}
                >
                  <Cpu size={13} color="#4f46e5" /> Predicted VM Resource Consumption
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  <div>
                    <div
                      style={{
                        display: 'flex',
                        justifyContent: 'space-between',
                        fontSize: '12px',
                        fontWeight: 600,
                        color: '#1e293b',
                        marginBottom: '4px',
                      }}
                    >
                      <span>
                        CPU: {formatNumber(resources.cpuInsns)} instructions ({resources.cpuInsns}{' '}
                        raw)
                      </span>
                      <span
                        style={{
                          color:
                            resources.cpuUtilizationPct >= 80 ? '#d97706' : '#475569',
                        }}
                      >
                        {resources.cpuUtilizationPct}% of 100M budget
                      </span>
                    </div>
                    <div
                      style={{
                        height: '6px',
                        borderRadius: '999px',
                        background: '#e2e8f0',
                        overflow: 'hidden',
                      }}
                    >
                      <div
                        style={{
                          width: `${Math.max(2, Math.min(100, resources.cpuUtilizationPct))}%`,
                          height: '100%',
                          background:
                            resources.cpuUtilizationPct >= 80 ? '#f59e0b' : '#4f46e5',
                          transition: 'width 0.3s ease',
                        }}
                      />
                    </div>
                  </div>

                  <div>
                    <div
                      style={{
                        display: 'flex',
                        justifyContent: 'space-between',
                        fontSize: '12px',
                        fontWeight: 600,
                        color: '#1e293b',
                        marginBottom: '4px',
                      }}
                    >
                      <span>
                        Memory: {formatNumber(resources.memBytes)} bytes ({resources.memBytes} raw)
                      </span>
                      <span
                        style={{
                          color:
                            resources.memUtilizationPct >= 80 ? '#d97706' : '#475569',
                        }}
                      >
                        {resources.memUtilizationPct}% of 40 MiB budget
                      </span>
                    </div>
                    <div
                      style={{
                        height: '6px',
                        borderRadius: '999px',
                        background: '#e2e8f0',
                        overflow: 'hidden',
                      }}
                    >
                      <div
                        style={{
                          width: `${Math.max(2, Math.min(100, resources.memUtilizationPct))}%`,
                          height: '100%',
                          background:
                            resources.memUtilizationPct >= 80 ? '#f59e0b' : '#0ea5e9',
                          transition: 'width 0.3s ease',
                        }}
                      />
                    </div>
                  </div>
                </div>
              </div>

              {/* 3. Storage Footprint Analysis (Persistent vs Temporary) */}
              <div
                data-testid="preflight-storage-footprint"
                style={{
                  background: '#f8fafc',
                  border: '1px solid #e2e8f0',
                  borderRadius: '12px',
                  padding: '12px 14px',
                }}
              >
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    marginBottom: '8px',
                  }}
                >
                  <div
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '6px',
                      fontSize: '11px',
                      fontWeight: 800,
                      color: '#475569',
                      textTransform: 'uppercase',
                      letterSpacing: '0.04em',
                    }}
                  >
                    <Database size={13} color="#0d9488" /> Storage Footprint Analysis
                  </div>
                  <span
                    style={{
                      fontSize: '11px',
                      fontWeight: 700,
                      color: '#0f766e',
                      background: '#ccfbf1',
                      padding: '2px 8px',
                      borderRadius: '999px',
                    }}
                  >
                    Storage Deposit: {footprint.storageDepositXlm} XLM
                  </span>
                </div>

                <div
                  style={{
                    display: 'grid',
                    gridTemplateColumns: 'repeat(2, minmax(0, 1fr))',
                    gap: '8px',
                  }}
                >
                  <div
                    style={{
                      background: '#ffffff',
                      border: '1px solid #e2e8f0',
                      borderRadius: '8px',
                      padding: '8px 10px',
                    }}
                  >
                    <div
                      style={{
                        fontSize: '10.5px',
                        fontWeight: 700,
                        color: '#64748b',
                        textTransform: 'uppercase',
                      }}
                    >
                      Persistent Ledger Entries
                    </div>
                    <div
                      style={{
                        fontSize: '12.5px',
                        fontWeight: 700,
                        color: '#0f172a',
                        marginTop: '2px',
                      }}
                    >
                      {footprint.persistentReads} Reads · {footprint.persistentWrites} Writes
                    </div>
                  </div>

                  <div
                    style={{
                      background: '#ffffff',
                      border: '1px solid #e2e8f0',
                      borderRadius: '8px',
                      padding: '8px 10px',
                    }}
                  >
                    <div
                      style={{
                        fontSize: '10.5px',
                        fontWeight: 700,
                        color: '#64748b',
                        textTransform: 'uppercase',
                      }}
                    >
                      Temporary Ledger Entries
                    </div>
                    <div
                      style={{
                        fontSize: '12.5px',
                        fontWeight: 700,
                        color: '#0f172a',
                        marginTop: '2px',
                      }}
                    >
                      {footprint.temporaryReads} Reads · {footprint.temporaryWrites} Writes
                    </div>
                  </div>
                </div>

                <div
                  style={{
                    marginTop: '8px',
                    fontSize: '11px',
                    color: '#64748b',
                    display: 'flex',
                    justifyContent: 'space-between',
                  }}
                >
                  <span>
                    Disk Read: {formatNumber(footprint.diskReadBytes)} B · Ledger Write:{' '}
                    {formatNumber(footprint.writeBytes)} B
                  </span>
                  <span>
                    {footprint.requiresRestore
                      ? 'Archival Restore Required'
                      : 'No Archival Restore Needed'}
                  </span>
                </div>
              </div>

              {/* 4. Simulation Diff Preview (State & Balance Changes) */}
              <div
                data-testid="preflight-diff-preview"
                style={{
                  background: '#f8fafc',
                  border: '1px solid #e2e8f0',
                  borderRadius: '12px',
                  padding: '12px 14px',
                }}
              >
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px',
                    fontSize: '11px',
                    fontWeight: 800,
                    color: '#475569',
                    textTransform: 'uppercase',
                    letterSpacing: '0.04em',
                    marginBottom: '8px',
                  }}
                >
                  <Layers size={13} color="#7c3aed" /> Simulation Diff Preview
                </div>

                {/* State Changes */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                  {stateChanges.map((sc) => (
                    <div
                      key={sc.id}
                      style={{
                        background: '#ffffff',
                        border: '1px solid #e2e8f0',
                        borderRadius: '8px',
                        padding: '7px 10px',
                        fontSize: '11.5px',
                      }}
                    >
                      <div
                        style={{
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'space-between',
                          marginBottom: '2px',
                        }}
                      >
                        <span style={{ fontWeight: 700, color: '#1e293b' }}>{sc.label}</span>
                        <span
                          style={{
                            fontSize: '10px',
                            fontWeight: 700,
                            textTransform: 'uppercase',
                            padding: '1px 6px',
                            borderRadius: '4px',
                            background:
                              sc.durability === 'persistent' ? '#ede9fe' : '#e0f2fe',
                            color:
                              sc.durability === 'persistent' ? '#6d28d9' : '#0369a1',
                          }}
                        >
                          {sc.durability} · {sc.changeType}
                        </span>
                      </div>
                      <div
                        style={{
                          display: 'flex',
                          alignItems: 'center',
                          gap: '6px',
                          color: '#64748b',
                          fontSize: '11px',
                        }}
                      >
                        <span>{sc.beforeSummary ?? 'Prior state'}</span>
                        <ArrowRight size={11} />
                        <span style={{ color: '#0f172a', fontWeight: 600 }}>
                          {sc.afterSummary}
                        </span>
                      </div>
                    </div>
                  ))}

                  {/* Balance Changes */}
                  {balanceChanges.map((bc, idx) => (
                    <div
                      key={idx}
                      style={{
                        background: '#ffffff',
                        border: '1px solid #e2e8f0',
                        borderRadius: '8px',
                        padding: '7px 10px',
                        fontSize: '11.5px',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                      }}
                    >
                      <div>
                        <span style={{ fontWeight: 700, color: '#1e293b' }}>
                          {bc.address} ({bc.asset})
                        </span>
                        <div style={{ fontSize: '10.5px', color: '#64748b' }}>
                          {bc.reason}
                        </div>
                      </div>
                      <div style={{ textAlign: 'right' }}>
                        <div style={{ fontWeight: 700, color: '#b45309' }}>
                          {bc.deltaFormatted}
                        </div>
                        {bc.beforeBalanceXlm && bc.afterBalanceXlm && (
                          <div style={{ fontSize: '10px', color: '#64748b' }}>
                            {bc.beforeBalanceXlm} → {bc.afterBalanceXlm}
                          </div>
                        )}
                      </div>
                    </div>
                  ))}
                </div>

                {/* Required Authorizations */}
                <div
                  style={{
                    marginTop: '8px',
                    paddingTop: '8px',
                    borderTop: '1px solid #e2e8f0',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    fontSize: '11px',
                  }}
                >
                  <span style={{ fontWeight: 700, color: '#64748b' }}>
                    Required Authorizations:
                  </span>
                  <span style={{ fontFamily: 'monospace', color: '#0f172a' }}>
                    {report.requiredAuths.length > 0
                      ? report.requiredAuths.join(', ')
                      : 'None'}
                  </span>
                </div>
              </div>
            </>
          )}

          {/* Footer Action Buttons */}
          <div style={{ display: 'flex', gap: '10px', marginTop: '4px' }}>
            <button
              type="button"
              id="sim-modal-cancel"
              onClick={onCancel}
              style={{
                flex: 1,
                padding: '11px',
                borderRadius: '10px',
                border: '1px solid #e2e8f0',
                background: '#ffffff',
                color: '#334155',
                fontWeight: 700,
                fontSize: '13px',
                cursor: 'pointer',
              }}
            >
              Cancel
            </button>
            {!isLoading && isSuccess && (
              <button
                type="button"
                id="sim-modal-confirm"
                disabled={!canSubmit}
                onClick={() => {
                  if (canSubmit) onConfirm();
                }}
                style={{
                  flex: 2,
                  padding: '11px',
                  borderRadius: '10px',
                  border: 'none',
                  background: canSubmit
                    ? 'linear-gradient(135deg, #16a34a, #22c55e)'
                    : '#94a3b8',
                  color: '#ffffff',
                  fontWeight: 700,
                  fontSize: '13px',
                  cursor: canSubmit ? 'pointer' : 'not-allowed',
                  opacity: canSubmit ? 1 : 0.75,
                }}
              >
                {canSubmit
                  ? 'Confirm & Sign in Wallet'
                  : blockingReason === 'insufficient_balance'
                    ? 'Insufficient XLM Balance'
                    : 'Submission Blocked'}
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
