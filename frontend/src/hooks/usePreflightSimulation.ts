import { useState, useCallback, useRef } from 'react';
import { rpc, xdr, BASE_FEE, Address, TransactionBuilder } from '@stellar/stellar-sdk';
import {
  DEFAULT_SOROBAN_RPC_URL,
  type SimulationPreview,
  type SimulationCost,
} from '../lib/soroban';

/** Standard Soroban per-transaction CPU instruction budget (100M instructions). */
export const SOROBAN_MAX_CPU_INSNS = 100_000_000;

/** Standard Soroban per-transaction memory budget (40 MiB = 41,943,040 bytes). */
export const SOROBAN_MAX_MEM_BYTES = 41_943_040;

/** 1 XLM = 10,000,000 stroops. */
export const STROOPS_PER_XLM = 10_000_000;

export type FootprintDurability = 'persistent' | 'temporary';

export interface FootprintEntryItem {
  keySummary: string;
  durability: FootprintDurability;
  mode: 'read' | 'write';
  entryKind: string;
}

export interface StorageFootprintAnalysis {
  persistentReads: number;
  persistentWrites: number;
  temporaryReads: number;
  temporaryWrites: number;
  totalReads: number;
  totalWrites: number;
  diskReadBytes: number;
  writeBytes: number;
  storageDepositStroops: string;
  storageDepositXlm: string;
  requiresRestore: boolean;
  entries: FootprintEntryItem[];
}

export interface FeeBreakdown {
  baseFeeStroops: string;
  baseFeeXlm: string;
  resourceFeeStroops: string;
  resourceFeeXlm: string;
  refundableFeeStroops: string;
  refundableFeeXlm: string;
  nonRefundableFeeStroops: string;
  nonRefundableFeeXlm: string;
  storageDepositStroops: string;
  storageDepositXlm: string;
  totalFeeStroops: string;
  totalFeeXlm: string;
}

export interface ResourceUtilization {
  cpuInsns: string;
  cpuLimit: number;
  cpuUtilizationPct: number;
  memBytes: string;
  memLimit: number;
  memUtilizationPct: number;
}

export interface SimulatedStateChange {
  id: string;
  label: string;
  durability: FootprintDurability;
  changeType: 'created' | 'updated' | 'restored';
  beforeSummary?: string;
  afterSummary: string;
}

export interface SimulatedBalanceChange {
  address: string;
  asset: string;
  deltaStroops: string;
  deltaFormatted: string;
  beforeBalanceXlm?: string;
  afterBalanceXlm?: string;
  reason: string;
}

export type RiskWarningCode =
  | 'contract_revert'
  | 'insufficient_balance'
  | 'archived_restore_required'
  | 'high_cpu_utilization'
  | 'high_memory_utilization'
  | 'heavy_persistent_writes';

export interface PreflightRiskWarning {
  code: RiskWarningCode;
  severity: 'critical' | 'warning' | 'info';
  title: string;
  message: string;
}

export interface PreflightSimulationContext {
  baseFeeStroops?: string | number;
  accountBalanceStroops?: string | bigint | null;
  sourceAddress?: string;
  counterpartyAddress?: string;
  operationName?: string;
  isEncrypted?: boolean;
  hasValidationRules?: boolean;
  attestorCount?: number;
}

export interface PreflightSimulationReport extends SimulationPreview {
  canSubmit: boolean;
  blockingReason: 'contract_revert' | 'insufficient_balance' | null;
  fees: FeeBreakdown;
  resources: ResourceUtilization;
  footprint: StorageFootprintAnalysis;
  stateChanges: SimulatedStateChange[];
  balanceChanges: SimulatedBalanceChange[];
  warnings: PreflightRiskWarning[];
  projectedReturnSummary?: string;
}

export function stroopsToXlm(stroops: string | number | bigint): string {
  try {
    const n = Number(stroops);
    if (!Number.isFinite(n) || n < 0) return '0.0000000';
    return (n / STROOPS_PER_XLM).toFixed(7);
  } catch {
    return '0.0000000';
  }
}

function parseSorobanTransactionData(
  rawTxData: unknown,
): xdr.SorobanTransactionData | null {
  if (!rawTxData) return null;
  try {
    if (typeof rawTxData === 'string' && rawTxData.trim().length > 0) {
      return xdr.SorobanTransactionData.fromXDR(rawTxData.trim(), 'base64');
    }
    if (typeof rawTxData === 'object') {
      const candidate = rawTxData as {
        resources?: () => xdr.SorobanResources;
        build?: () => xdr.SorobanTransactionData;
        toXDR?: (fmt?: 'raw' | 'hex' | 'base64') => string | Buffer;
      };
      if (typeof candidate.resources === 'function') {
        return candidate as unknown as xdr.SorobanTransactionData;
      }
      if (typeof candidate.build === 'function') {
        return candidate.build();
      }
      if (typeof candidate.toXDR === 'function') {
        const b64 = candidate.toXDR('base64');
        if (typeof b64 === 'string' && b64.length > 0) {
          return xdr.SorobanTransactionData.fromXDR(b64, 'base64');
        }
      }
    }
  } catch {
    return null;
  }
  return null;
}

function classifyLedgerKey(
  key: xdr.LedgerKey,
  mode: 'read' | 'write',
  index: number,
): FootprintEntryItem {
  try {
    const switchName = key.switch().name;
    if (switchName === 'contractData') {
      const cd = key.contractData();
      const durName = cd.durability().name;
      const durability: FootprintDurability =
        durName === 'temporary' ? 'temporary' : 'persistent';
      let keyLabel = `ContractData #${index + 1}`;
      try {
        const scvKey = cd.key();
        if (scvKey.switch().name === 'scvSymbol') {
          keyLabel = `ContractData(${scvKey.sym().toString()})`;
        } else if (scvKey.switch().name === 'scvVec') {
          const vec = scvKey.vec() ?? [];
          if (vec.length > 0 && vec[0].switch().name === 'scvSymbol') {
            keyLabel = `ContractData(${vec[0].sym().toString()})`;
          }
        }
      } catch {
        // fallback label
      }
      return {
        keySummary: keyLabel,
        durability,
        mode,
        entryKind: 'contractData',
      };
    }
    if (switchName === 'contractCode') {
      return {
        keySummary: `ContractCode WASM #${index + 1}`,
        durability: 'persistent',
        mode,
        entryKind: 'contractCode',
      };
    }
    if (switchName === 'account') {
      return {
        keySummary: `AccountEntry #${index + 1}`,
        durability: 'persistent',
        mode,
        entryKind: 'account',
      };
    }
    if (switchName === 'trustline') {
      return {
        keySummary: `TrustLineEntry #${index + 1}`,
        durability: 'persistent',
        mode,
        entryKind: 'trustline',
      };
    }
    return {
      keySummary: `${switchName} #${index + 1}`,
      durability: 'persistent',
      mode,
      entryKind: switchName,
    };
  } catch {
    return {
      keySummary: `LedgerKey #${index + 1}`,
      durability: 'persistent',
      mode,
      entryKind: 'unknown',
    };
  }
}

export function extractStorageFootprint(
  simulation: rpc.Api.SimulateTransactionResponse | Record<string, unknown>,
  resourceFeeStroops: bigint,
): StorageFootprintAnalysis {
  const simAny = simulation as Record<string, unknown>;
  const txData = parseSorobanTransactionData(simAny.transactionData);

  let persistentReads = 0;
  let persistentWrites = 0;
  let temporaryReads = 0;
  let temporaryWrites = 0;
  let diskReadBytes = 0;
  let writeBytes = 0;
  const entries: FootprintEntryItem[] = [];

  if (txData) {
    try {
      const resources = txData.resources();
      diskReadBytes = Number(resources.diskReadBytes?.() ?? 0);
      writeBytes = Number(resources.writeBytes?.() ?? 0);
      const footprint = resources.footprint();
      const readOnlyKeys = footprint.readOnly() ?? [];
      const readWriteKeys = footprint.readWrite() ?? [];

      readOnlyKeys.forEach((k, idx) => {
        const item = classifyLedgerKey(k, 'read', idx);
        entries.push(item);
        if (item.durability === 'temporary') {
          temporaryReads += 1;
        } else {
          persistentReads += 1;
        }
      });

      readWriteKeys.forEach((k, idx) => {
        const item = classifyLedgerKey(k, 'write', idx);
        entries.push(item);
        if (item.durability === 'temporary') {
          temporaryWrites += 1;
        } else {
          persistentWrites += 1;
        }
      });
    } catch {
      // ignore malformed XDR footprint
    }
  }

  const restorePreamble = simAny.restorePreamble as
    | { minResourceFee?: string; transactionData?: unknown }
    | undefined;
  const requiresRestore = Boolean(
    restorePreamble &&
      restorePreamble.minResourceFee &&
      restorePreamble.minResourceFee !== '0',
  );

  const totalReads = persistentReads + temporaryReads;
  const totalWrites = persistentWrites + temporaryWrites;

  // Estimate storage deposit requirement from write bytes and persistent/temporary writes
  const writeByteDeposit = BigInt(Math.max(0, writeBytes)) * 10n;
  const entryDeposit =
    BigInt(persistentWrites) * 25_000n + BigInt(temporaryWrites) * 5_000n;
  const rawStorageDeposit = writeByteDeposit + entryDeposit;
  const cappedDeposit =
    resourceFeeStroops > 0n && rawStorageDeposit > resourceFeeStroops
      ? resourceFeeStroops
      : rawStorageDeposit;

  const storageDepositStroops = cappedDeposit.toString();

  return {
    persistentReads,
    persistentWrites,
    temporaryReads,
    temporaryWrites,
    totalReads,
    totalWrites,
    diskReadBytes,
    writeBytes,
    storageDepositStroops,
    storageDepositXlm: stroopsToXlm(storageDepositStroops),
    requiresRestore,
    entries,
  };
}

function parseRequiredAuths(simulation: Record<string, unknown>): string[] {
  const requiredAuths: string[] = [];
  const resultObj = simulation.result as { auth?: unknown[] } | undefined;
  const resultsArr = simulation.results as Array<{ auth?: unknown[] }> | undefined;
  const authList =
    resultObj?.auth ??
    (Array.isArray(resultsArr) && resultsArr[0]?.auth ? resultsArr[0].auth : []);

  if (Array.isArray(authList)) {
    for (const auth of authList) {
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
  return requiredAuths;
}

/**
 * Pure analyzer that converts a raw Soroban `simulateTransaction` response and optional
 * context into a comprehensive `PreflightSimulationReport`.
 */
export function analyzePreflightSimulation(
  simulation: rpc.Api.SimulateTransactionResponse | Record<string, unknown>,
  context: PreflightSimulationContext = {},
): PreflightSimulationReport {
  const simAny = simulation as Record<string, unknown>;
  const isError =
    rpc.Api.isSimulationError(simulation as rpc.Api.SimulateTransactionResponse) ||
    (typeof simAny.error === 'string' && simAny.error.trim().length > 0);

  const rawBaseFee = context.baseFeeStroops ?? BASE_FEE ?? '100';
  const parsedBaseFee = BigInt(rawBaseFee);
  const baseFeeBigInt = parsedBaseFee > 0n ? parsedBaseFee : BigInt(BASE_FEE ?? '100');
  const minResourceFeeStr =
    typeof simAny.minResourceFee === 'string' && simAny.minResourceFee.trim()
      ? simAny.minResourceFee.trim()
      : '0';
  const resourceFeeBigInt = isError ? 0n : BigInt(minResourceFeeStr);

  const costObj = (simAny.cost ?? {}) as {
    cpuInsns?: string | number;
    memBytes?: string | number;
  };
  const cpuInsnsStr = String(
    costObj.cpuInsns ?? simAny.cpuInsns ?? '0',
  );
  const memBytesStr = String(
    costObj.memBytes ?? simAny.memoryBytes ?? simAny.memBytes ?? '0',
  );

  const cpuNum = Number(cpuInsnsStr) || 0;
  const memNum = Number(memBytesStr) || 0;
  const cpuUtilizationPct = Math.min(
    100,
    Number(((cpuNum / SOROBAN_MAX_CPU_INSNS) * 100).toFixed(2)),
  );
  const memUtilizationPct = Math.min(
    100,
    Number(((memNum / SOROBAN_MAX_MEM_BYTES) * 100).toFixed(2)),
  );

  const footprint = extractStorageFootprint(simulation, resourceFeeBigInt);

  // Split resource fee into refundable (rent/events) and non-refundable (inclusion/CPU/read)
  const storageDepositBigInt = BigInt(footprint.storageDepositStroops);
  const refundableFeeBigInt =
    storageDepositBigInt > 0n
      ? storageDepositBigInt
      : (resourceFeeBigInt * 35n) / 100n;
  const nonRefundableFeeBigInt =
    resourceFeeBigInt > refundableFeeBigInt
      ? resourceFeeBigInt - refundableFeeBigInt
      : 0n;
  const totalFeeBigInt = isError ? 0n : baseFeeBigInt + resourceFeeBigInt;

  const fees: FeeBreakdown = {
    baseFeeStroops: baseFeeBigInt.toString(),
    baseFeeXlm: stroopsToXlm(baseFeeBigInt),
    resourceFeeStroops: resourceFeeBigInt.toString(),
    resourceFeeXlm: stroopsToXlm(resourceFeeBigInt),
    refundableFeeStroops: refundableFeeBigInt.toString(),
    refundableFeeXlm: stroopsToXlm(refundableFeeBigInt),
    nonRefundableFeeStroops: nonRefundableFeeBigInt.toString(),
    nonRefundableFeeXlm: stroopsToXlm(nonRefundableFeeBigInt),
    storageDepositStroops: footprint.storageDepositStroops,
    storageDepositXlm: footprint.storageDepositXlm,
    totalFeeStroops: totalFeeBigInt.toString(),
    totalFeeXlm: stroopsToXlm(totalFeeBigInt),
  };

  const resources: ResourceUtilization = {
    cpuInsns: cpuInsnsStr,
    cpuLimit: SOROBAN_MAX_CPU_INSNS,
    cpuUtilizationPct,
    memBytes: memBytesStr,
    memLimit: SOROBAN_MAX_MEM_BYTES,
    memUtilizationPct,
  };

  // Legacy SimulationCost shape for backward compatibility with SimulationPreview
  const cost: SimulationCost | undefined = isError
    ? undefined
    : {
        feeStroops: resourceFeeBigInt.toString(),
        feeXlm: stroopsToXlm(resourceFeeBigInt),
        cpuInsns: cpuInsnsStr,
        memBytes: memBytesStr,
      };

  const requiredAuths = isError ? [] : parseRequiredAuths(simAny);

  // Build state diff preview
  const stateChanges: SimulatedStateChange[] = [];
  if (!isError) {
    const rawStateChanges = simAny.stateChanges as
      | Array<{ type?: string | number; key?: string; before?: string | null; after?: string | null }>
      | undefined;

    if (Array.isArray(rawStateChanges) && rawStateChanges.length > 0) {
      rawStateChanges.forEach((sc, idx) => {
        const isCreate = !sc.before || String(sc.type) === '1' || sc.type === 'created';
        stateChanges.push({
          id: `state-change-${idx}`,
          label: `Ledger Entry #${idx + 1}`,
          durability: 'persistent',
          changeType: isCreate ? 'created' : 'updated',
          beforeSummary: sc.before ? 'Existing state' : 'None (unallocated)',
          afterSummary: sc.after ? 'Updated contract state' : 'Committed on-chain',
        });
      });
    } else {
      const writeEntries = footprint.entries.filter((e) => e.mode === 'write');
      if (writeEntries.length > 0) {
        writeEntries.forEach((entry, idx) => {
          stateChanges.push({
            id: `footprint-write-${idx}`,
            label: entry.keySummary,
            durability: entry.durability,
            changeType: idx === 0 ? 'created' : 'updated',
            beforeSummary: idx === 0 ? 'Unallocated slot' : 'Current ledger entry',
            afterSummary:
              entry.durability === 'persistent'
                ? 'Persistent ledger state updated'
                : 'Temporary TTL state updated',
          });
        });
      } else {
        const opName = context.operationName ?? 'create_commitment';
        stateChanges.push({
          id: 'projected-commitment-entry',
          label: `ContractData (${opName})`,
          durability: 'persistent',
          changeType: 'created',
          beforeSummary: 'Unallocated commitment slot',
          afterSummary: context.counterpartyAddress
            ? `Active commitment with ${context.counterpartyAddress.slice(0, 6)}...${context.counterpartyAddress.slice(-4)}`
            : 'New on-chain commitment record',
        });
        if (context.isEncrypted) {
          stateChanges.push({
            id: 'projected-encrypted-hash',
            label: 'ContractData (TermsHash · E2E Encrypted)',
            durability: 'persistent',
            changeType: 'created',
            beforeSummary: 'None',
            afterSummary: 'SHA-256 commitment hash anchored on-chain',
          });
        }
        if (context.hasValidationRules) {
          stateChanges.push({
            id: 'projected-validation-rules',
            label: 'ContractData (ValidationRules AST)',
            durability: 'temporary',
            changeType: 'updated',
            beforeSummary: 'Default rule set',
            afterSummary: 'Custom validation conditions verified',
          });
        }
      }
    }
  }

  // Build balance diff preview
  const balanceChanges: SimulatedBalanceChange[] = [];
  const hasKnownBalance =
    context.accountBalanceStroops !== undefined &&
    context.accountBalanceStroops !== null;
  const accountBalanceBigInt = hasKnownBalance
    ? BigInt(context.accountBalanceStroops!)
    : null;

  if (!isError) {
    const afterBalanceBigInt =
      accountBalanceBigInt !== null ? accountBalanceBigInt - totalFeeBigInt : null;
    balanceChanges.push({
      address: context.sourceAddress
        ? `${context.sourceAddress.slice(0, 6)}...${context.sourceAddress.slice(-4)}`
        : 'Source Account',
      asset: 'XLM',
      deltaStroops: `-${totalFeeBigInt.toString()}`,
      deltaFormatted: `-${stroopsToXlm(totalFeeBigInt)} XLM`,
      beforeBalanceXlm:
        accountBalanceBigInt !== null ? `${stroopsToXlm(accountBalanceBigInt)} XLM` : undefined,
      afterBalanceXlm:
        afterBalanceBigInt !== null && afterBalanceBigInt >= 0n
          ? `${stroopsToXlm(afterBalanceBigInt)} XLM`
          : undefined,
      reason: 'Base inclusion fee + Soroban resource & storage deposit',
    });
  }

  // Evaluate risk warnings and submission gate
  const warnings: PreflightRiskWarning[] = [];
  let blockingReason: 'contract_revert' | 'insufficient_balance' | null = null;

  if (isError) {
    blockingReason = 'contract_revert';
    warnings.push({
      code: 'contract_revert',
      severity: 'critical',
      title: 'Contract Revert Detected',
      message:
        (typeof simAny.error === 'string' && simAny.error) ||
        'Preflight simulation indicates this transaction will revert on-chain. Submission is blocked to prevent wasted fees.',
    });
  } else {
    if (accountBalanceBigInt !== null && accountBalanceBigInt < totalFeeBigInt) {
      blockingReason = 'insufficient_balance';
      warnings.push({
        code: 'insufficient_balance',
        severity: 'critical',
        title: 'Insufficient XLM Balance',
        message: `Account balance (${stroopsToXlm(accountBalanceBigInt)} XLM) is below the required total fee and storage deposit (${stroopsToXlm(totalFeeBigInt)} XLM).`,
      });
    }

    if (footprint.requiresRestore) {
      warnings.push({
        code: 'archived_restore_required',
        severity: 'warning',
        title: 'Archived State Restoration Required',
        message:
          'One or more persistent ledger entries referenced by this contract call are archived and require a restore preamble transaction.',
      });
    }

    if (cpuUtilizationPct >= 80) {
      warnings.push({
        code: 'high_cpu_utilization',
        severity: 'warning',
        title: `High CPU Utilization (${cpuUtilizationPct}%)`,
        message:
          'Predicted CPU instructions exceed 80% of the Soroban per-transaction instruction limit. Consider simplifying validation rules if contention occurs.',
      });
    }

    if (memUtilizationPct >= 80) {
      warnings.push({
        code: 'high_memory_utilization',
        severity: 'warning',
        title: `High Memory Utilization (${memUtilizationPct}%)`,
        message:
          'Predicted linear memory usage exceeds 80% of the Soroban transaction memory limit.',
      });
    }

    if (footprint.persistentWrites >= 5) {
      warnings.push({
        code: 'heavy_persistent_writes',
        severity: 'info',
        title: `Multi-Entry Persistent Footprint (${footprint.persistentWrites} writes)`,
        message:
          'This multi-operation contract call writes multiple persistent ledger entries, increasing the refundable storage rent deposit.',
      });
    }
  }

  return {
    success: !isError,
    error: isError
      ? (typeof simAny.error === 'string' && simAny.error) ||
        'Simulation failed with unknown error.'
      : undefined,
    cost,
    requiredAuths,
    rawSimulation: simulation as rpc.Api.SimulateTransactionResponse,
    canSubmit: blockingReason === null,
    blockingReason,
    fees,
    resources,
    footprint,
    stateChanges,
    balanceChanges,
    warnings,
  };
}

export async function fetchNativeAccountBalanceStroops(
  server: rpc.Server,
  accountAddress: string,
): Promise<bigint | null> {
  try {
    const ledgerKey = xdr.LedgerKey.account(
      new xdr.LedgerKeyAccount({
        accountId: Address.fromString(accountAddress).toScAddress().accountId(),
      }),
    );
    const resp = await server.getLedgerEntries(ledgerKey);
    const entries = resp?.entries ?? [];
    if (entries.length === 0) return null;
    const first = entries[0] as unknown as {
      val?: xdr.LedgerEntryData;
      xdr?: string;
    };
    const entryData =
      first.val ??
      (typeof first.xdr === 'string'
        ? xdr.LedgerEntryData.fromXDR(first.xdr, 'base64')
        : null);
    if (!entryData || entryData.switch().name !== 'account') return null;
    const balanceStr = entryData.account().balance().toString();
    return BigInt(balanceStr);
  } catch {
    return null;
  }
}

export interface RunPreflightSimulationOptions extends PreflightSimulationContext {
  rpcUrl?: string;
  checkAccountBalance?: boolean;
}

export async function runPreflightSimulation(
  tx: ReturnType<TransactionBuilder['build']>,
  options: RunPreflightSimulationOptions = {},
): Promise<PreflightSimulationReport> {
  const rpcUrl =
    options.rpcUrl ||
    import.meta.env.VITE_SOROBAN_RPC_URL ||
    DEFAULT_SOROBAN_RPC_URL;
  const server = new rpc.Server(rpcUrl, { allowHttp: true });

  const [simulation, fetchedBalance] = await Promise.all([
    server.simulateTransaction(tx),
    options.accountBalanceStroops !== undefined
      ? Promise.resolve(
          options.accountBalanceStroops !== null
            ? BigInt(options.accountBalanceStroops)
            : null,
        )
      : options.checkAccountBalance && options.sourceAddress
        ? fetchNativeAccountBalanceStroops(server, options.sourceAddress)
        : Promise.resolve(null),
  ]);

  const txFee = (tx as unknown as { fee?: string | number })?.fee ?? BASE_FEE;

  return analyzePreflightSimulation(simulation, {
    ...options,
    baseFeeStroops: options.baseFeeStroops ?? txFee,
    accountBalanceStroops: fetchedBalance,
  });
}

export interface UsePreflightSimulationReturn {
  isOpen: boolean;
  isLoading: boolean;
  report: PreflightSimulationReport | null;
  simulate: (
    tx: ReturnType<TransactionBuilder['build']>,
    options?: RunPreflightSimulationOptions,
  ) => Promise<PreflightSimulationReport>;
  openModal: () => void;
  closeModal: () => void;
  setReport: (report: PreflightSimulationReport | null) => void;
  waitForConfirmation: () => Promise<void>;
  confirm: () => void;
  cancel: () => void;
  reset: () => void;
}

export function usePreflightSimulation(): UsePreflightSimulationReturn {
  const [isOpen, setIsOpen] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [report, setReport] = useState<PreflightSimulationReport | null>(null);
  const resolverRef = useRef<{
    resolve: () => void;
    reject: (err: Error) => void;
  } | null>(null);

  const openModal = useCallback(() => {
    setIsOpen(true);
  }, []);

  const closeModal = useCallback(() => {
    setIsOpen(false);
  }, []);

  const simulate = useCallback(
    async (
      tx: ReturnType<TransactionBuilder['build']>,
      options: RunPreflightSimulationOptions = {},
    ): Promise<PreflightSimulationReport> => {
      setIsLoading(true);
      setReport(null);
      try {
        const result = await runPreflightSimulation(tx, options);
        setReport(result);
        return result;
      } finally {
        setIsLoading(false);
      }
    },
    [],
  );

  const waitForConfirmation = useCallback((): Promise<void> => {
    return new Promise<void>((resolve, reject) => {
      resolverRef.current = { resolve, reject };
    });
  }, []);

  const confirm = useCallback(() => {
    if (report && !report.canSubmit) {
      return;
    }
    if (resolverRef.current) {
      resolverRef.current.resolve();
      resolverRef.current = null;
    }
    setIsOpen(false);
  }, [report]);

  const cancel = useCallback(() => {
    if (resolverRef.current) {
      resolverRef.current.reject(new Error('User cancelled preflight.'));
      resolverRef.current = null;
    }
    setIsOpen(false);
  }, []);

  const reset = useCallback(() => {
    setIsOpen(false);
    setIsLoading(false);
    setReport(null);
    resolverRef.current = null;
  }, []);

  return {
    isOpen,
    isLoading,
    report,
    simulate,
    openModal,
    closeModal,
    setReport,
    waitForConfirmation,
    confirm,
    cancel,
    reset,
  };
}
