import {
  Account,
  BASE_FEE,
  Contract,
  Keypair,
  TransactionBuilder,
  nativeToScVal,
  rpc,
  scValToNative,
} from '@stellar/stellar-sdk';

import {
  cuckoo_filter_contains,
  cuckoo_filter_insert,
  cuckoo_filter_reset,
  evaluateCuckooInclusionProof,
  sha256Hex,
  verifySpvHeaderChain,
  type LedgerHeaderEntry,
  type MerkleBranchStep,
} from '../../workers/validation.worker';
import type { LocalIndexerRpcClient } from './poller';

export interface SpvSecurityWarningBanner {
  severity: 'critical' | 'warning';
  code:
    | 'SPOOFED_ACCOUNT_BALANCE'
    | 'TAMPERED_COMMITMENT_PAYLOAD'
    | 'UNINDEXED_PHANTOM_COMMITMENT'
    | 'INVALID_LEDGER_HEADER_CHAIN';
  bannerMessage: string;
  commitmentId?: number;
  accountAddress?: string;
  detectedAt: number;
}

export interface SpvCommitmentProof {
  commitmentId: number;
  expectedLeafHash: string;
  merkleBranch: MerkleBranchStep[];
  expectedBucketRoot: string;
}

export interface SpvAccountBalanceProof {
  accountAddress: string;
  expectedBalanceStroops: bigint;
  merkleBranch: MerkleBranchStep[];
  expectedBucketRoot: string;
}

/**
 * SPV State Manager connecting local indexer RPC queries with client-side Cuckoo Filter
 * and Stellar ledger header chain cryptographic verification (#301).
 */
export class SpvStateManager {
  private readonly encoder = new TextEncoder();
  private readonly commitmentProofs = new Map<number, SpvCommitmentProof>();
  private readonly balanceProofs = new Map<string, SpvAccountBalanceProof>();
  private readonly warningBanners: SpvSecurityWarningBanner[] = [];
  private readonly onWarningBanner?: (banner: SpvSecurityWarningBanner) => void;
  private trustedValidatorKeys: string[];
  private latestVerifiedBucketRoot: string | null = null;

  constructor(options?: {
    trustedValidatorKeys?: string[];
    onWarningBanner?: (banner: SpvSecurityWarningBanner) => void;
    resetFilterOnInit?: boolean;
  }) {
    this.trustedValidatorKeys = options?.trustedValidatorKeys ?? [];
    this.onWarningBanner = options?.onWarningBanner;
    if (options?.resetFilterOnInit !== false) {
      cuckoo_filter_reset();
    }
  }

  public getWarningBanners(): SpvSecurityWarningBanner[] {
    return [...this.warningBanners];
  }

  public getLatestVerifiedBucketRoot(): string | null {
    return this.latestVerifiedBucketRoot;
  }

  private emitWarning(
    code: SpvSecurityWarningBanner['code'],
    bannerMessage: string,
    meta?: { commitmentId?: number; accountAddress?: string },
  ): SpvSecurityWarningBanner {
    const banner: SpvSecurityWarningBanner = {
      severity: 'critical',
      code,
      bannerMessage,
      commitmentId: meta?.commitmentId,
      accountAddress: meta?.accountAddress,
      detectedAt: Date.now(),
    };
    this.warningBanners.push(banner);
    this.onWarningBanner?.(banner);
    return banner;
  }

  /**
   * Verifies a continuous stream of Stellar ledger headers and pins the latest verified
   * bucket list root for subsequent commitment & balance inclusion checks.
   */
  public ingestLedgerHeaderStream(headers: LedgerHeaderEntry[]): boolean {
    const res = verifySpvHeaderChain(headers, this.trustedValidatorKeys);
    if (!res.valid) {
      this.emitWarning(
        'INVALID_LEDGER_HEADER_CHAIN',
        `WARNING: Blocked untrusted RPC ledger header stream — ${res.error ?? 'verification failed'}`,
      );
      return false;
    }
    const lastHeader = headers[headers.length - 1];
    this.latestVerifiedBucketRoot = lastHeader.bucketListHash;
    return true;
  }

  /**
   * Registers an SPV commitment proof and inserts its commitment key into the WASM Cuckoo Filter.
   */
  public registerCommitmentProof(
    commitment: Record<string, unknown>,
    merkleBranch: MerkleBranchStep[],
    expectedBucketRoot: string,
  ): string {
    const id = Number(commitment.id);
    const key = `commitment:${id}`;
    cuckoo_filter_insert(this.encoder.encode(key));
    const leafHash = computeCommitmentLeafHash(commitment);
    this.commitmentProofs.set(id, {
      commitmentId: id,
      expectedLeafHash: leafHash,
      merkleBranch,
      expectedBucketRoot,
    });
    return leafHash;
  }

  /**
   * Registers an SPV account balance proof and inserts the account key into the WASM Cuckoo Filter.
   */
  public registerAccountBalanceProof(
    accountAddress: string,
    expectedBalanceStroops: bigint,
    merkleBranch: MerkleBranchStep[],
    expectedBucketRoot: string,
  ): string {
    const key = `account:${accountAddress}`;
    cuckoo_filter_insert(this.encoder.encode(key));
    this.balanceProofs.set(accountAddress, {
      accountAddress,
      expectedBalanceStroops,
      merkleBranch,
      expectedBucketRoot,
    });
    return sha256Hex(`${accountAddress}:${expectedBalanceStroops.toString()}`);
  }

  /**
   * Validates an RPC-returned commitment record against the Cuckoo Filter and SPV Merkle proof.
   * Flags and blocks tampered or unindexed phantom commitments with a warning banner.
   */
  public validateCommitmentResponse(
    id: number,
    rawCommitment: Record<string, unknown> | null,
  ): Record<string, unknown> | null {
    if (!rawCommitment) return null;

    const key = `commitment:${id}`;
    if (!cuckoo_filter_contains(this.encoder.encode(key))) {
      this.emitWarning(
        'UNINDEXED_PHANTOM_COMMITMENT',
        `WARNING: Blocked unverified RPC commitment #${id} — absent from client SPV Cuckoo Filter.`,
        { commitmentId: id },
      );
      return null;
    }

    const proof = this.commitmentProofs.get(id);
    if (!proof) {
      return rawCommitment;
    }

    const actualLeafHash = computeCommitmentLeafHash(rawCommitment);
    const inclusion = evaluateCuckooInclusionProof({
      commitmentKey: key,
      leafHash: actualLeafHash,
      merkleBranch: proof.merkleBranch,
      expectedBucketRoot: proof.expectedBucketRoot,
    });

    if (!inclusion.isValid || actualLeafHash !== proof.expectedLeafHash) {
      this.emitWarning(
        'TAMPERED_COMMITMENT_PAYLOAD',
        `WARNING: Malicious RPC response blocked — tampered commitment #${id} failed SPV Merkle verification.`,
        { commitmentId: id },
      );
      return null;
    }

    return rawCommitment;
  }

  /**
   * Validates an RPC-returned account balance against the Cuckoo Filter and SPV Merkle proof.
   * Flags and blocks spoofed balances with a warning banner.
   */
  public validateAccountBalanceResponse(
    accountAddress: string,
    reportedBalanceStroops: bigint,
  ): bigint | null {
    const key = `account:${accountAddress}`;
    const proof = this.balanceProofs.get(accountAddress);

    if (!cuckoo_filter_contains(this.encoder.encode(key)) || !proof) {
      this.emitWarning(
        'SPOOFED_ACCOUNT_BALANCE',
        `WARNING: Malicious RPC response blocked — unverified balance for ${accountAddress}.`,
        { accountAddress },
      );
      return null;
    }

    const leafHash = sha256Hex(`${accountAddress}:${reportedBalanceStroops.toString()}`);
    const inclusion = evaluateCuckooInclusionProof({
      commitmentKey: key,
      leafHash,
      merkleBranch: proof.merkleBranch,
      expectedBucketRoot: proof.expectedBucketRoot,
    });

    if (!inclusion.isValid || reportedBalanceStroops !== proof.expectedBalanceStroops) {
      this.emitWarning(
        'SPOOFED_ACCOUNT_BALANCE',
        `WARNING: Malicious RPC response blocked — spoofed balance (${reportedBalanceStroops.toString()} stroops) for account ${accountAddress}.`,
        { accountAddress },
      );
      return null;
    }

    return reportedBalanceStroops;
  }
}

export function computeCommitmentLeafHash(raw: Record<string, unknown>): string {
  const id = String(raw.id ?? '');
  const issuer = String(raw.issuer ?? '');
  const counterparty = String(raw.counterparty ?? '');
  const dueAt = String(raw.due_at ?? '');
  const status = String(raw.status ?? '');
  const termsBytes =
    raw.terms_hash instanceof Uint8Array
      ? Array.from(raw.terms_hash)
          .map((b) => b.toString(16).padStart(2, '0'))
          .join('')
      : String(raw.terms_hash ?? '');
  return sha256Hex(`${id}|${issuer}|${counterparty}|${termsBytes}|${dueAt}|${status}`);
}

export interface SorobanIndexerRpcClientConfig {
  rpcUrl: string;
  contractId: string;
  networkPassphrase: string;
  spvStateManager?: SpvStateManager;
}

/** A throwaway, never-funded, never-signing source account — required by the SDK to build a simulate-only read call. */
function readOnlyAccount(): Account {
  return new Account(Keypair.random().publicKey(), '0');
}

/** Real Soroban RPC-backed implementation of `LocalIndexerRpcClient`, used by `indexer.worker.ts`. */
export function createSorobanIndexerRpcClient(
  config: SorobanIndexerRpcClientConfig,
): LocalIndexerRpcClient {
  const server = new rpc.Server(config.rpcUrl, { allowHttp: true });
  const contract = new Contract(config.contractId);

  return {
    async getLatestLedger() {
      const ledger = await server.getLatestLedger();
      return { sequence: ledger.sequence };
    },

    async getEvents(request) {
      const response = await server.getEvents(request);
      return {
        events: response.events.map((event) => ({ topic: event.topic, value: event.value })),
        cursor: response.cursor,
      };
    },

    async getCommitment(id) {
      const transaction = new TransactionBuilder(readOnlyAccount(), {
        fee: BASE_FEE,
        networkPassphrase: config.networkPassphrase,
      })
        .addOperation(contract.call('get_commitment', nativeToScVal(id, { type: 'u64' })))
        .setTimeout(30)
        .build();

      const simulation = await server.simulateTransaction(transaction);
      if (rpc.Api.isSimulationError(simulation) || !simulation.result) return null;

      const value = scValToNative(simulation.result.retval);
      const raw = value && typeof value === 'object' ? (value as Record<string, unknown>) : null;
      if (config.spvStateManager) {
        return config.spvStateManager.validateCommitmentResponse(id, raw);
      }
      return raw;
    },
  };
}
