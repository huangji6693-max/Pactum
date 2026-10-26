import { Keypair, hash as stellarSha256 } from '@stellar/stellar-sdk';
import { Buffer } from 'buffer';
import initWasm, {
  cuckoo_filter_contains,
  cuckoo_filter_delete,
  cuckoo_filter_insert,
  cuckoo_filter_len,
  cuckoo_filter_reset,
  evaluate_ast_binary,
  validate_commitment_params,
} from '../wasm/pactum-validation/pactum_validation.js';
import wasmUrl from '../wasm/pactum-validation/pactum_validation_bg.wasm?url';

export interface ValidationRequest {
  type?: 'VALIDATE_COMMITMENT';
  id: string;
  dueAt: number;
  currentTime: number;
  milestoneCount: number;
}

export interface AstValidationRequest {
  type: 'EVALUATE_AST';
  id: string;
  ruleSetBinary: Uint8Array;
  values: Record<string, unknown>;
  now: number;
  gasLimit?: number;
  recordSteps?: boolean;
}

export interface LedgerHeaderEntry {
  sequence: number;
  previousHeaderHash: string;
  bucketListHash: string;
  headerXdrBase64?: string;
  validatorPublicKey: string;
  validatorSignatureHex: string;
  bucketEntries?: string[];
}

export interface SpvHeaderChainRequest {
  type: 'VERIFY_SPV_HEADER_CHAIN';
  id: string;
  headers: LedgerHeaderEntry[];
  trustedValidatorKeys?: string[];
}

export interface MerkleBranchStep {
  sibling: string;
  isLeft: boolean;
}

export interface CuckooInclusionRequest {
  type: 'VERIFY_CUCKOO_INCLUSION';
  id: string;
  commitmentKey: string;
  leafHash: string;
  merkleBranch: MerkleBranchStep[];
  expectedBucketRoot: string;
  populateKeys?: string[];
  resetFilter?: boolean;
}

export type WorkerRequest =
  ValidationRequest | AstValidationRequest | SpvHeaderChainRequest | CuckooInclusionRequest;

export interface ValidationResponse {
  id: string;
  isValid: boolean;
  error?: string;
  trace?: unknown;
  elapsedMs?: number;
  cuckooHit?: boolean;
  merkleValid?: boolean;
  verifiedHeaderCount?: number;
  headHash?: string;
}

let wasmInitialized = false;
let initPromise: Promise<void> | null = null;

async function ensureWasmInitialized(): Promise<void> {
  if (wasmInitialized) return;
  if (!initPromise) {
    initPromise = initWasm(wasmUrl)
      .then(() => {
        wasmInitialized = true;
      })
      .catch((err) => {
        initPromise = null;
        throw err;
      });
  }
  await initPromise;
}

function normalizeHex(hex: string): string {
  return hex.startsWith('0x') ? hex.slice(2).toLowerCase() : hex.toLowerCase();
}

export function sha256Hex(data: Uint8Array | string): string {
  const buf = typeof data === 'string' ? Buffer.from(data, 'utf8') : Buffer.from(data);
  return Buffer.from(stellarSha256(buf)).toString('hex');
}

export function sha256PairHex(leftHex: string, rightHex: string): string {
  const combined = Buffer.concat([
    Buffer.from(normalizeHex(leftHex), 'hex'),
    Buffer.from(normalizeHex(rightHex), 'hex'),
  ]);
  return Buffer.from(stellarSha256(combined)).toString('hex');
}

/**
 * Computes the binary SHA-256 Merkle root over a list of hex or UTF-8 bucket entries.
 */
export function computeBucketListRootHex(entries: string[]): string {
  if (entries.length === 0) {
    return sha256Hex('');
  }
  let layer = entries.map((e) => (/^[0-9a-fA-F]{64}$/.test(e) ? e.toLowerCase() : sha256Hex(e)));
  while (layer.length > 1) {
    const next: string[] = [];
    for (let i = 0; i < layer.length; i += 2) {
      const left = layer[i];
      const right = i + 1 < layer.length ? layer[i + 1] : layer[i];
      next.push(sha256PairHex(left, right));
    }
    layer = next;
  }
  return layer[0];
}

/**
 * Computes the canonical SHA-256 digest of a Stellar SPV ledger header.
 */
export function computeLedgerHeaderHashHex(
  header: Pick<
    LedgerHeaderEntry,
    'sequence' | 'previousHeaderHash' | 'bucketListHash' | 'headerXdrBase64'
  >,
): string {
  const canonical = `${header.sequence}:${normalizeHex(header.previousHeaderHash)}:${normalizeHex(
    header.bucketListHash,
  )}:${header.headerXdrBase64 ?? ''}`;
  return sha256Hex(canonical);
}

/**
 * Verifies a continuous stream of Stellar ledger headers:
 * 1. Monotonic sequence continuity (`seq[i] === seq[i-1] + 1`) and `previousHeaderHash` linkage.
 * 2. SHA-256 bucket list hash integrity against `bucketEntries` (when provided).
 * 3. Ed25519 validator signature authenticity over each header hash.
 */
export function verifySpvHeaderChain(
  headers: LedgerHeaderEntry[],
  trustedValidatorKeys?: string[],
): { valid: boolean; verifiedCount: number; headHash?: string; error?: string } {
  if (headers.length === 0) {
    return { valid: false, verifiedCount: 0, error: 'Empty ledger header stream' };
  }

  const trustedSet =
    trustedValidatorKeys && trustedValidatorKeys.length > 0 ? new Set(trustedValidatorKeys) : null;

  let prevHash: string | null = null;
  let prevSeq: number | null = null;

  for (let i = 0; i < headers.length; i++) {
    const header = headers[i];

    if (prevSeq !== null && header.sequence !== prevSeq + 1) {
      return {
        valid: false,
        verifiedCount: i,
        error: `Non-continuous ledger sequence at index ${i}: expected ${prevSeq + 1}, got ${header.sequence}`,
      };
    }

    if (prevHash !== null && normalizeHex(header.previousHeaderHash) !== prevHash) {
      return {
        valid: false,
        verifiedCount: i,
        error: `Broken header hash chain at ledger ${header.sequence}`,
      };
    }

    if (trustedSet && !trustedSet.has(header.validatorPublicKey)) {
      return {
        valid: false,
        verifiedCount: i,
        error: `Untrusted validator public key ${header.validatorPublicKey} at ledger ${header.sequence}`,
      };
    }

    if (header.bucketEntries && header.bucketEntries.length > 0) {
      const computedBucketRoot = computeBucketListRootHex(header.bucketEntries);
      if (computedBucketRoot !== normalizeHex(header.bucketListHash)) {
        return {
          valid: false,
          verifiedCount: i,
          error: `Bucket list SHA-256 root mismatch at ledger ${header.sequence}`,
        };
      }
    }

    const headerHashHex = computeLedgerHeaderHashHex(header);
    try {
      const kp = Keypair.fromPublicKey(header.validatorPublicKey);
      const msgBuf = Buffer.from(headerHashHex, 'hex');
      const sigBuf = Buffer.from(normalizeHex(header.validatorSignatureHex), 'hex');
      if (!kp.verify(msgBuf, sigBuf)) {
        return {
          valid: false,
          verifiedCount: i,
          error: `Invalid Ed25519 validator signature at ledger ${header.sequence}`,
        };
      }
    } catch {
      return {
        valid: false,
        verifiedCount: i,
        error: `Malformed validator key or signature at ledger ${header.sequence}`,
      };
    }

    prevHash = headerHashHex;
    prevSeq = header.sequence;
  }

  return {
    valid: true,
    verifiedCount: headers.length,
    headHash: prevHash ?? undefined,
  };
}

/**
 * Evaluates commitment membership in the zero-allocation Cuckoo Filter and verifies
 * its SHA-256 Merkle inclusion branch against `expectedBucketRoot` in < 5ms.
 */
export function evaluateCuckooInclusionProof(req: Omit<CuckooInclusionRequest, 'type' | 'id'>): {
  isValid: boolean;
  cuckooHit: boolean;
  merkleValid: boolean;
  elapsedMs: number;
  filterCount: number;
  error?: string;
} {
  const start = performance.now();
  const encoder = new TextEncoder();

  if (req.resetFilter) {
    cuckoo_filter_reset();
  }

  if (req.populateKeys) {
    for (const key of req.populateKeys) {
      cuckoo_filter_insert(encoder.encode(key));
    }
  }

  const cuckooHit = cuckoo_filter_contains(encoder.encode(req.commitmentKey));
  if (!cuckooHit) {
    const elapsedMs = performance.now() - start;
    return {
      isValid: false,
      cuckooHit: false,
      merkleValid: false,
      elapsedMs,
      filterCount: cuckoo_filter_len(),
      error: `Commitment '${req.commitmentKey}' absent from SPV Cuckoo Filter`,
    };
  }

  let currentHash = normalizeHex(req.leafHash);
  for (const step of req.merkleBranch) {
    const siblingHex = normalizeHex(step.sibling);
    currentHash = step.isLeft
      ? sha256PairHex(siblingHex, currentHash)
      : sha256PairHex(currentHash, siblingHex);
  }

  const merkleValid = currentHash === normalizeHex(req.expectedBucketRoot);
  const elapsedMs = performance.now() - start;

  return {
    isValid: cuckooHit && merkleValid,
    cuckooHit,
    merkleValid,
    elapsedMs,
    filterCount: cuckoo_filter_len(),
    error: merkleValid ? undefined : 'SPV Merkle inclusion root mismatch',
  };
}

export {
  cuckoo_filter_contains,
  cuckoo_filter_delete,
  cuckoo_filter_insert,
  cuckoo_filter_len,
  cuckoo_filter_reset,
};

if (typeof self !== 'undefined' && typeof self.postMessage === 'function') {
  self.onmessage = async (event: MessageEvent<WorkerRequest>) => {
    const req = event.data;
    try {
      if (req.type === 'VERIFY_SPV_HEADER_CHAIN') {
        const res = verifySpvHeaderChain(req.headers, req.trustedValidatorKeys);
        const response: ValidationResponse = {
          id: req.id,
          isValid: res.valid,
          verifiedHeaderCount: res.verifiedCount,
          headHash: res.headHash,
          error: res.error,
        };
        self.postMessage(response);
        return;
      }

      if (req.type === 'VERIFY_CUCKOO_INCLUSION') {
        const res = evaluateCuckooInclusionProof(req);
        const response: ValidationResponse = {
          id: req.id,
          isValid: res.isValid,
          cuckooHit: res.cuckooHit,
          merkleValid: res.merkleValid,
          elapsedMs: res.elapsedMs,
          error: res.error,
        };
        self.postMessage(response);
        return;
      }

      await ensureWasmInitialized();

      if (req.type === 'EVALUATE_AST') {
        const { id, ruleSetBinary, values, now, gasLimit, recordSteps } = req;
        const contextJson = JSON.stringify({ values, now });
        const trace = evaluate_ast_binary(
          ruleSetBinary,
          contextJson,
          gasLimit ?? 100_000,
          recordSteps ?? false,
        ) as { valid?: boolean };
        const response: ValidationResponse = {
          id,
          isValid: trace?.valid === true,
          trace,
        };
        self.postMessage(response);
      } else {
        const { id, dueAt, currentTime, milestoneCount } = req;
        validate_commitment_params(BigInt(dueAt), BigInt(currentTime), milestoneCount);
        const response: ValidationResponse = { id, isValid: true };
        self.postMessage(response);
      }
    } catch (err: unknown) {
      const errorMsg =
        typeof err === 'string'
          ? err
          : err instanceof Error
            ? err.message
            : 'WASM validation failed.';
      const response: ValidationResponse = { id: req.id, isValid: false, error: errorMsg };
      self.postMessage(response);
    }
  };
}
