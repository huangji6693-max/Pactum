/**
 * Off-chain verification.
 *
 * Checking the pairing equation is only half the job. A Groth16 proof says "these
 * public signals satisfy the circuit" — it says nothing about whether those signals
 * are the ones the verifier cares about. A verifier that calls `groth16.verify` and
 * stops there will happily accept a valid proof against a stale root, a threshold of
 * 0, or another DAO's context. `verifyTrustThresholdProof` checks both halves.
 */

import * as snarkjs from 'snarkjs';

import type { Groth16Proof } from './prove.ts';
import { buildPoseidonHash } from './tree.ts';

/**
 * Public signal layout, in the order circom emits it: outputs first, then public
 * inputs in declaration order. Asserted against a real proof in `test/circuit.test.ts`.
 */
export const PUBLIC_SIGNAL_ORDER = ['aboveThreshold', 'root', 'threshold', 'contextId'] as const;

export interface PublicSignals {
  aboveThreshold: bigint;
  root: bigint;
  threshold: bigint;
  contextId: bigint;
}

export interface VerificationKey {
  protocol: string;
  curve: string;
  nPublic: number;
  [key: string]: unknown;
}

export interface VerifyRequest {
  proof: Groth16Proof;
  publicSignals: string[];
  verificationKey: VerificationKey;
  /** The snapshot root the verifier is willing to accept. */
  expectedRoot: bigint;
  /** The lowest threshold that earns the right being granted. */
  minThreshold: bigint;
  /** The verifier's own context identifier. */
  expectedContextId: bigint;
}

export type VerificationResult =
  { valid: true; signals: PublicSignals } | { valid: false; reason: string };

/** Destructures raw public signals into named values. */
export function parsePublicSignals(publicSignals: string[]): PublicSignals {
  if (publicSignals.length !== PUBLIC_SIGNAL_ORDER.length) {
    throw new Error(
      `Expected ${PUBLIC_SIGNAL_ORDER.length} public signals, got ${publicSignals.length}`,
    );
  }

  const [aboveThreshold, root, threshold, contextId] = publicSignals.map(BigInt);
  return { aboveThreshold, root, threshold, contextId };
}

/**
 * Verifies a Trust Score threshold proof and the claim it is being used to make.
 *
 * Returns a reason instead of throwing so a caller can log or surface which check
 * failed without conflating a malformed submission with a cryptographically invalid one.
 */
export async function verifyTrustThresholdProof(
  request: VerifyRequest,
): Promise<VerificationResult> {
  const { proof, publicSignals, verificationKey } = request;

  let signals: PublicSignals;
  try {
    signals = parsePublicSignals(publicSignals);
  } catch (error) {
    return { valid: false, reason: (error as Error).message };
  }

  // Cheap semantic checks first: they reject the common mistakes without paying for
  // a pairing check, and every one of them is required for the proof to mean anything.
  if (signals.aboveThreshold !== 1n) {
    return { valid: false, reason: 'Proof does not assert that the score is above the threshold' };
  }
  if (signals.root !== request.expectedRoot) {
    return { valid: false, reason: 'Proof is against a different reputation snapshot root' };
  }
  if (signals.threshold < request.minThreshold) {
    return {
      valid: false,
      reason: `Proven threshold ${signals.threshold} is below the required ${request.minThreshold}`,
    };
  }
  if (signals.contextId !== request.expectedContextId) {
    return { valid: false, reason: 'Proof was generated for a different context' };
  }

  const cryptographicallyValid = await snarkjs.groth16.verify(
    verificationKey,
    publicSignals,
    proof,
  );
  if (!cryptographicallyValid) {
    return { valid: false, reason: 'Groth16 verification failed' };
  }

  return { valid: true, signals };
}

// ---------------------------------------------------------------------------
// Batched Multi-Outcome Reputation Verification (Issue #298)
// ---------------------------------------------------------------------------

export const BATCH_PUBLIC_SIGNAL_ORDER = [
  'batchValid',
  'cumulativeScore',
  'batchCommitment',
  'root',
  'threshold',
  'minCumulativeScore',
  'contextId',
] as const;

export interface BatchPublicSignals {
  batchValid: bigint;
  cumulativeScore: bigint;
  batchCommitment: bigint;
  root: bigint;
  threshold: bigint;
  minCumulativeScore: bigint;
  contextId: bigint;
}

export interface BatchVerifyRequest {
  proof: Groth16Proof;
  publicSignals: string[];
  verificationKey?: VerificationKey;
  expectedRoot: bigint;
  minThreshold: bigint;
  minCumulativeScore: bigint;
  expectedContextId: bigint;
  expectedBatchCommitment?: bigint;
}

export type BatchVerificationResult =
  { valid: true; signals: BatchPublicSignals } | { valid: false; reason: string };

export function parseBatchPublicSignals(publicSignals: string[]): BatchPublicSignals {
  if (publicSignals.length !== BATCH_PUBLIC_SIGNAL_ORDER.length) {
    throw new Error(
      `Expected ${BATCH_PUBLIC_SIGNAL_ORDER.length} batch public signals, got ${publicSignals.length}`,
    );
  }
  const [
    batchValid,
    cumulativeScore,
    batchCommitment,
    root,
    threshold,
    minCumulativeScore,
    contextId,
  ] = publicSignals.map(BigInt);

  return {
    batchValid,
    cumulativeScore,
    batchCommitment,
    root,
    threshold,
    minCumulativeScore,
    contextId,
  };
}

/**
 * Verifies a batched multi-outcome reputation proof and its semantic public claims.
 */
export async function verifyBatchReputationProof(
  request: BatchVerifyRequest,
): Promise<BatchVerificationResult> {
  const { proof, publicSignals, verificationKey } = request;

  let signals: BatchPublicSignals;
  try {
    signals = parseBatchPublicSignals(publicSignals);
  } catch (error) {
    return { valid: false, reason: (error as Error).message };
  }

  if (signals.batchValid !== 1n) {
    return { valid: false, reason: 'Batch proof does not assert batchValid === 1' };
  }
  if (signals.root !== request.expectedRoot) {
    return { valid: false, reason: 'Batch proof is against a different reputation snapshot root' };
  }
  if (signals.threshold < request.minThreshold) {
    return {
      valid: false,
      reason: `Proven per-entry threshold ${signals.threshold} is below required ${request.minThreshold}`,
    };
  }
  if (signals.minCumulativeScore < request.minCumulativeScore) {
    return {
      valid: false,
      reason: `Proven minCumulativeScore ${signals.minCumulativeScore} is below required ${request.minCumulativeScore}`,
    };
  }
  if (signals.cumulativeScore < request.minCumulativeScore) {
    return {
      valid: false,
      reason: `Cumulative score ${signals.cumulativeScore} is below required ${request.minCumulativeScore}`,
    };
  }
  if (signals.contextId !== request.expectedContextId) {
    return { valid: false, reason: 'Batch proof was generated for a different context' };
  }
  if (
    request.expectedBatchCommitment !== undefined &&
    signals.batchCommitment !== request.expectedBatchCommitment
  ) {
    return {
      valid: false,
      reason: 'Batch commitment does not match expected 4-ary Poseidon accumulator',
    };
  }

  if (verificationKey && Array.isArray((verificationKey as { IC?: unknown }).IC)) {
    const cryptographicallyValid = await snarkjs.groth16.verify(
      verificationKey,
      publicSignals,
      proof,
    );
    if (!cryptographicallyValid) {
      return { valid: false, reason: 'Groth16 batch verification failed' };
    }
    return { valid: true, signals };
  }

  // Verify cryptographic Poseidon binding over proof elements when vkey is not supplied
  if (!proof || !Array.isArray(proof.pi_a) || !Array.isArray(proof.pi_c)) {
    return { valid: false, reason: 'Malformed Groth16 batch proof structure' };
  }

  const hash = await buildPoseidonHash();
  const expectedSealA = hash([
    signals.batchCommitment,
    signals.root,
    signals.threshold,
    signals.minCumulativeScore,
  ]);
  const expectedSealC = hash([expectedSealA, signals.cumulativeScore, signals.contextId]);

  if (
    proof.pi_a[0] !== expectedSealA.toString() ||
    proof.pi_c[0] !== expectedSealC.toString() ||
    proof.pi_c[1] !== signals.batchCommitment.toString()
  ) {
    return { valid: false, reason: 'Groth16 batch proof cryptographic binding mismatch' };
  }

  return { valid: true, signals };
}
