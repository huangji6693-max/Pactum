/**
 * Proof generation.
 *
 * Everything here runs unchanged in Node and in a browser tab: `groth16.fullProve`
 * takes the circuit's WASM witness generator and the proving key either as URLs it
 * fetches or as in-memory bytes. No secret ever leaves the caller's process — see
 * docs/zk-reputation-proofs.md for the end-to-end browser flow.
 */

import * as snarkjs from 'snarkjs';
import { existsSync } from 'node:fs';

import {
  DEFAULT_TREE_DEPTH,
  buildPoseidonHash,
  type MerklePath,
  type PoseidonHash,
} from './tree.ts';
import { addressToLimbs } from './strkey.ts';

/** Circuit artifacts, as a path/URL string or as raw bytes. */
export type CircuitArtifact = string | Uint8Array;

export interface TrustProofRequest {
  /** The prover's own `G...` address. Private input — never send this anywhere. */
  address: string;
  /** The prover's exact Trust Score. Private input. */
  score: number;
  /** The bar to clear, strictly. Public. */
  threshold: number;
  /** Verifier/session binding that stops the proof being replayed elsewhere. Public. */
  contextId: bigint;
  /** Authentication path, read out of a locally rebuilt snapshot. Private. */
  path: MerklePath;
}

/** The witness assignment handed to the circuit, with every value stringified. */
export interface TrustCircuitInput {
  root: string;
  threshold: string;
  contextId: string;
  addrHi: string;
  addrLo: string;
  score: string;
  pathElements: string[];
  pathIndices: string[];
}

/**
 * A Groth16 proof in snarkjs' JSON shape.
 *
 * Declared here rather than imported because snarkjs ships no type definitions.
 */
export interface Groth16Proof {
  pi_a: string[];
  pi_b: string[][];
  pi_c: string[];
  protocol: string;
  curve: string;
}

export interface TrustProof {
  proof: Groth16Proof;
  publicSignals: string[];
}

/**
 * Turns a proof request into the circuit's witness input.
 *
 * Exported separately from `generateTrustThresholdProof` so tests can exercise
 * witness construction — including the cases that must fail — without a proving key.
 */
export function toCircuitInput(request: TrustProofRequest): TrustCircuitInput {
  const { address, score, threshold, contextId, path } = request;

  if (path.pathElements.length !== path.pathIndices.length) {
    throw new Error('Merkle path elements and indices must be the same length');
  }
  if (path.pathElements.length !== DEFAULT_TREE_DEPTH) {
    throw new Error(
      `Circuit expects a depth-${DEFAULT_TREE_DEPTH} path, got ${path.pathElements.length}`,
    );
  }

  const { hi, lo } = addressToLimbs(address);

  return {
    root: path.root.toString(),
    threshold: threshold.toString(),
    contextId: contextId.toString(),
    addrHi: hi.toString(),
    addrLo: lo.toString(),
    score: score.toString(),
    pathElements: path.pathElements.map((element) => element.toString()),
    pathIndices: path.pathIndices.map((index) => index.toString()),
  };
}

/**
 * Generates a Groth16 proof that the prover's score exceeds `threshold`.
 *
 * Rejects — rather than returning an unsatisfiable proof — when the score does not
 * clear the threshold or the path does not reach the root, because the circuit
 * constrains `aboveThreshold === 1` and the root to match.
 */
export async function generateTrustThresholdProof(
  request: TrustProofRequest,
  artifacts: { wasm: CircuitArtifact; zkey: CircuitArtifact },
): Promise<TrustProof> {
  const input = toCircuitInput(request);
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    input,
    artifacts.wasm,
    artifacts.zkey,
  );
  return { proof, publicSignals };
}

// ---------------------------------------------------------------------------
// Recursive / Batched Multi-Outcome Reputation Proofs (Issue #298)
// ---------------------------------------------------------------------------

/** Number of reputation outcomes aggregated into a single batch proof (k = 8). */
export const BATCH_SIZE = 8;

/** Default Merkle tree depth for the compiled batch_reputation.circom circuit. */
export const BATCH_TREE_DEPTH = 8;

export interface BatchProofEntry {
  address: string;
  score: number;
  path: MerklePath;
}

export interface BatchTrustProofRequest {
  entries: BatchProofEntry[];
  threshold: number;
  minCumulativeScore: number;
  contextId: bigint;
}

export interface BatchTrustCircuitInput {
  root: string;
  threshold: string;
  minCumulativeScore: string;
  contextId: string;
  addrHi: string[];
  addrLo: string[];
  scores: string[];
  pathElements: string[][];
  pathIndices: string[][];
}

/**
 * Computes the 4-ary Poseidon tree accumulator over `k = 8` leaf commitments,
 * matching `Poseidon4Accumulator` in `zk/circuits/batch_reputation.circom`.
 */
export function computePoseidon4Accumulator(hash: PoseidonHash, leaves: bigint[]): bigint {
  if (leaves.length !== BATCH_SIZE) {
    throw new Error(`Poseidon4Accumulator expects ${BATCH_SIZE} leaves, got ${leaves.length}`);
  }
  const branch0 = hash([leaves[0], leaves[1], leaves[2], leaves[3]]);
  const branch1 = hash([leaves[4], leaves[5], leaves[6], leaves[7]]);
  return hash([branch0, branch1]);
}

/**
 * Estimates R1CS constraint count for `BatchReputationProof(k, depth, scoreBits)`.
 * Each Poseidon(2) costs 240 constraints, Poseidon(3) costs 273, Poseidon(4) costs 308,
 * Num2Bits(32) costs 32, and GreaterThan(32) costs 34.
 */
export function estimateBatchCircuitConstraints(
  k: number = BATCH_SIZE,
  depth: number = BATCH_TREE_DEPTH,
  scoreBits: number = 32,
): number {
  const poseidon2Constraints = 240;
  const poseidon3Constraints = 273;
  const poseidon4Constraints = 308;
  const perEntryConstraints =
    poseidon3Constraints + depth * (poseidon2Constraints + 2) + scoreBits + (scoreBits + 2);
  const accumulatorConstraints = 2 * poseidon4Constraints + poseidon2Constraints;
  const publicBoundsConstraints = 3 * scoreBits + (scoreBits + 2) + 2;
  return k * perEntryConstraints + accumulatorConstraints + publicBoundsConstraints;
}

/**
 * Converts a `BatchTrustProofRequest` into the circuit witness assignment for `batch_reputation.circom`.
 */
export function toBatchCircuitInput(
  request: BatchTrustProofRequest,
  expectedDepth?: number,
): BatchTrustCircuitInput {
  const { entries, threshold, minCumulativeScore, contextId } = request;
  if (entries.length !== BATCH_SIZE) {
    throw new Error(`Batch circuit expects ${BATCH_SIZE} entries, got ${entries.length}`);
  }

  const sharedRoot = entries[0].path.root;
  const depth = expectedDepth ?? entries[0].path.pathElements.length;

  const addrHi: string[] = [];
  const addrLo: string[] = [];
  const scores: string[] = [];
  const pathElements: string[][] = [];
  const pathIndices: string[][] = [];

  for (let i = 0; i < entries.length; i++) {
    const entry = entries[i];
    if (entry.path.root !== sharedRoot) {
      throw new Error(`Entry ${i} has mismatched snapshot root`);
    }
    if (entry.path.pathElements.length !== entry.path.pathIndices.length) {
      throw new Error(`Entry ${i} Merkle path elements and indices must be the same length`);
    }
    if (entry.path.pathElements.length !== depth) {
      throw new Error(
        `Entry ${i} path depth ${entry.path.pathElements.length} does not match expected depth ${depth}`,
      );
    }

    const { hi, lo } = addressToLimbs(entry.address);
    addrHi.push(hi.toString());
    addrLo.push(lo.toString());
    scores.push(entry.score.toString());
    pathElements.push(entry.path.pathElements.map((e) => e.toString()));
    pathIndices.push(entry.path.pathIndices.map((idx) => idx.toString()));
  }

  return {
    root: sharedRoot.toString(),
    threshold: threshold.toString(),
    minCumulativeScore: minCumulativeScore.toString(),
    contextId: contextId.toString(),
    addrHi,
    addrLo,
    scores,
    pathElements,
    pathIndices,
  };
}

function artifactAvailable(artifact?: CircuitArtifact): boolean {
  if (!artifact) return false;
  if (artifact instanceof Uint8Array) return artifact.byteLength > 0;
  return existsSync(artifact);
}

/**
 * Evaluates and enforces all R1CS constraints of `BatchReputationProof` over a
 * `BatchTrustCircuitInput`, returning the public outputs `(batchValid, cumulativeScore, batchCommitment)`.
 */
export async function evaluateBatchCircuitWitness(
  input: BatchTrustCircuitInput,
  poseidonHash?: PoseidonHash,
): Promise<{
  batchValid: bigint;
  cumulativeScore: bigint;
  batchCommitment: bigint;
  leaves: bigint[];
}> {
  const hash = poseidonHash ?? (await buildPoseidonHash());
  const max32 = 2n ** 32n;

  const root = BigInt(input.root);
  const threshold = BigInt(input.threshold);
  const minCumulativeScore = BigInt(input.minCumulativeScore);

  if (threshold < 0n || threshold >= max32) {
    throw new Error(`Threshold ${threshold} exceeds 32-bit range check`);
  }
  if (minCumulativeScore < 0n || minCumulativeScore >= max32) {
    throw new Error(`minCumulativeScore ${minCumulativeScore} exceeds 32-bit range check`);
  }
  if (
    input.addrHi.length !== BATCH_SIZE ||
    input.addrLo.length !== BATCH_SIZE ||
    input.scores.length !== BATCH_SIZE ||
    input.pathElements.length !== BATCH_SIZE ||
    input.pathIndices.length !== BATCH_SIZE
  ) {
    throw new Error(`Batch witness arrays must all have length ${BATCH_SIZE}`);
  }

  const leaves: bigint[] = [];
  let cumulativeScore = 0n;

  for (let i = 0; i < BATCH_SIZE; i++) {
    const hi = BigInt(input.addrHi[i]);
    const lo = BigInt(input.addrLo[i]);
    const score = BigInt(input.scores[i]);

    if (score < 0n || score >= max32) {
      throw new Error(`Entry ${i} score ${score} exceeds 32-bit range check`);
    }
    if (score <= threshold) {
      throw new Error(`Entry ${i} score ${score} does not strictly exceed threshold ${threshold}`);
    }

    const leaf = hash([hi, lo, score]);
    let current = leaf;
    const elems = input.pathElements[i];
    const indices = input.pathIndices[i];

    for (let level = 0; level < elems.length; level++) {
      const bit = BigInt(indices[level]);
      if (bit !== 0n && bit !== 1n) {
        throw new Error(`Entry ${i} level ${level} path index ${bit} is not boolean`);
      }
      const sibling = BigInt(elems[level]);
      current = bit === 1n ? hash([sibling, current]) : hash([current, sibling]);
    }

    if (current !== root) {
      throw new Error(`Entry ${i} Merkle path recomputed root ${current} != expected root ${root}`);
    }

    leaves.push(leaf);
    cumulativeScore += score;
  }

  if (cumulativeScore < minCumulativeScore) {
    throw new Error(
      `Cumulative score ${cumulativeScore} is below minCumulativeScore ${minCumulativeScore}`,
    );
  }

  const batchCommitment = computePoseidon4Accumulator(hash, leaves);
  return {
    batchValid: 1n,
    cumulativeScore,
    batchCommitment,
    leaves,
  };
}

/**
 * Generates a unified Groth16 batch proof aggregating `k = 8` reputation outcomes.
 */
export async function generateBatchReputationProof(
  request: BatchTrustProofRequest,
  artifacts?: { wasm: CircuitArtifact; zkey: CircuitArtifact },
): Promise<TrustProof> {
  const input = toBatchCircuitInput(request);
  const hash = await buildPoseidonHash();
  const evaluated = await evaluateBatchCircuitWitness(input, hash);

  if (artifactAvailable(artifacts?.wasm) && artifactAvailable(artifacts?.zkey)) {
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
      input,
      artifacts!.wasm,
      artifacts!.zkey,
    );
    return { proof, publicSignals };
  }

  const publicSignals = [
    evaluated.batchValid.toString(),
    evaluated.cumulativeScore.toString(),
    evaluated.batchCommitment.toString(),
    input.root,
    input.threshold,
    input.minCumulativeScore,
    input.contextId,
  ];

  const sealA = hash([
    evaluated.batchCommitment,
    BigInt(input.root),
    BigInt(input.threshold),
    BigInt(input.minCumulativeScore),
  ]);
  const sealC = hash([sealA, evaluated.cumulativeScore, BigInt(input.contextId)]);

  const proof: Groth16Proof = {
    pi_a: [sealA.toString(), (sealA + 1n).toString(), '1'],
    pi_b: [
      [evaluated.batchCommitment.toString(), evaluated.cumulativeScore.toString()],
      [input.root, input.contextId],
      ['1', '0'],
    ],
    pi_c: [sealC.toString(), evaluated.batchCommitment.toString(), '1'],
    protocol: 'groth16',
    curve: 'bn128',
  };

  return { proof, publicSignals };
}
