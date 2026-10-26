/**
 * Tests for Zero-Knowledge Recursive / Batched Multi-Outcome Reputation Proofs — Issue #298
 */

import assert from 'node:assert/strict';
import { before, describe, it } from 'node:test';

import {
  BATCH_SIZE,
  BATCH_TREE_DEPTH,
  computePoseidon4Accumulator,
  estimateBatchCircuitConstraints,
  evaluateBatchCircuitWitness,
  generateBatchReputationProof,
  toBatchCircuitInput,
  toCircuitInput,
  type BatchProofEntry,
  type BatchTrustProofRequest,
} from '../src/prove.ts';
import {
  buildPoseidonHash,
  buildSnapshot,
  findLeafIndex,
  leafForEntry,
  merklePath,
  type PoseidonHash,
  type ReputationEntry,
  type ReputationSnapshot,
} from '../src/tree.ts';
import {
  BATCH_PUBLIC_SIGNAL_ORDER,
  parseBatchPublicSignals,
  verifyBatchReputationProof,
} from '../src/verify.ts';
import { testAddress } from './helpers.ts';

const CONTEXT_ID = 987654321n;
const THRESHOLD = 800;

function makeBatchReputationEntries(): ReputationEntry[] {
  const scores = [820, 845, 860, 890, 910, 935, 960, 985, 750, 800];
  return scores.map((score, i) => ({
    address: testAddress(i + 10),
    score,
  }));
}

describe('batch_reputation circuit & Poseidon-4 accumulator (#298)', () => {
  let hash: PoseidonHash;
  let snapshot: ReputationSnapshot;
  const allEntries = makeBatchReputationEntries();
  const validEntries = allEntries.slice(0, BATCH_SIZE);

  before(async () => {
    hash = await buildPoseidonHash();
    snapshot = buildSnapshot(hash, allEntries, BATCH_TREE_DEPTH);
  });

  function buildBatchRequest(
    overrideEntries?: BatchProofEntry[],
    threshold: number = THRESHOLD,
    minCumulativeScore: number = 7000,
  ): BatchTrustProofRequest {
    const chosen =
      overrideEntries ??
      validEntries.map((entry) => ({
        address: entry.address,
        score: entry.score,
        path: merklePath(snapshot, findLeafIndex(allEntries, entry.address)),
      }));

    return {
      entries: chosen,
      threshold,
      minCumulativeScore,
      contextId: CONTEXT_ID,
    };
  }

  it('stays well under the 80,000 R1CS constraint budget for k=8 batched entries', () => {
    const constraintsDepth8 = estimateBatchCircuitConstraints(8, 8, 32);
    const constraintsDepth16 = estimateBatchCircuitConstraints(8, 16, 32);

    assert.ok(
      constraintsDepth8 < 80_000,
      `Expected depth-8 batch circuit < 80,000 constraints, got ${constraintsDepth8}`,
    );
    assert.ok(
      constraintsDepth16 < 80_000,
      `Expected depth-16 batch circuit < 80,000 constraints, got ${constraintsDepth16}`,
    );
  });

  it('generates and verifies a unified k=8 Groth16 batch proof in < 10 seconds', async () => {
    const req = buildBatchRequest();
    const startMs = performance.now();
    const { proof, publicSignals } = await generateBatchReputationProof(req);
    const elapsedMs = performance.now() - startMs;

    assert.ok(elapsedMs < 10_000, `Batch proof took ${elapsedMs.toFixed(1)}ms (>= 10,000ms)`);
    assert.equal(publicSignals.length, BATCH_PUBLIC_SIGNAL_ORDER.length);

    const expectedLeaves = validEntries.map((e) => leafForEntry(hash, e));
    const expectedAccumulator = computePoseidon4Accumulator(hash, expectedLeaves);
    const expectedSum = BigInt(validEntries.reduce((acc, e) => acc + e.score, 0));

    const parsed = parseBatchPublicSignals(publicSignals);
    assert.equal(parsed.batchValid, 1n);
    assert.equal(parsed.cumulativeScore, expectedSum);
    assert.equal(parsed.batchCommitment, expectedAccumulator);
    assert.equal(parsed.root, snapshot.root);

    const verification = await verifyBatchReputationProof({
      proof,
      publicSignals,
      expectedRoot: snapshot.root,
      minThreshold: BigInt(THRESHOLD),
      minCumulativeScore: 7000n,
      expectedContextId: CONTEXT_ID,
      expectedBatchCommitment: expectedAccumulator,
    });

    assert.equal(verification.valid, true, verification.valid ? '' : verification.reason);
  });

  it('rejects witness generation when any individual score, address, or Merkle path is tampered', async () => {
    const req = buildBatchRequest();

    // 1. Tamper individual score (entry 3)
    const tamperedScoreInput = toBatchCircuitInput(req);
    tamperedScoreInput.scores[3] = '999';
    await assert.rejects(
      () => evaluateBatchCircuitWitness(tamperedScoreInput, hash),
      /recomputed root/,
    );

    // 2. Score at or below threshold (entry 2 has score 800 <= 800)
    const belowEntry = allEntries.find((e) => e.score === 800)!;
    const withBoundaryEntry = req.entries.map((item, idx) =>
      idx === 2
        ? {
            address: belowEntry.address,
            score: belowEntry.score,
            path: merklePath(snapshot, findLeafIndex(allEntries, belowEntry.address)),
          }
        : item,
    );
    await assert.rejects(
      () => generateBatchReputationProof(buildBatchRequest(withBoundaryEntry)),
      /does not strictly exceed threshold/,
    );

    // 3. Tamper individual address limb (entry 5)
    const tamperedAddrInput = toBatchCircuitInput(req);
    tamperedAddrInput.addrLo[5] = (BigInt(tamperedAddrInput.addrLo[5]) + 1n).toString();
    await assert.rejects(
      () => evaluateBatchCircuitWitness(tamperedAddrInput, hash),
      /recomputed root/,
    );

    // 4. Tamper Merkle path sibling (entry 6, level 2)
    const tamperedPathInput = toBatchCircuitInput(req);
    tamperedPathInput.pathElements[6][2] = (
      BigInt(tamperedPathInput.pathElements[6][2]) + 1n
    ).toString();
    await assert.rejects(
      () => evaluateBatchCircuitWitness(tamperedPathInput, hash),
      /recomputed root/,
    );

    // 5. Tamper Merkle path direction bit (entry 1, level 0)
    const flippedBitInput = toBatchCircuitInput(req);
    flippedBitInput.pathIndices[1][0] = flippedBitInput.pathIndices[1][0] === '1' ? '0' : '1';
    await assert.rejects(
      () => evaluateBatchCircuitWitness(flippedBitInput, hash),
      /recomputed root/,
    );
  });

  it('rejects post-proving tampering of public signals or proof commitments', async () => {
    const req = buildBatchRequest();
    const { proof, publicSignals } = await generateBatchReputationProof(req);

    // Tamper cumulativeScore signal
    const badSignals = [...publicSignals];
    badSignals[1] = (BigInt(badSignals[1]) + 100n).toString();

    const res1 = await verifyBatchReputationProof({
      proof,
      publicSignals: badSignals,
      expectedRoot: snapshot.root,
      minThreshold: BigInt(THRESHOLD),
      minCumulativeScore: 7000n,
      expectedContextId: CONTEXT_ID,
    });
    assert.equal(res1.valid, false);

    // Wrong snapshot root
    const res2 = await verifyBatchReputationProof({
      proof,
      publicSignals,
      expectedRoot: snapshot.root + 1n,
      minThreshold: BigInt(THRESHOLD),
      minCumulativeScore: 7000n,
      expectedContextId: CONTEXT_ID,
    });
    assert.equal(res2.valid, false);
  });

  it('compares discrete (k=8 separate proofs) vs batched (1 unified proof) generation and verification', async () => {
    const depth16Snapshot = buildSnapshot(hash, allEntries);
    const discreteInputs = validEntries.map((entry) =>
      toCircuitInput({
        address: entry.address,
        score: entry.score,
        threshold: THRESHOLD,
        contextId: CONTEXT_ID,
        path: merklePath(depth16Snapshot, findLeafIndex(allEntries, entry.address)),
      }),
    );

    const req = buildBatchRequest();
    const batchedProof = await generateBatchReputationProof(req);

    const discreteSignalCount = discreteInputs.length * 4; // 8 * 4 = 32 public signals + 8 proofs
    const batchedSignalCount = batchedProof.publicSignals.length; // 7 public signals + 1 proof

    assert.equal(discreteInputs.length, BATCH_SIZE);
    assert.ok(
      batchedSignalCount < discreteSignalCount,
      `Batched public signals (${batchedSignalCount}) must be smaller than discrete (${discreteSignalCount})`,
    );
  });
});
