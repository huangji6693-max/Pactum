/**
 * Unit tests for the Bulletproof-style range proof module — Issue #190
 *
 * Uses Node.js built-in test runner (node:test + node:assert/strict),
 * matching the existing test style in the project.
 */

import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  fiatShamirChallenge,
  generateRangeProof,
  verifyRangeProof,
  verifyRangeProofBatch,
  generateBulletproof,
  verifyBulletproof,
  verifyBulletproofStrict,
  verifyBulletproofBatch,
  verifyBulletproofBatchStrict,
  serializeBulletproof,
  deserializeBulletproof,
  BulletproofRangeError,
  BulletproofVerificationError,
  PEDERSEN_P,
  PEDERSEN_G,
  PEDERSEN_H,
  RATING_MIN,
  RATING_MAX,
  RangeProof,
} from './bulletproof';
import { modPow, multiExp, encAddBatch, keyPairFromPrimes, encrypt, decrypt } from './paillier';

// Use the compact modulus as the pkN in all tests.
const PK_N = PEDERSEN_P;

// ---------------------------------------------------------------------------
// fiatShamirChallenge
// ---------------------------------------------------------------------------

test('fiatShamirChallenge is deterministic', () => {
  const c1 = fiatShamirChallenge(999n, PK_N);
  const c2 = fiatShamirChallenge(999n, PK_N);
  assert.equal(c1, c2);
});

test('fiatShamirChallenge is never zero', () => {
  const seeds = [0n, 1n, 100n, PK_N / 2n, PK_N - 1n];
  for (const seed of seeds) {
    const c = fiatShamirChallenge(seed, PK_N);
    assert.notEqual(c, 0n, `challenge should not be 0 for seed ${seed}`);
  }
});

test('fiatShamirChallenge is less than PEDERSEN_P', () => {
  for (const seed of [42n, 12345n, PK_N - 2n]) {
    const c = fiatShamirChallenge(seed, PK_N);
    assert.ok(c < PEDERSEN_P, `challenge ${c} should be < PEDERSEN_P`);
  }
});

test('fiatShamirChallenge changes when commitment changes', () => {
  const c1 = fiatShamirChallenge(100n, PK_N);
  const c2 = fiatShamirChallenge(101n, PK_N);
  assert.notEqual(c1, c2);
});

// ---------------------------------------------------------------------------
// generateRangeProof / verifyRangeProof — valid ratings
// ---------------------------------------------------------------------------

for (const rating of [1n, 2n, 3n, 4n, 5n]) {
  test(`valid proof for rating ${rating} verifies`, () => {
    const blinding = 12345n + rating;
    const proof = generateRangeProof(rating, blinding, PK_N);

    assert.ok(verifyRangeProof(proof, PK_N), `proof for rating ${rating} should verify`);
  });
}

test('proof commitment is a valid Pedersen commitment C = g^v · h^r mod p', () => {
  const rating = 3n;
  const blinding = 99999n;
  const proof = generateRangeProof(rating, blinding, PK_N);

  const p = PEDERSEN_P;
  const expected = (modPow(PEDERSEN_G, rating, p) * modPow(PEDERSEN_H, blinding, p)) % p;
  assert.equal(proof.commitment, expected);
});

// ---------------------------------------------------------------------------
// Rejection of out-of-range ratings
// ---------------------------------------------------------------------------

test('generateRangeProof throws for rating 0 (below minimum)', () => {
  assert.throws(() => generateRangeProof(0n, 1n, PK_N), RangeError);
});

test('generateRangeProof throws for rating 6 (above maximum)', () => {
  assert.throws(() => generateRangeProof(6n, 1n, PK_N), RangeError);
});

// ---------------------------------------------------------------------------
// Tampered proofs must not verify
// ---------------------------------------------------------------------------

test('tampered witnessA fails verification', () => {
  const proof = generateRangeProof(3n, 12345n, PK_N);
  const tampered: RangeProof = { ...proof, witnessA: proof.witnessA + 1n };
  assert.equal(verifyRangeProof(tampered, PK_N), false);
});

test('tampered witnessB fails verification', () => {
  const proof = generateRangeProof(3n, 12345n, PK_N);
  const tampered: RangeProof = { ...proof, witnessB: proof.witnessB + 1n };
  assert.equal(verifyRangeProof(tampered, PK_N), false);
});

test('tampered commitment fails verification', () => {
  const proof = generateRangeProof(3n, 12345n, PK_N);
  const tampered: RangeProof = { ...proof, commitment: proof.commitment + 1n };
  assert.equal(verifyRangeProof(tampered, PK_N), false);
});

test('zeroed witnesses fail verification', () => {
  const proof = generateRangeProof(3n, 12345n, PK_N);
  const tampered: RangeProof = { ...proof, witnessA: 0n, witnessB: 0n };
  assert.equal(verifyRangeProof(tampered, PK_N), false);
});

// ---------------------------------------------------------------------------
// Cross-proof: witness from one rating does not verify for another commitment
// ---------------------------------------------------------------------------

test('witness from rating 3 does not satisfy commitment for rating 4', () => {
  const proofFor3 = generateRangeProof(3n, 12345n, PK_N);
  const proofFor4 = generateRangeProof(4n, 12345n, PK_N);

  // Swap the commitment: witnesses from proof-3 against commitment-4.
  const tampered: RangeProof = {
    commitment: proofFor4.commitment,
    witnessA: proofFor3.witnessA,
    witnessB: proofFor3.witnessB,
  };
  assert.equal(verifyRangeProof(tampered, PK_N), false);
});

// ---------------------------------------------------------------------------
// Different blinding factors produce different commitments for same rating
// ---------------------------------------------------------------------------

test('distinct blinding factors produce distinct commitments', () => {
  const p1 = generateRangeProof(3n, 100n, PK_N);
  const p2 = generateRangeProof(3n, 200n, PK_N);
  assert.notEqual(p1.commitment, p2.commitment);
  // Both should still verify.
  assert.ok(verifyRangeProof(p1, PK_N));
  assert.ok(verifyRangeProof(p2, PK_N));
});

// ---------------------------------------------------------------------------
// Issue #306 — Logarithmic IPA Bulletproofs (32-bit and 64-bit) & Batch Verification
// ---------------------------------------------------------------------------

test('32-bit IPA Bulletproof generates and verifies boundary and interior values', () => {
  const values = [0n, 1n, 42n, 65535n, (1n << 32n) - 1n];
  for (const v of values) {
    const proof = generateBulletproof(v, 98765n + v, PK_N, 32);
    assert.equal(proof.ipa.L.length, 5, '32-bit proof must have log2(32) = 5 IPA rounds');
    assert.ok(verifyBulletproof(proof, PK_N), `32-bit proof for ${v} should verify`);
  }
});

test('64-bit IPA Bulletproof generates and verifies with compact size < 1 KB', () => {
  const values = [0n, 1n, 5n, 1_000_000_000n, (1n << 63n) - 1n, (1n << 64n) - 1n];
  for (const v of values) {
    const proof = generateBulletproof(v, 54321n + (v & 0xffffn), PK_N, 64);
    assert.equal(proof.ipa.L.length, 6, '64-bit proof must have log2(64) = 6 IPA rounds');
    assert.ok(verifyBulletproof(proof, PK_N), `64-bit proof for ${v} should verify`);

    const serialized = serializeBulletproof(proof);
    assert.ok(
      serialized.byteLength < 1024,
      `serialized 64-bit proof size (${serialized.byteLength} B) must be < 1 KB`,
    );
    assert.equal(serialized.byteLength, 177);

    const roundTrip = deserializeBulletproof(serialized);
    assert.ok(verifyBulletproof(roundTrip, PK_N), 'deserialized proof must verify');
  }
});

test('Batch verification of 100 64-bit Bulletproofs runs in < 50ms', () => {
  const proofs = [];
  for (let i = 0; i < 100; i++) {
    const val = BigInt(i * 1_000_003 + 7);
    proofs.push(generateBulletproof(val, BigInt(10_000 + i), PK_N, 64));
  }

  // Warm up JIT once before timing
  verifyBulletproofBatch(proofs.slice(0, 4), PK_N);

  const start = performance.now();
  const ok = verifyBulletproofBatch(proofs, PK_N);
  const elapsedMs = performance.now() - start;

  assert.equal(ok, true, 'batch of 100 valid 64-bit proofs must verify');
  assert.ok(
    elapsedMs < 50,
    `batch verification of 100 proofs took ${elapsedMs.toFixed(2)}ms (expected < 50ms)`,
  );
});

test('Out-of-range values fail with explicit BulletproofRangeError codes', () => {
  assert.throws(
    () => generateBulletproof(-1n, 123n, PK_N, 64),
    (err: unknown) =>
      err instanceof BulletproofRangeError && err.code === 'NEGATIVE_VALUE',
  );

  assert.throws(
    () => generateBulletproof(1n << 32n, 123n, PK_N, 32),
    (err: unknown) =>
      err instanceof BulletproofRangeError && err.code === 'OUT_OF_RANGE',
  );

  assert.throws(
    () => generateBulletproof(1n << 64n, 123n, PK_N, 64),
    (err: unknown) =>
      err instanceof BulletproofRangeError && err.code === 'OUT_OF_RANGE',
  );
});

test('Tampered commitments and IPA witnesses fail with explicit BulletproofVerificationError codes', () => {
  const valid = generateBulletproof(123456789n, 777n, PK_N, 64);

  // 1. Out-of-subgroup commitment
  assert.throws(
    () => verifyBulletproofStrict({ ...valid, commitment: 0n }, PK_N),
    (err: unknown) =>
      err instanceof BulletproofVerificationError && err.code === 'TAMPERED_COMMITMENT',
  );

  // 2. Tampered polynomial evaluation tHat
  assert.throws(
    () => verifyBulletproofStrict({ ...valid, tHat: valid.tHat + 1n }, PK_N),
    (err: unknown) =>
      err instanceof BulletproofVerificationError && err.code === 'POLYNOMIAL_IDENTITY_FAILED',
  );

  // 3. Tampered IPA final scalar a
  assert.throws(
    () =>
      verifyBulletproofStrict(
        { ...valid, ipa: { ...valid.ipa, a: valid.ipa.a + 1n } },
        PK_N,
      ),
    (err: unknown) =>
      err instanceof BulletproofVerificationError && err.code === 'IPA_VERIFICATION_FAILED',
  );

  // 4. Batch containing one tampered proof fails with BATCH_VERIFICATION_FAILED
  const p2 = generateBulletproof(42n, 888n, PK_N, 64);
  const tamperedBatch = [
    valid,
    { ...p2, ipa: { ...p2.ipa, b: p2.ipa.b + 1n } },
  ];
  assert.throws(
    () => verifyBulletproofBatchStrict(tamperedBatch, PK_N),
    (err: unknown) =>
      err instanceof BulletproofVerificationError && err.code === 'BATCH_VERIFICATION_FAILED',
  );
});

test('multiExp and encAddBatch compute weighted multi-exponentiation accurately', () => {
  const bases = [3n, 5n, 7n, 11n, 13n];
  const exps = [19n, 23n, 29n, 31n, 37n];
  const mod = 1_000_000_007n;

  let naive = 1n;
  for (let i = 0; i < bases.length; i++) {
    naive = (naive * modPow(bases[i], exps[i], mod)) % mod;
  }
  assert.equal(multiExp(bases, exps, mod), naive);

  const kp = keyPairFromPrimes(61n, 53n);
  const cts = [
    encrypt(kp.publicKey, 2n, 3n),
    encrypt(kp.publicKey, 4n, 5n),
    encrypt(kp.publicKey, 6n, 7n),
  ];
  const combined = encAddBatch(kp.publicKey, cts, [10n, 20n, 30n]);
  // 2*10 + 4*20 + 6*30 = 20 + 80 + 180 = 280
  assert.equal(decrypt(kp, combined), 280n);

  const schnorrBatch = [
    generateRangeProof(1n, 11n, PK_N),
    generateRangeProof(3n, 22n, PK_N),
    generateRangeProof(5n, 33n, PK_N),
  ];
  assert.equal(verifyRangeProofBatch(schnorrBatch, PK_N), true);
});

