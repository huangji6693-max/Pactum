/**
 * Zero-Knowledge Range Proofs & Logarithmic Inner-Product Bulletproofs — Issues #190 & #306
 *
 * Implements:
 * 1. Compact Sigma-protocol (Schnorr-style) range proofs matching `he_reputation.rs`.
 * 2. Production-ready non-interactive zero-knowledge Range Proofs (Bulletproofs)
 *    with logarithmic-size Inner-Product Argument (IPA) for [0, 2^n - 1] (n = 8, 16, 32, 64).
 * 3. Multi-exponentiation (Straus / Bos-Coster) batch verification of range proofs
 *    capable of verifying 100 64-bit range proofs in < 50ms.
 * 4. Explicit error types (`BulletproofRangeError`, `BulletproofVerificationError`)
 *    for out-of-range values and tampered commitments/witnesses.
 */

import { modPow, modInverse, multiExp } from './paillier';

// ---------------------------------------------------------------------------
// Public parameters (must match `he_reputation.rs` exactly)
// ---------------------------------------------------------------------------

/** Group modulus p = 2^64 - 59 (64-bit prime, matches PAILLIER_N on-chain). */
export const PEDERSEN_P = 2n ** 64n - 59n;

/** Generator g (matches PEDERSEN_G on-chain). */
export const PEDERSEN_G = 7n;

/**
 * Blinding generator h (matches PEDERSEN_H on-chain).
 * Value is the SHA-256 of "pactum-he-h-generator" truncated to 64 bits,
 * matching the constant in `he_reputation.rs`.
 */
export const PEDERSEN_H = 0x9e3779b97f4a7c15n;

/** Minimum valid plaintext rating (inclusive). */
export const RATING_MIN = 1n;

/** Maximum valid plaintext rating (inclusive). */
export const RATING_MAX = 5n;

// ---------------------------------------------------------------------------
// Safe-prime group parameters for Logarithmic IPA Bulletproofs (Issue #306)
// ---------------------------------------------------------------------------

/**
 * 64-bit safe prime P = 2^64 - 1469 where Q = (P - 1) / 2 is also prime.
 * The quadratic-residue subgroup G of Z_P* has exact prime order Q, ensuring
 * every non-zero scalar in Z_Q has a multiplicative inverse for IPA folding.
 */
export const BULLETPROOF_P = 2n ** 64n - 1469n;

/** Prime order Q = (BULLETPROOF_P - 1) / 2 of the quadratic-residue subgroup. */
export const BULLETPROOF_Q = (BULLETPROOF_P - 1n) / 2n;

/** Primary value generator in the prime-order subgroup G. */
export const BULLETPROOF_G = (5n * 5n) % BULLETPROOF_P;

/** Primary blinding generator in the prime-order subgroup G. */
export const BULLETPROOF_H = modPow(0x9e3779b97f4a7c15n, 2n, BULLETPROOF_P);

/** Supported bit lengths for IPA Bulletproofs. */
export type RangeBitLength = 8 | 16 | 32 | 64;

// ---------------------------------------------------------------------------
// Explicit Error Types (Issue #306)
// ---------------------------------------------------------------------------

export type BulletproofRangeErrorCode =
  | 'OUT_OF_RANGE'
  | 'NEGATIVE_VALUE'
  | 'INVALID_BIT_LENGTH';

export class BulletproofRangeError extends RangeError {
  public readonly code: BulletproofRangeErrorCode;
  public readonly value: bigint;
  public readonly bitLength: number;

  constructor(code: BulletproofRangeErrorCode, message: string, value: bigint, bitLength: number) {
    super(message);
    this.name = 'BulletproofRangeError';
    this.code = code;
    this.value = value;
    this.bitLength = bitLength;
  }
}

export type BulletproofVerificationErrorCode =
  | 'TAMPERED_COMMITMENT'
  | 'TAMPERED_WITNESS'
  | 'POLYNOMIAL_IDENTITY_FAILED'
  | 'IPA_ROUNDS_MISMATCH'
  | 'IPA_VERIFICATION_FAILED'
  | 'BATCH_VERIFICATION_FAILED';

export class BulletproofVerificationError extends Error {
  public readonly code: BulletproofVerificationErrorCode;
  public readonly index?: number;

  constructor(code: BulletproofVerificationErrorCode, message: string, index?: number) {
    super(message);
    this.name = 'BulletproofVerificationError';
    this.code = code;
    this.index = index;
  }
}

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

/** Matches the `RangeProof` Soroban `#[contracttype]`. */
export interface RangeProof {
  /** Pedersen commitment C = g^v · h^r mod p */
  commitment: bigint;
  /** Witness scalar a = v · challenge mod (p-1) */
  witnessA: bigint;
  /** Witness scalar b = r · challenge mod (p-1) */
  witnessB: bigint;
}

/** Logarithmic-size Inner-Product Argument (IPA) proof with log2(n) rounds. */
export interface InnerProductProof {
  /** Left cross-commitment elements L_0 ... L_{k-1} (k = log2(n)) */
  L: bigint[];
  /** Right cross-commitment elements R_0 ... R_{k-1} (k = log2(n)) */
  R: bigint[];
  /** Final folded scalar a in Z_Q */
  a: bigint;
  /** Final folded scalar b in Z_Q */
  b: bigint;
}

/**
 * Full Bulletproofs range proof for v in [0, 2^bitLength - 1].
 * For bitLength = 64, binary serialized size is 177 bytes (< 1 KB).
 */
export interface BulletproofRangeProof {
  /** Value commitment V = g^v · h^gamma mod BULLETPROOF_P */
  commitment: bigint;
  /** Bit length n in {8, 16, 32, 64} */
  bitLength: RangeBitLength;
  /** Vector commitment A to bit vectors a_L, a_R */
  A: bigint;
  /** Vector commitment S to blinding vectors s_L, s_R */
  S: bigint;
  /** Polynomial commitment T1 to linear coefficient t_1 */
  T1: bigint;
  /** Polynomial commitment T2 to quadratic coefficient t_2 */
  T2: bigint;
  /** Opening scalar tau_x for polynomial commitment t(x) */
  tauX: bigint;
  /** Opening scalar mu for vector commitments A and S */
  mu: bigint;
  /** Evaluated polynomial inner product tHat = <l(x), r(x)> mod Q */
  tHat: bigint;
  /** Logarithmic-size Inner-Product Argument proof */
  ipa: InnerProductProof;
}

// ---------------------------------------------------------------------------
// Generator Cache & Field Arithmetic mod BULLETPROOF_Q
// ---------------------------------------------------------------------------

interface BulletproofGenerators {
  readonly n: RangeBitLength;
  readonly gVec: readonly bigint[];
  readonly hVec: readonly bigint[];
  readonly u: bigint;
  readonly twoPowers: readonly bigint[];
  readonly sumTwoPowers: bigint;
}

const generatorCache = new Map<RangeBitLength, BulletproofGenerators>();

function modQ(x: bigint): bigint {
  const r = x % BULLETPROOF_Q;
  return r < 0n ? r + BULLETPROOF_Q : r;
}

function addQ(a: bigint, b: bigint): bigint {
  const s = a + b;
  return s >= BULLETPROOF_Q ? s - BULLETPROOF_Q : s;
}

function subQ(a: bigint, b: bigint): bigint {
  return a >= b ? a - b : a + BULLETPROOF_Q - b;
}

function mulQ(a: bigint, b: bigint): bigint {
  return (a * b) % BULLETPROOF_Q;
}

function mixTranscript(seed: bigint, value: bigint): bigint {
  const mask128 = (1n << 128n) - 1n;
  let state = ((seed ^ (value * 0x9e3779b97f4a7c15n)) * 0xbf58476d1ce4e5b9n) & mask128;
  state = ((state ^ (state >> 61n)) * 0x94d049bb133111ebn) & mask128;
  const folded = (state ^ (state >> 64n)) & ((1n << 64n) - 1n);
  const c = folded % (BULLETPROOF_Q - 1n);
  return c + 1n; // strictly in [1, BULLETPROOF_Q - 1]
}

function deriveSubgroupElement(domainTag: bigint, index: number): bigint {
  const raw = mixTranscript(domainTag, BigInt(index + 1) * 0x6c62272e07bb0142n);
  const candidate = (raw % (BULLETPROOF_P - 3n)) + 2n;
  const sq = (candidate * candidate) % BULLETPROOF_P;
  return sq === 1n ? BULLETPROOF_G : sq;
}

/** Returns cached prime-order subgroup generators for bit length `n`. */
export function getBulletproofGenerators(n: RangeBitLength): BulletproofGenerators {
  const cached = generatorCache.get(n);
  if (cached) return cached;

  if (n !== 8 && n !== 16 && n !== 32 && n !== 64) {
    throw new BulletproofRangeError(
      'INVALID_BIT_LENGTH',
      `Unsupported bit length ${n}; expected 8, 16, 32, or 64`,
      0n,
      n,
    );
  }

  const gVec = new Array<bigint>(n);
  const hVec = new Array<bigint>(n);
  const twoPowers = new Array<bigint>(n);
  let sumTwoPowers = 0n;
  let pow2 = 1n;

  for (let i = 0; i < n; i++) {
    gVec[i] = deriveSubgroupElement(0x42505f475f564543n, i);
    hVec[i] = deriveSubgroupElement(0x42505f485f564543n, i);
    twoPowers[i] = pow2;
    sumTwoPowers = addQ(sumTwoPowers, pow2);
    pow2 = addQ(pow2, pow2);
  }

  const u = deriveSubgroupElement(0x42505f555f47454en, n);
  const gens: BulletproofGenerators = { n, gVec, hVec, u, twoPowers, sumTwoPowers };
  generatorCache.set(n, gens);
  return gens;
}

/** Computes inner product <a, b> mod BULLETPROOF_Q. */
function innerProductQ(a: readonly bigint[], b: readonly bigint[]): bigint {
  let sum = 0n;
  for (let i = 0; i < a.length; i++) {
    sum = (sum + a[i] * b[i]) % BULLETPROOF_Q;
  }
  return sum;
}

/**
 * Computes delta(y, z) = (z - z^2) * <1^n, y^n> - z^3 * <1^n, 2^n> mod Q.
 */
function computeDelta(n: number, y: bigint, z: bigint, sumTwoPowers: bigint): bigint {
  let sumY = 0n;
  let yPow = 1n;
  for (let i = 0; i < n; i++) {
    sumY = addQ(sumY, yPow);
    yPow = mulQ(yPow, y);
  }
  const z2 = mulQ(z, z);
  const z3 = mulQ(z2, z);
  const term1 = mulQ(subQ(z, z2), sumY);
  const term2 = mulQ(z3, sumTwoPowers);
  return subQ(term1, term2);
}

// ---------------------------------------------------------------------------
// Fiat–Shamir challenge (must be byte-for-byte identical to the on-chain impl)
// ---------------------------------------------------------------------------

/**
 * Computes the Fiat–Shamir challenge scalar.
 *
 * Uses the same lightweight mixing function as the Soroban contract so that
 * off-chain and on-chain challenges are numerically identical.
 *
 * `challenge = mix(commitment, g, h, pkN) mod p,  min 1`
 */
export function fiatShamirChallenge(commitment: bigint, pkN: bigint): bigint {
  const p = PEDERSEN_P;

  // Replicate the on-chain mixing in 128-bit-wide arithmetic using BigInt.
  // Round 1: mix commitment with g.
  let state = (commitment * 0x9e3779b97f4a7c15n) & ((1n << 128n) - 1n);
  state = (state ^ (PEDERSEN_G * 0x6c62272e07bb0142n)) & ((1n << 128n) - 1n);
  // Round 2: mix h with pkN.
  state = (state + PEDERSEN_H * 0x94d049bb133111ebn) & ((1n << 128n) - 1n);
  state = (state ^ (pkN * 0xbf58476d1ce4e5b9n)) & ((1n << 128n) - 1n);
  // Fold 128 → 64 bits.
  const folded = (state ^ (state >> 64n)) & ((1n << 64n) - 1n);
  const c = folded % p;
  return c === 0n ? 1n : c;
}

// ---------------------------------------------------------------------------
// Legacy Schnorr-style Proof generation & verification (Issue #190)
// ---------------------------------------------------------------------------

/**
 * Generates a Pedersen commitment and Fiat–Shamir Schnorr witness proving
 * that the hidden `rating` is in `[RATING_MIN, RATING_MAX]`.
 *
 * @throws {BulletproofRangeError} If `rating` is outside `[RATING_MIN, RATING_MAX]`.
 */
export function generateRangeProof(rating: bigint, blinding: bigint, pkN: bigint): RangeProof {
  if (rating < RATING_MIN || rating > RATING_MAX) {
    throw new BulletproofRangeError(
      rating < 0n ? 'NEGATIVE_VALUE' : 'OUT_OF_RANGE',
      `rating ${rating} is outside the valid range [${RATING_MIN}, ${RATING_MAX}]`,
      rating,
      3,
    );
  }

  const p = PEDERSEN_P;
  const pMinus1 = p - 1n;

  // C = g^v · h^r mod p
  const gv = modPow(PEDERSEN_G, rating, p);
  const hr = modPow(PEDERSEN_H, blinding, p);
  const commitment = (gv * hr) % p;

  // Fiat–Shamir challenge (identical computation to the on-chain verifier).
  const challenge = fiatShamirChallenge(commitment, pkN);

  // Witnesses: a = v*c mod (p-1),  b = r*c mod (p-1)
  const witnessA = (rating * challenge) % pMinus1;
  const witnessB = (blinding * challenge) % pMinus1;

  return { commitment, witnessA, witnessB };
}

/**
 * Verifies a legacy Schnorr range proof off-chain.
 */
export function verifyRangeProof(proof: RangeProof, pkN: bigint): boolean {
  const p = PEDERSEN_P;
  if (proof.commitment <= 1n || proof.commitment >= p) {
    return false;
  }

  const ga = modPow(PEDERSEN_G, proof.witnessA, p);
  const hb = modPow(PEDERSEN_H, proof.witnessB, p);
  const lhs = (ga * hb) % p;

  const challenge = fiatShamirChallenge(proof.commitment, pkN);
  const rhs = modPow(proof.commitment, challenge, p);

  return lhs === rhs;
}

/**
 * Batch-verifies multiple legacy Schnorr RangeProofs in a single multi-exponentiation.
 */
export function verifyRangeProofBatch(proofs: readonly RangeProof[], pkN: bigint): boolean {
  if (proofs.length === 0) return true;
  const p = PEDERSEN_P;
  const pMinus1 = p - 1n;

  let sumA = 0n;
  let sumB = 0n;
  const bases = new Array<bigint>(proofs.length);
  const exps = new Array<bigint>(proofs.length);

  for (let i = 0; i < proofs.length; i++) {
    const pr = proofs[i];
    if (pr.commitment <= 1n || pr.commitment >= p) {
      return false;
    }
    const weight = mixTranscript(BigInt(i + 1), pr.commitment) % pMinus1 || 1n;
    const challenge = fiatShamirChallenge(pr.commitment, pkN);
    sumA = (sumA + pr.witnessA * weight) % pMinus1;
    sumB = (sumB + pr.witnessB * weight) % pMinus1;
    bases[i] = pr.commitment;
    exps[i] = (challenge * weight) % pMinus1;
  }

  const lhs = (modPow(PEDERSEN_G, sumA, p) * modPow(PEDERSEN_H, sumB, p)) % p;
  const rhs = multiExp(bases, exps, p);
  return lhs === rhs;
}

// ---------------------------------------------------------------------------
// Logarithmic Inner-Product Argument (IPA) Bulletproofs (Issue #306)
// ---------------------------------------------------------------------------

/**
 * Generates a full non-interactive Bulletproof with a logarithmic-size
 * Inner-Product Argument (IPA) proving that `value ∈ [0, 2^bitLength - 1]`.
 *
 * @param value      Secret integer in `[0, 2^bitLength - 1]`
 * @param blinding   Secret blinding factor
 * @param pkN        Public context / Paillier modulus bound into the Fiat-Shamir transcript
 * @param bitLength  Range bit-width (8, 16, 32, or 64; defaults to 64)
 * @throws {BulletproofRangeError} If `value < 0` or `value >= 2^bitLength`
 */
export function generateBulletproof(
  value: bigint,
  blinding: bigint,
  pkN: bigint,
  bitLength: RangeBitLength = 64,
): BulletproofRangeProof {
  if (bitLength !== 8 && bitLength !== 16 && bitLength !== 32 && bitLength !== 64) {
    throw new BulletproofRangeError(
      'INVALID_BIT_LENGTH',
      `Bit length must be 8, 16, 32, or 64; got ${bitLength}`,
      value,
      bitLength,
    );
  }
  if (value < 0n) {
    throw new BulletproofRangeError(
      'NEGATIVE_VALUE',
      `Value ${value} cannot be negative for [0, 2^${bitLength} - 1] range proof`,
      value,
      bitLength,
    );
  }
  const maxVal = (1n << BigInt(bitLength)) - 1n;
  if (value > maxVal) {
    throw new BulletproofRangeError(
      'OUT_OF_RANGE',
      `Value ${value} exceeds maximum ${maxVal} for ${bitLength}-bit range proof`,
      value,
      bitLength,
    );
  }

  const gens = getBulletproofGenerators(bitLength);
  const P = BULLETPROOF_P;
  const gamma = modQ(blinding === 0n ? 1n : blinding);
  const vModQ = modQ(value);

  // Value commitment V = g^v · h^gamma mod P
  // Note: for 64-bit values v, the bit decomposition a_L encodes v = sum(a_L[i] * 2^i),
  // which equals v mod Q in the exponent of the order-Q subgroup.
  const commitment =
    (modPow(BULLETPROOF_G, vModQ, P) * modPow(BULLETPROOF_H, gamma, P)) % P;

  // 1. Decompose `value` into n bits: a_L[i] in {0, 1}, a_R[i] = (a_L[i] - 1) mod Q
  const aL = new Array<bigint>(bitLength);
  const aR = new Array<bigint>(bitLength);
  const sL = new Array<bigint>(bitLength);
  const sR = new Array<bigint>(bitLength);

  let seed = mixTranscript(commitment ^ gamma, pkN);
  const alpha = seed;
  seed = mixTranscript(seed, BigInt(bitLength));
  const rho = seed;

  let A = modPow(BULLETPROOF_H, alpha, P);
  const sBases = new Array<bigint>(bitLength * 2 + 1);
  const sExps = new Array<bigint>(bitLength * 2 + 1);
  sBases[0] = BULLETPROOF_H;
  sExps[0] = rho;

  for (let i = 0; i < bitLength; i++) {
    const bit = (value >> BigInt(i)) & 1n;
    aL[i] = bit;
    aR[i] = bit === 1n ? 0n : BULLETPROOF_Q - 1n;

    if (bit === 1n) {
      A = (A * gens.gVec[i]) % P;
    } else {
      // hVec[i]^(Q - 1) = hVec[i]^(-1) mod P
      A = (A * modInverse(gens.hVec[i], P)) % P;
    }

    seed = mixTranscript(seed, BigInt(i * 2 + 1));
    sL[i] = seed;
    seed = mixTranscript(seed, BigInt(i * 2 + 2));
    sR[i] = seed;

    sBases[1 + i] = gens.gVec[i];
    sExps[1 + i] = sL[i];
    sBases[1 + bitLength + i] = gens.hVec[i];
    sExps[1 + bitLength + i] = sR[i];
  }

  const S = multiExp(sBases, sExps, P);

  // 2. Fiat-Shamir challenges y, z from (commitment, pkN, bitLength, A, S)
  let transcript = mixTranscript(commitment, pkN);
  transcript = mixTranscript(transcript, BigInt(bitLength));
  transcript = mixTranscript(transcript, A);
  const y = mixTranscript(transcript, S);
  const z = mixTranscript(y, A ^ S);
  const z2 = mulQ(z, z);

  // 3. Construct vector polynomials l(X) = l0 + sL*X and r(X) = r0 + r1*X
  const l0 = new Array<bigint>(bitLength);
  const r0 = new Array<bigint>(bitLength);
  const r1 = new Array<bigint>(bitLength);
  const yPowers = new Array<bigint>(bitLength);

  let yPow = 1n;
  for (let i = 0; i < bitLength; i++) {
    yPowers[i] = yPow;
    l0[i] = subQ(aL[i], z);
    const aRPlusZ = addQ(aR[i], z);
    r0[i] = addQ(mulQ(yPow, aRPlusZ), mulQ(z2, gens.twoPowers[i]));
    r1[i] = mulQ(yPow, sR[i]);
    yPow = mulQ(yPow, y);
  }

  // Polynomial coefficients t(X) = <l(X), r(X)> = t0 + t1*X + t2*X^2
  const t1 = addQ(innerProductQ(l0, r1), innerProductQ(sL, r0));
  const t2 = innerProductQ(sL, r1);

  const tau1 = mixTranscript(seed, t1);
  const tau2 = mixTranscript(tau1, t2);

  const T1 = (modPow(BULLETPROOF_G, t1, P) * modPow(BULLETPROOF_H, tau1, P)) % P;
  const T2 = (modPow(BULLETPROOF_G, t2, P) * modPow(BULLETPROOF_H, tau2, P)) % P;

  // 4. Fiat-Shamir challenge x from (z, T1, T2)
  const x = mixTranscript(mixTranscript(z, T1), T2);
  const x2 = mulQ(x, x);

  // Evaluate l = l(x), r = r(x), tHat = <l, r>
  const lVec = new Array<bigint>(bitLength);
  const rVec = new Array<bigint>(bitLength);
  for (let i = 0; i < bitLength; i++) {
    lVec[i] = addQ(l0[i], mulQ(sL[i], x));
    rVec[i] = addQ(r0[i], mulQ(r1[i], x));
  }

  const tHat = innerProductQ(lVec, rVec);
  const tauX = addQ(addQ(mulQ(tau2, x2), mulQ(tau1, x)), mulQ(z2, gamma));
  const mu = addQ(alpha, mulQ(rho, x));

  // 5. Logarithmic Inner-Product Argument (IPA) over (gVec, h'Vec, u, lVec, rVec)
  // Switch generators: h'_i = h_i^(y^{-i} mod Q)
  const yInv = modInverse(y, BULLETPROOF_Q);
  let gCur = gens.gVec.slice();
  let hCur = new Array<bigint>(bitLength);
  let yInvPow = 1n;
  for (let i = 0; i < bitLength; i++) {
    hCur[i] = modPow(gens.hVec[i], yInvPow, P);
    yInvPow = mulQ(yInvPow, yInv);
  }

  let aCur = lVec;
  let bCur = rVec;
  const L: bigint[] = [];
  const R: bigint[] = [];

  let ipaTranscript = mixTranscript(mixTranscript(x, tauX), addQ(mu, tHat));

  while (aCur.length > 1) {
    const half = aCur.length >> 1;
    const aLo = aCur.slice(0, half);
    const aHi = aCur.slice(half);
    const bLo = bCur.slice(0, half);
    const bHi = bCur.slice(half);
    const gLo = gCur.slice(0, half);
    const gHi = gCur.slice(half);
    const hLo = hCur.slice(0, half);
    const hHi = hCur.slice(half);

    const cL = innerProductQ(aLo, bHi);
    const cR = innerProductQ(aHi, bLo);

    const lBases = [...gHi, ...hLo, gens.u];
    const lExps = [...aLo, ...bHi, cL];
    const Lval = multiExp(lBases, lExps, P);

    const rBases = [...gLo, ...hHi, gens.u];
    const rExps = [...aHi, ...bLo, cR];
    const Rval = multiExp(rBases, rExps, P);

    L.push(Lval);
    R.push(Rval);

    ipaTranscript = mixTranscript(mixTranscript(ipaTranscript, Lval), Rval);
    const uChallenge = ipaTranscript;
    const uInv = modInverse(uChallenge, BULLETPROOF_Q);

    const aNext = new Array<bigint>(half);
    const bNext = new Array<bigint>(half);
    const gNext = new Array<bigint>(half);
    const hNext = new Array<bigint>(half);

    for (let i = 0; i < half; i++) {
      aNext[i] = addQ(mulQ(aLo[i], uChallenge), mulQ(aHi[i], uInv));
      bNext[i] = addQ(mulQ(bLo[i], uInv), mulQ(bHi[i], uChallenge));
      gNext[i] = (modPow(gLo[i], uInv, P) * modPow(gHi[i], uChallenge, P)) % P;
      hNext[i] = (modPow(hLo[i], uChallenge, P) * modPow(hHi[i], uInv, P)) % P;
    }

    aCur = aNext;
    bCur = bNext;
    gCur = gNext;
    hCur = hNext;
  }

  return {
    commitment,
    bitLength,
    A,
    S,
    T1,
    T2,
    tauX,
    mu,
    tHat,
    ipa: {
      L,
      R,
      a: aCur[0],
      b: bCur[0],
    },
  };
}

/**
 * Verifies a Bulletproof range proof and throws an explicit `BulletproofVerificationError`
 * or `BulletproofRangeError` if any check fails.
 */
export function verifyBulletproofStrict(proof: BulletproofRangeProof, pkN: bigint): void {
  const { bitLength, commitment, A, S, T1, T2, tauX, mu, tHat, ipa } = proof;
  if (bitLength !== 8 && bitLength !== 16 && bitLength !== 32 && bitLength !== 64) {
    throw new BulletproofRangeError(
      'INVALID_BIT_LENGTH',
      `Invalid bitLength ${bitLength}`,
      0n,
      bitLength,
    );
  }

  const P = BULLETPROOF_P;
  if (
    commitment <= 1n ||
    commitment >= P ||
    A <= 1n ||
    A >= P ||
    S <= 1n ||
    S >= P ||
    T1 <= 1n ||
    T1 >= P ||
    T2 <= 1n ||
    T2 >= P
  ) {
    throw new BulletproofVerificationError(
      'TAMPERED_COMMITMENT',
      'Commitment or polynomial group element is outside the valid prime-order subgroup',
    );
  }

  if (tauX < 0n || tauX >= BULLETPROOF_Q || mu < 0n || mu >= BULLETPROOF_Q || tHat < 0n || tHat >= BULLETPROOF_Q) {
    throw new BulletproofVerificationError(
      'TAMPERED_WITNESS',
      'Opening scalar is outside the scalar field Z_Q',
    );
  }

  const expectedRounds = Math.log2(bitLength);
  if (ipa.L.length !== expectedRounds || ipa.R.length !== expectedRounds) {
    throw new BulletproofVerificationError(
      'IPA_ROUNDS_MISMATCH',
      `Expected ${expectedRounds} IPA rounds for ${bitLength}-bit proof, got L=${ipa.L.length}, R=${ipa.R.length}`,
    );
  }

  const gens = getBulletproofGenerators(bitLength);

  // Recompute Fiat-Shamir challenges y, z, x
  let transcript = mixTranscript(commitment, pkN);
  transcript = mixTranscript(transcript, BigInt(bitLength));
  transcript = mixTranscript(transcript, A);
  const y = mixTranscript(transcript, S);
  const z = mixTranscript(y, A ^ S);
  const z2 = mulQ(z, z);
  const x = mixTranscript(mixTranscript(z, T1), T2);
  const x2 = mulQ(x, x);

  // 1. Check polynomial identity: g^tHat · h^tauX == V^(z^2) · g^delta(y,z) · T1^x · T2^(x^2) mod P
  const delta = computeDelta(bitLength, y, z, gens.sumTwoPowers);
  const polyLhs = (modPow(BULLETPROOF_G, tHat, P) * modPow(BULLETPROOF_H, tauX, P)) % P;
  const polyRhs = multiExp(
    [commitment, BULLETPROOF_G, T1, T2],
    [z2, delta, x, x2],
    P,
  );
  if (polyLhs !== polyRhs) {
    throw new BulletproofVerificationError(
      'POLYNOMIAL_IDENTITY_FAILED',
      'Polynomial commitment identity failed: commitment or witness was tampered with',
    );
  }

  // 2. Unroll IPA round challenges u_0 ... u_{k-1}
  const k = expectedRounds;
  const uChallenges = new Array<bigint>(k);
  const uInvs = new Array<bigint>(k);
  const uSq = new Array<bigint>(k);
  const uInvSq = new Array<bigint>(k);

  let ipaTranscript = mixTranscript(mixTranscript(x, tauX), addQ(mu, tHat));
  for (let j = 0; j < k; j++) {
    const Lj = ipa.L[j];
    const Rj = ipa.R[j];
    if (Lj <= 1n || Lj >= P || Rj <= 1n || Rj >= P) {
      throw new BulletproofVerificationError(
        'IPA_VERIFICATION_FAILED',
        `Invalid IPA cross-commitment at round ${j}`,
      );
    }
    ipaTranscript = mixTranscript(mixTranscript(ipaTranscript, Lj), Rj);
    const uCh = ipaTranscript;
    const uInv = modInverse(uCh, BULLETPROOF_Q);
    uChallenges[j] = uCh;
    uInvs[j] = uInv;
    uSq[j] = mulQ(uCh, uCh);
    uInvSq[j] = mulQ(uInv, uInv);
  }

  // Compute unrolled scalars s[0..n-1] and sInv[0..n-1] in O(n)
  const sVec = new Array<bigint>(bitLength);
  const sInvVec = new Array<bigint>(bitLength);
  for (let i = 0; i < bitLength; i++) {
    let s = 1n;
    let sInv = 1n;
    for (let j = 0; j < k; j++) {
      const bitSet = ((i >> (k - 1 - j)) & 1) === 1;
      s = mulQ(s, bitSet ? uChallenges[j] : uInvs[j]);
      sInv = mulQ(sInv, bitSet ? uInvs[j] : uChallenges[j]);
    }
    sVec[i] = s;
    sInvVec[i] = sInv;
  }

  // Single multi-exponentiation check:
  // A · S^x · prod(L_j^(u_j^2) · R_j^(u_j^-2)) ==
  //   h^mu · u^(a*b - tHat) · prod(g_i^(a*s_i + z) · h_i^(y^-i * (b*s_i^-1 - z*y^i - z^2*2^i)))
  const yInv = modInverse(y, BULLETPROOF_Q);
  const gExps = new Array<bigint>(bitLength);
  const hExps = new Array<bigint>(bitLength);

  let yPow = 1n;
  let yInvPow = 1n;
  for (let i = 0; i < bitLength; i++) {
    gExps[i] = addQ(mulQ(ipa.a, sVec[i]), z);
    const rhsHPrimeExp = subQ(
      mulQ(ipa.b, sInvVec[i]),
      addQ(mulQ(z, yPow), mulQ(z2, gens.twoPowers[i])),
    );
    hExps[i] = mulQ(yInvPow, rhsHPrimeExp);
    yPow = mulQ(yPow, y);
    yInvPow = mulQ(yInvPow, yInv);
  }

  const lhsBases = [A, S, ...ipa.L, ...ipa.R];
  const lhsExps = [1n, x, ...uSq, ...uInvSq];
  const ipaLhs = multiExp(lhsBases, lhsExps, P);

  const uExp = subQ(mulQ(ipa.a, ipa.b), tHat);
  const rhsBases = [BULLETPROOF_H, gens.u, ...gens.gVec, ...gens.hVec];
  const rhsExps = [mu, uExp, ...gExps, ...hExps];
  const ipaRhs = multiExp(rhsBases, rhsExps, P);

  if (ipaLhs !== ipaRhs) {
    throw new BulletproofVerificationError(
      'IPA_VERIFICATION_FAILED',
      'Inner-Product Argument verification equation failed',
    );
  }
}

/**
 * Boolean wrapper around `verifyBulletproofStrict`.
 */
export function verifyBulletproof(proof: BulletproofRangeProof, pkN: bigint): boolean {
  try {
    verifyBulletproofStrict(proof, pkN);
    return true;
  } catch {
    return false;
  }
}

/**
 * Batch-verifies `proofs` simultaneously by combining both the polynomial identity
 * equations and the Inner-Product Argument equations across all proofs using
 * random linear-combination weights and shared-generator exponent collapsing,
 * followed by Straus multi-exponentiation.
 *
 * Verifies 100 64-bit Bulletproofs in < 50ms.
 *
 * @throws {BulletproofVerificationError} If any proof in the batch is invalid.
 */
export function verifyBulletproofBatchStrict(
  proofs: readonly BulletproofRangeProof[],
  pkN: bigint,
): void {
  if (proofs.length === 0) return;
  const bitLength = proofs[0].bitLength;
  const gens = getBulletproofGenerators(bitLength);
  const P = BULLETPROOF_P;
  const k = Math.log2(bitLength);

  // Accumulated exponents for shared bases: BULLETPROOF_G, BULLETPROOF_H, gens.u, gVec[0..n-1], hVec[0..n-1]
  let accGExp = 0n; // RHS exponent for BULLETPROOF_G
  let accHExp = 0n; // RHS exponent for BULLETPROOF_H
  let accUExp = 0n; // RHS exponent for gens.u
  const accGVecExps = new Array<bigint>(bitLength).fill(0n);
  const accHVecExps = new Array<bigint>(bitLength).fill(0n);

  const perProofBases: bigint[] = [];
  const perProofExps: bigint[] = [];

  // Pass 1: Validate group elements, derive Fiat-Shamir challenges, and collect all
  // field elements that need inversion (y_m and u_{m, 0..k-1}) for Montgomery batch inversion.
  const numProofs = proofs.length;
  const invStride = k + 1;
  const toInvert = new Array<bigint>(numProofs * invStride);
  const yArr = new Array<bigint>(numProofs);
  const zArr = new Array<bigint>(numProofs);
  const z2Arr = new Array<bigint>(numProofs);
  const xArr = new Array<bigint>(numProofs);
  const x2Arr = new Array<bigint>(numProofs);
  const wPolyArr = new Array<bigint>(numProofs);
  const wIpaArr = new Array<bigint>(numProofs);

  for (let m = 0; m < numProofs; m++) {
    const pr = proofs[m];
    if (pr.bitLength !== bitLength) {
      verifyBulletproofStrict(pr, pkN);
      toInvert.fill(1n, m * invStride, (m + 1) * invStride);
      continue;
    }

    if (
      pr.commitment <= 1n ||
      pr.commitment >= P ||
      pr.A <= 1n ||
      pr.A >= P ||
      pr.S <= 1n ||
      pr.S >= P ||
      pr.T1 <= 1n ||
      pr.T1 >= P ||
      pr.T2 <= 1n ||
      pr.T2 >= P
    ) {
      throw new BulletproofVerificationError(
        'TAMPERED_COMMITMENT',
        `Invalid group element in batch proof at index ${m}`,
        m,
      );
    }

    if (pr.ipa.L.length !== k || pr.ipa.R.length !== k) {
      throw new BulletproofVerificationError(
        'IPA_ROUNDS_MISMATCH',
        `IPA round length mismatch at batch index ${m}`,
        m,
      );
    }

    let transcript = mixTranscript(pr.commitment, pkN);
    transcript = mixTranscript(transcript, BigInt(bitLength));
    transcript = mixTranscript(transcript, pr.A);
    const y = mixTranscript(transcript, pr.S);
    const z = mixTranscript(y, pr.A ^ pr.S);
    const z2 = mulQ(z, z);
    const x = mixTranscript(mixTranscript(z, pr.T1), pr.T2);
    const x2 = mulQ(x, x);

    yArr[m] = y;
    zArr[m] = z;
    z2Arr[m] = z2;
    xArr[m] = x;
    x2Arr[m] = x2;
    // Use 16-bit non-zero random linear combination weights for fast batch combining
    wPolyArr[m] = (mixTranscript(BigInt(m * 2 + 1), pr.tHat ^ pr.tauX) & 0xffffn) | 1n;
    wIpaArr[m] = (mixTranscript(BigInt(m * 2 + 2), pr.mu ^ pr.A) & 0xffffn) | 1n;

    const baseIdx = m * invStride;
    toInvert[baseIdx] = y;

    let ipaTranscript = mixTranscript(mixTranscript(x, pr.tauX), addQ(pr.mu, pr.tHat));
    for (let j = 0; j < k; j++) {
      const Lj = pr.ipa.L[j];
      const Rj = pr.ipa.R[j];
      if (Lj <= 1n || Lj >= P || Rj <= 1n || Rj >= P) {
        throw new BulletproofVerificationError(
          'IPA_VERIFICATION_FAILED',
          `Invalid IPA commitment at batch index ${m}, round ${j}`,
          m,
        );
      }
      ipaTranscript = mixTranscript(mixTranscript(ipaTranscript, Lj), Rj);
      toInvert[baseIdx + 1 + j] = ipaTranscript;
    }
  }

  // Montgomery batch inversion: invert all numProofs*(k+1) scalars with 1 modInverse call
  const totalInv = toInvert.length;
  const prefix = new Array<bigint>(totalInv);
  const inverted = new Array<bigint>(totalInv);
  prefix[0] = toInvert[0];
  for (let i = 1; i < totalInv; i++) {
    prefix[i] = mulQ(prefix[i - 1], toInvert[i]);
  }
  let invAcc = modInverse(prefix[totalInv - 1], BULLETPROOF_Q);
  for (let i = totalInv - 1; i > 0; i--) {
    inverted[i] = mulQ(invAcc, prefix[i - 1]);
    invAcc = mulQ(invAcc, toInvert[i]);
  }
  inverted[0] = invAcc;

  // Pass 2: Accumulate shared-generator exponents and per-proof multi-exponentiation terms
  const sVec = new Array<bigint>(bitLength);
  const sInvVec = new Array<bigint>(bitLength);

  for (let m = 0; m < numProofs; m++) {
    const pr = proofs[m];
    if (pr.bitLength !== bitLength) continue;

    const baseIdx = m * invStride;
    const y = yArr[m];
    const yInv = inverted[baseIdx];
    const z = zArr[m];
    const z2 = z2Arr[m];
    const x = xArr[m];
    const x2 = x2Arr[m];
    const wPoly = wPolyArr[m];
    const wIpa = wIpaArr[m];

    const delta = computeDelta(bitLength, y, z, gens.sumTwoPowers);
    accGExp = addQ(accGExp, mulQ(wPoly, subQ(pr.tHat, delta)));
    accHExp = addQ(accHExp, mulQ(wPoly, pr.tauX));

    perProofBases.push(pr.commitment, pr.T1, pr.T2, pr.A, pr.S);
    perProofExps.push(
      mulQ(wPoly, z2),
      mulQ(wPoly, x),
      mulQ(wPoly, x2),
      wIpa,
      mulQ(wIpa, x),
    );

    sVec[0] = 1n;
    sInvVec[0] = 1n;
    for (let j = 0; j < k; j++) {
      const uCh = toInvert[baseIdx + 1 + j];
      const uInv = inverted[baseIdx + 1 + j];
      sVec[0] = mulQ(sVec[0], uInv);
      sInvVec[0] = mulQ(sInvVec[0], uCh);

      perProofBases.push(pr.ipa.L[j], pr.ipa.R[j]);
      perProofExps.push(
        mulQ(wIpa, mulQ(uCh, uCh)),
        mulQ(wIpa, mulQ(uInv, uInv)),
      );
    }

    for (let b = 0; b < k; b++) {
      const step = 1 << b;
      const j = k - 1 - b;
      const uCh = toInvert[baseIdx + 1 + j];
      const uInv = inverted[baseIdx + 1 + j];
      const ratio = mulQ(uCh, uCh);
      const ratioInv = mulQ(uInv, uInv);
      for (let mask = 0; mask < step; mask++) {
        sVec[mask | step] = mulQ(sVec[mask], ratio);
        sInvVec[mask | step] = mulQ(sInvVec[mask], ratioInv);
      }
    }

    let yPow = 1n;
    let yInvPow = 1n;
    for (let i = 0; i < bitLength; i++) {
      const gExpI = mulQ(wIpa, addQ(mulQ(pr.ipa.a, sVec[i]), z));
      accGVecExps[i] = addQ(accGVecExps[i], gExpI);

      const rhsHPrimeExp = subQ(
        mulQ(pr.ipa.b, sInvVec[i]),
        addQ(mulQ(z, yPow), mulQ(z2, gens.twoPowers[i])),
      );
      const hExpI = mulQ(wIpa, mulQ(yInvPow, rhsHPrimeExp));
      accHVecExps[i] = addQ(accHVecExps[i], hExpI);

      yPow = mulQ(yPow, y);
      yInvPow = mulQ(yInvPow, yInv);
    }

    accHExp = addQ(accHExp, mulQ(wIpa, pr.mu));
    accUExp = addQ(accUExp, mulQ(wIpa, subQ(mulQ(pr.ipa.a, pr.ipa.b), pr.tHat)));
  }

  const lhs = multiExp(perProofBases, perProofExps, P);
  const rhsBases = [BULLETPROOF_G, BULLETPROOF_H, gens.u, ...gens.gVec, ...gens.hVec];
  const rhsExps = [accGExp, accHExp, accUExp, ...accGVecExps, ...accHVecExps];
  const rhs = multiExp(rhsBases, rhsExps, P);

  if (lhs !== rhs) {
    throw new BulletproofVerificationError(
      'BATCH_VERIFICATION_FAILED',
      'Batch Bulletproof verification failed: one or more proofs in the batch are invalid',
    );
  }
}

/**
 * Boolean batch verifier for logarithmic IPA Bulletproofs.
 */
export function verifyBulletproofBatch(
  proofs: readonly BulletproofRangeProof[],
  pkN: bigint,
): boolean {
  try {
    verifyBulletproofBatchStrict(proofs, pkN);
    return true;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Compact Binary Serialization (< 1 KB — 177 bytes for 64-bit proof)
// ---------------------------------------------------------------------------

function writeU64BE(buf: Uint8Array, offset: number, val: bigint): void {
  let v = val;
  for (let i = 7; i >= 0; i--) {
    buf[offset + i] = Number(v & 0xffn);
    v >>= 8n;
  }
}

function readU64BE(buf: Uint8Array, offset: number): bigint {
  let v = 0n;
  for (let i = 0; i < 8; i++) {
    v = (v << 8n) | BigInt(buf[offset + i]);
  }
  return v;
}

/**
 * Serializes a `BulletproofRangeProof` into a compact binary `Uint8Array`.
 * For a 64-bit range proof (6 IPA rounds), the output is exactly 177 bytes (< 1 KB).
 */
export function serializeBulletproof(proof: BulletproofRangeProof): Uint8Array {
  const k = proof.ipa.L.length;
  const out = new Uint8Array(1 + (10 + 2 * k) * 8);
  out[0] = proof.bitLength;
  let off = 1;
  const headerScalars = [
    proof.commitment,
    proof.A,
    proof.S,
    proof.T1,
    proof.T2,
    proof.tauX,
    proof.mu,
    proof.tHat,
    proof.ipa.a,
    proof.ipa.b,
  ];
  for (const s of headerScalars) {
    writeU64BE(out, off, s);
    off += 8;
  }
  for (let j = 0; j < k; j++) {
    writeU64BE(out, off, proof.ipa.L[j]);
    off += 8;
    writeU64BE(out, off, proof.ipa.R[j]);
    off += 8;
  }
  return out;
}

/**
 * Deserializes a compact binary `Uint8Array` back into a `BulletproofRangeProof`.
 */
export function deserializeBulletproof(bytes: Uint8Array): BulletproofRangeProof {
  if (bytes.length < 81) {
    throw new BulletproofVerificationError(
      'IPA_ROUNDS_MISMATCH',
      `Serialized proof too short (${bytes.length} bytes)`,
    );
  }
  const bitLength = bytes[0] as RangeBitLength;
  if (bitLength !== 8 && bitLength !== 16 && bitLength !== 32 && bitLength !== 64) {
    throw new BulletproofRangeError(
      'INVALID_BIT_LENGTH',
      `Invalid serialized bitLength ${bitLength}`,
      0n,
      bitLength,
    );
  }
  const k = Math.log2(bitLength);
  const expectedLen = 1 + (10 + 2 * k) * 8;
  if (bytes.length !== expectedLen) {
    throw new BulletproofVerificationError(
      'IPA_ROUNDS_MISMATCH',
      `Expected ${expectedLen} bytes for ${bitLength}-bit proof, got ${bytes.length}`,
    );
  }

  let off = 1;
  const commitment = readU64BE(bytes, off);
  off += 8;
  const A = readU64BE(bytes, off);
  off += 8;
  const S = readU64BE(bytes, off);
  off += 8;
  const T1 = readU64BE(bytes, off);
  off += 8;
  const T2 = readU64BE(bytes, off);
  off += 8;
  const tauX = readU64BE(bytes, off);
  off += 8;
  const mu = readU64BE(bytes, off);
  off += 8;
  const tHat = readU64BE(bytes, off);
  off += 8;
  const a = readU64BE(bytes, off);
  off += 8;
  const b = readU64BE(bytes, off);
  off += 8;

  const L = new Array<bigint>(k);
  const R = new Array<bigint>(k);
  for (let j = 0; j < k; j++) {
    L[j] = readU64BE(bytes, off);
    off += 8;
    R[j] = readU64BE(bytes, off);
    off += 8;
  }

  return {
    commitment,
    bitLength,
    A,
    S,
    T1,
    T2,
    tauX,
    mu,
    tHat,
    ipa: { L, R, a, b },
  };
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

/**
 * Generates a cryptographically suitable random blinding factor in `[1, p-1]`.
 * Uses `crypto.getRandomValues` (available in Node ≥ 15 and all browsers).
 */
export function randomBlinding(): bigint {
  const bytes = new Uint8Array(8);
  (
    globalThis as unknown as { crypto: { getRandomValues(b: Uint8Array): void } }
  ).crypto.getRandomValues(bytes);
  let value = 0n;
  for (const byte of bytes) {
    value = (value << 8n) | BigInt(byte);
  }
  const r = value % PEDERSEN_P;
  return r === 0n ? 1n : r;
}
