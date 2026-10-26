/**
 * Distributed Threshold Signature Scheme (FROST / TSS) for Automated Oracle Relayer — Issue #299
 *
 * Implements:
 * 1. Dealerless Distributed Key Generation (Pedersen-VSS + Feldman-VSS + Schnorr PoK)
 *    across participating attestor nodes on secp256k1 without a central trusted dealer.
 * 2. Two-Round Flexible Round-Optimized Schnorr Threshold (FROST) t-of-n signing protocol
 *    with asynchronous / offline node tolerance (up to n - t nodes offline).
 * 3. Verifiable Signature Share Validation that detects tampered or malicious signature
 *    shares and identifies culprit node IDs with cryptographic slashing evidence.
 * 4. EVM-compatible Schnorr threshold signature emission verifiable on-chain in O(1) gas
 *    by `PactumTrustOracle.sol` via the secp256k1 `ecrecover` precompile.
 */

import { randomBytes } from 'node:crypto';

// ---------------------------------------------------------------------------
// Pure Ethereum Keccak-256 Implementation (FIPS-202 pre-standard 0x01 padding)
// ---------------------------------------------------------------------------

const KECCAK_ROUNDS = 24;
const KECCAK_RC: bigint[] = [
  0x0000000000000001n,
  0x0000000000008082n,
  0x800000000000808an,
  0x8000000080008000n,
  0x000000000000808bn,
  0x0000000080000001n,
  0x8000000080008081n,
  0x8000000000008009n,
  0x000000000000008an,
  0x0000000000000088n,
  0x0000000080008009n,
  0x000000008000000an,
  0x000000008000808bn,
  0x800000000000008bn,
  0x8000000000008089n,
  0x8000000000008003n,
  0x8000000000008002n,
  0x8000000000000080n,
  0x000000000000800an,
  0x800000008000000an,
  0x8000000080008081n,
  0x8000000000008080n,
  0x0000000080000001n,
  0x8000000080008008n,
];

const KECCAK_ROTC: number[] = [
  1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];

const KECCAK_PILN: number[] = [
  10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

const MASK_64 = 0xffffffffffffffffn;

function rotl64(x: bigint, n: number): bigint {
  const shift = BigInt(n);
  return ((x << shift) | (x >> (64n - shift))) & MASK_64;
}

function keccakF1600(state: bigint[]): void {
  const bc: bigint[] = new Array(5).fill(0n);
  for (let round = 0; round < KECCAK_ROUNDS; round++) {
    // Theta
    for (let i = 0; i < 5; i++) {
      bc[i] = state[i] ^ state[i + 5] ^ state[i + 10] ^ state[i + 15] ^ state[i + 20];
    }
    for (let i = 0; i < 5; i++) {
      const t = bc[(i + 4) % 5] ^ rotl64(bc[(i + 1) % 5], 1);
      for (let j = 0; j < 25; j += 5) {
        state[j + i] = (state[j + i] ^ t) & MASK_64;
      }
    }
    // Rho & Pi
    let t = state[1];
    for (let i = 0; i < 24; i++) {
      const j = KECCAK_PILN[i];
      bc[0] = state[j];
      state[j] = rotl64(t, KECCAK_ROTC[i]);
      t = bc[0];
    }
    // Chi
    for (let j = 0; j < 25; j += 5) {
      for (let i = 0; i < 5; i++) {
        bc[i] = state[j + i];
      }
      for (let i = 0; i < 5; i++) {
        state[j + i] = (bc[i] ^ (~bc[(i + 1) % 5] & MASK_64 & bc[(i + 2) % 5])) & MASK_64;
      }
    }
    // Iota
    state[0] = (state[0] ^ KECCAK_RC[round]) & MASK_64;
  }
}

export function keccak256Bytes(input: Uint8Array): Uint8Array {
  const rate = 136; // 1088 bits
  const state: bigint[] = new Array(25).fill(0n);
  const paddedLen = Math.ceil((input.length + 1) / rate) * rate;
  const padded = new Uint8Array(paddedLen);
  padded.set(input);
  padded[input.length] = 0x01;
  padded[paddedLen - 1] |= 0x80;

  for (let offset = 0; offset < paddedLen; offset += rate) {
    for (let i = 0; i < rate / 8; i++) {
      let lane = 0n;
      for (let b = 0; b < 8; b++) {
        lane |= BigInt(padded[offset + i * 8 + b]) << BigInt(b * 8);
      }
      state[i] = (state[i] ^ lane) & MASK_64;
    }
    keccakF1600(state);
  }

  const out = new Uint8Array(32);
  for (let i = 0; i < 4; i++) {
    const lane = state[i];
    for (let b = 0; b < 8; b++) {
      out[i * 8 + b] = Number((lane >> BigInt(b * 8)) & 0xffn);
    }
  }
  return out;
}

export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
  const normalized = clean.length % 2 === 1 ? '0' + clean : clean;
  return Uint8Array.from(Buffer.from(normalized, 'hex'));
}

export function bytesToHex(bytes: Uint8Array): string {
  return '0x' + Buffer.from(bytes).toString('hex');
}

export function keccak256Hex(data: Uint8Array | string): string {
  const bytes = typeof data === 'string' ? hexToBytes(data) : data;
  return bytesToHex(keccak256Bytes(bytes));
}

export function keccak256Utf8(text: string): string {
  return bytesToHex(keccak256Bytes(Buffer.from(text, 'utf8')));
}

// ---------------------------------------------------------------------------
// secp256k1 Domain Parameters
// ---------------------------------------------------------------------------

/** Prime field modulus P = 2^256 - 2^32 - 977 */
export const SECP256K1_P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;

/** Subgroup order Q */
export const SECP256K1_Q = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

/** Generator point G */
export const SECP256K1_GX = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n;
export const SECP256K1_GY = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n;

export interface CurvePoint {
  x: bigint;
  y: bigint;
  infinity?: boolean;
}

export const POINT_AT_INFINITY: CurvePoint = { x: 0n, y: 0n, infinity: true };
export const GENERATOR_G: CurvePoint = { x: SECP256K1_GX, y: SECP256K1_GY };

// ---------------------------------------------------------------------------
// Modular & Elliptic Curve Arithmetic (Pure BigInt, zero external native deps)
// ---------------------------------------------------------------------------

export function modP(n: bigint): bigint {
  const r = n % SECP256K1_P;
  return r < 0n ? r + SECP256K1_P : r;
}

export function modQ(n: bigint): bigint {
  const r = n % SECP256K1_Q;
  return r < 0n ? r + SECP256K1_Q : r;
}

export function modPow(base: bigint, exp: bigint, m: bigint): bigint {
  let result = 1n;
  let b = ((base % m) + m) % m;
  let e = exp;
  while (e > 0n) {
    if ((e & 1n) === 1n) {
      result = (result * b) % m;
    }
    b = (b * b) % m;
    e >>= 1n;
  }
  return result;
}

export function modInv(a: bigint, m: bigint): bigint {
  let t = 0n;
  let newT = 1n;
  let r = m;
  let newR = ((a % m) + m) % m;

  while (newR !== 0n) {
    const quotient = r / newR;
    [t, newT] = [newT, t - quotient * newT];
    [r, newR] = [newR, r - quotient * newR];
  }
  if (r > 1n) {
    throw new Error('Value is not invertible');
  }
  return t < 0n ? t + m : t;
}

export function pointAdd(p1: CurvePoint, p2: CurvePoint): CurvePoint {
  if (p1.infinity) return p2;
  if (p2.infinity) return p1;

  if (p1.x === p2.x) {
    if (modP(p1.y + p2.y) === 0n) {
      return POINT_AT_INFINITY;
    }
    return pointDouble(p1);
  }

  const slope = modP((p2.y - p1.y) * modInv(p2.x - p1.x, SECP256K1_P));
  const x3 = modP(slope * slope - p1.x - p2.x);
  const y3 = modP(slope * (p1.x - x3) - p1.y);
  return { x: x3, y: y3 };
}

export function pointDouble(p: CurvePoint): CurvePoint {
  if (p.infinity || p.y === 0n) return POINT_AT_INFINITY;
  const slope = modP(3n * p.x * p.x * modInv(2n * p.y, SECP256K1_P));
  const x3 = modP(slope * slope - 2n * p.x);
  const y3 = modP(slope * (p.x - x3) - p.y);
  return { x: x3, y: y3 };
}

export function pointNeg(p: CurvePoint): CurvePoint {
  if (p.infinity) return POINT_AT_INFINITY;
  return { x: p.x, y: modP(-p.y) };
}

export function pointMul(p: CurvePoint, scalar: bigint): CurvePoint {
  let k = modQ(scalar);
  if (k === 0n || p.infinity) return POINT_AT_INFINITY;

  let result: CurvePoint = POINT_AT_INFINITY;
  let addend: CurvePoint = p;

  while (k > 0n) {
    if ((k & 1n) === 1n) {
      result = pointAdd(result, addend);
    }
    addend = pointDouble(addend);
    k >>= 1n;
  }
  return result;
}

export function pointsEqual(a: CurvePoint, b: CurvePoint): boolean {
  if (a.infinity && b.infinity) return true;
  if (a.infinity || b.infinity) return false;
  return a.x === b.x && a.y === b.y;
}

/** Reconstructs curve point (x, y) from x-coordinate and parity v in {27, 28} */
export function liftPointFromXAndParity(x: bigint, parity: 27 | 28): CurvePoint | null {
  if (x <= 0n || x >= SECP256K1_P) return null;
  const ySq = modP(modP(x * x) * x + 7n);
  // Since P % 4 == 3 on secp256k1, sqrt(ySq) = ySq^((P + 1) / 4) mod P
  const yCandidate = modPow(ySq, (SECP256K1_P + 1n) / 4n, SECP256K1_P);
  if (modP(yCandidate * yCandidate) !== ySq) {
    return null;
  }
  const wantOdd = parity === 28;
  const isOdd = (yCandidate & 1n) === 1n;
  const y = wantOdd === isOdd ? yCandidate : modP(-yCandidate);
  return { x, y };
}

/** Deterministic second generator H for Pedersen VSS commitments */
export const GENERATOR_H: CurvePoint = pointMul(
  GENERATOR_G,
  modQ(BigInt(keccak256Utf8('PACTUM_FROST_PEDERSEN_GENERATOR_H_V1'))),
);

export function randomScalar(): bigint {
  while (true) {
    const buf = randomBytes(32);
    const k = modQ(BigInt('0x' + buf.toString('hex')));
    if (k > 0n) return k;
  }
}

export function toBytes32Hex(value: bigint): string {
  return '0x' + modP(value).toString(16).padStart(64, '0');
}

export function scalarToBytes32Hex(value: bigint): string {
  return '0x' + modQ(value).toString(16).padStart(64, '0');
}

export function pointParity(p: CurvePoint): 27 | 28 {
  if (p.infinity) {
    throw new Error('Cannot compute parity for point at infinity');
  }
  return (p.y & 1n) === 0n ? 27 : 28;
}

export function pointToEthAddress(p: CurvePoint): string {
  if (p.infinity) {
    throw new Error('Cannot compute Ethereum address for point at infinity');
  }
  const uncompressedNoPrefix =
    p.x.toString(16).padStart(64, '0') + p.y.toString(16).padStart(64, '0');
  const digest = keccak256Hex('0x' + uncompressedNoPrefix);
  return '0x' + digest.slice(26).toLowerCase();
}

// ---------------------------------------------------------------------------
// Distributed Key Generation (Pedersen-VSS + Feldman-VSS)
// ---------------------------------------------------------------------------

export interface SchnorrPoK {
  commitment: CurvePoint;
  response: bigint;
}

export interface DkgBroadcastPackage {
  dealerId: number;
  /** Feldman commitments C_{i,k} = a_{i,k} * G */
  feldmanCommitments: CurvePoint[];
  /** Pedersen commitments P_{i,k} = a_{i,k} * G + b_{i,k} * H */
  pedersenCommitments: CurvePoint[];
  /** Proof of knowledge of secret constant term a_{i,0} */
  pok: SchnorrPoK;
}

export interface DkgSharePackage {
  fromDealerId: number;
  toNodeId: number;
  secretEval: bigint;
  blindingEval: bigint;
}

export interface AttestorKeyShare {
  nodeId: number;
  threshold: number;
  totalNodes: number;
  secretShare: bigint;
  blindingShare: bigint;
  publicVerificationShare: CurvePoint;
  groupPublicKey: CurvePoint;
  groupPubKeyX: string;
  groupPubKeyParity: 27 | 28;
  groupEthAddress: string;
  peerVerificationShares: Map<number, CurvePoint>;
}

export interface DkgExecutionResult {
  groupPublicKey: CurvePoint;
  groupPubKeyX: string;
  groupPubKeyParity: 27 | 28;
  groupEthAddress: string;
  nodeShares: Map<number, AttestorKeyShare>;
  faultyDealers: number[];
}

function evaluatePolynomial(coeffs: bigint[], x: bigint): bigint {
  let result = 0n;
  let power = 1n;
  for (const coeff of coeffs) {
    result = modQ(result + modQ(coeff * power));
    power = modQ(power * x);
  }
  return result;
}

function computePokChallenge(
  dealerId: number,
  pubKeyShare0: CurvePoint,
  nonceCommitment: CurvePoint,
): bigint {
  const packed =
    Buffer.from('PACTUM_DKG_POK_V1', 'utf8').toString('hex') +
    dealerId.toString(16).padStart(8, '0') +
    pubKeyShare0.x.toString(16).padStart(64, '0') +
    pubKeyShare0.y.toString(16).padStart(64, '0') +
    nonceCommitment.x.toString(16).padStart(64, '0') +
    nonceCommitment.y.toString(16).padStart(64, '0');
  return modQ(BigInt(keccak256Hex('0x' + packed)));
}

export class DealerlessDkgParticipant {
  public readonly nodeId: number;
  public readonly threshold: number;
  public readonly totalNodes: number;
  private readonly secretCoeffs: bigint[];
  private readonly blindingCoeffs: bigint[];

  constructor(nodeId: number, threshold: number, totalNodes: number) {
    if (threshold < 2 || threshold > totalNodes) {
      throw new Error(`Invalid threshold parameters: t=${threshold}, n=${totalNodes}`);
    }
    if (nodeId < 1 || nodeId > totalNodes) {
      throw new Error(`Invalid nodeId ${nodeId}; expected 1..${totalNodes}`);
    }
    this.nodeId = nodeId;
    this.threshold = threshold;
    this.totalNodes = totalNodes;
    this.secretCoeffs = Array.from({ length: threshold }, () => randomScalar());
    this.blindingCoeffs = Array.from({ length: threshold }, () => randomScalar());
  }

  public generateBroadcastAndShares(): {
    broadcast: DkgBroadcastPackage;
    shares: DkgSharePackage[];
  } {
    const feldmanCommitments = this.secretCoeffs.map((a) => pointMul(GENERATOR_G, a));
    const pedersenCommitments = this.secretCoeffs.map((a, idx) =>
      pointAdd(pointMul(GENERATOR_G, a), pointMul(GENERATOR_H, this.blindingCoeffs[idx])),
    );

    const kNonce = randomScalar();
    const nonceCommitment = pointMul(GENERATOR_G, kNonce);
    const challenge = computePokChallenge(this.nodeId, feldmanCommitments[0], nonceCommitment);
    const response = modQ(kNonce + modQ(challenge * this.secretCoeffs[0]));

    const shares: DkgSharePackage[] = [];
    for (let targetId = 1; targetId <= this.totalNodes; targetId++) {
      const x = BigInt(targetId);
      shares.push({
        fromDealerId: this.nodeId,
        toNodeId: targetId,
        secretEval: evaluatePolynomial(this.secretCoeffs, x),
        blindingEval: evaluatePolynomial(this.blindingCoeffs, x),
      });
    }

    return {
      broadcast: {
        dealerId: this.nodeId,
        feldmanCommitments,
        pedersenCommitments,
        pok: { commitment: nonceCommitment, response },
      },
      shares,
    };
  }
}

export function verifyDkgBroadcastPok(pkg: DkgBroadcastPackage): boolean {
  if (
    pkg.feldmanCommitments.length === 0 ||
    pkg.feldmanCommitments.length !== pkg.pedersenCommitments.length
  ) {
    return false;
  }
  const c0 = pkg.feldmanCommitments[0];
  const challenge = computePokChallenge(pkg.dealerId, c0, pkg.pok.commitment);
  const lhs = pointMul(GENERATOR_G, pkg.pok.response);
  const rhs = pointAdd(pkg.pok.commitment, pointMul(c0, challenge));
  return pointsEqual(lhs, rhs);
}

export function verifyDkgShare(share: DkgSharePackage, broadcast: DkgBroadcastPackage): boolean {
  if (share.fromDealerId !== broadcast.dealerId) return false;
  const x = BigInt(share.toNodeId);

  // 1. Feldman VSS verification: s_{i->j} * G == sum_{k=0}^{t-1} (j^k * C_{i,k})
  let expectedFeldman = POINT_AT_INFINITY;
  let expectedPedersen = POINT_AT_INFINITY;
  let xPow = 1n;

  for (let k = 0; k < broadcast.feldmanCommitments.length; k++) {
    expectedFeldman = pointAdd(expectedFeldman, pointMul(broadcast.feldmanCommitments[k], xPow));
    expectedPedersen = pointAdd(expectedPedersen, pointMul(broadcast.pedersenCommitments[k], xPow));
    xPow = modQ(xPow * x);
  }

  const actualFeldman = pointMul(GENERATOR_G, share.secretEval);
  if (!pointsEqual(actualFeldman, expectedFeldman)) {
    return false;
  }

  // 2. Pedersen VSS verification: s_{i->j} * G + r_{i->j} * H == sum_{k=0}^{t-1} (j^k * P_{i,k})
  const actualPedersen = pointAdd(actualFeldman, pointMul(GENERATOR_H, share.blindingEval));
  return pointsEqual(actualPedersen, expectedPedersen);
}

/**
 * Executes an asynchronous dealerless DKG session across `totalNodes` attestor nodes.
 * Supports optional share tampering hooks for testing Byzantine dealer detection.
 */
export async function runAsynchronousDkg(
  threshold: number,
  totalNodes: number,
  corruptDealerHook?: (share: DkgSharePackage) => DkgSharePackage,
): Promise<DkgExecutionResult> {
  const participants = Array.from(
    { length: totalNodes },
    (_, i) => new DealerlessDkgParticipant(i + 1, threshold, totalNodes),
  );

  // Round 1 & 2 generated concurrently across all nodes
  const roundOutputs = await Promise.all(
    participants.map(async (p) => p.generateBroadcastAndShares()),
  );

  const broadcasts = new Map<number, DkgBroadcastPackage>();
  const allShares: DkgSharePackage[] = [];
  const faultyDealersSet = new Set<number>();

  for (const out of roundOutputs) {
    if (!verifyDkgBroadcastPok(out.broadcast)) {
      faultyDealersSet.add(out.broadcast.dealerId);
      continue;
    }
    broadcasts.set(out.broadcast.dealerId, out.broadcast);
    for (const s of out.shares) {
      allShares.push(corruptDealerHook ? corruptDealerHook({ ...s }) : s);
    }
  }

  // Validate every directed share against dealer's Feldman & Pedersen commitments
  for (const share of allShares) {
    const broadcast = broadcasts.get(share.fromDealerId);
    if (!broadcast || !verifyDkgShare(share, broadcast)) {
      faultyDealersSet.add(share.fromDealerId);
    }
  }

  const qualifiedDealerIds = Array.from(broadcasts.keys()).filter(
    (id) => !faultyDealersSet.has(id),
  );

  if (qualifiedDealerIds.length < threshold) {
    throw new Error(
      `Insufficient honest dealers during DKG: ${qualifiedDealerIds.length} < ${threshold}`,
    );
  }

  // Compute shared group public key Y = sum_{i in Qualified} C_{i,0}
  let groupPublicKey = POINT_AT_INFINITY;
  for (const dealerId of qualifiedDealerIds) {
    const b = broadcasts.get(dealerId)!;
    groupPublicKey = pointAdd(groupPublicKey, b.feldmanCommitments[0]);
  }

  // Compute public verification shares Y_j for every participant j = 1..totalNodes
  const peerVerificationShares = new Map<number, CurvePoint>();
  for (let nodeId = 1; nodeId <= totalNodes; nodeId++) {
    const x = BigInt(nodeId);
    let yJ = POINT_AT_INFINITY;
    for (const dealerId of qualifiedDealerIds) {
      const b = broadcasts.get(dealerId)!;
      let xPow = 1n;
      for (let k = 0; k < b.feldmanCommitments.length; k++) {
        yJ = pointAdd(yJ, pointMul(broadcasts.get(dealerId)!.feldmanCommitments[k], xPow));
        xPow = modQ(xPow * x);
      }
    }
    peerVerificationShares.set(nodeId, yJ);
  }

  const groupPubKeyX = toBytes32Hex(groupPublicKey.x);
  const groupPubKeyParity = pointParity(groupPublicKey);
  const groupEthAddress = pointToEthAddress(groupPublicKey);

  const nodeShares = new Map<number, AttestorKeyShare>();
  for (let nodeId = 1; nodeId <= totalNodes; nodeId++) {
    let secretShare = 0n;
    let blindingShare = 0n;

    for (const share of allShares) {
      if (share.toNodeId === nodeId && qualifiedDealerIds.includes(share.fromDealerId)) {
        secretShare = modQ(secretShare + share.secretEval);
        blindingShare = modQ(blindingShare + share.blindingEval);
      }
    }

    const publicVerificationShare = peerVerificationShares.get(nodeId)!;
    nodeShares.set(nodeId, {
      nodeId,
      threshold,
      totalNodes,
      secretShare,
      blindingShare,
      publicVerificationShare,
      groupPublicKey,
      groupPubKeyX,
      groupPubKeyParity,
      groupEthAddress,
      peerVerificationShares,
    });
  }

  return {
    groupPublicKey,
    groupPubKeyX,
    groupPubKeyParity,
    groupEthAddress,
    nodeShares,
    faultyDealers: Array.from(faultyDealersSet).sort((a, b) => a - b),
  };
}

// ---------------------------------------------------------------------------
// Two-Round FROST Threshold Signing & Culprit Detection
// ---------------------------------------------------------------------------

export interface FrostNonceCommitment {
  nodeId: number;
  hidingCommitment: CurvePoint; // D_i = d_i * G
  bindingCommitment: CurvePoint; // E_i = e_i * G
}

interface SecretNoncePair {
  hidingNonce: bigint;
  bindingNonce: bigint;
}

export interface FrostSignatureShare {
  nodeId: number;
  zShare: bigint;
}

export interface SlashingEvidence {
  culpritNodeId: number;
  messageHash: string;
  invalidZShare: string;
  expectedPoint: CurvePoint;
  actualPoint: CurvePoint;
  reason: string;
}

export interface ThresholdSignature {
  /** 20-byte Ethereum address of group nonce commitment point R */
  commitmentAddress: string;
  /** Aggregated Schnorr scalar z (bytes32 hex) */
  z: string;
  /** Shared public key x-coordinate (bytes32 hex) */
  groupPubKeyX: string;
  /** Shared public key parity (27 or 28) */
  groupPubKeyParity: 27 | 28;
  /** Participating signer node IDs */
  signers: number[];
  /** Slashing evidence for any detected malicious nodes during signing */
  slashedCulprits: SlashingEvidence[];
}

export class TssSlashingError extends Error {
  public readonly culprits: SlashingEvidence[];

  constructor(message: string, culprits: SlashingEvidence[]) {
    super(message);
    this.name = 'TssSlashingError';
    this.culprits = culprits;
  }
}

export function computeLagrangeCoefficient(nodeId: number, participantIds: number[]): bigint {
  const i = BigInt(nodeId);
  let num = 1n;
  let den = 1n;
  for (const peerId of participantIds) {
    if (peerId === nodeId) continue;
    const j = BigInt(peerId);
    num = modQ(num * j);
    den = modQ(den * modQ(j - i));
  }
  return modQ(num * modInv(den, SECP256K1_Q));
}

export function computeFrostBindingFactor(
  nodeId: number,
  messageHash: string,
  commitments: FrostNonceCommitment[],
): bigint {
  const sorted = [...commitments].sort((a, b) => a.nodeId - b.nodeId);
  const commitmentTranscript = sorted
    .map(
      (c) =>
        `${c.nodeId}:${c.hidingCommitment.x.toString(16)}:${c.hidingCommitment.y.toString(16)}:${c.bindingCommitment.x.toString(16)}:${c.bindingCommitment.y.toString(16)}`,
    )
    .join('|');

  const packed =
    Buffer.from('PACTUM_FROST_BIND_V1', 'utf8').toString('hex') +
    nodeId.toString(16).padStart(8, '0') +
    messageHash.replace(/^0x/, '').padStart(64, '0') +
    Buffer.from(commitmentTranscript, 'utf8').toString('hex');

  const rho = modQ(BigInt(keccak256Hex('0x' + packed)));
  return rho === 0n ? 1n : rho;
}

/**
 * Computes the Fiat-Shamir Schnorr challenge matching `PactumTrustOracle.sol`:
 *   c = uint256(keccak256(abi.encodePacked(commitmentAddress, groupPubKeyParity, groupPubKeyX, messageHash))) % SECP256K1_Q
 */
export function computeEvmSchnorrChallenge(
  commitmentAddress: string,
  groupPubKeyParity: 27 | 28,
  groupPubKeyX: string,
  messageHash: string,
): bigint {
  const packed =
    commitmentAddress.replace(/^0x/, '').toLowerCase().padStart(40, '0') +
    groupPubKeyParity.toString(16).padStart(2, '0') +
    groupPubKeyX.replace(/^0x/, '').padStart(64, '0') +
    messageHash.replace(/^0x/, '').padStart(64, '0');
  return modQ(BigInt(keccak256Hex('0x' + packed)));
}

/**
 * Verifies a combined FROST threshold signature using the exact EVM `ecrecover`
 * precompile equation executed by `PactumTrustOracle.sol`:
 *   Q_rec = r^{-1} * (ecS * Y - ecMsgHash * G) = z * G - c * Y == R
 */
export function verifyThresholdSignature(
  messageHash: string,
  signature: ThresholdSignature,
): boolean {
  const z = BigInt(signature.z);
  const pubKeyX = BigInt(signature.groupPubKeyX);
  if (z <= 0n || z >= SECP256K1_Q || pubKeyX <= 0n || pubKeyX >= SECP256K1_P) {
    return false;
  }

  const c = computeEvmSchnorrChallenge(
    signature.commitmentAddress,
    signature.groupPubKeyParity,
    signature.groupPubKeyX,
    messageHash,
  );
  if (c === 0n) return false;

  const yPoint = liftPointFromXAndParity(pubKeyX, signature.groupPubKeyParity);
  if (!yPoint) return false;

  // EVM ecrecover verification equation:
  // ecMsgHash = Q - mulmod(z, pubKeyX, Q)
  // ecS       = Q - mulmod(c, pubKeyX, Q)
  // Q_rec     = r^{-1} * (ecS * Y - ecMsgHash * G)
  const rModQ = modQ(pubKeyX);
  const zMulX = modQ(z * rModQ);
  const cMulX = modQ(c * rModQ);
  if (zMulX === 0n || cMulX === 0n) return false;

  const ecMsgHash = SECP256K1_Q - zMulX;
  const ecS = SECP256K1_Q - cMulX;
  const rInv = modInv(rModQ, SECP256K1_Q);

  const u1 = modQ(modQ(-ecMsgHash) * rInv);
  const u2 = modQ(ecS * rInv);
  const recoveredR = pointAdd(pointMul(GENERATOR_G, u1), pointMul(yPoint, u2));
  if (recoveredR.infinity) return false;

  const recoveredAddr = pointToEthAddress(recoveredR);
  return recoveredAddr.toLowerCase() === signature.commitmentAddress.toLowerCase();
}

/**
 * Coordinates 2-round FROST threshold signing across `n` attestor nodes,
 * tolerating up to `n - t` offline nodes and detecting/slashing malicious share signers.
 */
export class FrostTssCoordinator {
  public readonly threshold: number;
  public readonly totalNodes: number;
  private readonly nodeShares: Map<number, AttestorKeyShare>;
  public readonly groupPublicKey: CurvePoint;
  public readonly groupPubKeyX: string;
  public readonly groupPubKeyParity: 27 | 28;
  public readonly groupEthAddress: string;
  private readonly slashedNodeIds: Set<number> = new Set();

  constructor(dkgResult: DkgExecutionResult) {
    const firstShare = dkgResult.nodeShares.values().next().value as AttestorKeyShare | undefined;
    if (!firstShare) {
      throw new Error('DKG result contains no node shares');
    }
    this.threshold = firstShare.threshold;
    this.totalNodes = firstShare.totalNodes;
    this.nodeShares = dkgResult.nodeShares;
    this.groupPublicKey = dkgResult.groupPublicKey;
    this.groupPubKeyX = dkgResult.groupPubKeyX;
    this.groupPubKeyParity = dkgResult.groupPubKeyParity;
    this.groupEthAddress = dkgResult.groupEthAddress;
  }

  public getSlashedNodes(): number[] {
    return Array.from(this.slashedNodeIds).sort((a, b) => a - b);
  }

  /**
   * Executes the 2-round FROST signing protocol over `messageHash`.
   *
   * @param messageHash 32-byte hex digest (`0x...`)
   * @param options Optional simulation controls for offline nodes or malicious share injection
   */
  public async sign(
    messageHash: string,
    options?: {
      offlineNodeIds?: number[];
      corruptShareHooks?: Record<number, (share: bigint) => bigint>;
    },
  ): Promise<ThresholdSignature> {
    const offlineSet = new Set(options?.offlineNodeIds ?? []);
    const corruptHooks = options?.corruptShareHooks ?? {};

    // Filter online, unslashed attestor nodes
    let candidateNodeIds = Array.from(this.nodeShares.keys()).filter(
      (id) => !offlineSet.has(id) && !this.slashedNodeIds.has(id),
    );

    if (candidateNodeIds.length < this.threshold) {
      throw new Error(
        `Insufficient online attestor nodes for FROST signing: ${candidateNodeIds.length} < ${this.threshold}`,
      );
    }

    const accumulatedCulprits: SlashingEvidence[] = [];

    while (candidateNodeIds.length >= this.threshold) {
      const activeSubset = candidateNodeIds.slice(0, this.threshold);

      // Round 1: Each active node generates hiding & binding nonces and broadcasts commitments
      const secretNonces = new Map<number, SecretNoncePair>();
      const commitments: FrostNonceCommitment[] = [];

      for (const nodeId of activeSubset) {
        const hidingNonce = randomScalar();
        const bindingNonce = randomScalar();
        secretNonces.set(nodeId, { hidingNonce, bindingNonce });
        commitments.push({
          nodeId,
          hidingCommitment: pointMul(GENERATOR_G, hidingNonce),
          bindingCommitment: pointMul(GENERATOR_G, bindingNonce),
        });
      }

      // Compute binding factors and group nonce commitment point R = sum_{i in S} (D_i + rho_i * E_i)
      const bindingFactors = new Map<number, bigint>();
      const signerNoncePoints = new Map<number, CurvePoint>();
      let groupNoncePoint = POINT_AT_INFINITY;

      for (const c of commitments) {
        const rho = computeFrostBindingFactor(c.nodeId, messageHash, commitments);
        bindingFactors.set(c.nodeId, rho);
        const rI = pointAdd(c.hidingCommitment, pointMul(c.bindingCommitment, rho));
        signerNoncePoints.set(c.nodeId, rI);
        groupNoncePoint = pointAdd(groupNoncePoint, rI);
      }

      const commitmentAddress = pointToEthAddress(groupNoncePoint);
      const challenge = computeEvmSchnorrChallenge(
        commitmentAddress,
        this.groupPubKeyParity,
        this.groupPubKeyX,
        messageHash,
      );

      // Round 2: Each active node computes its signature share z_i
      const shares: FrostSignatureShare[] = [];
      for (const nodeId of activeSubset) {
        const keyShare = this.nodeShares.get(nodeId)!;
        const nonces = secretNonces.get(nodeId)!;
        const rho = bindingFactors.get(nodeId)!;
        const lambda = computeLagrangeCoefficient(nodeId, activeSubset);

        let zShare = modQ(
          nonces.hidingNonce +
            modQ(nonces.bindingNonce * rho) +
            modQ(modQ(lambda * keyShare.secretShare) * challenge),
        );

        if (corruptHooks[nodeId]) {
          zShare = modQ(corruptHooks[nodeId](zShare));
        }
        shares.push({ nodeId, zShare });
      }

      // Verifiable Share Check: z_i * G == R_i + (lambda_i * c) * Y_i
      const roundCulprits: SlashingEvidence[] = [];
      for (const share of shares) {
        const keyShare = this.nodeShares.get(share.nodeId)!;
        const rI = signerNoncePoints.get(share.nodeId)!;
        const lambda = computeLagrangeCoefficient(share.nodeId, activeSubset);
        const expectedPoint = pointAdd(
          rI,
          pointMul(keyShare.publicVerificationShare, modQ(lambda * challenge)),
        );
        const actualPoint = pointMul(GENERATOR_G, share.zShare);

        if (!pointsEqual(actualPoint, expectedPoint)) {
          const evidence: SlashingEvidence = {
            culpritNodeId: share.nodeId,
            messageHash,
            invalidZShare: scalarToBytes32Hex(share.zShare),
            expectedPoint,
            actualPoint,
            reason: `Invalid FROST signature share from attestor node ${share.nodeId}`,
          };
          roundCulprits.push(evidence);
          accumulatedCulprits.push(evidence);
          this.slashedNodeIds.add(share.nodeId);
        }
      }

      if (roundCulprits.length > 0) {
        // Evict slashed culprits and retry with remaining honest nodes if >= threshold remain
        candidateNodeIds = candidateNodeIds.filter((id) => !this.slashedNodeIds.has(id));
        if (candidateNodeIds.length < this.threshold) {
          throw new TssSlashingError(
            `FROST signing aborted: malicious share(s) detected from node(s) [${roundCulprits
              .map((c) => c.culpritNodeId)
              .join(', ')}] and insufficient honest nodes remain`,
            accumulatedCulprits,
          );
        }
        continue;
      }

      // Aggregate verified shares: z = sum_{i in S} z_i mod Q
      let zAgg = 0n;
      for (const share of shares) {
        zAgg = modQ(zAgg + share.zShare);
      }

      const signature: ThresholdSignature = {
        commitmentAddress,
        z: scalarToBytes32Hex(zAgg),
        groupPubKeyX: this.groupPubKeyX,
        groupPubKeyParity: this.groupPubKeyParity,
        signers: activeSubset,
        slashedCulprits: accumulatedCulprits,
      };

      if (!verifyThresholdSignature(messageHash, signature)) {
        throw new Error('Aggregated FROST signature failed internal verification');
      }

      return signature;
    }

    throw new TssSlashingError(
      'Unable to complete FROST signing due to malicious shares',
      accumulatedCulprits,
    );
  }
}
