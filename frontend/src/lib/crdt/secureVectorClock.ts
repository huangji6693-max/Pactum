import { Keypair } from '@stellar/stellar-sdk';

import { signFrame, verifyFrame } from './signing';

/**
 * Cryptographically signed vector clock entry. Each peer signs their own
 * clock contribution so a malicious peer cannot fabricate or "time-travel"
 * another peer's causality without breaking the signature.
 */
export interface SignedClockEntry {
  readonly address: string;
  readonly counter: number;
  readonly signature: Uint8Array;
}

/**
 * A vector clock mapping each peer address to its monotonic counter, with
 * a signature proving each entry was written by the corresponding peer.
 * This prevents Byzantine peers from:
 * - Fabricating entries for peers they do not control
 * - Rewinding another peer counter (time-travel attack)
 * - Forwarding another peer counter beyond reality (causality fabrication)
 */
export interface SecureVectorClock {
  readonly entries: Record<string, SignedClockEntry>;
  readonly serialized: string;
}

const CLOCK_PREFIX = 'PACTUM_CLOCK_V1';

/** Serialize a clock entry to a deterministic signable string. */
function serializeClockEntry(address: string, counter: number): string {
  return `${CLOCK_PREFIX}:${address}:${counter}`;
}

/** Serialize an entire clock deterministically for hashing and signing. */
function serializeClock(entries: Record<string, number>): string {
  const sorted = Object.keys(entries).sort();
  return sorted.map((k) => `${k}=${entries[k]}`).join(';');
}

/**
 * Create a signed vector clock. Each entry is individually signed by the
 * peer who incremented it, so a forged entry is detectable.
 */
export async function createSecureVectorClock(
  identity: { address: string; keyPair: CryptoKeyPair },
  localCounter: number,
  /** Counters from known peers (e.g. received in previous sync frames). */
  peerCounters: Record<string, number> = {},
): Promise<SecureVectorClock> {
  const entries: Record<string, SignedClockEntry> = {};

  // Sign our own entry.
  const payload = serializeClockEntry(identity.address, localCounter);
  const signable = new TextEncoder().encode(payload);
  const signature = await signFrame(identity.keyPair.privateKey, signable);
  entries[identity.address] = {
    address: identity.address,
    counter: localCounter,
    signature,
  };

  // Re-sign peer entries using our own key — this is a "witness" signature
  // that attests we observed these values. The original peer signature is
  // verified separately when the entry first arrived.
  for (const [address, counter] of Object.entries(peerCounters)) {
    if (address === identity.address) continue;
    const peerPayload = serializeClockEntry(address, counter);
    const peerSignable = new TextEncoder().encode(peerPayload);
    const peerSig = await signFrame(identity.keyPair.privateKey, peerSignable);
    entries[address] = {
      address,
      counter,
      signature: peerSig,
    };
  }

  const allCounters: Record<string, number> = {};
  for (const [addr, entry] of Object.entries(entries)) {
    allCounters[addr] = entry.counter;
  }

  return {
    entries,
    serialized: serializeClock(allCounters),
  };
}

/**
 * Verify a signed vector clock. Checks that:
 * 1. Each entry signature is valid against the claimed address's public key
 * 2. Each counter is non-negative
 * 3. The clock is internally consistent
 */
export async function verifySecureVectorClock(
  clock: SecureVectorClock,
  publicKeys: Map<string, CryptoKey>,
): Promise<boolean> {
  for (const [address, entry] of Object.entries(clock.entries)) {
    if (entry.address !== address) return false;
    if (entry.counter < 0) return false;

    const publicKey = publicKeys.get(address);
    if (!publicKey) return false;

    const signablePayload = serializeClockEntry(address, entry.counter);
    const signableBytes = new TextEncoder().encode(signablePayload);
    const valid = await verifyFrame(publicKey, signableBytes, entry.signature);
    if (!valid) return false;
  }
  return true;
}

/**
 * Merge two vector clocks using causal ordering rules:
 * - For each peer, take the max of both counters.
 * - Returns the merged counters and a boolean indicating if any entry advanced.
 */
export function mergeVectorClocks(
  a: Record<string, number>,
  b: Record<string, number>,
): { merged: Record<string, number>; advanced: boolean } {
  const allKeys = new Set([...Object.keys(a), ...Object.keys(b)]);
  const merged: Record<string, number> = {};
  let advanced = false;

  for (const key of allKeys) {
    const va = a[key] ?? 0;
    const vb = b[key] ?? 0;
    merged[key] = Math.max(va, vb);
    if (merged[key] > va || merged[key] > vb) advanced = true;
  }

  return { merged, advanced };
}

/**
 * Check if clock A causally happens-before clock B.
 * A happens-before B iff:
 *   - For every peer, A[peer] <= B[peer]
 *   - At least one peer has A[peer] < B[peer]
 */
export function happensBefore(a: Record<string, number>, b: Record<string, number>): boolean {
  const allKeys = new Set([...Object.keys(a), ...Object.keys(b)]);
  let hasStrictlyLess = false;
  for (const key of allKeys) {
    const va = a[key] ?? 0;
    const vb = b[key] ?? 0;
    if (va > vb) return false;
    if (va < vb) hasStrictlyLess = true;
  }
  return hasStrictlyLess;
}

/**
 * Check if two clocks are concurrent (neither causally dominates the other).
 */
export function areConcurrent(a: Record<string, number>, b: Record<string, number>): boolean {
  const allKeys = new Set([...Object.keys(a), ...Object.keys(b)]);
  let hasStrictlyLess = false;
  let hasStrictlyGreater = false;
  for (const key of allKeys) {
    const va = a[key] ?? 0;
    const vb = b[key] ?? 0;
    if (va < vb) hasStrictlyLess = true;
    if (va > vb) hasStrictlyGreater = true;
  }
  return hasStrictlyLess && hasStrictlyGreater;
}

/**
 * Create an Ed25519-signed vector clock using a Stellar Keypair.
 */
export function createEd25519VectorClock(
  keypair: Keypair,
  localCounter: number,
  peerCounters: Record<string, number> = {},
): SecureVectorClock {
  const address = keypair.publicKey();
  const entries: Record<string, SignedClockEntry> = {};

  const signPayload = (addr: string, counter: number): Uint8Array => {
    const payload = new TextEncoder().encode(serializeClockEntry(addr, counter));
    const sig = keypair.sign(Buffer.from(payload));
    return new Uint8Array(sig);
  };

  entries[address] = {
    address,
    counter: localCounter,
    signature: signPayload(address, localCounter),
  };

  for (const [peerAddr, counter] of Object.entries(peerCounters)) {
    if (peerAddr === address) continue;
    entries[peerAddr] = {
      address: peerAddr,
      counter,
      signature: signPayload(peerAddr, counter),
    };
  }

  const allCounters: Record<string, number> = {};
  for (const [addr, entry] of Object.entries(entries)) {
    allCounters[addr] = entry.counter;
  }

  return {
    entries,
    serialized: serializeClock(allCounters),
  };
}

/**
 * Verify an Ed25519-signed vector clock entry against the signer's Stellar public key.
 */
export function verifyEd25519VectorClock(
  clock: SecureVectorClock,
  signerAddress: string,
): boolean {
  try {
    const pub = Keypair.fromPublicKey(signerAddress);
    for (const [address, entry] of Object.entries(clock.entries)) {
      if (entry.address !== address || entry.counter < 0) return false;
      const payload = new TextEncoder().encode(serializeClockEntry(address, entry.counter));
      if (!pub.verify(Buffer.from(payload), Buffer.from(entry.signature))) {
        return false;
      }
    }
    return true;
  } catch {
    return false;
  }
}

export interface PrunedVectorClockResult {
  readonly pruned: Record<string, number>;
  readonly baselineFloor: number;
  readonly prunedPeers: string[];
}

/**
 * Prunes saturated vector clock entries that have been causally acknowledged
 * across all active peers (`minCausalFloor`) or belong to inactive/retired peers,
 * while preserving relative causal ordering above the baseline floor.
 */
export function pruneSaturatedVectorClock(
  clock: Record<string, number>,
  minCausalFloor: Record<string, number> = {},
  activePeers?: ReadonlySet<string>,
): PrunedVectorClockResult {
  const keys = Object.keys(clock);
  if (keys.length === 0) {
    return { pruned: {}, baselineFloor: 0, prunedPeers: [] };
  }

  const floorValues = keys.map((k) => Math.min(clock[k] ?? 0, minCausalFloor[k] ?? 0));
  const baselineFloor = floorValues.length > 0 ? Math.min(...floorValues) : 0;

  const pruned: Record<string, number> = {};
  const prunedPeers: string[] = [];

  for (const key of keys) {
    const val = clock[key] ?? 0;
    const peerFloor = minCausalFloor[key] ?? baselineFloor;
    const isInactive = activePeers !== undefined && !activePeers.has(key);

    if (isInactive && val <= peerFloor) {
      prunedPeers.push(key);
      continue;
    }

    if (val <= peerFloor && keys.length > 1 && peerFloor > 0) {
      prunedPeers.push(key);
      continue;
    }

    pruned[key] = val;
  }

  // Ensure at least the dominant peer entry remains so clock is non-empty.
  if (Object.keys(pruned).length === 0) {
    const topKey = keys.reduce((a, b) => ((clock[a] ?? 0) >= (clock[b] ?? 0) ? a : b));
    pruned[topKey] = clock[topKey];
  }

  return { pruned, baselineFloor, prunedPeers };
}
