import { Keypair } from '@stellar/stellar-sdk';

import { sha256 } from '@/lib/sha256';
import { mergeVectorClocks, pruneSaturatedVectorClock } from './secureVectorClock';

export type MilestoneStatus = 'pending' | 'fulfilled' | 'late' | 'breached' | 'tombstone';

export interface MilestoneOperation {
  readonly milestoneId: string;
  readonly status: MilestoneStatus;
  readonly updatedAt: number;
  readonly value?: string;
}

/**
 * A single node in the Merkle DAG. Each CRDT delta is wrapped in a DAG node
 * whose hash is derived from its content AND the hashes of every causal
 * dependency (its parents). This makes the history tamper-evident: modifying
 * any ancestor changes its hash, which invalidates every descendant.
 */
export interface DAGNode {
  readonly hash: string;
  readonly author: string;
  readonly seq: number;
  readonly timestamp: number;
  readonly payload: Uint8Array;
  readonly parents: readonly string[];
  readonly clockHash: string;
  readonly vectorClock: Record<string, number>;
  readonly signature?: Uint8Array;
  readonly signerPublicKey?: string;
  readonly isTombstone?: boolean;
}

function uint32BE(value: number): Uint8Array {
  const buf = new Uint8Array(4);
  new DataView(buf.buffer).setUint32(0, value, false);
  return buf;
}

function uint64BE(value: bigint): Uint8Array {
  const buf = new Uint8Array(8);
  new DataView(buf.buffer).setBigUint64(0, value, false);
  return buf;
}

function bytesToHex(bytes: Uint8Array): string {
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, '0');
  }
  return hex;
}

/** Deterministic bytes that get hashed to produce a node content hash. */
function nodeContentBytes(
  author: string,
  seq: number,
  timestamp: number,
  payload: Uint8Array,
  parents: readonly string[],
  clockHash: string,
): Uint8Array {
  const encoder = new TextEncoder();
  const parts: Uint8Array[] = [
    encoder.encode(author),
    uint64BE(BigInt(seq)),
    uint64BE(BigInt(timestamp)),
    uint32BE(payload.length),
    payload,
    uint32BE(parents.length),
    ...parents.map((p) => encoder.encode(p)),
    encoder.encode(clockHash),
  ];
  let totalLen = 0;
  for (const p of parts) totalLen += p.length;
  const combined = new Uint8Array(totalLen);
  let offset = 0;
  for (const p of parts) {
    combined.set(p, offset);
    offset += p.length;
  }
  return combined;
}

/** Hash vector clock deterministically for inclusion in node hash. */
export function hashVectorClock(clock: Record<string, number>): string {
  const sorted = Object.keys(clock).sort();
  const encoder = new TextEncoder();
  const parts: Uint8Array[] = [];
  for (const key of sorted) {
    parts.push(encoder.encode(key));
    parts.push(uint64BE(BigInt(clock[key])));
  }
  let totalLen = 0;
  for (const p of parts) totalLen += p.length;
  const combined = new Uint8Array(totalLen);
  let offset = 0;
  for (const p of parts) {
    combined.set(p, offset);
    offset += p.length;
  }
  return bytesToHex(sha256(combined));
}

/** Compute the SHA-256 content hash of a DAG node from its fields. */
export function computeNodeHash(
  author: string,
  seq: number,
  timestamp: number,
  payload: Uint8Array,
  parents: readonly string[],
  clockHash: string,
): string {
  return bytesToHex(sha256(nodeContentBytes(author, seq, timestamp, payload, parents, clockHash)));
}

/** Create a new DAG node. */
export function createDAGNode(
  author: string,
  seq: number,
  timestamp: number,
  payload: Uint8Array,
  parents: readonly string[],
  vectorClock: Record<string, number>,
): DAGNode {
  const clockHash = hashVectorClock(vectorClock);
  const hash = computeNodeHash(author, seq, timestamp, payload, parents, clockHash);
  return { hash, author, seq, timestamp, payload, parents, clockHash, vectorClock };
}

/** Verify a node content hash matches its declared fields. */
export function verifyNodeHash(node: DAGNode): boolean {
  const expected = computeNodeHash(
    node.author,
    node.seq,
    node.timestamp,
    node.payload,
    node.parents,
    node.clockHash,
  );
  return expected === node.hash;
}

const NODE_SIG_DOMAIN = 'PACTUM_DAG_NODE_ED25519_V1';

function nodeSignableBytes(node: DAGNode): Uint8Array {
  return new TextEncoder().encode(
    `${NODE_SIG_DOMAIN}:${node.hash}:${node.author}:${node.seq}:${node.timestamp}:${node.clockHash}`,
  );
}

/**
 * Signs an existing DAG node with the author's Stellar Ed25519 keypair.
 */
export function signDAGNode(node: DAGNode, keypair: Keypair): DAGNode {
  const sig = keypair.sign(Buffer.from(nodeSignableBytes(node)));
  return {
    ...node,
    signature: new Uint8Array(sig),
    signerPublicKey: keypair.publicKey(),
  };
}

/**
 * Creates and Ed25519-signs a DAG node with the participant's Stellar keypair.
 */
export function createSignedDAGNode(
  keypair: Keypair,
  seq: number,
  timestamp: number,
  payload: Uint8Array,
  parents: readonly string[],
  vectorClock: Record<string, number>,
  options: { isTombstone?: boolean } = {},
): DAGNode {
  const author = keypair.publicKey();
  const baseNode = createDAGNode(author, seq, timestamp, payload, parents, vectorClock);
  const withMeta: DAGNode = options.isTombstone
    ? { ...baseNode, isTombstone: true }
    : baseNode;
  return signDAGNode(withMeta, keypair);
}

/**
 * Verifies both the SHA-256 content hash and the Ed25519 cryptographic signature
 * of a signed DAG node. Rejects nodes with missing, invalid, or mismatched signatures.
 */
export function verifyNodeSignature(node: DAGNode): boolean {
  if (!verifyNodeHash(node)) return false;
  if (hashVectorClock(node.vectorClock) !== node.clockHash) return false;
  if (!node.signature || node.signature.length !== 64) return false;
  const expectedPub = node.signerPublicKey ?? node.author;
  if (expectedPub !== node.author) return false;
  try {
    const pub = Keypair.fromPublicKey(expectedPub);
    return pub.verify(Buffer.from(nodeSignableBytes(node)), Buffer.from(node.signature));
  } catch {
    return false;
  }
}

/** Encodes a structured milestone operation into a DAGNode payload. */
export function encodeMilestonePayload(op: MilestoneOperation): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(op));
}

/** Decodes a structured milestone operation from a DAGNode payload, if valid. */
export function decodeMilestonePayload(payload: Uint8Array): MilestoneOperation | null {
  try {
    const parsed = JSON.parse(new TextDecoder().decode(payload)) as Partial<MilestoneOperation>;
    if (
      typeof parsed?.milestoneId === 'string' &&
      typeof parsed?.status === 'string' &&
      typeof parsed?.updatedAt === 'number'
    ) {
      return parsed as MilestoneOperation;
    }
    return null;
  } catch {
    return null;
  }
}

const STATUS_PRIORITY: Record<MilestoneStatus, number> = {
  fulfilled: 5,
  breached: 4,
  late: 3,
  pending: 2,
  tombstone: 1,
};

function compareMilestoneOps(
  a: { op: MilestoneOperation; node: DAGNode },
  b: { op: MilestoneOperation; node: DAGNode },
): number {
  // Never let a tombstone overwrite a valid fulfilled/late/breached/pending milestone
  // unless both are tombstones.
  const aValid = a.op.status !== 'tombstone';
  const bValid = b.op.status !== 'tombstone';
  if (aValid !== bValid) return aValid ? 1 : -1;

  const prioDiff = (STATUS_PRIORITY[a.op.status] ?? 0) - (STATUS_PRIORITY[b.op.status] ?? 0);
  if (prioDiff !== 0) return prioDiff;

  if (a.op.updatedAt !== b.op.updatedAt) return a.op.updatedAt - b.op.updatedAt;
  if (a.node.timestamp !== b.node.timestamp) return a.node.timestamp - b.node.timestamp;
  if (a.node.seq !== b.node.seq) return a.node.seq - b.node.seq;
  return a.node.hash.localeCompare(b.node.hash);
}

/**
 * In-memory Merkle DAG storage with O(1) node lookup and cycle-safe traversal.
 */
export class MerkleDAG {
  private readonly nodes = new Map<string, DAGNode>();
  private readonly headSeqs = new Map<string, number>();
  private readonly tipSet = new Set<string>();

  addNode(node: DAGNode): boolean {
    if (this.nodes.has(node.hash)) return false;
    this.nodes.set(node.hash, node);
    this.tipSet.add(node.hash);
    for (const parentHash of node.parents) {
      this.tipSet.delete(parentHash);
    }
    const prevHead = this.headSeqs.get(node.author) ?? -1;
    if (node.seq > prevHead) this.headSeqs.set(node.author, node.seq);
    return true;
  }

  /**
   * Inserts a cryptographically signed node after verifying its content hash
   * and Ed25519 signature. Rejects nodes with invalid or mismatched signatures.
   */
  addSignedNode(node: DAGNode): boolean {
    if (!verifyNodeSignature(node)) return false;
    return this.addNode(node);
  }

  getNode(hash: string): DAGNode | undefined {
    return this.nodes.get(hash);
  }

  hasNode(hash: string): boolean {
    return this.nodes.has(hash);
  }

  get tips(): readonly string[] {
    return [...this.tipSet];
  }

  get size(): number {
    return this.nodes.size;
  }

  get authors(): string[] {
    return [...new Set([...this.nodes.values()].map((n) => n.author))];
  }

  headSeq(author: string): number {
    return this.headSeqs.get(author) ?? -1;
  }

  isKnown(hash: string): boolean {
    return this.nodes.has(hash);
  }

  /**
   * Walk the ancestry of startHash up to maxDepth hops, calling visitor for
   * each visited node. Returns the number of nodes visited. The visitor may
   * return false to prune a branch early.
   */
  walkAncestry(
    startHash: string,
    visitor: (node: DAGNode) => boolean | void,
    maxDepth = Infinity,
  ): number {
    const visited = new Set<string>();
    const stack: Array<{ hash: string; depth: number }> = [{ hash: startHash, depth: 0 }];
    let count = 0;

    while (stack.length > 0) {
      const { hash, depth } = stack.pop()!;
      if (visited.has(hash) || depth > maxDepth) continue;
      visited.add(hash);

      const node = this.nodes.get(hash);
      if (!node) continue;

      count++;
      const shouldContinue = visitor(node);
      if (shouldContinue === false) continue;

      for (const parentHash of node.parents) {
        stack.push({ hash: parentHash, depth: depth + 1 });
      }
    }
    return count;
  }

  /**
   * Find the lowest common ancestor of two nodes. Returns the LCA hash or
   * undefined if they share no common ancestor.
   */
  findLCA(hashA: string, hashB: string): string | undefined {
    const visitedA = new Set<string>();
    const queueA: Array<{ hash: string; depth: number }> = [{ hash: hashA, depth: 0 }];
    const queueB: Array<{ hash: string; depth: number }> = [{ hash: hashB, depth: 0 }];

    while (queueA.length > 0 || queueB.length > 0) {
      if (queueA.length > 0) {
        const { hash, depth } = queueA.shift()!;
        if (!visitedA.has(hash)) {
          visitedA.add(hash);
          const node = this.nodes.get(hash);
          if (node) {
            for (const p of node.parents) {
              queueA.push({ hash: p, depth: depth + 1 });
            }
          }
        }
      }

      if (queueB.length > 0) {
        const { hash, depth } = queueB.shift()!;
        if (visitedA.has(hash)) {
          return hash;
        }
        const node = this.nodes.get(hash);
        if (node) {
          for (const p of node.parents) {
            queueB.push({ hash: p, depth: depth + 1 });
          }
        }
      }
    }
    return undefined;
  }

  /**
   * Reconcile an incoming DAG with the local one. Returns newNodes not
   * present locally and divergentAuthors whose head seq diverges.
   * O(n) in the number of new nodes.
   */
  reconcile(incoming: MerkleDAG): {
    newNodes: DAGNode[];
    divergentAuthors: Map<string, { local: number; remote: number }>;
  } {
    const newNodes: DAGNode[] = [];
    const divergentAuthors = new Map<string, { local: number; remote: number }>();

    for (const node of incoming.nodes.values()) {
      if (!this.nodes.has(node.hash)) {
        newNodes.push(node);
      }
    }

    for (const [author, remoteSeq] of incoming.headSeqs) {
      const localSeq = this.headSeqs.get(author) ?? -1;
      if (remoteSeq > localSeq) {
        divergentAuthors.set(author, { local: localSeq, remote: remoteSeq });
      }
    }

    return { newNodes, divergentAuthors };
  }

  /**
   * Computes the deterministic linearizable milestone state across all non-tombstone
   * operations currently present in the DAG.
   */
  materializeMilestoneState(): Map<string, MilestoneOperation> {
    const winners = new Map<string, { op: MilestoneOperation; node: DAGNode }>();
    for (const node of this.nodes.values()) {
      if (node.isTombstone) continue;
      const op = decodeMilestonePayload(node.payload);
      if (!op || op.status === 'tombstone') continue;
      const existing = winners.get(op.milestoneId);
      if (!existing || compareMilestoneOps({ op, node }, existing) > 0) {
        winners.set(op.milestoneId, { op, node });
      }
    }
    const result = new Map<string, MilestoneOperation>();
    for (const [id, entry] of winners) {
      result.set(id, entry.op);
    }
    return result;
  }

  /**
   * Compacts historical tombstone operations, superseded intermediate deltas, and
   * saturated vector clocks while preserving causal consistency and linearizable state.
   */
  compact(
    options: {
      activePeers?: ReadonlySet<string>;
      signerKeypairs?: ReadonlyMap<string, Keypair>;
    } = {},
  ): {
    beforeBytes: number;
    afterBytes: number;
    reductionRatio: number;
    compactedDAG: MerkleDAG;
    linearizableState: Map<string, MilestoneOperation>;
  } {
    const beforeBytes = this.encode().byteLength;
    const linearizableState = this.materializeMilestoneState();

    // Determine the winning node for each live milestone plus the latest tip per active author.
    const winningNodesByMilestone = new Map<string, { op: MilestoneOperation; node: DAGNode }>();
    let globalClock: Record<string, number> = {};
    const minCausalFloor: Record<string, number> = {};

    for (const node of this.nodes.values()) {
      globalClock = mergeVectorClocks(globalClock, node.vectorClock).merged;
      for (const [peer, count] of Object.entries(node.vectorClock)) {
        minCausalFloor[peer] =
          minCausalFloor[peer] === undefined ? count : Math.min(minCausalFloor[peer], count);
      }
      if (node.isTombstone) continue;
      const op = decodeMilestonePayload(node.payload);
      if (op && op.status !== 'tombstone') {
        const existing = winningNodesByMilestone.get(op.milestoneId);
        if (!existing || compareMilestoneOps({ op, node }, existing) > 0) {
          winningNodesByMilestone.set(op.milestoneId, { op, node });
        }
      }
    }

    const compactedDAG = new MerkleDAG();
    const { pruned: prunedClock } = pruneSaturatedVectorClock(
      globalClock,
      minCausalFloor,
      options.activePeers,
    );

    if (winningNodesByMilestone.size > 0) {
      const sortedEntries = [...winningNodesByMilestone.values()].sort((a, b) =>
        a.op.milestoneId.localeCompare(b.op.milestoneId),
      );
      let prevHash: string | undefined;
      for (const { op, node } of sortedEntries) {
        const parents = prevHash ? [prevHash] : [];
        const payload = encodeMilestonePayload(op);
        const keypair = options.signerKeypairs?.get(node.author);
        const compactedNode = keypair
          ? createSignedDAGNode(keypair, node.seq, node.timestamp, payload, parents, prunedClock)
          : createDAGNode(node.author, node.seq, node.timestamp, payload, parents, prunedClock);
        compactedDAG.addNode(compactedNode);
        prevHash = compactedNode.hash;
      }
    } else {
      // Fallback for opaque payloads: retain only current non-tombstone tips with pruned clocks.
      for (const tipHash of this.tips) {
        const tip = this.nodes.get(tipHash);
        if (!tip || tip.isTombstone) continue;
        const compactedTip = createDAGNode(
          tip.author,
          tip.seq,
          tip.timestamp,
          tip.payload,
          [],
          prunedClock,
        );
        compactedDAG.addNode(compactedTip);
      }
    }

    const afterBytes = compactedDAG.encode().byteLength;
    const reductionRatio = beforeBytes > 0 ? (beforeBytes - afterBytes) / beforeBytes : 0;

    return {
      beforeBytes,
      afterBytes,
      reductionRatio,
      compactedDAG,
      linearizableState,
    };
  }

  /**
   * Reconciles divergent partition branches via deterministic 3-way merge rules
   * without losing valid milestones, rejecting any nodes with invalid hashes or signatures.
   */
  reconcileThreeWay(
    remote: MerkleDAG,
    options: { requireSignatures?: boolean } = {},
  ): {
    mergedDAG: MerkleDAG;
    lcaHash: string | undefined;
    mergedMilestones: Map<string, MilestoneOperation>;
    rejectedNodes: DAGNode[];
  } {
    const mergedDAG = new MerkleDAG();
    const rejectedNodes: DAGNode[] = [];

    const validateAndInsert = (node: DAGNode): void => {
      if (!verifyNodeHash(node)) {
        rejectedNodes.push(node);
        return;
      }
      if (options.requireSignatures || node.signature !== undefined) {
        if (!verifyNodeSignature(node)) {
          rejectedNodes.push(node);
          return;
        }
      }
      mergedDAG.addNode(node);
    };

    for (const node of this.nodes.values()) {
      validateAndInsert(node);
    }
    for (const node of remote.nodes.values()) {
      validateAndInsert(node);
    }

    const localTip = this.tips[0];
    const remoteTip = remote.tips[0];
    const lcaHash =
      localTip && remoteTip ? mergedDAG.findLCA(localTip, remoteTip) : undefined;

    const mergedMilestones = mergedDAG.materializeMilestoneState();

    return {
      mergedDAG,
      lcaHash,
      mergedMilestones,
      rejectedNodes,
    };
  }

  encode(): Uint8Array {
    const entries: object[] = [];
    for (const node of this.nodes.values()) {
      entries.push({
        ...node,
        payload: Array.from(node.payload),
        parents: [...node.parents],
        signature: node.signature ? Array.from(node.signature) : undefined,
      });
    }
    return new TextEncoder().encode(JSON.stringify(entries));
  }

  static decode(bytes: Uint8Array): MerkleDAG {
    const dag = new MerkleDAG();
    const entries: Array<{
      hash: string;
      author: string;
      seq: number;
      timestamp: number;
      payload: number[];
      parents: string[];
      clockHash: string;
      vectorClock: Record<string, number>;
      signature?: number[];
      signerPublicKey?: string;
      isTombstone?: boolean;
    }> = JSON.parse(new TextDecoder().decode(bytes));
    for (const entry of entries) {
      dag.addNode({
        ...entry,
        payload: new Uint8Array(entry.payload),
        signature: entry.signature ? new Uint8Array(entry.signature) : undefined,
      });
    }
    return dag;
  }
}
