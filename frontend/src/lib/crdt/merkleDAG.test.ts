import { Keypair } from '@stellar/stellar-sdk';
import { describe, expect, it } from 'vitest';

import { ByzantineHealer } from './byzantineHealer';
import {
  createDAGNode,
  createSignedDAGNode,
  verifyNodeHash,
  verifyNodeSignature,
  hashVectorClock,
  encodeMilestonePayload,
  MerkleDAG,
} from './merkleDAG';
import {
  createEd25519VectorClock,
  verifyEd25519VectorClock,
  pruneSaturatedVectorClock,
} from './secureVectorClock';

function randomBytes(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}

describe('MerkleDAG', () => {
  it('creates a node with a valid content hash', () => {
    const node = createDAGNode('alice', 1, 1000, randomBytes(32), [], { alice: 1 });
    expect(node.hash).toMatch(/^[0-9a-f]{64}$/);
    expect(verifyNodeHash(node)).toBe(true);
  });

  it('detects hash tampering', () => {
    const node = createDAGNode('alice', 1, 1000, randomBytes(32), [], { alice: 1 });
    const tampered = { ...node, seq: 2 };
    expect(verifyNodeHash(tampered)).toBe(false);
  });

  it('produces different hashes for different payloads', () => {
    const a = createDAGNode('alice', 1, 1000, randomBytes(32), [], { alice: 1 });
    const b = createDAGNode('alice', 1, 1000, randomBytes(32), [], { alice: 1 });
    expect(a.hash).not.toBe(b.hash);
  });

  it('produces different hashes for different parents', () => {
    const payload = randomBytes(32);
    const a = createDAGNode('alice', 1, 1000, payload, [], { alice: 1 });
    const b = createDAGNode('alice', 1, 1000, payload, ['fakeparent'], { alice: 1 });
    expect(a.hash).not.toBe(b.hash);
  });

  it('deterministically hashes vector clocks', () => {
    const clockA = { alice: 3, bob: 2 };
    const clockB = { bob: 2, alice: 3 };
    expect(hashVectorClock(clockA)).toBe(hashVectorClock(clockB));
  });

  it('addNode returns true for new nodes and false for duplicates', () => {
    const dag = new MerkleDAG();
    const node = createDAGNode('alice', 1, 1000, randomBytes(32), [], { alice: 1 });
    expect(dag.addNode(node)).toBe(true);
    expect(dag.addNode(node)).toBe(false);
  });

  it('tracks tips correctly', () => {
    const dag = new MerkleDAG();
    const root = createDAGNode('alice', 1, 1000, randomBytes(32), [], { alice: 1 });
    dag.addNode(root);
    expect(dag.tips).toEqual([root.hash]);

    const child = createDAGNode('alice', 2, 2000, randomBytes(32), [root.hash], { alice: 2 });
    dag.addNode(child);
    expect(dag.tips).toEqual([child.hash]);
  });

  it('maintains O(1) lookup', () => {
    const dag = new MerkleDAG();
    const node = createDAGNode('alice', 1, 1000, randomBytes(32), [], { alice: 1 });
    dag.addNode(node);
    expect(dag.getNode(node.hash)).toBe(node);
    expect(dag.hasNode(node.hash)).toBe(true);
    expect(dag.hasNode('nonexistent')).toBe(false);
  });

  it('tracks authors and headSeqs', () => {
    const dag = new MerkleDAG();
    const a1 = createDAGNode('alice', 1, 1000, randomBytes(32), [], { alice: 1 });
    const a2 = createDAGNode('alice', 3, 2000, randomBytes(32), [a1.hash], { alice: 3 });
    dag.addNode(a1);
    dag.addNode(a2);
    expect(dag.authors).toEqual(['alice']);
    expect(dag.headSeq('alice')).toBe(3);
  });

  it('walkAncestry visits all ancestors', () => {
    const dag = new MerkleDAG();
    const root = createDAGNode('alice', 1, 1000, randomBytes(32), [], { alice: 1 });
    const mid = createDAGNode('alice', 2, 2000, randomBytes(32), [root.hash], { alice: 2 });
    const tip = createDAGNode('alice', 3, 3000, randomBytes(32), [mid.hash], { alice: 3 });
    dag.addNode(root);
    dag.addNode(mid);
    dag.addNode(tip);

    const visited: string[] = [];
    const count = dag.walkAncestry(tip.hash, (node) => {
      visited.push(node.hash);
    });
    expect(count).toBe(3);
    expect(visited).toContain(root.hash);
    expect(visited).toContain(mid.hash);
    expect(visited).toContain(tip.hash);
  });

  it('walkAncestry respects maxDepth', () => {
    const dag = new MerkleDAG();
    const root = createDAGNode('alice', 1, 1000, randomBytes(32), [], { alice: 1 });
    const mid = createDAGNode('alice', 2, 2000, randomBytes(32), [root.hash], { alice: 2 });
    const tip = createDAGNode('alice', 3, 3000, randomBytes(32), [mid.hash], { alice: 3 });
    dag.addNode(root);
    dag.addNode(mid);
    dag.addNode(tip);

    const count = dag.walkAncestry(tip.hash, () => {}, 1);
    expect(count).toBe(2);
  });

  it('walkAncestry prunes when visitor returns false', () => {
    const dag = new MerkleDAG();
    const root = createDAGNode('alice', 1, 1000, randomBytes(32), [], { alice: 1 });
    const mid = createDAGNode('alice', 2, 2000, randomBytes(32), [root.hash], { alice: 2 });
    const tip = createDAGNode('alice', 3, 3000, randomBytes(32), [mid.hash], { alice: 3 });
    dag.addNode(root);
    dag.addNode(mid);
    dag.addNode(tip);

    const visited: string[] = [];
    dag.walkAncestry(tip.hash, (node) => {
      visited.push(node.hash);
      if (node.hash === mid.hash) return false;
    });
    expect(visited).not.toContain(root.hash);
  });

  it('findLCA returns the lowest common ancestor', () => {
    const dag = new MerkleDAG();
    const root = createDAGNode('alice', 1, 1000, randomBytes(32), [], { alice: 1 });
    const a2 = createDAGNode('alice', 2, 2000, randomBytes(32), [root.hash], { alice: 2 });
    const b2 = createDAGNode('bob', 1, 2000, randomBytes(32), [root.hash], { bob: 1 });
    dag.addNode(root);
    dag.addNode(a2);
    dag.addNode(b2);

    expect(dag.findLCA(a2.hash, b2.hash)).toBe(root.hash);
  });

  it('findLCA returns undefined for disjoint histories', () => {
    const dag = new MerkleDAG();
    const a = createDAGNode('alice', 1, 1000, randomBytes(32), [], { alice: 1 });
    const b = createDAGNode('bob', 1, 1000, randomBytes(32), [], { bob: 1 });
    dag.addNode(a);
    dag.addNode(b);
    expect(dag.findLCA(a.hash, b.hash)).toBeUndefined();
  });

  it('reconcile detects new nodes and divergent authors', () => {
    const local = new MerkleDAG();
    const remote = new MerkleDAG();

    const root = createDAGNode('alice', 1, 1000, randomBytes(32), [], { alice: 1 });
    local.addNode(root);
    remote.addNode(root);

    const remoteOnly = createDAGNode('bob', 1, 2000, randomBytes(32), [], { bob: 1 });
    remote.addNode(remoteOnly);

    const result = local.reconcile(remote);
    expect(result.newNodes.length).toBe(1);
    expect(result.newNodes[0].hash).toBe(remoteOnly.hash);
  });

  it('encode and decode round-trip preserves nodes', () => {
    const dag = new MerkleDAG();
    const a = createDAGNode('alice', 1, 1000, randomBytes(32), [], { alice: 1 });
    const b = createDAGNode('bob', 1, 2000, randomBytes(32), [a.hash], { alice: 1, bob: 1 });
    dag.addNode(a);
    dag.addNode(b);

    const encoded = dag.encode();
    const decoded = MerkleDAG.decode(encoded);

    expect(decoded.size).toBe(2);
    expect(decoded.getNode(a.hash)?.author).toBe('alice');
    expect(decoded.getNode(b.hash)?.author).toBe('bob');
  });

  it('is known works correctly', () => {
    const dag = new MerkleDAG();
    const node = createDAGNode('alice', 1, 1000, randomBytes(32), [], { alice: 1 });
    dag.addNode(node);
    expect(dag.isKnown(node.hash)).toBe(true);
    expect(dag.isKnown('nope')).toBe(false);
  });

  describe('Ed25519 cryptographic signatures, DAG compaction, and 3-way partition merge (Issue #309)', () => {
    it('accepts valid Ed25519 signed nodes and rejects nodes with invalid or mismatched signatures', () => {
      const aliceKey = Keypair.random();
      const attackerKey = Keypair.random();
      const dag = new MerkleDAG();

      const validSigned = createSignedDAGNode(
        aliceKey,
        1,
        1_000,
        encodeMilestonePayload({
          milestoneId: 'm-1',
          status: 'fulfilled',
          updatedAt: 1_000,
        }),
        [],
        { [aliceKey.publicKey()]: 1 },
      );

      expect(verifyNodeSignature(validSigned)).toBe(true);
      expect(dag.addSignedNode(validSigned)).toBe(true);

      // Mismatched signer public key (signed by attacker, claiming alice as author)
      const forgedByAttacker = {
        ...validSigned,
        signature: new Uint8Array(attackerKey.sign(Buffer.from('forged-payload'))),
      };
      expect(verifyNodeSignature(forgedByAttacker)).toBe(false);
      expect(dag.addSignedNode(forgedByAttacker)).toBe(false);

      // Unsigned node rejected by addSignedNode and by ByzantineHealer when requireSignatures=true
      const unsignedNode = createDAGNode(aliceKey.publicKey(), 2, 2_000, randomBytes(16), [], {
        [aliceKey.publicKey()]: 2,
      });
      expect(dag.addSignedNode(unsignedNode)).toBe(false);

      const incoming = new MerkleDAG();
      incoming.addNode(forgedByAttacker);
      const healer = new ByzantineHealer();
      const healRes = healer.heal(incoming, [], { requireSignatures: true });
      expect(healRes.rejected.length).toBe(1);
      expect(healRes.quarantined[0]?.reason).toBe('bad-signature');

      // Ed25519 vector clock verification
      const edClock = createEd25519VectorClock(aliceKey, 4, { bob: 2 });
      expect(verifyEd25519VectorClock(edClock, aliceKey.publicKey())).toBe(true);
      expect(verifyEd25519VectorClock(edClock, attackerKey.publicKey())).toBe(false);
    });

    it('compacts historical tombstones and saturated vector clocks with >= 60% storage reduction while preserving linearizable state', () => {
      const aliceKey = Keypair.random();
      const bobKey = Keypair.random();
      const dag = new MerkleDAG();

      // Build a saturated vector clock with 10 historical peers and 25 historical updates/tombstones
      const baseClock: Record<string, number> = {
        [aliceKey.publicKey()]: 1,
        [bobKey.publicKey()]: 1,
        retired_peer_1: 5,
        retired_peer_2: 5,
        retired_peer_3: 5,
        retired_peer_4: 5,
        retired_peer_5: 5,
        retired_peer_6: 5,
      };

      let parents: string[] = [];
      for (let i = 1; i <= 20; i++) {
        const clock = { ...baseClock, [aliceKey.publicKey()]: i };
        const isTombstone = i <= 14;
        const milestoneId = isTombstone ? `temp-${i}` : `milestone-${(i % 2) + 1}`;
        const status = isTombstone ? 'tombstone' : i >= 19 ? 'fulfilled' : 'pending';
        const node = createSignedDAGNode(
          aliceKey,
          i,
          1_000 + i * 100,
          encodeMilestonePayload({
            milestoneId,
            status,
            updatedAt: 1_000 + i * 100,
            value: `step-${i}`,
          }),
          parents,
          clock,
          { isTombstone },
        );
        dag.addSignedNode(node);
        parents = [node.hash];
      }

      const activePeers = new Set([aliceKey.publicKey(), bobKey.publicKey()]);
      const signerMap = new Map([[aliceKey.publicKey(), aliceKey]]);

      const stateBefore = dag.materializeMilestoneState();
      const { beforeBytes, afterBytes, reductionRatio, compactedDAG, linearizableState } =
        dag.compact({
          activePeers,
          signerKeypairs: signerMap,
        });

      expect(beforeBytes).toBeGreaterThan(afterBytes);
      expect(reductionRatio).toBeGreaterThanOrEqual(0.6);

      // Linearizable state before and after compaction must be identical
      expect(linearizableState).toEqual(stateBefore);
      expect(compactedDAG.materializeMilestoneState()).toEqual(stateBefore);
      expect(linearizableState.get('milestone-1')?.status).toBe('fulfilled');
      expect(linearizableState.get('milestone-2')?.status).toBe('fulfilled');

      // Saturated clock pruning drops retired peers at or below causal floor
      const prunedClock = pruneSaturatedVectorClock(baseClock, baseClock, activePeers);
      expect(prunedClock.prunedPeers.length).toBeGreaterThanOrEqual(6);
    });

    it('reconciles divergent network partition branches via 3-way merge without losing valid milestones', () => {
      const aliceKey = Keypair.random();
      const bobKey = Keypair.random();
      const alicePub = aliceKey.publicKey();
      const bobPub = bobKey.publicKey();

      // Shared genesis ancestor prior to network partition
      const genesis = createSignedDAGNode(
        aliceKey,
        1,
        1_000,
        encodeMilestonePayload({
          milestoneId: 'm-genesis',
          status: 'fulfilled',
          updatedAt: 1_000,
        }),
        [],
        { [alicePub]: 1 },
      );

      const branchA = new MerkleDAG();
      const branchB = new MerkleDAG();
      branchA.addSignedNode(genesis);
      branchB.addSignedNode(genesis);

      // Partition Branch A: Alice fulfills m-alpha and leaves m-shared as pending
      const a1 = createSignedDAGNode(
        aliceKey,
        2,
        2_000,
        encodeMilestonePayload({
          milestoneId: 'm-alpha',
          status: 'fulfilled',
          updatedAt: 2_000,
        }),
        [genesis.hash],
        { [alicePub]: 2 },
      );
      const a2 = createSignedDAGNode(
        aliceKey,
        3,
        2_500,
        encodeMilestonePayload({
          milestoneId: 'm-shared',
          status: 'pending',
          updatedAt: 2_500,
        }),
        [a1.hash],
        { [alicePub]: 3 },
      );
      branchA.addSignedNode(a1);
      branchA.addSignedNode(a2);

      // Partition Branch B: Bob fulfills m-beta and fulfills m-shared concurrently
      const b1 = createSignedDAGNode(
        bobKey,
        1,
        2_100,
        encodeMilestonePayload({
          milestoneId: 'm-beta',
          status: 'fulfilled',
          updatedAt: 2_100,
        }),
        [genesis.hash],
        { [alicePub]: 1, [bobPub]: 1 },
      );
      const b2 = createSignedDAGNode(
        bobKey,
        2,
        2_600,
        encodeMilestonePayload({
          milestoneId: 'm-shared',
          status: 'fulfilled',
          updatedAt: 2_600,
        }),
        [b1.hash],
        { [alicePub]: 1, [bobPub]: 2 },
      );
      branchB.addSignedNode(b1);
      branchB.addSignedNode(b2);

      // Reconcile A <- B and B <- A
      const mergeAB = branchA.reconcileThreeWay(branchB, { requireSignatures: true });
      const mergeBA = branchB.reconcileThreeWay(branchA, { requireSignatures: true });

      expect(mergeAB.rejectedNodes.length).toBe(0);
      expect(mergeAB.lcaHash).toBe(genesis.hash);

      // Both divergent branches converge to the exact same state without losing any valid milestone
      expect(mergeAB.mergedMilestones).toEqual(mergeBA.mergedMilestones);
      expect(mergeAB.mergedMilestones.get('m-genesis')?.status).toBe('fulfilled');
      expect(mergeAB.mergedMilestones.get('m-alpha')?.status).toBe('fulfilled');
      expect(mergeAB.mergedMilestones.get('m-beta')?.status).toBe('fulfilled');
      expect(mergeAB.mergedMilestones.get('m-shared')?.status).toBe('fulfilled');
    });
  });
});
