/**
 * Unit & protocol tests for FROST / TSS Distributed Key Generation & Signing — Issue #299
 */

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  runAsynchronousDkg,
  FrostTssCoordinator,
  verifyThresholdSignature,
  computeLagrangeCoefficient,
  pointMul,
  pointsEqual,
  modQ,
  GENERATOR_G,
  TssSlashingError,
  keccak256Utf8,
} from './index';

describe('FROST / TSS Distributed Key Generation & Threshold Signing (#299)', () => {
  it('executes asynchronous 3-of-5 dealerless DKG and yields a consistent shared public key across all 5 nodes', async () => {
    const dkg = await runAsynchronousDkg(3, 5);

    assert.equal(dkg.nodeShares.size, 5);
    assert.equal(dkg.faultyDealers.length, 0);
    assert.ok(dkg.groupPubKeyX.startsWith('0x'));
    assert.equal(dkg.groupPubKeyX.length, 66);
    assert.ok(dkg.groupPubKeyParity === 27 || dkg.groupPubKeyParity === 28);

    // Every node must hold the identical shared public key
    for (let nodeId = 1; nodeId <= 5; nodeId++) {
      const share = dkg.nodeShares.get(nodeId)!;
      assert.equal(share.groupPubKeyX, dkg.groupPubKeyX);
      assert.equal(share.groupPubKeyParity, dkg.groupPubKeyParity);
      assert.equal(share.groupEthAddress, dkg.groupEthAddress);

      // Verify Y_i == x_i * G
      const computedYi = pointMul(GENERATOR_G, share.secretShare);
      assert.equal(pointsEqual(computedYi, share.publicVerificationShare), true);
    }

    // Reconstruct the group secret via Lagrange interpolation over any 3-node subset (e.g. [1, 3, 5])
    const subset = [1, 3, 5];
    let reconstructedSecret = 0n;
    for (const nodeId of subset) {
      const lambda = computeLagrangeCoefficient(nodeId, subset);
      const xI = dkg.nodeShares.get(nodeId)!.secretShare;
      reconstructedSecret = modQ(reconstructedSecret + modQ(lambda * xI));
    }

    const reconstructedPubKey = pointMul(GENERATOR_G, reconstructedSecret);
    assert.equal(pointsEqual(reconstructedPubKey, dkg.groupPublicKey), true);
  });

  it('detects and isolates a Byzantine dealer sending corrupted VSS shares during DKG', async () => {
    const dkg = await runAsynchronousDkg(3, 5, (share) => {
      if (share.fromDealerId === 4 && share.toNodeId === 2) {
        return { ...share, secretEval: modQ(share.secretEval + 999n) };
      }
      return share;
    });

    assert.deepEqual(dkg.faultyDealers, [4]);
    assert.equal(dkg.nodeShares.size, 5);
  });

  it('generates a valid 3-of-5 threshold signature even when 2 nodes are offline', async () => {
    const dkg = await runAsynchronousDkg(3, 5);
    const coordinator = new FrostTssCoordinator(dkg);

    const messageHash = keccak256Utf8('pactum-batch-nonce-1');
    const sig = await coordinator.sign(messageHash, {
      offlineNodeIds: [2, 5],
    });

    assert.deepEqual(sig.signers, [1, 3, 4]);
    assert.equal(sig.slashedCulprits.length, 0);
    assert.equal(verifyThresholdSignature(messageHash, sig), true);

    // Rejects tampered message hash
    const wrongHash = keccak256Utf8('pactum-batch-nonce-2');
    assert.equal(verifyThresholdSignature(wrongHash, sig), false);
  });

  it('detects malicious signature shares, identifies culprit node for slashing, and recovers with remaining honest nodes', async () => {
    const dkg = await runAsynchronousDkg(3, 5);
    const coordinator = new FrostTssCoordinator(dkg);
    const messageHash = keccak256Utf8('pactum-slashing-test');

    // Node 2 injects a corrupted signature share while Node 5 is offline;
    // Coordinator must detect & slash Node 2 and complete signing with honest nodes [1, 3, 4].
    const sig = await coordinator.sign(messageHash, {
      offlineNodeIds: [5],
      corruptShareHooks: {
        2: (z) => modQ(z + 1337n),
      },
    });

    assert.equal(sig.slashedCulprits.length, 1);
    assert.equal(sig.slashedCulprits[0].culpritNodeId, 2);
    assert.deepEqual(coordinator.getSlashedNodes(), [2]);
    assert.deepEqual(sig.signers, [1, 3, 4]);
    assert.equal(verifyThresholdSignature(messageHash, sig), true);

    // If nodes 3 and 4 also go offline so fewer than 3 honest nodes remain, throws TssSlashingError
    await assert.rejects(
      async () => {
        const dkg2 = await runAsynchronousDkg(3, 5);
        const coord2 = new FrostTssCoordinator(dkg2);
        await coord2.sign(messageHash, {
          offlineNodeIds: [4, 5],
          corruptShareHooks: {
            1: (z) => modQ(z ^ 0xffn),
          },
        });
      },
      (err: unknown) => {
        assert.ok(err instanceof TssSlashingError);
        assert.equal(err.culprits.length, 1);
        assert.equal(err.culprits[0].culpritNodeId, 1);
        return true;
      },
    );
  });
});
