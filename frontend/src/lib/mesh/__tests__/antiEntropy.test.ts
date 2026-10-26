import { describe, it, expect } from 'vitest';
import { xdr } from '@stellar/stellar-sdk';
import { AntiEntropyManager, computeMerkleRoot } from '../antiEntropy.ts';
import type { SorobanIndexedEvent, AntiEntropyReqMessage, MeshProtocolMessage } from '../types.ts';

function makeEvent(id: string, ledgerSeq: number): SorobanIndexedEvent {
  return {
    id,
    contractId: 'CBADTVTJ6IN332HIKZ7LWUYMYTLPZYCEBV3X2HS47VHR5UDBHQ3GAA7E',
    topic: 'commitment_created',
    xdrPayload: xdr.ScVal.scvSymbol(id).toXDR('base64'),
    ledgerSeq,
    txHash: `0x${id}`,
    timestamp: Date.now(),
    originPeerId: 'origin-1',
  };
}

describe('AntiEntropyManager', () => {
  it('correctly indexes and serves range queries for partition healing', () => {
    const mockTransport = {
      localPeerId: 'node-sync-1',
      sendToPeer: () => {},
      getActivePeers: () => [],
    } as any;

    const manager = new AntiEntropyManager(mockTransport, { maxEventsPerSync: 50 });

    const event1 = makeEvent('e1', 100);
    const event2 = makeEvent('e2', 102);

    manager.recordEvent(event1);
    manager.recordEvent(event2);

    const req: AntiEntropyReqMessage = {
      type: 'ANTI_ENTROPY_REQ',
      fromLedger: 99,
      toLedger: 105,
      senderId: 'node-sync-2',
      timestamp: Date.now(),
    };

    const resp = manager.handleSyncRequest(req);
    expect(resp.events.length).toBe(2);
    expect(resp.events[0].id).toBe('e1');
    expect(resp.events[1].id).toBe('e2');
    expect(resp.merkleRoot).toBe(computeMerkleRoot([event1, event2]));

    // When requester already has the identical Merkle root, returns empty delta with inSync=true
    const inSyncResp = manager.handleSyncRequest({
      ...req,
      merkleRoot: resp.merkleRoot,
    });
    expect(inSyncResp.inSync).toBe(true);
    expect(inSyncResp.events.length).toBe(0);

    // Test invalid range bounds
    const invalidReq: AntiEntropyReqMessage = {
      type: 'ANTI_ENTROPY_REQ',
      fromLedger: 200,
      toLedger: 100, // from > to
      senderId: 'node-sync-2',
      timestamp: Date.now(),
    };
    const invalidResp = manager.handleSyncRequest(invalidReq);
    expect(invalidResp.events.length).toBe(0);

    // Test maxEventsPerSync cap
    const smallCapManager = new AntiEntropyManager(mockTransport, { maxEventsPerSync: 1 });
    smallCapManager.recordEvent(event1);
    smallCapManager.recordEvent(event2);
    const cappedResp = smallCapManager.handleSyncRequest(req);
    expect(cappedResp.events.length).toBe(1);

    manager.destroy();
    smallCapManager.destroy();
  });

  it('heals a partitioned 2-cluster mesh within <= 3 anti-entropy rounds', () => {
    const nodes = new Map<string, AntiEntropyManager>();
    const peerIds = ['node-1', 'node-2', 'node-3', 'node-4'];

    for (const id of peerIds) {
      const transport = {
        localPeerId: id,
        getActivePeers: () => peerIds.filter((p) => p !== id),
        sendToPeer: (targetId: string, msg: MeshProtocolMessage) => {
          const target = nodes.get(targetId);
          if (!target) return;
          if (msg.type === 'ANTI_ENTROPY_REQ') {
            const resp = target.handleSyncRequest(msg);
            const sender = nodes.get(id);
            sender?.handleSyncResponse(resp);
          }
        },
      } as any;

      nodes.set(id, new AntiEntropyManager(transport, { peerSubsetSize: 2, syncIntervalMs: 60000 }));
    }

    // Partition A (node-1, node-2) only saw events eA1, eA2
    // Partition B (node-3, node-4) only saw events eB1, eB2
    const eA1 = makeEvent('eA1', 10);
    const eA2 = makeEvent('eA2', 11);
    const eB1 = makeEvent('eB1', 12);
    const eB2 = makeEvent('eB2', 13);

    nodes.get('node-1')!.recordEvent(eA1);
    nodes.get('node-2')!.recordEvent(eA2);
    nodes.get('node-3')!.recordEvent(eB1);
    nodes.get('node-4')!.recordEvent(eB2);

    const expectedRoot = computeMerkleRoot([eA1, eA2, eB1, eB2]);

    let healedRound = -1;
    for (let round = 1; round <= 3; round++) {
      for (const manager of nodes.values()) {
        manager.runAntiEntropyRound(1, 20, 2);
      }
      const allConverged = Array.from(nodes.values()).every(
        (m) => m.getMerkleRoot(1, 20) === expectedRoot,
      );
      if (allConverged) {
        healedRound = round;
        break;
      }
    }

    expect(healedRound).toBeGreaterThanOrEqual(1);
    expect(healedRound).toBeLessThanOrEqual(3);

    for (const manager of nodes.values()) {
      expect(manager.getAllEvents().map((e) => e.id)).toEqual(['eA1', 'eA2', 'eB1', 'eB2']);
      manager.destroy();
    }
  });
});
