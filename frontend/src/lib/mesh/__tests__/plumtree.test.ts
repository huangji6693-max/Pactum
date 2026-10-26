import { describe, it, expect } from 'vitest';
import { xdr } from '@stellar/stellar-sdk';
import { PlumtreeEngine } from '../plumtreeEngine.ts';
import { PeerScoringManager } from '../peerScoring.ts';
import { AntiEntropyManager } from '../antiEntropy.ts';
import type { MeshProtocolMessage, SorobanIndexedEvent, GossipDataMessage } from '../types.ts';

describe('PlumtreeEngine', () => {
  function createEngine(localPeerId: string) {
    const sentMessages: { targetPeerId: string; message: MeshProtocolMessage }[] = [];
    const deliveredEvents: { event: SorobanIndexedEvent; senderId: string }[] = [];
    const disconnectedPeers: { peerId: string; reason: string }[] = [];

    const scoring = new PeerScoringManager();
    const engine = new PlumtreeEngine(
      { localPeerId, targetEagerFanout: 2, minEagerFanout: 1, maxEagerFanout: 4 },
      scoring,
      (targetPeerId, message) => sentMessages.push({ targetPeerId, message }),
      (event, senderId) => deliveredEvents.push({ event, senderId }),
      (peerId, reason) => disconnectedPeers.push({ peerId, reason }),
    );

    return { engine, scoring, sentMessages, deliveredEvents, disconnectedPeers };
  }

  function createMockEvent(id: string = 'msg-1', ledgerSeq: number = 104520): SorobanIndexedEvent {
    return {
      id,
      contractId: 'CA3D...PACTUM',
      topic: 'contract_invoked',
      xdrPayload: xdr.ScVal.scvSymbol('invoked').toXDR('base64'),
      ledgerSeq,
      txHash: `0x${id}`,
      timestamp: Date.now(),
      originPeerId: 'peer-alice',
    };
  }

  it('adds peers to eager and lazy overlays according to target fanout', () => {
    const { engine } = createEngine('node-a');

    engine.addPeer('node-b');
    engine.addPeer('node-c');
    engine.addPeer('node-d'); // exceeds targetEagerFanout of 2 -> added to lazy

    expect(engine.getEagerNeighbors()).toEqual(['node-b', 'node-c']);
    expect(engine.getLazyNeighbors()).toEqual(['node-d']);

    engine.destroy();
  });

  it('eagerly propagates novel messages to eager neighbors and delivers locally', () => {
    const { engine, sentMessages, deliveredEvents } = createEngine('node-a');
    engine.addPeer('node-b');
    engine.addPeer('node-c');

    const event = createMockEvent('msg-unique-1');
    const msg: GossipDataMessage = {
      type: 'GOSSIP_DATA',
      messageId: event.id,
      topic: event.topic,
      event,
      hopCount: 0,
      senderId: 'node-b',
      timestamp: Date.now(),
    };

    engine.handleMessage('node-b', msg);

    expect(deliveredEvents.length).toBe(1);
    expect(deliveredEvents[0].event.id).toBe('msg-unique-1');

    // Should forward to node-c (other eager peer)
    const forwarded = sentMessages.filter((s) => s.targetPeerId === 'node-c');
    expect(forwarded.length).toBe(1);
    expect(forwarded[0].message.type).toBe('GOSSIP_DATA');

    engine.destroy();
  });

  it('prunes eager peer upon receiving duplicate message', () => {
    const { engine, sentMessages } = createEngine('node-a');
    engine.addPeer('node-b');

    const event = createMockEvent('msg-dup-1');
    const msg: GossipDataMessage = {
      type: 'GOSSIP_DATA',
      messageId: event.id,
      topic: event.topic,
      event,
      hopCount: 0,
      senderId: 'node-b',
      timestamp: Date.now(),
    };

    // First arrival (novel)
    engine.handleMessage('node-b', msg);

    // Second arrival (duplicate)
    engine.handleMessage('node-b', msg);

    expect(engine.duplicatesPrunedCount).toBe(1);
    const pruneMsgs = sentMessages.filter(
      (s) => s.targetPeerId === 'node-b' && s.message.type === 'PRUNE',
    );
    expect(pruneMsgs.length).toBe(1);
    expect(engine.getLazyNeighbors().includes('node-b')).toBe(true);

    engine.destroy();
  });

  it('immediately disconnects and locally blacklists peer upon malformed/Byzantine message injection', () => {
    const { engine, scoring, deliveredEvents, disconnectedPeers } = createEngine('node-a');
    engine.addPeer('node-b');
    engine.addPeer('node-c');

    const byzantineEvent: SorobanIndexedEvent = {
      id: 'bad-msg',
      contractId: 'CA3D',
      topic: 'test',
      xdrPayload: 'not-base64!',
      ledgerSeq: -500,
      txHash: '0x123',
      timestamp: Date.now(),
      originPeerId: 'node-b',
    };

    const msg: GossipDataMessage = {
      type: 'GOSSIP_DATA',
      messageId: byzantineEvent.id,
      topic: byzantineEvent.topic,
      event: byzantineEvent,
      hopCount: 0,
      senderId: 'node-b',
      timestamp: Date.now(),
    };

    engine.handleMessage('node-b', msg);

    expect(deliveredEvents.length).toBe(0);
    expect(engine.byzantineDroppedCount).toBe(1);
    expect(scoring.isBlacklisted('node-b')).toBe(true);
    expect(scoring.isPeerBanned('node-b')).toBe(true);
    expect(engine.getEagerNeighbors()).not.toContain('node-b');
    expect(disconnectedPeers.some((d) => d.peerId === 'node-b')).toBe(true);

    engine.destroy();
  });

  it('maintains 100% honest node convergence under 30% Byzantine malicious peer ratio', () => {
    // 10-node mesh: 7 honest nodes, 3 Byzantine nodes (30% malicious ratio)
    const honestIds = ['h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'h7'];
    const byzantineIds = ['b1', 'b2', 'b3'];
    const allIds = [...honestIds, ...byzantineIds];

    const nodes = new Map<
      string,
      {
        engine: PlumtreeEngine;
        scoring: PeerScoringManager;
        antiEntropy: AntiEntropyManager;
        delivered: Set<string>;
      }
    >();

    for (const id of honestIds) {
      const scoring = new PeerScoringManager();
      const delivered = new Set<string>();
      const sendMessage = (targetId: string, msg: MeshProtocolMessage) => {
        const target = nodes.get(targetId);
        if (!target) return; // Byzantine peers drop/withhold messages
        target.engine.handleMessage(id, msg);
      };

      const engine = new PlumtreeEngine(
        { localPeerId: id, targetEagerFanout: 3, minEagerFanout: 2, maxEagerFanout: 5 },
        scoring,
        sendMessage,
        (ev) => delivered.add(ev.id),
      );

      const transportStub = {
        localPeerId: id,
        sendToPeer: sendMessage,
        getActivePeers: () =>
          allIds.filter((p) => p !== id && !scoring.isPeerBanned(p)),
      } as any;

      const antiEntropy = new AntiEntropyManager(transportStub, {
        scoring,
        peerSubsetSize: 3,
        syncIntervalMs: 60000,
        onEventReconciled: (ev) => delivered.add(ev.id),
      });
      engine.attachAntiEntropy(antiEntropy);

      nodes.set(id, { engine, scoring, antiEntropy, delivered });
    }

    // Connect all nodes (including the 30% Byzantine peers)
    for (const id of honestIds) {
      const node = nodes.get(id)!;
      for (const peerId of allIds) {
        if (peerId !== id) node.engine.addPeer(peerId);
      }
    }

    // All 3 Byzantine peers inject malformed XDR / negative ledger payloads into every honest node
    for (const bId of byzantineIds) {
      for (const hId of honestIds) {
        const target = nodes.get(hId)!;
        target.engine.handleMessage(bId, {
          type: 'GOSSIP_DATA',
          messageId: `attack-from-${bId}`,
          topic: 'corrupt',
          event: {
            id: `attack-from-${bId}`,
            contractId: 'C_BAD',
            topic: 'corrupt',
            xdrPayload: '!!!invalid-xdr!!!',
            ledgerSeq: -1,
            txHash: '0xbad',
            timestamp: Date.now(),
            originPeerId: bId,
          },
          hopCount: 0,
          senderId: bId,
          timestamp: Date.now(),
        });
      }
    }

    // Verify all 3 Byzantine peers were immediately slashed and blacklisted on all honest nodes
    for (const hId of honestIds) {
      const { scoring } = nodes.get(hId)!;
      for (const bId of byzantineIds) {
        expect(scoring.isBlacklisted(bId)).toBe(true);
      }
    }

    // Publish 5 valid events from different honest nodes
    const validEvents = [
      createMockEvent('ev-1', 201),
      createMockEvent('ev-2', 202),
      createMockEvent('ev-3', 203),
      createMockEvent('ev-4', 204),
      createMockEvent('ev-5', 205),
    ];

    validEvents.forEach((ev, idx) => {
      const publisherId = honestIds[idx % honestIds.length];
      const publisher = nodes.get(publisherId)!;
      publisher.delivered.add(ev.id);
      publisher.engine.publishEvent(ev);
    });

    // Run up to 3 anti-entropy rounds to reconcile any paths disrupted by the evicted Byzantine nodes
    for (let round = 1; round <= 3; round++) {
      for (const hId of honestIds) {
        nodes.get(hId)!.antiEntropy.runAntiEntropyRound(200, 210, 3);
      }
    }

    // Every honest node must have received all 5 valid events and 0 Byzantine events
    for (const hId of honestIds) {
      const { delivered, engine, antiEntropy } = nodes.get(hId)!;
      expect(Array.from(delivered).sort()).toEqual(['ev-1', 'ev-2', 'ev-3', 'ev-4', 'ev-5']);
      engine.destroy();
      antiEntropy.destroy();
    }
  });
});
