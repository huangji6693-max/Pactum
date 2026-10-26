import { describe, it, expect } from 'vitest';
import { xdr } from '@stellar/stellar-sdk';
import { PeerScoringManager } from '../peerScoring.ts';
import type { SorobanIndexedEvent } from '../types.ts';

describe('PeerScoringManager', () => {
  it('rewards peer score on delivering valid messages and tracks low delivery latency', () => {
    const manager = new PeerScoringManager();
    const peerId = 'peer-alice';

    manager.recordValidMessage(peerId);
    let rep = manager.getReputation(peerId);
    expect(rep.score).toBe(5);
    expect(rep.validMessagesDelivered).toBe(1);

    manager.recordValidMessage(peerId);
    rep = manager.getReputation(peerId);
    expect(rep.score).toBe(10);
    expect(rep.validMessagesDelivered).toBe(2);

    manager.recordDeliveryLatency(peerId, 80); // fast delivery <= 150ms (+2)
    expect(manager.getReputation(peerId).score).toBe(12);
    expect(manager.getReputation(peerId).averageLatencyMs).toBe(80);
  });

  it('penalizes duplicate messages, high duplicate ratios, and slow delivery latency', () => {
    const manager = new PeerScoringManager({ maxDuplicateRatio: 0.5 });
    const peerId = 'peer-bob';

    manager.recordDuplicateMessage(peerId);
    const rep = manager.getReputation(peerId);
    expect(rep.score).toBe(-2);
    expect(rep.duplicateMessages).toBe(1);

    // Trigger excess duplicate ratio penalty after >= 4 messages
    manager.recordDuplicateMessage(peerId);
    manager.recordDuplicateMessage(peerId);
    manager.recordDuplicateMessage(peerId);
    expect(manager.getDuplicateRatio(peerId)).toBe(1);
    expect(manager.getReputation(peerId).score).toBeLessThan(-8);

    manager.recordDeliveryLatency(peerId, 3500); // slow delivery >= 2000ms
    expect(manager.getReputation(peerId).averageLatencyMs).toBeGreaterThan(0);
  });

  it('quarantines, slashes, and locally blacklists peers broadcasting invalid or Byzantine state', () => {
    const slashedEvents: Array<{ peerId: string; reason: string }> = [];
    const manager = new PeerScoringManager({
      quarantineThreshold: -25,
      banThreshold: -50,
      onPeerSlashed: (peerId, reason) => slashedEvents.push({ peerId, reason }),
    });
    const peerId = 'peer-malicious';

    // Invalid message (-40)
    manager.recordInvalidMessage(peerId, false);
    let rep = manager.getReputation(peerId);
    expect(rep.score).toBe(-40);
    expect(rep.isQuarantined).toBe(true);
    expect(rep.isBanned).toBe(false);
    expect(manager.isPeerEligibleForEagerGossip(peerId)).toBe(false);

    // Byzantine attack (-80) -> crosses ban threshold (-50) and adds to blacklist
    manager.recordInvalidMessage(peerId, true);
    rep = manager.getReputation(peerId);
    expect(rep.score).toBe(-100);
    expect(rep.isBanned).toBe(true);
    expect(manager.isPeerBanned(peerId)).toBe(true);
    expect(manager.isBlacklisted(peerId)).toBe(true);
    expect(slashedEvents.length).toBe(1);
    expect(slashedEvents[0].peerId).toBe(peerId);
  });

  it('validates Soroban events correctly', () => {
    const manager = new PeerScoringManager();

    const realXdrPayload = xdr.ScVal.scvSymbol('transfer').toXDR('base64');

    const validEvent: SorobanIndexedEvent = {
      id: 'valid-123',
      contractId: 'C123',
      topic: 'transfer',
      xdrPayload: realXdrPayload,
      ledgerSeq: 100500,
      txHash: '0xabc',
      timestamp: Date.now(),
      originPeerId: 'peer-alice',
    };

    const validResult = manager.validateSorobanEvent(validEvent);
    expect(validResult.isValid).toBe(true);

    // Test Base64-compatible non-XDR payload (should be rejected as Byzantine)
    const nonXdrBase64Event: SorobanIndexedEvent = {
      ...validEvent,
      xdrPayload: btoa('valid-base64-string-but-not-valid-soroban-xdr'),
    };
    const nonXdrResult = manager.validateSorobanEvent(nonXdrBase64Event);
    expect(nonXdrResult.isValid).toBe(false);
    expect(nonXdrResult.isByzantine).toBe(true);

    const invalidSeqEvent: SorobanIndexedEvent = {
      ...validEvent,
      ledgerSeq: -1,
    };
    const invalidResult = manager.validateSorobanEvent(invalidSeqEvent);
    expect(invalidResult.isValid).toBe(false);
    expect(invalidResult.isByzantine).toBe(true);
  });

  it('decays scores periodically towards neutral baseline', () => {
    const manager = new PeerScoringManager({ decayFactor: 0.5 });
    const peerId = 'peer-recovering';

    manager.recordValidMessage(peerId);
    manager.recordValidMessage(peerId); // score = 10

    manager.decayScores();
    const rep = manager.getReputation(peerId);
    expect(rep.score).toBe(5);
  });
});
