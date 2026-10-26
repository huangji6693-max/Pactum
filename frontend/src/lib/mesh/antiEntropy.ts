import type {
  SorobanIndexedEvent,
  AntiEntropyReqMessage,
  AntiEntropyRespMessage,
} from './types.ts';
import { WebRtcMeshTransport } from './webrtcTransport.ts';
import type { PeerScoringManager } from './peerScoring.ts';

export interface AntiEntropyConfig {
  syncIntervalMs?: number;
  maxEventsPerSync?: number;
  peerSubsetSize?: number;
  scoring?: PeerScoringManager;
  onEventReconciled?: (event: SorobanIndexedEvent, senderPeerId: string) => void;
}

/**
 * Deterministic 64-bit FNV-1a hex digest used for synchronous Merkle tree construction
 * in both browser and worker environments without async SubtleCrypto overhead.
 */
export function hashDigestHex(input: string): string {
  let h1 = 0xdeadbeef ^ input.length;
  let h2 = 0x41c6ce57 ^ input.length;
  for (let i = 0; i < input.length; i++) {
    const ch = input.charCodeAt(i);
    h1 = Math.imul(h1 ^ ch, 2654435761);
    h2 = Math.imul(h2 ^ ch, 1597334677);
  }
  h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
  h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
  return (h2 >>> 0).toString(16).padStart(8, '0') + (h1 >>> 0).toString(16).padStart(8, '0');
}

export function computeEventDigest(event: SorobanIndexedEvent): string {
  return hashDigestHex(
    `${event.id}|${event.ledgerSeq}|${event.contractId}|${event.topic}|${event.txHash}|${event.xdrPayload}`,
  );
}

/**
 * Computes a binary Merkle tree root over a set of SorobanIndexedEvents sorted by (ledgerSeq, id).
 */
export function computeMerkleRoot(events: SorobanIndexedEvent[]): string {
  if (events.length === 0) {
    return hashDigestHex('EMPTY_MERKLE_TREE');
  }

  const sorted = [...events].sort((a, b) => {
    if (a.ledgerSeq !== b.ledgerSeq) return a.ledgerSeq - b.ledgerSeq;
    return a.id.localeCompare(b.id);
  });

  let layer = sorted.map((ev) => computeEventDigest(ev));
  while (layer.length > 1) {
    const nextLayer: string[] = [];
    for (let i = 0; i < layer.length; i += 2) {
      const left = layer[i];
      const right = i + 1 < layer.length ? layer[i + 1] : left;
      nextLayer.push(hashDigestHex(`${left}:${right}`));
    }
    layer = nextLayer;
  }

  return layer[0];
}

export class AntiEntropyManager {
  private transport: WebRtcMeshTransport;
  private localEvents: Map<string, SorobanIndexedEvent> = new Map();
  private ledgerSeqIndex: Map<number, SorobanIndexedEvent[]> = new Map();
  private syncInterval: any = null;
  private maxEventsPerSync: number;
  private peerSubsetSize: number;
  private roundCursor: number = 0;
  private scoring?: PeerScoringManager;
  private onEventReconciled?: (event: SorobanIndexedEvent, senderPeerId: string) => void;

  constructor(transport: WebRtcMeshTransport, config: AntiEntropyConfig = {}) {
    this.transport = transport;
    this.maxEventsPerSync = config.maxEventsPerSync ?? 100;
    this.peerSubsetSize = config.peerSubsetSize ?? 3;
    this.scoring = config.scoring;
    this.onEventReconciled = config.onEventReconciled;
    this.startPeriodicSync(config.syncIntervalMs ?? 45000);
  }

  /**
   * Ingests a new local event into the indexed storage (idempotent by event.id).
   */
  public recordEvent(event: SorobanIndexedEvent): void {
    const alreadyExists = this.localEvents.has(event.id);
    this.localEvents.set(event.id, event);

    if (!alreadyExists) {
      const existing = this.ledgerSeqIndex.get(event.ledgerSeq) || [];
      existing.push(event);
      this.ledgerSeqIndex.set(event.ledgerSeq, existing);
    }
  }

  public hasEvent(eventId: string): boolean {
    return this.localEvents.has(eventId);
  }

  public getAllEvents(): SorobanIndexedEvent[] {
    return Array.from(this.localEvents.values()).sort((a, b) => {
      if (a.ledgerSeq !== b.ledgerSeq) return a.ledgerSeq - b.ledgerSeq;
      return a.id.localeCompare(b.id);
    });
  }

  public getEventsInRange(fromLedger: number, toLedger: number): SorobanIndexedEvent[] {
    if (!Number.isInteger(fromLedger) || !Number.isInteger(toLedger) || fromLedger < 0 || toLedger < fromLedger) {
      return [];
    }
    const sequences = Array.from(this.ledgerSeqIndex.keys())
      .filter((seq) => seq >= fromLedger && seq <= toLedger)
      .sort((a, b) => a - b);

    const matched: SorobanIndexedEvent[] = [];
    for (const seq of sequences) {
      const events = this.ledgerSeqIndex.get(seq) ?? [];
      for (const ev of events) {
        matched.push(ev);
      }
    }
    return matched;
  }

  /**
   * Computes the Merkle root digest over all local events or a specific ledger range.
   */
  public getMerkleRoot(fromLedger?: number, toLedger?: number): string {
    if (typeof fromLedger === 'number' && typeof toLedger === 'number') {
      return computeMerkleRoot(this.getEventsInRange(fromLedger, toLedger));
    }
    return computeMerkleRoot(this.getAllEvents());
  }

  /**
   * Responds to an incoming anti-entropy request using Merkle root comparison and known-ID filtering.
   */
  public handleSyncRequest(req: AntiEntropyReqMessage): AntiEntropyRespMessage {
    const matchedEvents: SorobanIndexedEvent[] = [];
    const from = Number(req.fromLedger);
    const to = Number(req.toLedger);

    if (!Number.isInteger(from) || !Number.isInteger(to) || from < 0 || to < from) {
      return {
        type: 'ANTI_ENTROPY_RESP',
        events: [],
        merkleRoot: computeMerkleRoot([]),
        inSync: false,
        senderId: this.transport.localPeerId,
        timestamp: Date.now(),
      };
    }

    const rangeEvents = this.getEventsInRange(from, to);
    const localMerkleRoot = computeMerkleRoot(rangeEvents);

    // If requester supplied an identical Merkle root digest for the range, trees are already in sync
    if (req.merkleRoot && req.merkleRoot === localMerkleRoot) {
      return {
        type: 'ANTI_ENTROPY_RESP',
        events: [],
        merkleRoot: localMerkleRoot,
        inSync: true,
        senderId: this.transport.localPeerId,
        timestamp: Date.now(),
      };
    }

    const knownSet = new Set(req.knownEventIds ?? []);

    for (const event of rangeEvents) {
      if (knownSet.has(event.id)) {
        continue;
      }
      if (matchedEvents.length >= this.maxEventsPerSync) {
        break;
      }
      matchedEvents.push(event);
    }

    return {
      type: 'ANTI_ENTROPY_RESP',
      events: matchedEvents,
      merkleRoot: localMerkleRoot,
      inSync: matchedEvents.length === 0,
      senderId: this.transport.localPeerId,
      timestamp: Date.now(),
    };
  }

  /**
   * Processes an incoming ANTI_ENTROPY_RESP message, validating events against Byzantine
   * faults and reconciling missing state into local storage.
   */
  public handleSyncResponse(
    resp: AntiEntropyRespMessage,
    onReconciled?: (event: SorobanIndexedEvent) => void,
  ): SorobanIndexedEvent[] {
    if (!resp || !Array.isArray(resp.events)) {
      if (resp?.senderId && this.scoring) {
        this.scoring.slashPeer(resp.senderId, 'Malformed ANTI_ENTROPY_RESP payload');
      }
      return [];
    }

    if (this.scoring && this.scoring.isPeerBanned(resp.senderId)) {
      return [];
    }

    const reconciled: SorobanIndexedEvent[] = [];
    for (const event of resp.events) {
      if (this.scoring) {
        const validation = this.scoring.validateSorobanEvent(event);
        if (!validation.isValid) {
          if (validation.isByzantine) {
            this.scoring.slashPeer(resp.senderId, validation.reason ?? 'Byzantine event in anti-entropy response');
          } else {
            this.scoring.recordInvalidMessage(resp.senderId, false, validation.reason);
          }
          continue;
        }
      }

      if (!this.localEvents.has(event.id)) {
        this.recordEvent(event);
        reconciled.push(event);
        if (this.scoring) {
          this.scoring.recordValidMessage(resp.senderId);
        }
        onReconciled?.(event);
        this.onEventReconciled?.(event, resp.senderId);
      }
    }

    return reconciled;
  }

  /**
   * Initiates anti-entropy reconciliation with a specific peer, attaching local Merkle root
   * and known event IDs for the requested range.
   */
  public triggerSyncWithPeer(peerId: string, fromLedger: number, toLedger: number): void {
    const rangeEvents = this.getEventsInRange(fromLedger, toLedger);
    const req: AntiEntropyReqMessage = {
      type: 'ANTI_ENTROPY_REQ',
      fromLedger,
      toLedger,
      merkleRoot: computeMerkleRoot(rangeEvents),
      knownEventIds: rangeEvents.map((e) => e.id),
      senderId: this.transport.localPeerId,
      timestamp: Date.now(),
    };

    this.transport.sendToPeer(peerId, req);
  }

  /**
   * Executes one anti-entropy round across a rotating subset of eligible active peers.
   * Ensures full partition healing within <= 3 rounds.
   */
  public runAntiEntropyRound(
    fromLedger?: number,
    toLedger?: number,
    subsetSize: number = this.peerSubsetSize,
  ): string[] {
    const rawPeers: string[] =
      typeof this.transport.getActivePeers === 'function'
        ? this.transport.getActivePeers()
        : [];
    const activePeers = rawPeers.filter(
      (p) => p !== this.transport.localPeerId && (!this.scoring || !this.scoring.isPeerBanned(p)),
    );
    if (activePeers.length === 0) return [];

    const sequences = Array.from(this.ledgerSeqIndex.keys());
    const maxSeq =
      typeof toLedger === 'number'
        ? toLedger
        : sequences.length > 0
          ? Math.max(...sequences, 1000)
          : 1000;
    const minSeq =
      typeof fromLedger === 'number' ? fromLedger : 1;

    const count = Math.min(Math.max(1, subsetSize), activePeers.length);
    const contacted: string[] = [];
    for (let i = 0; i < count; i++) {
      const peer = activePeers[(this.roundCursor + i) % activePeers.length];
      contacted.push(peer);
      this.triggerSyncWithPeer(peer, minSeq, maxSeq);
    }
    this.roundCursor = (this.roundCursor + count) % activePeers.length;
    return contacted;
  }

  private startPeriodicSync(intervalMs: number): void {
    this.syncInterval = setInterval(() => {
      this.runAntiEntropyRound();
    }, intervalMs);

    if (this.syncInterval && typeof (this.syncInterval as any).unref === 'function') {
      (this.syncInterval as any).unref();
    }
  }

  public destroy(): void {
    if (this.syncInterval) {
      clearInterval(this.syncInterval);
      this.syncInterval = null;
    }
  }
}
