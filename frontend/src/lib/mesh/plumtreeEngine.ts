import type {
  GossipDataMessage,
  IHaveMessage,
  GraftMessage,
  PruneMessage,
  AntiEntropyReqMessage,
  AntiEntropyRespMessage,
  MeshProtocolMessage,
  SorobanIndexedEvent,
} from './types.ts';
import { PeerScoringManager } from './peerScoring.ts';
import type { AntiEntropyManager } from './antiEntropy.ts';

export interface PlumtreeConfig {
  localPeerId: string;
  targetEagerFanout?: number;
  minEagerFanout?: number;
  maxEagerFanout?: number;
  iHaveIntervalMs?: number;
  graftTimeoutMs?: number;
  messageCacheTtlMs?: number;
  maxHopCount?: number;
}

export type SendMessageHandler = (targetPeerId: string, message: MeshProtocolMessage) => void;
export type MessageDeliveryHandler = (event: SorobanIndexedEvent, senderPeerId: string) => void;
export type DisconnectPeerHandler = (peerId: string, reason: string) => void;

export class PlumtreeEngine {
  public localPeerId: string;
  private eagerNeighbors: Set<string> = new Set();
  private lazyNeighbors: Set<string> = new Set();
  private seenMessages: Map<string, number> = new Map(); // messageId -> timestamp
  private eventCache: Map<string, SorobanIndexedEvent> = new Map(); // messageId -> event
  private graftTimers: Map<string, { timer: any; peerId: string }> = new Map(); // messageId -> timer info
  private pendingIHave: Set<string> = new Set(); // messageIds awaiting lazy broadcast
  private iHaveInterval: any = null;
  private unsubscribeSlash?: () => void;

  public scoring: PeerScoringManager;
  private antiEntropy?: AntiEntropyManager;
  private sendMessage: SendMessageHandler;
  private onDeliver: MessageDeliveryHandler;
  private onDisconnect?: DisconnectPeerHandler;
  private config: Required<PlumtreeConfig>;

  // Metrics
  public messagesReceivedCount: number = 0;
  public messagesRelayedCount: number = 0;
  public duplicatesPrunedCount: number = 0;
  public byzantineDroppedCount: number = 0;

  constructor(
    config: PlumtreeConfig,
    scoring: PeerScoringManager,
    sendMessage: SendMessageHandler,
    onDeliver: MessageDeliveryHandler,
    onDisconnect?: DisconnectPeerHandler,
  ) {
    this.localPeerId = config.localPeerId;
    this.scoring = scoring;
    this.sendMessage = sendMessage;
    this.onDeliver = onDeliver;
    this.onDisconnect = onDisconnect;

    this.config = {
      localPeerId: config.localPeerId,
      targetEagerFanout: config.targetEagerFanout ?? 4,
      minEagerFanout: config.minEagerFanout ?? 3,
      maxEagerFanout: config.maxEagerFanout ?? 6,
      iHaveIntervalMs: config.iHaveIntervalMs ?? 300,
      graftTimeoutMs: config.graftTimeoutMs ?? 150,
      messageCacheTtlMs: config.messageCacheTtlMs ?? 5 * 60 * 1000,
      maxHopCount: config.maxHopCount ?? 12,
    };

    // Automatically evict & disconnect peers immediately upon slashing or ban
    this.unsubscribeSlash = this.scoring.onPeerSlashed((peerId, reason) => {
      this.evictPeer(peerId, reason);
    });

    this.startIHaveLoop();
  }

  /**
   * Attaches an AntiEntropyManager so ANTI_ENTROPY_REQ and ANTI_ENTROPY_RESP frames
   * routed through Plumtree are automatically reconciled and delivered.
   */
  public attachAntiEntropy(antiEntropy: AntiEntropyManager): void {
    this.antiEntropy = antiEntropy;
  }

  /**
   * Registers a newly connected peer into the overlay.
   */
  public addPeer(peerId: string): void {
    if (!peerId || peerId === this.localPeerId) return;
    if (this.scoring.isPeerBanned(peerId) || this.scoring.isBlacklisted(peerId)) {
      return;
    }

    if (this.eagerNeighbors.has(peerId) || this.lazyNeighbors.has(peerId)) {
      return;
    }

    // If we have fewer eager peers than target and peer is eligible, add as eager
    if (
      this.eagerNeighbors.size < this.config.targetEagerFanout &&
      this.scoring.isPeerEligibleForEagerGossip(peerId)
    ) {
      this.eagerNeighbors.add(peerId);
    } else {
      this.lazyNeighbors.add(peerId);
    }
  }

  /**
   * Removes a disconnected peer from all overlays and rebalances eager fanout.
   */
  public removePeer(peerId: string): void {
    this.eagerNeighbors.delete(peerId);
    this.lazyNeighbors.delete(peerId);

    // Rebalance eager fanout if below threshold
    this.rebalanceOverlays();
  }

  /**
   * Evicts a Byzantine/banned peer from overlays and triggers transport disconnection.
   */
  public evictPeer(peerId: string, reason: string = 'Peer banned'): void {
    const wasPresent = this.eagerNeighbors.has(peerId) || this.lazyNeighbors.has(peerId);
    this.eagerNeighbors.delete(peerId);
    this.lazyNeighbors.delete(peerId);
    if (wasPresent) {
      this.rebalanceOverlays();
    }
    this.onDisconnect?.(peerId, reason);
  }

  /**
   * Publishes a new locally-indexed Soroban event to the gossip mesh.
   */
  public publishEvent(event: SorobanIndexedEvent): void {
    const messageId = event.id;
    this.seenMessages.set(messageId, Date.now());
    this.eventCache.set(messageId, event);
    this.antiEntropy?.recordEvent(event);

    const message: GossipDataMessage = {
      type: 'GOSSIP_DATA',
      messageId,
      topic: event.topic,
      event,
      hopCount: 0,
      senderId: this.localPeerId,
      timestamp: Date.now(),
    };

    // Eager push to all eager neighbors
    for (const peerId of this.eagerNeighbors) {
      if (this.scoring.isPeerEligibleForEagerGossip(peerId)) {
        this.sendMessage(peerId, message);
        this.messagesRelayedCount++;
      }
    }

    // Queue for lazy push
    this.pendingIHave.add(messageId);
  }

  /**
   * Ingests and processes an incoming protocol message.
   */
  public handleMessage(senderPeerId: string, message: MeshProtocolMessage): void {
    if (this.scoring.isPeerBanned(senderPeerId) || this.scoring.isBlacklisted(senderPeerId)) {
      this.evictPeer(senderPeerId, 'Peer is blacklisted');
      return;
    }

    if (!message || typeof message !== 'object' || typeof message.type !== 'string') {
      this.byzantineDroppedCount++;
      this.scoring.slashPeer(senderPeerId, 'Malformed protocol message envelope');
      return;
    }

    switch (message.type) {
      case 'GOSSIP_DATA':
        this.handleGossipData(senderPeerId, message);
        break;
      case 'IHAVE':
        this.handleIHave(senderPeerId, message);
        break;
      case 'GRAFT':
        this.handleGraft(senderPeerId, message);
        break;
      case 'PRUNE':
        this.handlePrune(senderPeerId, message);
        break;
      case 'ANTI_ENTROPY_REQ':
        this.handleAntiEntropyReq(senderPeerId, message);
        break;
      case 'ANTI_ENTROPY_RESP':
        this.handleAntiEntropyResp(senderPeerId, message);
        break;
      default:
        break;
    }
  }

  private handleGossipData(senderPeerId: string, msg: GossipDataMessage): void {
    this.messagesReceivedCount++;

    // Detect Sybil routing loop / invalid hop count
    if (
      typeof msg.hopCount !== 'number' ||
      msg.hopCount < 0 ||
      msg.hopCount > this.config.maxHopCount ||
      !msg.messageId
    ) {
      this.byzantineDroppedCount++;
      this.scoring.slashPeer(senderPeerId, 'Invalid hopCount or missing messageId in GOSSIP_DATA');
      return;
    }

    // 1. Validate event structure & cryptographic integrity
    const validation = this.scoring.validateSorobanEvent(msg.event);
    if (!validation.isValid) {
      this.byzantineDroppedCount++;
      if (validation.isByzantine) {
        this.scoring.slashPeer(
          senderPeerId,
          validation.reason ?? 'Malformed or Byzantine Soroban event injection',
        );
      } else {
        this.scoring.recordInvalidMessage(senderPeerId, false, validation.reason);
      }
      return;
    }

    const isDuplicate = this.seenMessages.has(msg.messageId);

    // Cancel any active graft timer for this message
    const graftEntry = this.graftTimers.get(msg.messageId);
    if (graftEntry) {
      clearTimeout(graftEntry.timer);
      this.graftTimers.delete(msg.messageId);
    }

    if (!isDuplicate) {
      const now = Date.now();
      const deliveryLatencyMs =
        typeof msg.timestamp === 'number' && msg.timestamp <= now
          ? now - msg.timestamp
          : undefined;

      // Novel message
      this.seenMessages.set(msg.messageId, now);
      this.eventCache.set(msg.messageId, msg.event);
      this.antiEntropy?.recordEvent(msg.event);
      this.scoring.recordValidMessage(senderPeerId, deliveryLatencyMs);

      // Ensure sender is on eager overlay if eligible
      if (
        this.lazyNeighbors.has(senderPeerId) &&
        this.scoring.isPeerEligibleForEagerGossip(senderPeerId)
      ) {
        this.lazyNeighbors.delete(senderPeerId);
        this.eagerNeighbors.add(senderPeerId);
      }

      // Deliver to local application/indexer
      this.onDeliver(msg.event, senderPeerId);

      // Forward eagerly to other eager peers
      const forwardMsg: GossipDataMessage = {
        ...msg,
        hopCount: msg.hopCount + 1,
        senderId: this.localPeerId,
      };

      for (const peerId of this.eagerNeighbors) {
        if (peerId !== senderPeerId && this.scoring.isPeerEligibleForEagerGossip(peerId)) {
          this.sendMessage(peerId, forwardMsg);
          this.messagesRelayedCount++;
        }
      }

      // Enqueue for lazy announcement
      this.pendingIHave.add(msg.messageId);
    } else {
      // Duplicate message received via eager link -> Prune sender to optimize spanning tree
      this.scoring.recordDuplicateMessage(senderPeerId);
      this.duplicatesPrunedCount++;

      if (this.eagerNeighbors.has(senderPeerId)) {
        this.eagerNeighbors.delete(senderPeerId);
        this.lazyNeighbors.add(senderPeerId);

        const pruneMsg: PruneMessage = {
          type: 'PRUNE',
          senderId: this.localPeerId,
          timestamp: Date.now(),
        };
        this.sendMessage(senderPeerId, pruneMsg);
      }
    }
  }

  private handleIHave(senderPeerId: string, msg: IHaveMessage): void {
    if (!Array.isArray(msg.messageIds)) {
      this.byzantineDroppedCount++;
      this.scoring.slashPeer(senderPeerId, 'Malformed IHAVE messageIds array');
      return;
    }

    for (const msgId of msg.messageIds) {
      if (!this.seenMessages.has(msgId) && !this.graftTimers.has(msgId)) {
        // Start a graft timer: if message is not received via eager links within timeout, send GRAFT
        const timer = setTimeout(() => {
          this.graftTimers.delete(msgId);
          if (!this.seenMessages.has(msgId)) {
            this.sendGraft(senderPeerId, msgId);
          }
        }, this.config.graftTimeoutMs);

        this.graftTimers.set(msgId, { timer, peerId: senderPeerId });
      }
    }
  }

  private handleGraft(senderPeerId: string, msg: GraftMessage): void {
    if (this.scoring.isPeerBanned(senderPeerId)) return;

    // Promote sender from lazy to eager overlay
    this.lazyNeighbors.delete(senderPeerId);
    this.eagerNeighbors.add(senderPeerId);

    // If a specific missing message was requested, replay it from local cache
    if (msg.messageId && this.eventCache.has(msg.messageId)) {
      const cachedEvent = this.eventCache.get(msg.messageId)!;
      const replayMsg: GossipDataMessage = {
        type: 'GOSSIP_DATA',
        messageId: cachedEvent.id,
        topic: cachedEvent.topic,
        event: cachedEvent,
        hopCount: 0,
        senderId: this.localPeerId,
        timestamp: Date.now(),
      };
      this.sendMessage(senderPeerId, replayMsg);
      this.messagesRelayedCount++;
    }
  }

  private handlePrune(senderPeerId: string, _msg: PruneMessage): void {
    // Demote peer to lazy overlay
    if (this.eagerNeighbors.has(senderPeerId)) {
      this.eagerNeighbors.delete(senderPeerId);
      this.lazyNeighbors.add(senderPeerId);
    }
  }

  private handleAntiEntropyReq(senderPeerId: string, msg: AntiEntropyReqMessage): void {
    if (!this.antiEntropy) return;
    const resp = this.antiEntropy.handleSyncRequest(msg);
    this.sendMessage(senderPeerId, resp);
  }

  private handleAntiEntropyResp(senderPeerId: string, msg: AntiEntropyRespMessage): void {
    if (!this.antiEntropy) return;
    const reconciled = this.antiEntropy.handleSyncResponse(msg, (event) => {
      if (!this.seenMessages.has(event.id)) {
        this.seenMessages.set(event.id, Date.now());
        this.eventCache.set(event.id, event);
        this.onDeliver(event, senderPeerId);
      }
    });

    if (reconciled.length > 0 && this.lazyNeighbors.has(senderPeerId)) {
      // Promote helpful anti-entropy peer to heal partition
      if (
        this.eagerNeighbors.size < this.config.maxEagerFanout &&
        this.scoring.isPeerEligibleForEagerGossip(senderPeerId)
      ) {
        this.lazyNeighbors.delete(senderPeerId);
        this.eagerNeighbors.add(senderPeerId);
      }
    }
  }

  private sendGraft(peerId: string, messageId?: string): void {
    if (this.scoring.isPeerBanned(peerId)) return;

    // Promote to eager
    this.lazyNeighbors.delete(peerId);
    this.eagerNeighbors.add(peerId);

    const graftMsg: GraftMessage = {
      type: 'GRAFT',
      messageId,
      senderId: this.localPeerId,
      timestamp: Date.now(),
    };
    this.sendMessage(peerId, graftMsg);
  }

  private rebalanceOverlays(): void {
    while (this.eagerNeighbors.size < this.config.minEagerFanout && this.lazyNeighbors.size > 0) {
      const candidates = Array.from(this.lazyNeighbors).filter((p) =>
        this.scoring.isPeerEligibleForEagerGossip(p),
      );

      if (candidates.length === 0) break;
      const promoted = candidates[Math.floor(Math.random() * candidates.length)];
      this.sendGraft(promoted);
    }
  }

  private startIHaveLoop(): void {
    this.iHaveInterval = setInterval(() => {
      if (this.pendingIHave.size > 0 && this.lazyNeighbors.size > 0) {
        const messageIds = Array.from(this.pendingIHave);
        this.pendingIHave.clear();

        const iHaveMsg: IHaveMessage = {
          type: 'IHAVE',
          messageIds,
          senderId: this.localPeerId,
          timestamp: Date.now(),
        };

        for (const peerId of this.lazyNeighbors) {
          if (!this.scoring.isPeerBanned(peerId)) {
            this.sendMessage(peerId, iHaveMsg);
          }
        }
      }

      this.pruneOldCache();
    }, this.config.iHaveIntervalMs);

    if (this.iHaveInterval && typeof (this.iHaveInterval as any).unref === 'function') {
      (this.iHaveInterval as any).unref();
    }
  }

  private pruneOldCache(): void {
    const now = Date.now();
    for (const [msgId, timestamp] of this.seenMessages.entries()) {
      if (now - timestamp > this.config.messageCacheTtlMs) {
        this.seenMessages.delete(msgId);
        this.eventCache.delete(msgId);
      }
    }
  }

  public destroy(): void {
    if (this.unsubscribeSlash) {
      this.unsubscribeSlash();
      this.unsubscribeSlash = undefined;
    }
    if (this.iHaveInterval) {
      clearInterval(this.iHaveInterval);
      this.iHaveInterval = null;
    }
    for (const { timer } of this.graftTimers.values()) {
      clearTimeout(timer);
    }
    this.graftTimers.clear();
  }

  public getEagerNeighbors(): string[] {
    return Array.from(this.eagerNeighbors);
  }

  public getLazyNeighbors(): string[] {
    return Array.from(this.lazyNeighbors);
  }
}
