import type { PeerReputation, SorobanIndexedEvent } from './types.ts';
import { xdr } from '@stellar/stellar-sdk';

export interface PeerScoringConfig {
  initialScore?: number;
  validMessageReward?: number;
  duplicateMessagePenalty?: number;
  invalidMessagePenalty?: number;
  byzantineAttackPenalty?: number;
  quarantineThreshold?: number;
  banThreshold?: number;
  banDurationMs?: number;
  decayIntervalMs?: number;
  decayFactor?: number;
  fastDeliveryThresholdMs?: number;
  slowDeliveryThresholdMs?: number;
  fastDeliveryReward?: number;
  slowDeliveryPenalty?: number;
  maxDuplicateRatio?: number;
  excessDuplicatePenalty?: number;
  onPeerSlashed?: (peerId: string, reason: string) => void;
}

export class PeerScoringManager {
  private reputations: Map<string, PeerReputation> = new Map();
  private blacklist: Set<string> = new Set();
  private slashListeners: Set<(peerId: string, reason: string) => void> = new Set();
  private config: Required<Omit<PeerScoringConfig, 'onPeerSlashed'>>;

  constructor(config?: PeerScoringConfig) {
    this.config = {
      initialScore: config?.initialScore ?? 0,
      validMessageReward: config?.validMessageReward ?? 5,
      duplicateMessagePenalty: config?.duplicateMessagePenalty ?? 2,
      invalidMessagePenalty: config?.invalidMessagePenalty ?? 40,
      byzantineAttackPenalty: config?.byzantineAttackPenalty ?? 80,
      quarantineThreshold: config?.quarantineThreshold ?? -25,
      banThreshold: config?.banThreshold ?? -50,
      banDurationMs: config?.banDurationMs ?? 5 * 60 * 1000, // 5 min ban
      decayIntervalMs: config?.decayIntervalMs ?? 60 * 1000, // 1 min decay
      decayFactor: config?.decayFactor ?? 0.95, // 5% decay towards 0
      fastDeliveryThresholdMs: config?.fastDeliveryThresholdMs ?? 150,
      slowDeliveryThresholdMs: config?.slowDeliveryThresholdMs ?? 2000,
      fastDeliveryReward: config?.fastDeliveryReward ?? 2,
      slowDeliveryPenalty: config?.slowDeliveryPenalty ?? 8,
      maxDuplicateRatio: config?.maxDuplicateRatio ?? 0.65,
      excessDuplicatePenalty: config?.excessDuplicatePenalty ?? 10,
    };

    if (config?.onPeerSlashed) {
      this.slashListeners.add(config.onPeerSlashed);
    }
  }

  /**
   * Registers a callback invoked immediately when a peer is slashed or banned.
   */
  public onPeerSlashed(listener: (peerId: string, reason: string) => void): () => void {
    this.slashListeners.add(listener);
    return () => this.slashListeners.delete(listener);
  }

  /**
   * Retrieves or initializes reputation record for a peer.
   */
  public getReputation(peerId: string): PeerReputation {
    const existing = this.reputations.get(peerId);
    const now = Date.now();

    if (!existing) {
      const rep: PeerReputation = {
        peerId,
        score: this.config.initialScore,
        validMessagesDelivered: 0,
        duplicateMessages: 0,
        invalidMessages: 0,
        lastActive: now,
        isQuarantined: false,
        isBanned: false,
        averageLatencyMs: 0,
        duplicateRatio: 0,
      };
      this.reputations.set(peerId, rep);
      return rep;
    }

    // Check if temporary ban has expired (permanently blacklisted peers remain banned)
    if (
      existing.isBanned &&
      !this.blacklist.has(peerId) &&
      existing.banExpiry &&
      now >= existing.banExpiry
    ) {
      existing.isBanned = false;
      existing.isQuarantined = false;
      existing.score = this.config.quarantineThreshold + 5;
      delete existing.banExpiry;
    }

    return existing;
  }

  /**
   * Records a valid, novel message delivery from a peer, optionally incorporating delivery latency.
   */
  public recordValidMessage(peerId: string, deliveryLatencyMs?: number): void {
    const rep = this.getReputation(peerId);
    if (rep.isBanned || this.blacklist.has(peerId)) return;

    rep.validMessagesDelivered += 1;
    rep.lastActive = Date.now();
    this.updateDuplicateRatio(rep);
    this.adjustScore(rep, this.config.validMessageReward);

    if (typeof deliveryLatencyMs === 'number' && deliveryLatencyMs >= 0) {
      this.recordDeliveryLatency(peerId, deliveryLatencyMs);
    }
  }

  /**
   * Scores peer based on message delivery latency (exponential moving average).
   */
  public recordDeliveryLatency(peerId: string, latencyMs: number): void {
    const rep = this.getReputation(peerId);
    if (rep.isBanned || this.blacklist.has(peerId)) return;

    const cleanLatency = Math.max(0, latencyMs);
    const prevAvg = rep.averageLatencyMs ?? 0;
    rep.averageLatencyMs =
      prevAvg === 0
        ? cleanLatency
        : Math.round((prevAvg * 0.7 + cleanLatency * 0.3) * 100) / 100;

    if (cleanLatency <= this.config.fastDeliveryThresholdMs) {
      this.adjustScore(rep, this.config.fastDeliveryReward);
    } else if (cleanLatency >= this.config.slowDeliveryThresholdMs) {
      this.adjustScore(rep, -this.config.slowDeliveryPenalty, 'Excessive gossip delivery latency');
    }
  }

  /**
   * Records a duplicate message delivery (subtle penalty, prompts PRUNE, and penalizes high duplicate ratios).
   */
  public recordDuplicateMessage(peerId: string): void {
    const rep = this.getReputation(peerId);
    if (rep.isBanned || this.blacklist.has(peerId)) return;

    rep.duplicateMessages += 1;
    rep.lastActive = Date.now();
    this.updateDuplicateRatio(rep);

    let penalty = this.config.duplicateMessagePenalty;
    const total = rep.validMessagesDelivered + rep.duplicateMessages;
    if (total >= 4 && (rep.duplicateRatio ?? 0) > this.config.maxDuplicateRatio) {
      penalty += this.config.excessDuplicatePenalty;
    }

    this.adjustScore(rep, -penalty, 'Duplicate message flooding');
  }

  /**
   * Records an invalid / malformed message from a peer.
   */
  public recordInvalidMessage(
    peerId: string,
    isByzantineAttack: boolean = false,
    reason?: string,
  ): void {
    const rep = this.getReputation(peerId);
    rep.invalidMessages += 1;
    rep.lastActive = Date.now();
    const penalty = isByzantineAttack
      ? this.config.byzantineAttackPenalty
      : this.config.invalidMessagePenalty;
    const wasBanned = rep.isBanned;
    this.adjustScore(
      rep,
      -penalty,
      reason ?? (isByzantineAttack ? 'Byzantine protocol violation' : 'Invalid gossip message'),
    );

    if (rep.isBanned && !wasBanned) {
      this.blacklist.add(peerId);
    }
  }

  /**
   * Immediately slashes a peer's score to -100, permanently blacklists the peer locally,
   * and triggers disconnection callbacks.
   */
  public slashPeer(peerId: string, reason: string = 'Malformed or Byzantine message injection'): void {
    const rep = this.getReputation(peerId);
    rep.invalidMessages += 1;
    rep.lastActive = Date.now();
    rep.score = -100;
    rep.isQuarantined = true;
    rep.isBanned = true;
    rep.slashedReason = reason;
    rep.banExpiry = Date.now() + this.config.banDurationMs;
    this.blacklist.add(peerId);
    this.notifySlashed(peerId, reason);
  }

  /**
   * Returns whether a peer is in the local Byzantine blacklist.
   */
  public isBlacklisted(peerId: string): boolean {
    return this.blacklist.has(peerId);
  }

  /**
   * Returns all locally blacklisted peer IDs.
   */
  public getBlacklistedPeers(): string[] {
    return Array.from(this.blacklist);
  }

  /**
   * Computes current duplicate message ratio (0..1) for a peer.
   */
  public getDuplicateRatio(peerId: string): number {
    const rep = this.getReputation(peerId);
    return rep.duplicateRatio ?? 0;
  }

  /**
   * Validates a Soroban indexed event against Byzantine faults.
   */
  public validateSorobanEvent(event: SorobanIndexedEvent): {
    isValid: boolean;
    isByzantine: boolean;
    reason?: string;
  } {
    if (!event || typeof event !== 'object') {
      return {
        isValid: false,
        isByzantine: true,
        reason: 'Malformed event payload object',
      };
    }

    if (!event.id || !event.contractId || !event.topic || !event.xdrPayload) {
      return { isValid: false, isByzantine: false, reason: 'Missing mandatory event fields' };
    }

    if (typeof event.ledgerSeq !== 'number' || event.ledgerSeq <= 0) {
      return {
        isValid: false,
        isByzantine: true,
        reason: 'Invalid or non-positive ledger sequence',
      };
    }

    // Verify timestamp within reasonable clock skew (e.g. 10 minutes)
    const now = Date.now();
    const skew = Math.abs(now - event.timestamp);
    if (skew > 10 * 60 * 1000) {
      return {
        isValid: false,
        isByzantine: true,
        reason: 'Event timestamp skewed beyond acceptable boundary',
      };
    }

    // Verify valid Soroban XDR structure (either ScVal or ContractEvent)
    try {
      xdr.ScVal.fromXDR(event.xdrPayload, 'base64');
    } catch {
      try {
        xdr.ContractEvent.fromXDR(event.xdrPayload, 'base64');
      } catch {
        return {
          isValid: false,
          isByzantine: true,
          reason: 'Malformed or invalid Soroban XDR structure',
        };
      }
    }

    return { isValid: true, isByzantine: false };
  }

  /**
   * Decays all peer scores periodically towards 0 to allow recovery.
   */
  public decayScores(): void {
    for (const rep of this.reputations.values()) {
      if (!rep.isBanned && !this.blacklist.has(rep.peerId)) {
        rep.score = Math.round(rep.score * this.config.decayFactor * 100) / 100;
        this.updateFlags(rep);
      }
    }
  }

  /**
   * Returns whether a peer is allowed to participate in eager gossip.
   */
  public isPeerEligibleForEagerGossip(peerId: string): boolean {
    if (this.blacklist.has(peerId)) return false;
    const rep = this.getReputation(peerId);
    return !rep.isBanned && !rep.isQuarantined;
  }

  /**
   * Returns whether a connection should be actively terminated due to ban or blacklist.
   */
  public isPeerBanned(peerId: string): boolean {
    if (this.blacklist.has(peerId)) return true;
    const rep = this.getReputation(peerId);
    return rep.isBanned;
  }

  private updateDuplicateRatio(rep: PeerReputation): void {
    const total = rep.validMessagesDelivered + rep.duplicateMessages;
    rep.duplicateRatio =
      total > 0 ? Math.round((rep.duplicateMessages / total) * 1000) / 1000 : 0;
  }

  private adjustScore(rep: PeerReputation, delta: number, reason?: string): void {
    const wasBanned = rep.isBanned;
    rep.score = Math.max(-100, Math.min(100, rep.score + delta));
    this.updateFlags(rep, reason);
    if (!wasBanned && rep.isBanned) {
      this.blacklist.add(rep.peerId);
      this.notifySlashed(rep.peerId, rep.slashedReason ?? reason ?? 'Score dropped below ban cutoff');
    }
  }

  private updateFlags(rep: PeerReputation, reason?: string): void {
    if (this.blacklist.has(rep.peerId) || rep.score <= this.config.banThreshold) {
      rep.isBanned = true;
      rep.isQuarantined = true;
      rep.banExpiry = Date.now() + this.config.banDurationMs;
      if (reason && !rep.slashedReason) {
        rep.slashedReason = reason;
      }
    } else if (rep.score <= this.config.quarantineThreshold) {
      rep.isQuarantined = true;
      rep.isBanned = false;
    } else {
      rep.isQuarantined = false;
      rep.isBanned = false;
    }
  }

  private notifySlashed(peerId: string, reason: string): void {
    for (const listener of this.slashListeners) {
      try {
        listener(peerId, reason);
      } catch {
        // ignore listener error
      }
    }
  }
}
