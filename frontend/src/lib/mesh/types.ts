/**
 * BFT Gossip Protocol & Service Worker Mesh Type Definitions
 */

export interface SorobanIndexedEvent {
  id: string; // sha256(ledgerSeq + contractId + eventTopic + xdrHash)
  contractId: string;
  topic: string;
  xdrPayload: string; // Base64 encoded XDR data
  ledgerSeq: number;
  txHash: string;
  timestamp: number;
  originPeerId: string;
  signature?: string;
}

export type GossipMessageType =
  | 'GOSSIP_DATA'
  | 'IHAVE'
  | 'GRAFT'
  | 'PRUNE'
  | 'PEER_EXCHANGE'
  | 'PING'
  | 'PONG'
  | 'ANTI_ENTROPY_REQ'
  | 'ANTI_ENTROPY_RESP';

export interface BaseGossipMessage {
  type: GossipMessageType;
  senderId: string;
  timestamp: number;
}

export interface GossipDataMessage extends BaseGossipMessage {
  type: 'GOSSIP_DATA';
  messageId: string;
  topic: string;
  event: SorobanIndexedEvent;
  hopCount: number;
}

export interface IHaveMessage extends BaseGossipMessage {
  type: 'IHAVE';
  messageIds: string[];
}

export interface GraftMessage extends BaseGossipMessage {
  type: 'GRAFT';
  messageId?: string; // Optional requested message ID
}

export interface PruneMessage extends BaseGossipMessage {
  type: 'PRUNE';
}

export interface PeerExchangeMessage extends BaseGossipMessage {
  type: 'PEER_EXCHANGE';
  peers: PeerCandidate[];
}

export interface PingMessage extends BaseGossipMessage {
  type: 'PING';
}

export interface PongMessage extends BaseGossipMessage {
  type: 'PONG';
}

export interface AntiEntropyReqMessage extends BaseGossipMessage {
  type: 'ANTI_ENTROPY_REQ';
  fromLedger: number;
  toLedger: number;
  merkleRoot?: string;
  knownEventIds?: string[];
}

export interface AntiEntropyRespMessage extends BaseGossipMessage {
  type: 'ANTI_ENTROPY_RESP';
  events: SorobanIndexedEvent[];
  merkleRoot?: string;
  inSync?: boolean;
}

export type MeshProtocolMessage =
  | GossipDataMessage
  | IHaveMessage
  | GraftMessage
  | PruneMessage
  | PeerExchangeMessage
  | PingMessage
  | PongMessage
  | AntiEntropyReqMessage
  | AntiEntropyRespMessage;

export interface PeerCandidate {
  peerId: string;
  sessionDescription?: RTCSessionDescriptionInit;
  iceCandidates?: RTCIceCandidateInit[];
  lastSeen: number;
}

export interface PeerReputation {
  peerId: string;
  score: number; // Range: -100 to +100
  validMessagesDelivered: number;
  duplicateMessages: number;
  invalidMessages: number;
  lastActive: number;
  isQuarantined: boolean;
  isBanned: boolean;
  banExpiry?: number;
  averageLatencyMs?: number;
  duplicateRatio?: number;
  slashedReason?: string;
}

export interface MeshTopologyStats {
  peerId: string;
  activeNeighbors: string[];
  passiveNeighbors: string[];
  totalPeers: number;
  messagesReceived: number;
  messagesRelayed: number;
  duplicatesPruned: number;
  byzantineDropped: number;
  rpcOffloadRatio: number;
}
