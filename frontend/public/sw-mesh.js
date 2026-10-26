/**
 * Pactum Service Worker Mesh Gateway (v1.1.0)
 * Persists P2P mesh state, Merkle root digests, event ring buffer, and Byzantine
 * peer blacklists across client page navigation and background tab throttling.
 */

const MESH_CHANNEL_NAME = 'pactum-webrtc-mesh-signaling';
const MAX_CACHED_EVENTS = 250;

let meshBroadcastChannel = null;

/** @type {Map<string, object>} */
const cachedEvents = new Map();

/** @type {Set<string>} */
const blacklistedPeers = new Set();

/** @type {Map<string, { peerId: string, lastSeen: number }>} */
const activeMeshPeers = new Map();

function computeDigestHex(input) {
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

function computeWorkerMerkleRoot() {
  const events = Array.from(cachedEvents.values());
  if (events.length === 0) {
    return computeDigestHex('EMPTY_MERKLE_TREE');
  }
  events.sort((a, b) => {
    if ((a.ledgerSeq || 0) !== (b.ledgerSeq || 0)) {
      return (a.ledgerSeq || 0) - (b.ledgerSeq || 0);
    }
    return String(a.id || '').localeCompare(String(b.id || ''));
  });
  let layer = events.map((ev) =>
    computeDigestHex(
      `${ev.id}|${ev.ledgerSeq}|${ev.contractId}|${ev.topic}|${ev.txHash}|${ev.xdrPayload}`,
    ),
  );
  while (layer.length > 1) {
    const next = [];
    for (let i = 0; i < layer.length; i += 2) {
      const left = layer[i];
      const right = i + 1 < layer.length ? layer[i + 1] : left;
      next.push(computeDigestHex(`${left}:${right}`));
    }
    layer = next;
  }
  return layer[0];
}

function recordCachedEvent(event) {
  if (!event || !event.id) return false;
  if (event.originPeerId && blacklistedPeers.has(event.originPeerId)) {
    return false;
  }
  const isNew = !cachedEvents.has(event.id);
  cachedEvents.set(event.id, event);
  if (cachedEvents.size > MAX_CACHED_EVENTS) {
    const oldestKey = cachedEvents.keys().next().value;
    if (oldestKey) cachedEvents.delete(oldestKey);
  }
  return isNew;
}

function broadcastToWindowClients(payload) {
  self.clients.matchAll({ includeUncontrolled: true }).then((clients) => {
    clients.forEach((client) => {
      client.postMessage(payload);
    });
  });
}

self.addEventListener('install', () => {
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(self.clients.claim());
  initMeshChannel();
});

// Re-initialize on every worker start, not only on activation.
initMeshChannel();

function initMeshChannel() {
  if (typeof BroadcastChannel !== 'undefined' && !meshBroadcastChannel) {
    meshBroadcastChannel = new BroadcastChannel(MESH_CHANNEL_NAME);
    meshBroadcastChannel.onmessage = (event) => {
      const msg = event.data;
      if (!msg) return;

      if (msg.senderId && blacklistedPeers.has(msg.senderId)) {
        return;
      }

      if (msg.senderId) {
        activeMeshPeers.set(msg.senderId, {
          peerId: msg.senderId,
          lastSeen: Date.now(),
        });
      }

      // Forward disseminated Soroban events to all connected window clients
      if (msg.type === 'SOROBAN_EVENT_DISSEMINATED' && msg.event) {
        recordCachedEvent(msg.event);
        broadcastToWindowClients(msg);
      } else if (msg.type === 'PEER_SLASHED' && msg.peerId) {
        blacklistedPeers.add(msg.peerId);
        activeMeshPeers.delete(msg.peerId);
        broadcastToWindowClients(msg);
      }
    };
  }
}

self.addEventListener('message', (event) => {
  const data = event.data;
  if (!data || typeof data !== 'object') return;

  if (data.type === 'PUBLISH_SOROBAN_EVENT' && data.event) {
    recordCachedEvent(data.event);
    const payload = {
      type: 'SOROBAN_EVENT_DISSEMINATED',
      event: data.event,
      merkleRoot: computeWorkerMerkleRoot(),
    };
    if (meshBroadcastChannel) {
      meshBroadcastChannel.postMessage(payload);
    }
    broadcastToWindowClients(payload);
    return;
  }

  if (data.type === 'REPORT_BYZANTINE_PEER' && data.peerId) {
    blacklistedPeers.add(data.peerId);
    activeMeshPeers.delete(data.peerId);
    const slashPayload = {
      type: 'PEER_SLASHED',
      peerId: data.peerId,
      reason: data.reason || 'Byzantine fault reported to Service Worker gateway',
      timestamp: Date.now(),
    };
    if (meshBroadcastChannel) {
      meshBroadcastChannel.postMessage(slashPayload);
    }
    broadcastToWindowClients(slashPayload);
    return;
  }

  if (data.type === 'SYNC_MESH_STATE' || data.type === 'CLIENT_NAVIGATION_HYDRATE') {
    const knownSet = new Set(Array.isArray(data.knownEventIds) ? data.knownEventIds : []);
    const missingEvents = Array.from(cachedEvents.values()).filter(
      (ev) => !knownSet.has(ev.id),
    );
    const snapshot = {
      type: 'MESH_STATE_SNAPSHOT',
      merkleRoot: computeWorkerMerkleRoot(),
      events: missingEvents,
      blacklistedPeers: Array.from(blacklistedPeers),
      activePeers: Array.from(activeMeshPeers.values()),
      timestamp: Date.now(),
    };
    if (event.source && typeof event.source.postMessage === 'function') {
      event.source.postMessage(snapshot);
    } else {
      broadcastToWindowClients(snapshot);
    }
  }
});
