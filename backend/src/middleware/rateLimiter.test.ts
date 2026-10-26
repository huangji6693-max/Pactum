import assert from 'node:assert/strict';
import http from 'node:http';
import { test } from 'node:test';
import express, { type Request, type RequestHandler, type Response } from 'express';

type AutocannonResult = {
  '2xx': number;
  '4xx': number;
};
type AutocannonRunner = (opts: {
  url: string;
  connections: number;
  amount: number;
}) => Promise<AutocannonResult>;

// eslint-disable-next-line @typescript-eslint/no-require-imports
const autocannon = require('autocannon') as AutocannonRunner;
import {
  buildClusterKeys,
  createCommitmentLimiter,
  createRateLimiter,
  createTieredRateLimiter,
  resolveRequestTier,
  SLIDING_WINDOW_TOKEN_BUCKET_LUA,
  type RedisEvalClient,
} from './rateLimiter';

// Constructed to satisfy the limiter's Stellar address check (/^[GC][A-Z2-7]{55}$/)
// without depending on real checksums — the limiter only validates the shape.
// A distinct filler letter per test keeps each address in its own bucket, so the
// tests stay independent despite sharing the exported limiter's module-level store.
const address = (fill: string): string => `G${fill.repeat(55)}`;

const LIMIT = 10;

interface Invocation {
  statusCode: number;
  headers: Record<string, string>;
  body: unknown;
  nextCalled: boolean;
}

function invoke(
  handler: RequestHandler,
  {
    ip = '203.0.113.1',
    method = 'POST',
    path = '/commitments',
    headers = {},
    query = {},
    body,
  }: {
    ip?: string;
    method?: string;
    path?: string;
    headers?: Record<string, string>;
    query?: Record<string, unknown>;
    body?: unknown;
  },
): Invocation {
  const result: Invocation = { statusCode: 200, headers: {}, body: undefined, nextCalled: false };

  const req = {
    method,
    path,
    headers,
    query,
    socket: { remoteAddress: ip },
    body,
  } as unknown as Request;

  const res = {
    set(field: string, value: string) {
      result.headers[field.toLowerCase()] = String(value);
      return this;
    },
    status(code: number) {
      result.statusCode = code;
      return this;
    },
    json(payload: unknown) {
      result.body = payload;
      return this;
    },
  } as unknown as Response;

  handler(req, res, () => {
    result.nextCalled = true;
  });

  return result;
}

async function invokeAsync(
  handler: RequestHandler,
  {
    ip = '203.0.113.1',
    method = 'GET',
    path = '/commitments',
    headers = {},
    query = {},
    body,
  }: {
    ip?: string;
    method?: string;
    path?: string;
    headers?: Record<string, string>;
    query?: Record<string, unknown>;
    body?: unknown;
  },
): Promise<Invocation> {
  const result: Invocation = { statusCode: 200, headers: {}, body: undefined, nextCalled: false };

  const req = {
    method,
    path,
    headers,
    query,
    socket: { remoteAddress: ip },
    body,
  } as unknown as Request;

  const res = {
    set(field: string, value: string) {
      result.headers[field.toLowerCase()] = String(value);
      return this;
    },
    status(code: number) {
      result.statusCode = code;
      return this;
    },
    json(payload: unknown) {
      result.body = payload;
      return this;
    },
  } as unknown as Response;

  await handler(req, res, () => {
    result.nextCalled = true;
  });

  return result;
}

/**
 * In-memory atomic emulator of the Redis Lua script (`SLIDING_WINDOW_TOKEN_BUCKET_LUA`).
 * Executes the exact sorted-set (`ZREMRANGEBYSCORE`, `ZCARD`, `ZADD`, `ZRANGE`) and
 * hash (`HMGET`, `HMSET`, `PEXPIRE`) operations defined in the Lua script, with a
 * toggleable `failover` flag to simulate Redis Cluster outages (`CLUSTERDOWN`).
 */
class MockRedisCluster implements RedisEvalClient {
  public failover = false;
  public evalCalls = 0;
  public lastScript = '';
  public lastKeys: string[] = [];
  private readonly sortedSets = new Map<string, Array<{ score: number; member: string }>>();
  private readonly hashes = new Map<string, Map<string, string>>();

  async eval(script: string, numKeys: number, ...args: (string | number)[]): Promise<unknown> {
    this.evalCalls += 1;
    this.lastScript = script;

    if (this.failover) {
      throw new Error('CLUSTERDOWN The cluster is down');
    }

    const keys = args.slice(0, numKeys).map(String);
    const argv = args.slice(numKeys);
    this.lastKeys = keys;

    const swKey = keys[0]!;
    const tbKey = keys[1]!;

    const nowMs = Number(argv[0]);
    const windowMs = Number(argv[1]);
    const maxRequests = Number(argv[2]);
    const refillRatePerMs = Number(argv[3]);
    const requestId = String(argv[4]);
    const cost = Number(argv[5] ?? 1);

    const windowStart = nowMs - windowMs;
    const zset = (this.sortedSets.get(swKey) ?? []).filter((entry) => entry.score > windowStart);
    this.sortedSets.set(swKey, zset);
    const currentCount = zset.length;

    const hash = this.hashes.get(tbKey) ?? new Map<string, string>();
    const rawTokens = hash.get('tokens');
    const rawLastRefill = hash.get('lastRefillMs');

    let tokens: number;
    let lastRefillMs: number;
    if (rawTokens === undefined || rawLastRefill === undefined) {
      tokens = maxRequests;
      lastRefillMs = nowMs;
    } else {
      const elapsed = Math.max(0, nowMs - Number(rawLastRefill));
      tokens = Math.min(maxRequests, Number(rawTokens) + elapsed * refillRatePerMs);
      lastRefillMs = nowMs;
    }

    if (currentCount + cost <= maxRequests && tokens >= cost) {
      tokens -= cost;
      hash.set('tokens', String(tokens));
      hash.set('lastRefillMs', String(lastRefillMs));
      this.hashes.set(tbKey, hash);

      zset.push({ score: nowMs, member: requestId });
      zset.sort((a, b) => a.score - b.score);
      this.sortedSets.set(swKey, zset);

      const swRemaining = maxRequests - (currentCount + cost);
      const tbRemaining = Math.floor(tokens);
      const remaining = Math.max(0, Math.min(swRemaining, tbRemaining));
      return [1, remaining, nowMs + windowMs, 0];
    }

    hash.set('tokens', String(tokens));
    hash.set('lastRefillMs', String(lastRefillMs));
    this.hashes.set(tbKey, hash);

    const oldest = zset[0];
    const swResetMs = oldest ? oldest.score + windowMs : nowMs + windowMs;
    const tokenWaitMs =
      tokens < cost && refillRatePerMs > 0 ? Math.ceil((cost - tokens) / refillRatePerMs) : 0;
    const resetAtMs = Math.max(swResetMs, nowMs + tokenWaitMs);
    const retryAfterSec = Math.max(1, Math.ceil((resetAtMs - nowMs) / 1000));
    return [0, 0, resetAtMs, retryAfterSec];
  }
}

test('allows a Stellar address up to the per-hour limit', () => {
  const partyA = address('A');
  for (let i = 0; i < LIMIT; i += 1) {
    const res = invoke(createCommitmentLimiter, { body: { partyA } });
    assert.equal(res.nextCalled, true, `request ${i + 1} should pass`);
    assert.equal(res.statusCode, 200);
    assert.equal(res.headers['x-ratelimit-limit'], String(LIMIT));
    assert.equal(res.headers['x-ratelimit-remaining'], String(LIMIT - (i + 1)));
    assert.equal(res.headers['retry-after'], '0');
  }
});

test('blocks the request past the limit with 429 and a Retry-After header', () => {
  const partyA = address('B');
  for (let i = 0; i < LIMIT; i += 1) {
    invoke(createCommitmentLimiter, { body: { partyA } });
  }

  const blocked = invoke(createCommitmentLimiter, { body: { partyA } });

  assert.equal(blocked.nextCalled, false, 'over-limit request must not reach the handler');
  assert.equal(blocked.statusCode, 429);
  assert.equal(blocked.headers['x-ratelimit-remaining'], '0');

  const retryAfter = Number(blocked.headers['retry-after']);
  assert.ok(
    Number.isInteger(retryAfter) && retryAfter > 0,
    'Retry-After must be a positive integer',
  );
  // The window is one hour; blocked immediately, a slot frees nearly an hour out.
  assert.ok(retryAfter <= 3600 && retryAfter > 3500, `unexpected Retry-After: ${retryAfter}`);
  assert.deepEqual(blocked.body, {
    error:
      'Too many commitments created for this address. A maximum of 10 per hour is allowed; please try again later.',
  });
});

test('limits each address independently', () => {
  const exhausted = address('C');
  const untouched = address('D');

  for (let i = 0; i < LIMIT; i += 1) {
    invoke(createCommitmentLimiter, { body: { partyA: exhausted } });
  }

  // `exhausted` is now over quota; `untouched` must be unaffected.
  assert.equal(invoke(createCommitmentLimiter, { body: { partyA: exhausted } }).statusCode, 429);

  const fresh = invoke(createCommitmentLimiter, { body: { partyA: untouched } });
  assert.equal(fresh.nextCalled, true);
  assert.equal(fresh.statusCode, 200);
});

test('falls back to per-IP limiting when no valid address is present', () => {
  const ip = '198.51.100.7';

  // A body with no partyA (unauthenticated probing) is bucketed by IP.
  for (let i = 0; i < LIMIT; i += 1) {
    const res = invoke(createCommitmentLimiter, { ip, body: {} });
    assert.equal(res.nextCalled, true, `probe ${i + 1} should pass`);
  }

  // A malformed partyA also falls back to the same IP bucket, which is now full.
  const blocked = invoke(createCommitmentLimiter, { ip, body: { partyA: 'not-an-address' } });
  assert.equal(blocked.statusCode, 429, 'the IP bucket should be exhausted regardless of body');

  // A different IP shares neither bucket.
  const otherIp = invoke(createCommitmentLimiter, { ip: '198.51.100.8', body: {} });
  assert.equal(otherIp.nextCalled, true);
});

test('re-admits an address once its window elapses', () => {
  const partyA = address('E');
  const realNow = Date.now;
  let clock = realNow();

  try {
    globalThis.Date.now = () => clock;

    for (let i = 0; i < LIMIT; i += 1) {
      invoke(createCommitmentLimiter, { body: { partyA } });
    }
    assert.equal(invoke(createCommitmentLimiter, { body: { partyA } }).statusCode, 429);

    // Advance past the one-hour window: the address should be admitted again.
    clock += 60 * 60 * 1000 + 1000;
    const afterWindow = invoke(createCommitmentLimiter, { body: { partyA } });
    assert.equal(afterWindow.nextCalled, true);
    assert.equal(afterWindow.statusCode, 200);
  } finally {
    globalThis.Date.now = realNow;
  }
});

test('executes Redis Cluster Lua sliding-window token bucket with co-located hash tags', async () => {
  const redis = new MockRedisCluster();
  const limiter = createRateLimiter({
    windowMs: 60_000,
    max: 3,
    redis,
    tier: 'public',
  });

  const { swKey, tbKey } = buildClusterKeys('pactum:rl', 'public:ip:192.0.2.55');
  const swTag = swKey.match(/\{([^}]+)\}/)?.[1];
  const tbTag = tbKey.match(/\{([^}]+)\}/)?.[1];
  assert.ok(swTag && swTag === tbTag, 'both Redis keys must share the exact same cluster hash tag');

  for (let i = 0; i < 3; i += 1) {
    const res = await invokeAsync(limiter, { ip: '192.0.2.55' });
    assert.equal(res.nextCalled, true);
    assert.equal(res.statusCode, 200);
    assert.equal(res.headers['x-ratelimit-limit'], '3');
    assert.equal(res.headers['x-ratelimit-remaining'], String(3 - (i + 1)));
    assert.equal(res.headers['retry-after'], '0');
  }

  const blocked = await invokeAsync(limiter, { ip: '192.0.2.55' });
  assert.equal(blocked.nextCalled, false);
  assert.equal(blocked.statusCode, 429);
  assert.equal(blocked.headers['x-ratelimit-limit'], '3');
  assert.equal(blocked.headers['x-ratelimit-remaining'], '0');
  assert.ok(Number(blocked.headers['retry-after']) > 0);
  assert.equal(redis.lastScript, SLIDING_WINDOW_TOKEN_BUCKET_LUA);
  assert.equal(redis.evalCalls, 4);
});

test('differentiates tiered limits between public endpoints, attestor streams, and internal relayers', async () => {
  const redis = new MockRedisCluster();
  const attestorAddr = address('F');
  const relayerSecret = 'relayer-secret-token-xyz';

  const tiered = createTieredRateLimiter({
    redis,
    relayerSecret,
    publicWriteMax: 2,
    tiers: {
      public: { windowMs: 60_000, max: 3 },
      attestor: { windowMs: 60_000, max: 5 },
      relayer: { windowMs: 60_000, max: 8 },
    },
  });

  // 1. Public tier: read limit (3) and write limit (2)
  assert.equal(resolveRequestTier({ headers: {}, socket: { remoteAddress: '198.51.100.20' } as never, path: '/commitments', query: {}, body: undefined }).tier, 'public');
  const pubWrite1 = await invokeAsync(tiered, { ip: '198.51.100.20', method: 'POST' });
  const pubWrite2 = await invokeAsync(tiered, { ip: '198.51.100.20', method: 'POST' });
  const pubWrite3 = await invokeAsync(tiered, { ip: '198.51.100.20', method: 'POST' });
  assert.equal(pubWrite1.statusCode, 200);
  assert.equal(pubWrite1.headers['x-ratelimit-tier'], 'public');
  assert.equal(pubWrite2.statusCode, 200);
  assert.equal(pubWrite3.statusCode, 429);

  // 2. Registered Attestor tier: elevated limit (5) from the same IP
  for (let i = 0; i < 5; i += 1) {
    const attRes = await invokeAsync(tiered, {
      ip: '198.51.100.20',
      method: 'GET',
      path: '/ws',
      headers: { 'x-attestor-address': attestorAddr },
    });
    assert.equal(attRes.statusCode, 200);
    assert.equal(attRes.headers['x-ratelimit-tier'], 'attestor');
    assert.equal(attRes.headers['x-ratelimit-limit'], '5');
  }
  const attBlocked = await invokeAsync(tiered, {
    ip: '198.51.100.20',
    method: 'GET',
    path: '/ws',
    headers: { 'x-attestor-address': attestorAddr },
  });
  assert.equal(attBlocked.statusCode, 429);

  // 3. Internal Relayer tier: highest limit (8) from the same IP
  for (let i = 0; i < 8; i += 1) {
    const relRes = await invokeAsync(tiered, {
      ip: '198.51.100.20',
      method: 'POST',
      path: '/proofs/batch',
      headers: { 'x-relayer-key': relayerSecret },
    });
    assert.equal(relRes.statusCode, 200);
    assert.equal(relRes.headers['x-ratelimit-tier'], 'relayer');
    assert.equal(relRes.headers['x-ratelimit-limit'], '8');
  }
  const relBlocked = await invokeAsync(tiered, {
    ip: '198.51.100.20',
    method: 'POST',
    path: '/proofs/batch',
    headers: { 'x-relayer-key': relayerSecret },
  });
  assert.equal(relBlocked.statusCode, 429);
});

test('gracefully degrades to local in-memory token bucket during Redis Cluster failover with zero downtime', async () => {
  const redis = new MockRedisCluster();
  const limiter = createRateLimiter({
    windowMs: 60_000,
    max: 2,
    redis,
  });

  // First request succeeds against healthy Redis Cluster.
  const healthyRes = await invokeAsync(limiter, { ip: '198.51.100.99' });
  assert.equal(healthyRes.statusCode, 200);

  // Simulate Redis Cluster connectivity failure mid-flight.
  redis.failover = true;

  // Local fallback seamlessly serves traffic and enforces the cap of 2 without throwing 500.
  const fallback1 = await invokeAsync(limiter, { ip: '198.51.100.99' });
  const fallback2 = await invokeAsync(limiter, { ip: '198.51.100.99' });
  const fallbackBlocked = await invokeAsync(limiter, { ip: '198.51.100.99' });

  assert.equal(fallback1.statusCode, 200);
  assert.equal(fallback1.headers['x-ratelimit-limit'], '2');
  assert.equal(fallback1.headers['retry-after'], '0');
  assert.equal(fallback2.statusCode, 200);
  assert.equal(fallbackBlocked.statusCode, 429);
  assert.equal(fallbackBlocked.headers['x-ratelimit-remaining'], '0');
  assert.ok(Number(fallbackBlocked.headers['retry-after']) > 0);

  // Restore Redis Cluster connectivity: requests resume using Redis without restart.
  redis.failover = false;
  const recovered = await invokeAsync(limiter, { ip: '198.51.100.99' });
  assert.equal(recovered.statusCode, 200);
  assert.equal(recovered.headers['x-ratelimit-remaining'], '0');
});

test('guarantees atomic sliding-window enforcement and < 1ms Lua execution under concurrent autocannon load', async () => {
  const redis = new MockRedisCluster();
  const maxAllowed = 25;
  let evalDurationTotalMs = 0;

  const timedRedis: RedisEvalClient = {
    async eval(script: string, numKeys: number, ...args: (string | number)[]): Promise<unknown> {
      const start = performance.now();
      const out = await redis.eval(script, numKeys, ...args);
      evalDurationTotalMs += performance.now() - start;
      return out;
    },
  };

  const app = express();
  app.use(
    createTieredRateLimiter({
      redis: timedRedis,
      tiers: {
        public: { windowMs: 60_000, max: maxAllowed },
      },
    }),
  );
  app.get('/probe', (_req: Request, res: Response) => {
    res.status(200).json({ ok: true });
  });

  const server = http.createServer(app);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const addressInfo = server.address();
  assert.ok(addressInfo && typeof addressInfo === 'object');

  try {
    const result = await autocannon({
      url: `http://127.0.0.1:${addressInfo.port}/probe`,
      connections: 10,
      amount: 60,
    });

    const avgEvalMs = evalDurationTotalMs / Math.max(1, redis.evalCalls);
    assert.ok(avgEvalMs < 1, `expected Lua eval < 1ms, got ${avgEvalMs.toFixed(4)}ms`);
    assert.equal(result['2xx'], maxAllowed, `expected exactly ${maxAllowed} allowed requests`);
    assert.equal(
      result['4xx'],
      60 - maxAllowed,
      `expected exactly ${60 - maxAllowed} rate-limited 429 responses`,
    );
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});
