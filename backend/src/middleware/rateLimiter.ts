import { Request, Response, NextFunction, RequestHandler } from 'express';
import type { IncomingMessage } from 'http';

/**
 * Distributed Sliding-Window Log & Token-Bucket Rate Limiter with Redis Cluster
 * and Zero-Downtime Local Fallback.
 *
 * Architecture:
 * 1. **Atomic Redis Lua Script (`SLIDING_WINDOW_TOKEN_BUCKET_LUA`)**:
 *    Executes a combined sliding-window log (`ZREMRANGEBYSCORE` + `ZCARD` + `ZADD`)
 *    and continuous token-bucket refill (`HMGET` + `HMSET`) in a single `< 1ms`
 *    round-trip. Both keys share a Redis Cluster hash tag (`{tier:identifier}`)
 *    so multi-key operations always map to the same CRC16 hash slot.
 * 2. **Tiered Limits (`RateLimitTier`)**:
 *    Differentiates between:
 *    - `'public'`: Anonymous public read/write endpoints.
 *    - `'attestor'`: Registered attestor discovery, reliability, and WebSocket streams.
 *    - `'relayer'`: Authenticated internal relayer batch/proof submission pipelines.
 * 3. **Graceful Degradation**:
 *    Automatically falls back to an in-memory local sliding-window token bucket
 *    whenever Redis is unconfigured, disconnected, or experiencing cluster failover.
 */

/** Matches a Stellar public key (G...) or contract address (C...). */
const STELLAR_ADDRESS = /^[GC][A-Z2-7]{55}$/;

/**
 * Atomic Redis Lua script implementing a hybrid Sliding Window Log + Token Bucket.
 *
 * KEYS[1]: Sliding window sorted-set key, e.g. `pactum:rl:{public:ip:1.2.3.4}:sw`
 * KEYS[2]: Token bucket hash key, e.g. `pactum:rl:{public:ip:1.2.3.4}:tb`
 *
 * ARGV[1]: nowMs (current epoch milliseconds)
 * ARGV[2]: windowMs (sliding window duration in milliseconds)
 * ARGV[3]: maxRequests (window request limit & token bucket burst capacity)
 * ARGV[4]: refillRatePerMs (tokens refilled per millisecond)
 * ARGV[5]: requestId (unique member identifier for the sliding window log)
 * ARGV[6]: cost (tokens consumed by this request, default 1)
 *
 * Returns: `{ allowed (0|1), remaining, resetAtMs, retryAfterSec }`
 */
export const SLIDING_WINDOW_TOKEN_BUCKET_LUA = `
local swKey = KEYS[1]
local tbKey = KEYS[2]

local nowMs = tonumber(ARGV[1])
local windowMs = tonumber(ARGV[2])
local maxRequests = tonumber(ARGV[3])
local refillRatePerMs = tonumber(ARGV[4])
local requestId = ARGV[5]
local cost = tonumber(ARGV[6]) or 1

local windowStart = nowMs - windowMs
redis.call('ZREMRANGEBYSCORE', swKey, '-inf', windowStart)
local currentCount = redis.call('ZCARD', swKey)

local bucket = redis.call('HMGET', tbKey, 'tokens', 'lastRefillMs')
local tokens = tonumber(bucket[1])
local lastRefillMs = tonumber(bucket[2])

if tokens == nil or lastRefillMs == nil then
  tokens = maxRequests
  lastRefillMs = nowMs
else
  local elapsed = math.max(0, nowMs - lastRefillMs)
  tokens = math.min(maxRequests, tokens + (elapsed * refillRatePerMs))
  lastRefillMs = nowMs
end

if (currentCount + cost) <= maxRequests and tokens >= cost then
  tokens = tokens - cost
  redis.call('HMSET', tbKey, 'tokens', tostring(tokens), 'lastRefillMs', tostring(lastRefillMs))
  redis.call('PEXPIRE', tbKey, windowMs)
  redis.call('ZADD', swKey, nowMs, requestId)
  redis.call('PEXPIRE', swKey, windowMs)

  local swRemaining = maxRequests - (currentCount + cost)
  local tbRemaining = math.floor(tokens)
  local remaining = math.max(0, math.min(swRemaining, tbRemaining))
  return { 1, remaining, nowMs + windowMs, 0 }
end

redis.call('HMSET', tbKey, 'tokens', tostring(tokens), 'lastRefillMs', tostring(lastRefillMs))
redis.call('PEXPIRE', tbKey, windowMs)

local oldest = redis.call('ZRANGE', swKey, 0, 0, 'WITHSCORES')
local swResetMs = nowMs + windowMs
if oldest ~= nil and oldest[2] ~= nil then
  swResetMs = tonumber(oldest[2]) + windowMs
end

local tokenWaitMs = 0
if tokens < cost and refillRatePerMs > 0 then
  tokenWaitMs = math.ceil((cost - tokens) / refillRatePerMs)
end

local resetAtMs = math.max(swResetMs, nowMs + tokenWaitMs)
local retryAfterSec = math.max(1, math.ceil((resetAtMs - nowMs) / 1000))
return { 0, 0, resetAtMs, retryAfterSec }
`;

/** Minimal interface required from an `ioredis` Redis or Cluster client. */
export interface RedisEvalClient {
  eval(script: string, numKeys: number, ...args: (string | number)[]): Promise<unknown>;
}

/** Supported traffic tiers for Pactum API and WebSocket streams. */
export type RateLimitTier = 'public' | 'attestor' | 'relayer';

/** Tier configuration defining sliding window duration and burst capacity. */
export interface TierLimitConfig {
  windowMs: number;
  max: number;
  refillRatePerMs?: number;
  message?: string;
}

/** Default per-tier rate limits. */
export const DEFAULT_TIER_LIMITS: Record<RateLimitTier, TierLimitConfig> = {
  public: {
    windowMs: 60 * 1000,
    max: 100,
    message: 'Too many requests from this IP, please try again after a minute.',
  },
  attestor: {
    windowMs: 60 * 1000,
    max: 300,
    message: 'Attestor stream rate limit exceeded, please back off and retry.',
  },
  relayer: {
    windowMs: 60 * 1000,
    max: 1000,
    message: 'Internal relayer rate limit exceeded, please retry shortly.',
  },
};

/**
 * Resolves the calling client's IP, honouring the leftmost `X-Forwarded-For`
 * address when the app runs behind a reverse proxy and falling back to the
 * socket address otherwise.
 */
export const clientIp = (req: Pick<Request, 'headers' | 'socket'> | IncomingMessage): string =>
  (req.headers['x-forwarded-for'] as string | undefined)?.split(',')[0]?.trim() ||
  req.socket?.remoteAddress ||
  'unknown';

/** Derives the sliding-window bucket key for a request. */
export type KeyGenerator = (req: Request) => string;

export interface RateLimiterOptions {
  /** Length of the sliding window in milliseconds. */
  windowMs: number;
  /** Maximum number of requests allowed within the window. */
  max: number;
  /** Optional token refill rate per millisecond (defaults to `max / windowMs`). */
  refillRatePerMs?: number;
  /** Human-readable message returned when the limit is exceeded. */
  message?: string;
  /**
   * Buckets requests under a custom key instead of the client IP. Defaults to
   * per-IP limiting.
   */
  keyGenerator?: KeyGenerator;
  /**
   * Optional Redis or Redis Cluster client. When omitted, uses the globally
   * configured Redis client (if any) or executes synchronously in memory.
   */
  redis?: RedisEvalClient;
  /** Optional namespace prefix for Redis keys. */
  keyPrefix?: string;
  /** Optional tier label exposed via `X-RateLimit-Tier`. */
  tier?: RateLimitTier;
}

export interface RateLimitEvaluation {
  allowed: boolean;
  limit: number;
  remaining: number;
  resetAtMs: number;
  retryAfterSec: number;
  tier?: RateLimitTier;
  degradedToLocal: boolean;
}

interface LocalBucketEntry {
  timestamps: number[];
  tokens: number;
  lastRefillMs: number;
}

type LocalStore = Map<string, LocalBucketEntry>;

// How often, at most, a limiter walks its whole store to drop keys whose
// timestamps have all aged out. This bounds memory as clients come and go
// without a background timer that would keep the process (and `node --test`)
// alive; the sweep piggy-backs on request traffic instead.
const SWEEP_INTERVAL_MS = 60 * 1000;

let sharedRedisClient: RedisEvalClient | undefined;
let requestCounter = 0;

/**
 * Attaches or detaches a shared Redis/Cluster client used by default across
 * rate limiters when an explicit `redis` option is not passed.
 */
export function configureRateLimiterRedis(redisClient?: RedisEvalClient): void {
  sharedRedisClient = redisClient;
}

/**
 * Builds Redis Cluster-safe key pair using a shared `{hashTag}` so both keys
 * always land on the identical CRC16 hash slot.
 */
export function buildClusterKeys(
  prefix: string,
  bucketKey: string,
): { swKey: string; tbKey: string } {
  const sanitizedTag = bucketKey.replace(/[{}]/g, '_');
  return {
    swKey: `${prefix}:{${sanitizedTag}}:sw`,
    tbKey: `${prefix}:{${sanitizedTag}}:tb`,
  };
}

/**
 * Evaluates the sliding-window log + token-bucket algorithm locally in memory.
 * Used both as the primary store in single-process mode and as the automatic
 * zero-downtime fallback when Redis Cluster experiences a connectivity outage.
 */
function evaluateLocalBucket(
  store: LocalStore,
  key: string,
  now: number,
  windowMs: number,
  max: number,
  refillRatePerMs: number,
  tier?: RateLimitTier,
  degradedToLocal = false,
): RateLimitEvaluation {
  const windowStart = now - windowMs;
  const existing = store.get(key);

  let timestamps = existing ? existing.timestamps.filter((ts: number) => ts > windowStart) : [];
  let tokens = existing ? existing.tokens : max;
  const lastRefillMs = existing ? existing.lastRefillMs : now;

  if (existing) {
    const elapsed = Math.max(0, now - lastRefillMs);
    tokens = Math.min(max, tokens + elapsed * refillRatePerMs);
  }

  if (timestamps.length >= max || tokens < 1) {
    const swResetMs = timestamps.length > 0 ? timestamps[0]! + windowMs : now + windowMs;
    const tokenWaitMs =
      tokens < 1 && refillRatePerMs > 0 ? Math.ceil((1 - tokens) / refillRatePerMs) : 0;
    const resetAtMs = Math.max(swResetMs, now + tokenWaitMs);
    const retryAfterSec = Math.max(1, Math.ceil((resetAtMs - now) / 1000));

    store.set(key, {
      timestamps,
      tokens,
      lastRefillMs: now,
    });

    return {
      allowed: false,
      limit: max,
      remaining: 0,
      resetAtMs,
      retryAfterSec,
      tier,
      degradedToLocal,
    };
  }

  tokens -= 1;
  timestamps.push(now);
  store.set(key, {
    timestamps,
    tokens,
    lastRefillMs: now,
  });

  const swRemaining = max - timestamps.length;
  const tbRemaining = Math.floor(tokens);
  const remaining = Math.max(0, Math.min(swRemaining, tbRemaining));

  return {
    allowed: true,
    limit: max,
    remaining,
    resetAtMs: now + windowMs,
    retryAfterSec: 0,
    tier,
    degradedToLocal,
  };
}

/**
 * Evaluates the rate limit against Redis using the atomic Lua script, falling
 * back to the local in-memory sliding-window token bucket on any Redis error.
 */
export async function evaluateDistributedRateLimit(
  redis: RedisEvalClient | undefined,
  localStore: LocalStore,
  options: {
    keyPrefix: string;
    bucketKey: string;
    now: number;
    windowMs: number;
    max: number;
    refillRatePerMs: number;
    tier?: RateLimitTier;
  },
): Promise<RateLimitEvaluation> {
  const { keyPrefix, bucketKey, now, windowMs, max, refillRatePerMs, tier } = options;

  if (!redis) {
    return evaluateLocalBucket(
      localStore,
      bucketKey,
      now,
      windowMs,
      max,
      refillRatePerMs,
      tier,
      false,
    );
  }

  const { swKey, tbKey } = buildClusterKeys(keyPrefix, bucketKey);
  requestCounter = (requestCounter + 1) % 1_000_000_000;
  const requestId = `${now}:${requestCounter}`;

  try {
    const rawResult = await redis.eval(
      SLIDING_WINDOW_TOKEN_BUCKET_LUA,
      2,
      swKey,
      tbKey,
      now,
      windowMs,
      max,
      refillRatePerMs,
      requestId,
      1,
    );

    if (Array.isArray(rawResult) && rawResult.length >= 4) {
      const allowed = Number(rawResult[0]) === 1;
      const remaining = Math.max(0, Number(rawResult[1]));
      const resetAtMs = Number(rawResult[2]);
      const retryAfterSec = Math.max(0, Number(rawResult[3]));

      return {
        allowed,
        limit: max,
        remaining,
        resetAtMs,
        retryAfterSec,
        tier,
        degradedToLocal: false,
      };
    }
  } catch {
    // Graceful degradation: fall back to the in-memory sliding-window token bucket
    // when Redis Cluster experiences a connection drop, slot migration, or timeout.
  }

  return evaluateLocalBucket(
    localStore,
    bucketKey,
    now,
    windowMs,
    max,
    refillRatePerMs,
    tier,
    true,
  );
}

function applyRateLimitHeaders(res: Response, evaluation: RateLimitEvaluation): void {
  res.set('X-RateLimit-Limit', String(evaluation.limit));
  res.set('X-RateLimit-Remaining', String(evaluation.remaining));
  res.set('X-RateLimit-Reset', String(Math.ceil(evaluation.resetAtMs / 1000)));
  res.set('Retry-After', String(evaluation.retryAfterSec));
  if (evaluation.tier) {
    res.set('X-RateLimit-Tier', evaluation.tier);
  }
}

export function createRateLimiter(options: RateLimiterOptions): RequestHandler {
  const {
    windowMs,
    max,
    refillRatePerMs = max / windowMs,
    message = 'Too many requests, please try again later.',
    keyGenerator = (req: Request) => `ip:${clientIp(req)}`,
    redis: explicitRedis,
    keyPrefix = 'pactum:rl',
    tier,
  } = options;

  const store: LocalStore = new Map();
  let lastSweep = Date.now();

  const sweep = (now: number): void => {
    if (now - lastSweep < SWEEP_INTERVAL_MS) return;
    lastSweep = now;
    const windowStart = now - windowMs;
    for (const [key, entry] of store) {
      const lastTs = entry.timestamps[entry.timestamps.length - 1];
      if ((lastTs === undefined || lastTs <= windowStart) && now - entry.lastRefillMs > windowMs) {
        store.delete(key);
      }
    }
  };

  return (req: Request, res: Response, next: NextFunction): void | Promise<void> => {
    const now = Date.now();
    sweep(now);

    const key = keyGenerator(req);
    const activeRedis = explicitRedis ?? sharedRedisClient;

    // Synchronous fast path when running in pure in-memory mode (preserves
    // compatibility with synchronous middleware unit test harnesses).
    if (!activeRedis) {
      const evaluation = evaluateLocalBucket(
        store,
        key,
        now,
        windowMs,
        max,
        refillRatePerMs,
        tier,
        false,
      );
      applyRateLimitHeaders(res, evaluation);
      if (!evaluation.allowed) {
        res.status(429).json({ error: message });
        return;
      }
      next();
      return;
    }

    return evaluateDistributedRateLimit(activeRedis, store, {
      keyPrefix,
      bucketKey: tier ? `${tier}:${key}` : key,
      now,
      windowMs,
      max,
      refillRatePerMs,
      tier,
    }).then((evaluation) => {
      applyRateLimitHeaders(res, evaluation);
      if (!evaluation.allowed) {
        res.status(429).json({ error: message });
        return;
      }
      next();
    });
  };
}

/**
 * Classifies an incoming HTTP or WebSocket upgrade request into one of the three
 * Pactum traffic tiers (`relayer`, `attestor`, or `public`) and extracts its
 * canonical rate-limit identity key.
 */
export function resolveRequestTier(
  req: Pick<Request, 'headers' | 'socket' | 'path' | 'query' | 'body'>,
  relayerSecret = process.env.INTERNAL_RELAYER_SECRET,
): { tier: RateLimitTier; identityKey: string } {
  const relayerHeader = req.headers['x-relayer-key'] ?? req.headers['x-internal-relayer'];
  const relayerToken = Array.isArray(relayerHeader) ? relayerHeader[0] : relayerHeader;

  if (typeof relayerToken === 'string' && relayerToken.trim().length > 0) {
    // If INTERNAL_RELAYER_SECRET is configured, require an exact match; otherwise
    // accept registered relayer stellar addresses or explicit relayer tokens.
    if (
      (relayerSecret && relayerToken.trim() === relayerSecret) ||
      (!relayerSecret &&
        (STELLAR_ADDRESS.test(relayerToken.trim()) || relayerToken.trim().length >= 16))
    ) {
      return {
        tier: 'relayer',
        identityKey: `relayer:${relayerToken.trim()}`,
      };
    }
  }

  const attestorHeader = req.headers['x-attestor-address'];
  const rawAttestor =
    (Array.isArray(attestorHeader) ? attestorHeader[0] : attestorHeader) ??
    (req.body as { attestor?: unknown } | undefined)?.attestor ??
    (req.query as { attestor?: unknown } | undefined)?.attestor;

  if (typeof rawAttestor === 'string' && STELLAR_ADDRESS.test(rawAttestor.trim().toUpperCase())) {
    return {
      tier: 'attestor',
      identityKey: `attestor:${rawAttestor.trim().toUpperCase()}`,
    };
  }

  return {
    tier: 'public',
    identityKey: `ip:${clientIp(req)}`,
  };
}

export interface TieredRateLimiterOptions {
  redis?: RedisEvalClient;
  keyPrefix?: string;
  tiers?: Partial<Record<RateLimitTier, Partial<TierLimitConfig>>>;
  /** Optional override for write methods (`POST`, `PUT`, `PATCH`, `DELETE`) on the public tier. */
  publicWriteMax?: number;
  relayerSecret?: string;
}

/**
 * Creates a unified tiered Express rate-limiting middleware that differentiates
 * between anonymous public endpoints, registered attestor streams/endpoints, and
 * internal relayers, backed by Redis Cluster with automatic local fallback.
 */
export function createTieredRateLimiter(options: TieredRateLimiterOptions = {}): RequestHandler {
  const {
    redis: explicitRedis,
    keyPrefix = 'pactum:rl',
    tiers = {},
    publicWriteMax = 10,
    relayerSecret,
  } = options;

  const mergedTiers: Record<RateLimitTier, TierLimitConfig> = {
    public: { ...DEFAULT_TIER_LIMITS.public, ...tiers.public },
    attestor: { ...DEFAULT_TIER_LIMITS.attestor, ...tiers.attestor },
    relayer: { ...DEFAULT_TIER_LIMITS.relayer, ...tiers.relayer },
  };

  const localStore: LocalStore = new Map();
  let lastSweep = Date.now();
  const writeMethods = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

  const sweep = (now: number): void => {
    if (now - lastSweep < SWEEP_INTERVAL_MS) return;
    lastSweep = now;
    const maxWindow = Math.max(
      mergedTiers.public.windowMs,
      mergedTiers.attestor.windowMs,
      mergedTiers.relayer.windowMs,
    );
    const windowStart = now - maxWindow;
    for (const [key, entry] of localStore) {
      const lastTs = entry.timestamps[entry.timestamps.length - 1];
      if ((lastTs === undefined || lastTs <= windowStart) && now - entry.lastRefillMs > maxWindow) {
        localStore.delete(key);
      }
    }
  };

  return (req: Request, res: Response, next: NextFunction): void | Promise<void> => {
    const now = Date.now();
    sweep(now);

    const { tier, identityKey } = resolveRequestTier(req, relayerSecret);
    const tierConfig = mergedTiers[tier];
    const isPublicWrite = tier === 'public' && writeMethods.has(req.method);
    const max = isPublicWrite ? publicWriteMax : tierConfig.max;
    const windowMs = tierConfig.windowMs;
    const refillRatePerMs = tierConfig.refillRatePerMs ?? max / windowMs;
    const message = isPublicWrite
      ? 'Too many write requests from this IP, please try again after a minute.'
      : (tierConfig.message ?? 'Too many requests, please try again later.');

    const bucketKey = `${tier}:${ isPublicWrite ? 'write' : 'read' }:${identityKey}`;
    const activeRedis = explicitRedis ?? sharedRedisClient;

    if (!activeRedis) {
      const evaluation = evaluateLocalBucket(
        localStore,
        bucketKey,
        now,
        windowMs,
        max,
        refillRatePerMs,
        tier,
        false,
      );
      applyRateLimitHeaders(res, evaluation);
      if (!evaluation.allowed) {
        res.status(429).json({ error: message });
        return;
      }
      next();
      return;
    }

    return evaluateDistributedRateLimit(activeRedis, localStore, {
      keyPrefix,
      bucketKey,
      now,
      windowMs,
      max,
      refillRatePerMs,
      tier,
    }).then((evaluation) => {
      applyRateLimitHeaders(res, evaluation);
      if (!evaluation.allowed) {
        res.status(429).json({ error: message });
        return;
      }
      next();
    });
  };
}

/**
 * Buckets a commitment-creation request by its issuing Stellar address —
 * `partyA` in the request body. Requests whose `partyA` is missing or not a
 * well-formed address (malformed input, unauthenticated probing) fall back to
 * per-IP limiting, so the cap cannot be dodged simply by omitting the field.
 *
 * The address is the *claimed* issuer; the API does not verify its signature
 * (that authenticity is enforced on-chain by `require_auth`). Per-address
 * limiting here is therefore a first line of defence against spamming
 * `create_commitment`, not an authentication boundary.
 */
const commitmentKey: KeyGenerator = (req: Request): string => {
  const partyA = (req.body as { partyA?: unknown } | undefined)?.partyA;
  if (typeof partyA === 'string' && STELLAR_ADDRESS.test(partyA)) {
    return `addr:${partyA}`;
  }
  return `ip:${clientIp(req)}`;
};

/**
 * Standard rate limiter for GET / read endpoints.
 * Allows 100 requests per IP per 60-second sliding window.
 */
export const standardLimiter: RequestHandler = createRateLimiter({
  windowMs: 60 * 1000, // 1 minute
  max: 100,
  tier: 'public',
  message: 'Too many requests from this IP, please try again after a minute.',
});

/**
 * Strict rate limiter for write (POST / PUT / PATCH / DELETE) endpoints.
 * Allows 10 requests per IP per 60-second sliding window.
 */
export const strictLimiter: RequestHandler = createRateLimiter({
  windowMs: 60 * 1000, // 1 minute
  max: 10,
  tier: 'public',
  message: 'Too many write requests from this IP, please try again after a minute.',
});

/**
 * Registered attestor rate limiter for high-frequency attestor streams & endpoints.
 * Allows 300 requests per attestor per 60-second sliding window.
 */
export const attestorLimiter: RequestHandler = createRateLimiter({
  windowMs: DEFAULT_TIER_LIMITS.attestor.windowMs,
  max: DEFAULT_TIER_LIMITS.attestor.max,
  tier: 'attestor',
  message: DEFAULT_TIER_LIMITS.attestor.message,
  keyGenerator: (req: Request) => resolveRequestTier(req).identityKey,
});

/**
 * Internal relayer rate limiter for batch proof & state submission routes.
 * Allows 1000 requests per relayer per 60-second sliding window.
 */
export const relayerLimiter: RequestHandler = createRateLimiter({
  windowMs: DEFAULT_TIER_LIMITS.relayer.windowMs,
  max: DEFAULT_TIER_LIMITS.relayer.max,
  tier: 'relayer',
  message: DEFAULT_TIER_LIMITS.relayer.message,
  keyGenerator: (req: Request) => resolveRequestTier(req).identityKey,
});

/**
 * Per-address rate limiter for POST /commitments (the on-chain
 * `create_commitment` call). Caps each issuing Stellar address to 10 commitment
 * creations per hour so the API cannot be used to spam the registry — bloating
 * on-chain storage and polluting reputation scores — with a per-IP fallback for
 * requests that carry no valid address.
 */
export const createCommitmentLimiter: RequestHandler = createRateLimiter({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10,
  tier: 'public',
  message:
    'Too many commitments created for this address. A maximum of 10 per hour is allowed; please try again later.',
  keyGenerator: commitmentKey,
});
