import type { IdempotencyClaimStatus, IdempotencyStore } from '../idempotency.js';
import type { RateLimitStore, RateLimitStoreState } from '../rate-limit.js';
import type { ReplayStore } from '../webhooks.js';

export interface NodeRedisLike {
  set(key: string, value: string, options: { NX: true; PX: number }): Promise<string | null> | string | null;
  eval(script: string, options: { keys: string[]; arguments: string[] }): Promise<unknown> | unknown;
}

export interface IORedisLike {
  set(key: string, value: string, mode: 'PX', ttlMs: number, condition: 'NX'): Promise<string | null> | string | null;
  eval(script: string, numberOfKeys: number, ...args: string[]): Promise<unknown> | unknown;
}

const RATE_LIMIT_SCRIPT = `local current = redis.call('INCR', KEYS[1])
local ttl = redis.call('PTTL', KEYS[1])
if current == 1 or ttl < 0 then
  redis.call('PEXPIRE', KEYS[1], ARGV[1])
  ttl = tonumber(ARGV[1])
end
return {current, ttl}`;

const IDEMPOTENCY_SCRIPT = `local existing = redis.call('GET', KEYS[1])
if existing then
  if existing == ARGV[1] then return 0 end
  return 1
end
local claimed = redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[2], 'NX')
if claimed then return 2 end
local after = redis.call('GET', KEYS[1])
if after == ARGV[1] then return 0 end
return 1`;

const SHA256_HEX = /^[a-f0-9]{64}$/;

function ttlFromExpiry(expiresAt: number, now: number): number {
  if (!Number.isFinite(expiresAt)) throw new RangeError('expiresAt must be finite');
  if (!Number.isFinite(now) || now < 0) throw new RangeError('now must be a non-negative finite timestamp');
  return Math.max(0, Math.ceil(expiresAt - now));
}

function parseRateState(raw: unknown, now: number): RateLimitStoreState {
  if (!Array.isArray(raw) || raw.length < 2) throw new Error('Redis rate-limit script returned an invalid result');
  const count = Number(String(raw[0]));
  const ttl = Number(String(raw[1]));
  if (!Number.isSafeInteger(count) || count < 1 || !Number.isSafeInteger(ttl) || ttl < 0) {
    throw new Error('Redis rate-limit script returned invalid counters');
  }
  return { count, resetAt: now + ttl };
}

function parseIdempotencyStatus(raw: unknown): IdempotencyClaimStatus {
  const value = Number(String(raw));
  if (value === 0) return 'replay';
  if (value === 1) return 'conflict';
  if (value === 2) return 'accepted';
  throw new Error('Redis idempotency script returned an invalid result');
}

function validateIdempotencyInput(keyHash: string, fingerprint: string, ttl: number): void {
  if (!SHA256_HEX.test(keyHash)) throw new TypeError('keyHash must be a lowercase SHA-256 hex digest');
  if (!SHA256_HEX.test(fingerprint)) throw new TypeError('fingerprint must be a lowercase SHA-256 hex digest');
  if (ttl <= 0) throw new RangeError('expiresAt must be in the future');
}

function keyWithPrefix(prefix: string, key: string): string {
  return `${prefix}${key}`;
}

function validateWindow(windowMs: number, now: number): void {
  if (!Number.isInteger(windowMs) || windowMs < 1) throw new RangeError('windowMs must be a positive integer');
  if (!Number.isFinite(now) || now < 0) throw new RangeError('now must be a non-negative finite timestamp');
}

export function createNodeRedisReplayStore(client: NodeRedisLike, prefix = 'axiomguard:replay:'): ReplayStore {
  return {
    async claim(key: string, expiresAt: number, now = Date.now()): Promise<boolean> {
      const ttl = ttlFromExpiry(expiresAt, now);
      if (ttl <= 0) return false;
      return (await client.set(keyWithPrefix(prefix, key), '1', { NX: true, PX: ttl })) === 'OK';
    },
  };
}

export function createIORedisReplayStore(client: IORedisLike, prefix = 'axiomguard:replay:'): ReplayStore {
  return {
    async claim(key: string, expiresAt: number, now = Date.now()): Promise<boolean> {
      const ttl = ttlFromExpiry(expiresAt, now);
      if (ttl <= 0) return false;
      return (await client.set(keyWithPrefix(prefix, key), '1', 'PX', ttl, 'NX')) === 'OK';
    },
  };
}

export function createNodeRedisRateLimitStore(client: NodeRedisLike, prefix = 'axiomguard:rate:'): RateLimitStore {
  return {
    async consume(key: string, windowMs: number, now = Date.now()): Promise<RateLimitStoreState> {
      validateWindow(windowMs, now);
      const raw = await client.eval(RATE_LIMIT_SCRIPT, { keys: [keyWithPrefix(prefix, key)], arguments: [String(windowMs)] });
      return parseRateState(raw, now);
    },
  };
}

export function createIORedisRateLimitStore(client: IORedisLike, prefix = 'axiomguard:rate:'): RateLimitStore {
  return {
    async consume(key: string, windowMs: number, now = Date.now()): Promise<RateLimitStoreState> {
      validateWindow(windowMs, now);
      const raw = await client.eval(RATE_LIMIT_SCRIPT, 1, keyWithPrefix(prefix, key), String(windowMs));
      return parseRateState(raw, now);
    },
  };
}

export function createNodeRedisIdempotencyStore(client: NodeRedisLike, prefix = 'axiomguard:idempotency:'): IdempotencyStore {
  return {
    async claim(keyHash: string, fingerprint: string, expiresAt: number, now = Date.now()): Promise<IdempotencyClaimStatus> {
      const ttl = ttlFromExpiry(expiresAt, now);
      validateIdempotencyInput(keyHash, fingerprint, ttl);
      const raw = await client.eval(IDEMPOTENCY_SCRIPT, {
        keys: [keyWithPrefix(prefix, keyHash)],
        arguments: [fingerprint, String(ttl)],
      });
      return parseIdempotencyStatus(raw);
    },
  };
}

export function createIORedisIdempotencyStore(client: IORedisLike, prefix = 'axiomguard:idempotency:'): IdempotencyStore {
  return {
    async claim(keyHash: string, fingerprint: string, expiresAt: number, now = Date.now()): Promise<IdempotencyClaimStatus> {
      const ttl = ttlFromExpiry(expiresAt, now);
      validateIdempotencyInput(keyHash, fingerprint, ttl);
      const raw = await client.eval(IDEMPOTENCY_SCRIPT, 1, keyWithPrefix(prefix, keyHash), fingerprint, String(ttl));
      return parseIdempotencyStatus(raw);
    },
  };
}
