import type { RateLimitStore, RateLimitStoreState } from '../rate-limit.js';
import type { ReplayStore } from '../webhooks.js';

export interface NodeRedisLike {
  set(key: string, value: string, options: { NX: true; PX: number }): Promise<string | null> | string | null;
  eval(script: string, options: { keys: string[]; arguments: string[] }): Promise<unknown> | unknown;
}

export interface IORedisLike {
  set(key: string, value: string, mode: 'PX', ttlMs: number, condition: 'NX'): Promise<string | null> | string | null;
  eval(script: string, numberOfKeys: number, key: string, windowMs: string): Promise<unknown> | unknown;
}

const RATE_LIMIT_SCRIPT = `local current = redis.call('INCR', KEYS[1])
if current == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[1]) end
local ttl = redis.call('PTTL', KEYS[1])
return {current, ttl}`;

function ttlFromExpiry(expiresAt: number): number {
  if (!Number.isFinite(expiresAt)) throw new RangeError('expiresAt must be finite');
  return Math.max(0, Math.ceil(expiresAt - Date.now()));
}

function parseRateState(raw: unknown, now: number): RateLimitStoreState {
  if (!Array.isArray(raw) || raw.length < 2) throw new Error('Redis rate-limit script returned an invalid result');
  const count = Number(String(raw[0]));
  const ttl = Number(String(raw[1]));
  if (!Number.isInteger(count) || count < 1 || !Number.isFinite(ttl)) throw new Error('Redis rate-limit script returned invalid counters');
  return { count, resetAt: now + Math.max(ttl, 0) };
}

function keyWithPrefix(prefix: string, key: string): string {
  return `${prefix}${key}`;
}

export function createNodeRedisReplayStore(client: NodeRedisLike, prefix = 'axiomguard:replay:'): ReplayStore {
  return {
    async claim(key: string, expiresAt: number): Promise<boolean> {
      const ttl = ttlFromExpiry(expiresAt);
      if (ttl <= 0) return false;
      return (await client.set(keyWithPrefix(prefix, key), '1', { NX: true, PX: ttl })) === 'OK';
    },
  };
}

export function createIORedisReplayStore(client: IORedisLike, prefix = 'axiomguard:replay:'): ReplayStore {
  return {
    async claim(key: string, expiresAt: number): Promise<boolean> {
      const ttl = ttlFromExpiry(expiresAt);
      if (ttl <= 0) return false;
      return (await client.set(keyWithPrefix(prefix, key), '1', 'PX', ttl, 'NX')) === 'OK';
    },
  };
}

export function createNodeRedisRateLimitStore(client: NodeRedisLike, prefix = 'axiomguard:rate:'): RateLimitStore {
  return {
    async consume(key: string, windowMs: number, now = Date.now()): Promise<RateLimitStoreState> {
      const raw = await client.eval(RATE_LIMIT_SCRIPT, { keys: [keyWithPrefix(prefix, key)], arguments: [String(windowMs)] });
      return parseRateState(raw, now);
    },
  };
}

export function createIORedisRateLimitStore(client: IORedisLike, prefix = 'axiomguard:rate:'): RateLimitStore {
  return {
    async consume(key: string, windowMs: number, now = Date.now()): Promise<RateLimitStoreState> {
      const raw = await client.eval(RATE_LIMIT_SCRIPT, 1, keyWithPrefix(prefix, key), String(windowMs));
      return parseRateState(raw, now);
    },
  };
}
