export interface RateLimitStoreState {
  count: number;
  resetAt: number;
}

export interface RateLimitStore {
  consume(key: string, windowMs: number, now?: number): RateLimitStoreState | Promise<RateLimitStoreState>;
}

export interface RateLimitOptions {
  limit: number;
  windowMs: number;
  store: RateLimitStore;
  now?: number;
}

export interface RateLimitResult extends RateLimitStoreState {
  allowed: boolean;
  limit: number;
  remaining: number;
  retryAfterSeconds: number;
}

export class MemoryRateLimitStore implements RateLimitStore {
  private readonly entries = new Map<string, RateLimitStoreState>();

  consume(key: string, windowMs: number, now = Date.now()): RateLimitStoreState {
    const current = this.entries.get(key);
    if (!current || current.resetAt <= now) {
      const state = { count: 1, resetAt: now + windowMs };
      this.entries.set(key, state);
      return { ...state };
    }
    current.count += 1;
    return { ...current };
  }

  clear(): void {
    this.entries.clear();
  }
}

export async function checkRateLimit(key: string, options: RateLimitOptions): Promise<RateLimitResult> {
  if (typeof key !== 'string' || key.length === 0 || key.length > 512) throw new TypeError('rate-limit key must be 1-512 characters');
  if (!Number.isInteger(options.limit) || options.limit < 1) throw new RangeError('limit must be a positive integer');
  if (!Number.isInteger(options.windowMs) || options.windowMs < 1) throw new RangeError('windowMs must be a positive integer');
  const now = options.now ?? Date.now();
  if (!Number.isFinite(now) || now < 0) throw new RangeError('now must be a non-negative finite timestamp');

  const state = await options.store.consume(key, options.windowMs, now);
  if (!Number.isInteger(state.count) || state.count < 1 || !Number.isFinite(state.resetAt)) throw new Error('rate-limit store returned an invalid state');
  const allowed = state.count <= options.limit;
  return {
    ...state,
    allowed,
    limit: options.limit,
    remaining: Math.max(options.limit - state.count, 0),
    retryAfterSeconds: allowed ? 0 : Math.max(1, Math.ceil((state.resetAt - now) / 1000)),
  };
}
