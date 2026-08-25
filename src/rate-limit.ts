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
  windowMs: number;
}

export interface RateLimitHeaderOptions {
  now?: number;
  policyName?: string;
  includeDraftFields?: boolean;
  includeLegacyFields?: boolean;
  includeRetryAfter?: boolean;
}

export class MemoryRateLimitStore implements RateLimitStore {
  private readonly entries = new Map<string, RateLimitStoreState>();
  private operations = 0;

  constructor(private readonly maxEntries = 10_000) {
    if (!Number.isInteger(maxEntries) || maxEntries < 1 || maxEntries > 1_000_000) {
      throw new RangeError('maxEntries must be an integer between 1 and 1000000');
    }
  }

  private sweepExpired(now: number): void {
    for (const [candidate, state] of this.entries) {
      if (state.resetAt <= now) this.entries.delete(candidate);
    }
  }

  consume(key: string, windowMs: number, now = Date.now()): RateLimitStoreState {
    if (!Number.isInteger(windowMs) || windowMs < 1) throw new RangeError('windowMs must be a positive integer');
    if (!Number.isFinite(now) || now < 0) throw new RangeError('now must be a non-negative finite timestamp');

    this.operations += 1;
    if (this.operations % 256 === 0 || this.entries.size >= this.maxEntries) this.sweepExpired(now);

    const current = this.entries.get(key);
    if (!current || current.resetAt <= now) {
      if (current) this.entries.delete(key);
      while (this.entries.size >= this.maxEntries) {
        const oldest = this.entries.keys().next().value as string | undefined;
        if (oldest === undefined) break;
        this.entries.delete(oldest);
      }
      const state = { count: 1, resetAt: now + windowMs };
      this.entries.set(key, state);
      return { ...state };
    }

    if (current.count < Number.MAX_SAFE_INTEGER) current.count += 1;
    return { ...current };
  }

  clear(): void {
    this.entries.clear();
    this.operations = 0;
  }
}

export async function checkRateLimit(key: string, options: RateLimitOptions): Promise<RateLimitResult> {
  if (typeof key !== 'string' || key.length === 0 || key.length > 512) throw new TypeError('rate-limit key must be 1-512 characters');
  if (!Number.isInteger(options.limit) || options.limit < 1) throw new RangeError('limit must be a positive integer');
  if (!Number.isInteger(options.windowMs) || options.windowMs < 1) throw new RangeError('windowMs must be a positive integer');
  const now = options.now ?? Date.now();
  if (!Number.isFinite(now) || now < 0) throw new RangeError('now must be a non-negative finite timestamp');

  const state = await options.store.consume(key, options.windowMs, now);
  if (!Number.isSafeInteger(state.count) || state.count < 1 || !Number.isFinite(state.resetAt) || state.resetAt < now) {
    throw new Error('rate-limit store returned an invalid state');
  }
  const allowed = state.count <= options.limit;
  return {
    ...state,
    allowed,
    limit: options.limit,
    remaining: Math.max(options.limit - state.count, 0),
    retryAfterSeconds: allowed ? 0 : Math.max(1, Math.ceil((state.resetAt - now) / 1000)),
    windowMs: options.windowMs,
  };
}

export function createRateLimitHeaders(result: RateLimitResult, options: RateLimitHeaderOptions = {}): Record<string, string> {
  if (!Number.isInteger(result.limit) || result.limit < 1) throw new Error('rate-limit result has an invalid limit');
  if (!Number.isInteger(result.remaining) || result.remaining < 0) throw new Error('rate-limit result has an invalid remaining count');
  if (!Number.isInteger(result.windowMs) || result.windowMs < 1) throw new Error('rate-limit result has an invalid windowMs');
  if (!Number.isFinite(result.resetAt)) throw new Error('rate-limit result has an invalid resetAt');

  const now = options.now ?? Date.now();
  if (!Number.isFinite(now) || now < 0) throw new RangeError('now must be a non-negative finite timestamp');

  const policyName = options.policyName ?? 'default';
  if (!/^[A-Za-z0-9._-]{1,64}$/.test(policyName)) {
    throw new Error('policyName must contain only letters, numbers, dot, underscore, or hyphen');
  }

  const resetSeconds = Math.max(0, Math.ceil((result.resetAt - now) / 1000));
  const windowSeconds = Math.max(1, Math.ceil(result.windowMs / 1000));
  const headers: Record<string, string> = {};

  if (options.includeDraftFields ?? true) {
    headers['RateLimit-Policy'] = `"${policyName}";q=${result.limit};w=${windowSeconds}`;
    headers.RateLimit = `"${policyName}";r=${result.remaining};t=${resetSeconds}`;
  }

  if (options.includeLegacyFields ?? true) {
    headers['RateLimit-Limit'] = String(result.limit);
    headers['RateLimit-Remaining'] = String(result.remaining);
    headers['RateLimit-Reset'] = String(resetSeconds);
  }

  if (!result.allowed && (options.includeRetryAfter ?? true)) {
    headers['Retry-After'] = String(Math.max(1, result.retryAfterSeconds));
  }

  return headers;
}
