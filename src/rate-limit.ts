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
  /** Timestamp used to calculate reset delay. Defaults to Date.now(). */
  now?: number;
  /** Stable policy identifier used in current IETF draft fields. Default: "default". */
  policyName?: string;
  /** Emit RateLimit-Policy and RateLimit draft fields. Default: true. */
  includeDraftFields?: boolean;
  /** Emit widely deployed RateLimit-Limit/Remaining/Reset compatibility fields. Default: true. */
  includeLegacyFields?: boolean;
  /** Emit Retry-After only when the request is blocked. Default: true. */
  includeRetryAfter?: boolean;
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
    windowMs: options.windowMs,
  };
}

/**
 * Convert a RateLimitResult into response headers without exposing the key
 * used to partition the limiter. Current IETF RateLimit fields are still a
 * draft, so compatibility fields can be emitted alongside them.
 */
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
