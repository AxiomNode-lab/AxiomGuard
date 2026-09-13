import { isIP } from 'node:net';

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
    if (current && current.resetAt > now) {
      if (current.count < Number.MAX_SAFE_INTEGER) current.count += 1;
      return { ...current };
    }
    if (current) this.entries.delete(key);

    // Do not silently evict a live identity when the store is saturated: that
    // would let high-cardinality traffic reset another client's rate-limit
    // history. Saturate unknown identities instead until tracked windows expire.
    if (this.entries.size >= this.maxEntries) {
      return { count: Number.MAX_SAFE_INTEGER, resetAt: now + windowMs };
    }

    const state = { count: 1, resetAt: now + windowMs };
    this.entries.set(key, state);
    return { ...state };
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

export interface ClientIpOptions {
  /**
   * Number of trusted reverse proxies in front of the service. The client IP
   * is taken that many hops from the right of `X-Forwarded-For`; entries
   * further left are attacker-controlled. Default: 0 (ignore the header).
   */
  trustedProxyCount?: number;
}

function normalizeIp(value: string): string | null {
  let candidate = value.trim();
  if (candidate.startsWith('[') && candidate.endsWith(']')) candidate = candidate.slice(1, -1);
  if (/^::ffff:\d{1,3}(?:\.\d{1,3}){3}$/i.test(candidate)) candidate = candidate.slice('::ffff:'.length);
  const family = isIP(candidate);
  if (family === 0) return null;
  return family === 6 ? candidate.toLowerCase() : candidate;
}

/**
 * Derive a rate-limit partition key from the socket address and, only when
 * `trustedProxyCount` is set, the `X-Forwarded-For` chain. Anything the
 * client could have written is ignored, so the result cannot be spoofed to
 * escape a limit or to poison someone else's bucket.
 */
export function getClientIp(remoteAddress: string | undefined | null, forwardedFor: string | readonly string[] | undefined | null, options: ClientIpOptions = {}): string | null {
  const trusted = options.trustedProxyCount ?? 0;
  if (!Number.isInteger(trusted) || trusted < 0 || trusted > 32) throw new RangeError('trustedProxyCount must be an integer between 0 and 32');
  const socket = typeof remoteAddress === 'string' ? normalizeIp(remoteAddress) : null;
  if (trusted === 0) return socket;

  const raw = Array.isArray(forwardedFor) ? forwardedFor.join(',') : typeof forwardedFor === 'string' ? forwardedFor : '';
  const hops = raw.split(',').map((hop) => hop.trim()).filter((hop) => hop.length > 0);
  // The socket peer is proxy #1; the header lists the rest right-to-left.
  const index = hops.length - trusted;
  if (index < 0) return socket;
  const candidate = hops[index];
  return candidate === undefined ? socket : normalizeIp(candidate) ?? socket;
}

/** Bucket an IPv6 address by its /64 so one host cannot rotate through a whole prefix. Returns IPv4 unchanged. */
export function rateLimitBucketForIp(ip: string): string {
  const normalized = normalizeIp(ip);
  if (!normalized) throw new TypeError('ip must be a valid IPv4 or IPv6 address');
  if (isIP(normalized) === 4) return normalized;
  const expanded = normalized.split('::');
  const left = expanded[0] ? expanded[0].split(':') : [];
  const right = expanded[1] ? expanded[1].split(':') : [];
  const missing = 8 - left.length - right.length;
  const words = [...left, ...Array.from({ length: expanded.length > 1 ? missing : 0 }, () => '0'), ...right];
  return `${words.slice(0, 4).map((word) => word.padStart(4, '0')).join(':')}::/64`;
}
