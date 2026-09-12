import { createHash } from 'node:crypto';

export type IdempotencyClaimStatus = 'accepted' | 'replay' | 'conflict' | 'capacity';

export interface IdempotencyStore {
  /**
   * Claim a hashed idempotency key for a request fingerprint until expiresAt.
   * Implementations must make the check-and-set operation atomic.
   */
  claim(
    keyHash: string,
    fingerprint: string,
    expiresAt: number,
    now?: number,
  ): IdempotencyClaimStatus | Promise<IdempotencyClaimStatus>;
}

interface MemoryIdempotencyEntry {
  fingerprint: string;
  expiresAt: number;
}

/**
 * Bounded single-process claim store. It fails closed with `capacity` rather
 * than evicting a live claim. Multi-instance deployments must use a shared
 * store such as the Redis adapters.
 */
export class MemoryIdempotencyStore implements IdempotencyStore {
  private readonly entries = new Map<string, MemoryIdempotencyEntry>();
  private operations = 0;
  private nextExpiry = Number.POSITIVE_INFINITY;

  constructor(private readonly maxEntries = 10_000) {
    if (!Number.isInteger(maxEntries) || maxEntries < 1 || maxEntries > 1_000_000) {
      throw new RangeError('maxEntries must be an integer between 1 and 1000000');
    }
  }

  protected sweepExpired(now: number): void {
    let next = Number.POSITIVE_INFINITY;
    for (const [key, entry] of this.entries) {
      if (entry.expiresAt <= now) this.entries.delete(key);
      else if (entry.expiresAt < next) next = entry.expiresAt;
    }
    this.nextExpiry = next;
  }

  claim(keyHash: string, fingerprint: string, expiresAt: number, now = Date.now()): IdempotencyClaimStatus {
    validateStoreInputs(keyHash, fingerprint, expiresAt, now);
    this.operations += 1;
    // Sweeping is O(n); only do it when at least one entry can have expired so
    // a saturated store does not scan everything on every claim.
    if ((this.operations % 256 === 0 || this.entries.size >= this.maxEntries) && this.nextExpiry <= now) this.sweepExpired(now);

    const existing = this.entries.get(keyHash);
    if (existing && existing.expiresAt > now) {
      return existing.fingerprint === fingerprint ? 'replay' : 'conflict';
    }
    if (existing) this.entries.delete(keyHash);

    // Fail closed instead of evicting a live idempotency claim. Silent
    // eviction would permit a high-cardinality request stream to make an
    // earlier operation appear new again.
    if (this.entries.size >= this.maxEntries) return 'capacity';

    this.entries.set(keyHash, { fingerprint, expiresAt });
    if (expiresAt < this.nextExpiry) this.nextExpiry = expiresAt;
    return 'accepted';
  }

  clear(): void {
    this.entries.clear();
    this.operations = 0;
    this.nextExpiry = Number.POSITIVE_INFINITY;
  }

  get size(): number {
    return this.entries.size;
  }
}

export interface IdempotencyFingerprintInput {
  method: string;
  target: string;
  body?: string | Buffer | Uint8Array;
  contentType?: string;
}

export interface ClaimIdempotencyKeyOptions {
  store: IdempotencyStore;
  /** Claim lifetime. Default: 24 hours. */
  ttlMs?: number;
  now?: number;
  /**
   * Namespace the key belongs to, normally the authenticated principal or
   * tenant. Without a scope, two callers presenting the same key collide:
   * one sees `replay` or `conflict` for the other's operation.
   */
  scope?: string;
}

/** Outcome of `claimIdempotencyKey`, including header-shape failures that stores never see. */
export type IdempotencyClaimResult = IdempotencyClaimStatus | 'missing-key' | 'invalid-key';

const METHOD_TOKEN = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
const HEX_SHA256 = /^[a-f0-9]{64}$/;

function validateTimestamp(now: number): void {
  if (!Number.isFinite(now) || now < 0) throw new RangeError('now must be a non-negative finite timestamp');
}

function validateStoreInputs(keyHash: string, fingerprint: string, expiresAt: number, now: number): void {
  validateTimestamp(now);
  if (!HEX_SHA256.test(keyHash)) throw new TypeError('keyHash must be a lowercase SHA-256 hex digest');
  if (!HEX_SHA256.test(fingerprint)) throw new TypeError('fingerprint must be a lowercase SHA-256 hex digest');
  if (!Number.isFinite(expiresAt) || expiresAt <= now) throw new RangeError('expiresAt must be a future finite timestamp');
}

function decodeQuotedKey(value: string): string | null {
  if (value.length < 2 || value[0] !== '"' || value[value.length - 1] !== '"') return null;
  let result = '';
  for (let index = 1; index < value.length - 1; index += 1) {
    const char = value[index]!;
    if (char === '\\') {
      const next = value[index + 1];
      if (next !== '\\' && next !== '"') throw new TypeError('Invalid quoted Idempotency-Key escape');
      result += next;
      index += 1;
      continue;
    }
    if (char === '"') throw new TypeError('Unescaped quote in Idempotency-Key');
    result += char;
  }
  return result;
}

/**
 * Normalize a caller supplied Idempotency-Key value. Both ordinary visible
 * ASCII values and quoted Structured-Field-style strings are accepted.
 */
export function normalizeIdempotencyKey(value: string): string {
  if (typeof value !== 'string') throw new TypeError('Idempotency-Key must be a string');
  const trimmed = value.trim();
  if (!trimmed) throw new TypeError('Idempotency-Key must not be empty');
  const decoded = trimmed.startsWith('"') ? decodeQuotedKey(trimmed) : trimmed;
  if (decoded === null || !decoded) throw new TypeError('Invalid Idempotency-Key');
  if (Buffer.byteLength(decoded, 'utf8') > 255) throw new RangeError('Idempotency-Key must be at most 255 bytes');
  if (/[^\x20-\x7e]/.test(decoded)) throw new TypeError('Idempotency-Key must contain visible ASCII characters only');
  return decoded;
}

/**
 * Return a stable non-secret store key so raw client keys need not become
 * Redis keys or logs. `scope` (tenant, user id) namespaces the key.
 */
export function createIdempotencyStoreKey(key: string, scope?: string): string {
  const hash = createHash('sha256');
  if (scope !== undefined) {
    if (typeof scope !== 'string' || scope.length === 0 || scope.length > 512) throw new TypeError('scope must be a non-empty string of at most 512 characters');
    hash.update('scope\0', 'utf8').update(scope, 'utf8').update('\0', 'utf8');
  }
  return hash.update(normalizeIdempotencyKey(key), 'utf8').digest('hex');
}

function updatePart(hash: ReturnType<typeof createHash>, label: string, value: Buffer): void {
  hash.update(label, 'utf8');
  hash.update('\0', 'utf8');
  hash.update(String(value.byteLength), 'utf8');
  hash.update('\0', 'utf8');
  hash.update(value);
  hash.update('\0', 'utf8');
}

/**
 * Fingerprint the request semantics that must remain stable when a client
 * retries an idempotent operation with the same key.
 *
 * The fingerprint covers the exact bytes of method, request target (including
 * query-string order), normalized content type (including parameters) and
 * body. Proxies that re-serialize any of these produce a `conflict`.
 */
export function createIdempotencyFingerprint(input: IdempotencyFingerprintInput): string {
  const method = input.method.trim().toUpperCase();
  if (!method || !METHOD_TOKEN.test(method)) throw new TypeError('method must be a valid HTTP method token');
  if (!input.target || input.target.length > 8192 || /[\u0000-\u001f\u007f]/.test(input.target)) {
    throw new TypeError('target must be a non-empty request target without control characters');
  }
  const contentType = input.contentType?.trim().toLowerCase() ?? '';
  if (contentType.length > 512 || /[\u0000-\u001f\u007f]/.test(contentType)) throw new TypeError('contentType is invalid');
  const body = typeof input.body === 'string'
    ? Buffer.from(input.body, 'utf8')
    : input.body === undefined
      ? Buffer.alloc(0)
      : Buffer.from(input.body);

  const hash = createHash('sha256');
  updatePart(hash, 'method', Buffer.from(method, 'utf8'));
  updatePart(hash, 'target', Buffer.from(input.target, 'utf8'));
  updatePart(hash, 'content-type', Buffer.from(contentType, 'utf8'));
  updatePart(hash, 'body', body);
  return hash.digest('hex');
}

/**
 * Claim an `Idempotency-Key` for a request fingerprint. The raw header value
 * (string, single-element array, or absent) is accepted directly; malformed or
 * missing keys are reported as statuses rather than thrown so handlers can map
 * them to 400 responses.
 */
export async function claimIdempotencyKey(
  key: string | readonly string[] | undefined | null,
  fingerprint: string,
  options: ClaimIdempotencyKeyOptions,
): Promise<IdempotencyClaimResult> {
  if (!HEX_SHA256.test(fingerprint)) throw new TypeError('fingerprint must be a lowercase SHA-256 hex digest');
  const ttlMs = options.ttlMs ?? 86_400_000;
  if (!Number.isInteger(ttlMs) || ttlMs < 1_000 || ttlMs > 604_800_000) {
    throw new RangeError('ttlMs must be an integer between 1000 and 604800000');
  }
  const now = options.now ?? Date.now();
  validateTimestamp(now);

  let single: string | undefined;
  if (typeof key === 'string') single = key;
  else if (key === undefined || key === null) single = undefined;
  else if (key.length > 1) return 'invalid-key';
  else single = key[0];
  if (single === undefined || single === '') return 'missing-key';
  let keyHash: string;
  try {
    keyHash = createIdempotencyStoreKey(single, options.scope);
  } catch (error) {
    if (error instanceof TypeError && /scope/.test(error.message)) throw error;
    return 'invalid-key';
  }
  return await options.store.claim(keyHash, fingerprint, now + ttlMs, now);
}
