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

export class MemoryIdempotencyStore implements IdempotencyStore {
  private readonly entries = new Map<string, MemoryIdempotencyEntry>();
  private operations = 0;

  constructor(private readonly maxEntries = 10_000) {
    if (!Number.isInteger(maxEntries) || maxEntries < 1 || maxEntries > 1_000_000) {
      throw new RangeError('maxEntries must be an integer between 1 and 1000000');
    }
  }

  private sweepExpired(now: number): void {
    for (const [key, entry] of this.entries) {
      if (entry.expiresAt <= now) this.entries.delete(key);
    }
  }

  claim(keyHash: string, fingerprint: string, expiresAt: number, now = Date.now()): IdempotencyClaimStatus {
    validateStoreInputs(keyHash, fingerprint, expiresAt, now);
    this.operations += 1;
    if (this.operations % 256 === 0 || this.entries.size >= this.maxEntries) this.sweepExpired(now);

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
    return 'accepted';
  }

  clear(): void {
    this.entries.clear();
    this.operations = 0;
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
  ttlMs?: number;
  now?: number;
}

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

/** Return a stable non-secret store key so raw client keys need not become Redis keys or logs. */
export function createIdempotencyStoreKey(key: string): string {
  return createHash('sha256').update(normalizeIdempotencyKey(key), 'utf8').digest('hex');
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

export async function claimIdempotencyKey(
  key: string,
  fingerprint: string,
  options: ClaimIdempotencyKeyOptions,
): Promise<IdempotencyClaimStatus> {
  if (!HEX_SHA256.test(fingerprint)) throw new TypeError('fingerprint must be a lowercase SHA-256 hex digest');
  const ttlMs = options.ttlMs ?? 86_400_000;
  if (!Number.isInteger(ttlMs) || ttlMs < 1_000 || ttlMs > 604_800_000) {
    throw new RangeError('ttlMs must be an integer between 1000 and 604800000');
  }
  const now = options.now ?? Date.now();
  validateTimestamp(now);
  const keyHash = createIdempotencyStoreKey(key);
  return await options.store.claim(keyHash, fingerprint, now + ttlMs, now);
}
