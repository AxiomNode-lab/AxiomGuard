import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

export interface CreateApiKeyOptions {
  /** Human-readable prefix, 2-16 characters starting with a letter. Default: `axg`. */
  prefix?: string;
  /** Random bytes in the secret part. Default: 32. */
  bytes?: number;
  /** Random bytes in the public identifier. Default: 6. */
  idBytes?: number;
}

export interface CreatedApiKey {
  /** Full credential `prefix_id_secret`. Show it once and never store it. */
  token: string;
  /** Non-secret identifier for database lookups. */
  id: string;
  /** SHA-256 hex digest of `token` to store instead of the token. */
  digest: string;
  /** First 12 hex characters of `digest`, safe for logs and support tickets. */
  fingerprint: string;
}

export interface ParsedApiKey { prefix: string; id: string; secret: string; }

export interface HashApiKeyOptions {
  /**
   * Optional server-held secret (>= 16 characters). When supplied the digest is
   * an HMAC-SHA256 so a leaked database of digests cannot be verified offline.
   */
  pepper?: string;
}

const BASE62 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
const TOKEN_PART = /^[0-9A-Za-z]+$/;

function assertPrefix(prefix: string): void {
  if (!/^[A-Za-z][A-Za-z0-9_-]{1,15}$/.test(prefix)) {
    throw new TypeError('prefix must start with a letter and contain 2-16 safe characters');
  }
}

/** Encode random bytes without the `_` delimiter so tokens stay parseable. */
function randomBase62(bytes: number): string {
  let value = BigInt(`0x${randomBytes(bytes).toString('hex')}`);
  let output = '';
  const radix = BigInt(BASE62.length);
  while (value > 0n) {
    output = BASE62[Number(value % radix)] + output;
    value /= radix;
  }
  return output || '0';
}

function resolvePepper(options: HashApiKeyOptions | undefined): string | undefined {
  const pepper = options?.pepper;
  if (pepper === undefined) return undefined;
  if (typeof pepper !== 'string' || pepper.length < 16) throw new TypeError('pepper must be a string of at least 16 characters');
  return pepper;
}

/** Hash an API key for storage. Plain SHA-256 by default, HMAC-SHA256 when a pepper is supplied. */
export function hashApiKey(token: string, options: HashApiKeyOptions = {}): string {
  if (typeof token !== 'string' || token.length < 16) {
    throw new TypeError('token must be a non-empty API key string');
  }
  const pepper = resolvePepper(options);
  return pepper === undefined
    ? createHash('sha256').update(token, 'utf8').digest('hex')
    : createHmac('sha256', pepper).update(token, 'utf8').digest('hex');
}

/**
 * Generate an opaque high-entropy API key. Persist `id` and `digest`, return
 * `token` to the caller exactly once.
 */
export function createApiKey(options: CreateApiKeyOptions = {}): CreatedApiKey {
  const prefix = options.prefix ?? 'axg';
  const bytes = options.bytes ?? 32;
  const idBytes = options.idBytes ?? 6;
  assertPrefix(prefix);
  if (!Number.isInteger(bytes) || bytes < 24 || bytes > 128) {
    throw new RangeError('bytes must be an integer between 24 and 128');
  }
  if (!Number.isInteger(idBytes) || idBytes < 4 || idBytes > 16) {
    throw new RangeError('idBytes must be an integer between 4 and 16');
  }

  const id = randomBase62(idBytes);
  const secret = randomBase62(bytes);
  const token = `${prefix}_${id}_${secret}`;
  const digest = hashApiKey(token);
  return { token, id, digest, fingerprint: digest.slice(0, 12) };
}

/**
 * Split a presented token into prefix, id and secret so the stored digest can
 * be looked up by `id` before verification. Returns `null` for anything that
 * is not shaped like a `createApiKey` token.
 */
export function parseApiKey(token: string): ParsedApiKey | null {
  if (typeof token !== 'string' || token.length < 16 || token.length > 512) return null;
  const secretStart = token.lastIndexOf('_');
  if (secretStart <= 0) return null;
  const idStart = token.lastIndexOf('_', secretStart - 1);
  if (idStart <= 0) return null;
  const prefix = token.slice(0, idStart);
  const id = token.slice(idStart + 1, secretStart);
  const secret = token.slice(secretStart + 1);
  if (!TOKEN_PART.test(id) || !TOKEN_PART.test(secret) || !/^[A-Za-z][A-Za-z0-9_-]{1,15}$/.test(prefix)) return null;
  return { prefix, id, secret };
}

/** Verify a presented token against a stored digest in constant time. */
export function verifyApiKey(token: string, expectedDigest: string, options: HashApiKeyOptions = {}): boolean {
  if (typeof expectedDigest !== 'string' || !/^[a-fA-F0-9]{64}$/.test(expectedDigest)) return false;
  let actualDigest: string;
  try {
    actualDigest = hashApiKey(token, options);
  } catch (error) {
    if (error instanceof TypeError && /pepper/.test(error.message)) throw error;
    return false;
  }
  return timingSafeEqual(Buffer.from(actualDigest, 'hex'), Buffer.from(expectedDigest, 'hex'));
}

/** Mask a token for logs: keeps the prefix and at most four trailing characters. */
export function maskApiKey(token: string): string {
  if (typeof token !== 'string' || token.length < 12) return '[REDACTED]';
  const marker = token.indexOf('_');
  const prefix = marker > 0 && marker <= 16 ? token.slice(0, marker) : 'key';
  return `${prefix}_...${token.slice(-4)}`;
}
