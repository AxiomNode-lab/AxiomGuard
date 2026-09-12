import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

export type HmacAlgorithm = 'sha256' | 'sha512';
export type HmacEncoding = 'hex' | 'base64';

const DIGEST_BYTES: Record<HmacAlgorithm, number> = { sha256: 32, sha512: 64 };

/** Generate a URL-safe random token with at least 128 bits of entropy. */
export function secureToken(bytes = 32): string {
  if (!Number.isInteger(bytes) || bytes < 16 || bytes > 1024) {
    throw new RangeError('bytes must be an integer between 16 and 1024');
  }
  return randomBytes(bytes).toString('base64url');
}

/**
 * Compare two values without leaking their contents through timing. Inputs of
 * different lengths are hashed first so the comparison cost does not depend on
 * where the first difference occurs.
 */
export function constantTimeCompare(left: string | Buffer, right: string | Buffer): boolean {
  const leftBuffer = Buffer.isBuffer(left) ? left : Buffer.from(left, 'utf8');
  const rightBuffer = Buffer.isBuffer(right) ? right : Buffer.from(right, 'utf8');

  const leftDigest = createHash('sha256').update(leftBuffer).digest();
  const rightDigest = createHash('sha256').update(rightBuffer).digest();
  return timingSafeEqual(leftDigest, rightDigest) && leftBuffer.length === rightBuffer.length;
}

export interface VerifyHmacWebhookOptions {
  /** HMAC hash function. Default: sha256. */
  algorithm?: HmacAlgorithm;
  /** Signature prefix, e.g. `sha256=`. Defaults to `${algorithm}=`; pass `''` for bare digests. */
  prefix?: string;
  /** Digest text encoding. Default: hex. Shopify, Svix and Twilio-style providers use base64. */
  encoding?: HmacEncoding;
  /** Reject signatures that do not start with `prefix`. Default: false (the prefix is optional). */
  requirePrefix?: boolean;
}

export type SignHmacWebhookOptions = Pick<VerifyHmacWebhookOptions, 'algorithm' | 'prefix' | 'encoding'>;

function assertSecret(secret: string): void {
  if (typeof secret !== 'string' || secret.length === 0) throw new TypeError('secret must be a non-empty string');
}

function resolveAlgorithm(algorithm: HmacAlgorithm | undefined): HmacAlgorithm {
  const value = algorithm ?? 'sha256';
  if (value !== 'sha256' && value !== 'sha512') throw new TypeError('algorithm must be sha256 or sha512');
  return value;
}

function resolveEncoding(encoding: HmacEncoding | undefined): HmacEncoding {
  const value = encoding ?? 'hex';
  if (value !== 'hex' && value !== 'base64') throw new TypeError('encoding must be hex or base64');
  return value;
}

/** Decode a textual digest strictly; returns null when the text is not a canonical encoding of `expectedBytes`. */
export function decodeDigest(text: string, encoding: HmacEncoding, expectedBytes: number): Buffer | null {
  if (encoding === 'hex') {
    if (text.length !== expectedBytes * 2 || !/^[a-fA-F0-9]+$/.test(text)) return null;
    return Buffer.from(text, 'hex');
  }
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(text) || text.length % 4 !== 0) return null;
  const decoded = Buffer.from(text, 'base64');
  if (decoded.length !== expectedBytes || decoded.toString('base64') !== text) return null;
  return decoded;
}

/**
 * Compute the HMAC of `payload` with the same options `verifyHmacWebhook`
 * accepts. The result is the textual signature (including prefix) a provider
 * would send.
 */
export function computeHmacSignature(payload: string | Buffer, secret: string, options: SignHmacWebhookOptions = {}): { digest: Buffer; signature: string } {
  assertSecret(secret);
  const algorithm = resolveAlgorithm(options.algorithm);
  const encoding = resolveEncoding(options.encoding);
  const prefix = options.prefix ?? `${algorithm}=`;
  const digest = createHmac(algorithm, secret).update(payload).digest();
  return { digest, signature: `${prefix}${digest.toString(encoding)}` };
}

/** Sign a payload the way a webhook provider would. Useful for tests, fixtures and outbound webhooks. */
export function signHmacWebhook(payload: string | Buffer, secret: string, options: SignHmacWebhookOptions = {}): string {
  return computeHmacSignature(payload, secret, options).signature;
}

/**
 * Verify an HMAC signature over the exact raw payload bytes.
 *
 * The comparison is constant-time. A missing or malformed signature returns
 * `false`; a missing secret throws because that is an operator error that
 * would otherwise silently reject every webhook.
 */
export function verifyHmacWebhook(
  payload: string | Buffer,
  signature: string | undefined | null,
  secret: string,
  options: VerifyHmacWebhookOptions = {},
): boolean {
  assertSecret(secret);
  if (typeof signature !== 'string' || signature.length === 0 || signature.length > 1024) return false;

  const algorithm = resolveAlgorithm(options.algorithm);
  const encoding = resolveEncoding(options.encoding);
  const prefix = options.prefix ?? `${algorithm}=`;
  let normalizedSignature = signature;
  if (prefix && signature.startsWith(prefix)) normalizedSignature = signature.slice(prefix.length);
  else if (prefix && options.requirePrefix) return false;

  const received = decodeDigest(normalizedSignature, encoding, DIGEST_BYTES[algorithm]);
  if (!received) return false;

  const expected = createHmac(algorithm, secret).update(payload).digest();
  return timingSafeEqual(expected, received);
}
