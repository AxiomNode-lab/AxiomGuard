import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

export type HmacAlgorithm = 'sha256' | 'sha512';

export function secureToken(bytes = 32): string {
  if (!Number.isInteger(bytes) || bytes < 16 || bytes > 1024) {
    throw new RangeError('bytes must be an integer between 16 and 1024');
  }
  return randomBytes(bytes).toString('base64url');
}

export function constantTimeCompare(left: string | Buffer, right: string | Buffer): boolean {
  const leftBuffer = Buffer.isBuffer(left) ? left : Buffer.from(left, 'utf8');
  const rightBuffer = Buffer.isBuffer(right) ? right : Buffer.from(right, 'utf8');

  const leftDigest = createHash('sha256').update(leftBuffer).digest();
  const rightDigest = createHash('sha256').update(rightBuffer).digest();
  return timingSafeEqual(leftDigest, rightDigest) && leftBuffer.length === rightBuffer.length;
}

export interface VerifyHmacWebhookOptions {
  algorithm?: HmacAlgorithm;
  prefix?: string;
}

export function verifyHmacWebhook(
  payload: string | Buffer,
  signature: string | undefined | null,
  secret: string,
  options: VerifyHmacWebhookOptions = {},
): boolean {
  if (!signature || !secret) return false;

  const algorithm = options.algorithm ?? 'sha256';
  const prefix = options.prefix ?? `${algorithm}=`;
  const normalizedSignature = signature.startsWith(prefix)
    ? signature.slice(prefix.length)
    : signature;

  if (!/^[a-fA-F0-9]+$/.test(normalizedSignature) || normalizedSignature.length % 2 !== 0) {
    return false;
  }

  const expected = createHmac(algorithm, secret).update(payload).digest();
  const received = Buffer.from(normalizedSignature, 'hex');
  if (expected.length !== received.length) return false;
  return timingSafeEqual(expected, received);
}
