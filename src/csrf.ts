import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

export interface CreateCsrfTokenOptions {
  sessionId?: string;
  now?: number;
  nonceBytes?: number;
}

export interface VerifyCsrfTokenOptions {
  sessionId?: string;
  now?: number;
  maxAgeSeconds?: number;
}

function sessionFingerprint(sessionId: string | undefined): string {
  return sessionId ? createHash('sha256').update(sessionId, 'utf8').digest('base64url').slice(0, 22) : '-';
}

export function createCsrfToken(secret: string, options: CreateCsrfTokenOptions = {}): string {
  if (secret.length < 16) throw new TypeError('CSRF secret must be at least 16 characters');
  const nonceBytes = options.nonceBytes ?? 18;
  if (!Number.isInteger(nonceBytes) || nonceBytes < 16 || nonceBytes > 64) throw new RangeError('nonceBytes must be 16-64');
  const timestamp = Math.floor((options.now ?? Date.now()) / 1000);
  const nonce = randomBytes(nonceBytes).toString('base64url');
  const body = `v1.${timestamp}.${nonce}.${sessionFingerprint(options.sessionId)}`;
  const signature = createHmac('sha256', secret).update(body).digest('base64url');
  return `${body}.${signature}`;
}

export function verifyCsrfToken(token: string, secret: string, options: VerifyCsrfTokenOptions = {}): boolean {
  if (secret.length < 16 || typeof token !== 'string') return false;
  const parts = token.split('.');
  if (parts.length !== 5 || parts[0] !== 'v1') return false;
  const [version, timestampText, nonce, sessionHash, signature] = parts as [string, string, string, string, string];
  if (!/^\d+$/.test(timestampText) || !/^[A-Za-z0-9_-]{20,}$/.test(nonce)) return false;
  if (sessionHash !== sessionFingerprint(options.sessionId)) return false;

  const timestamp = Number(timestampText);
  const maxAgeSeconds = options.maxAgeSeconds ?? 7200;
  if (!Number.isFinite(maxAgeSeconds) || maxAgeSeconds <= 0 || maxAgeSeconds > 86_400) return false;
  const nowSeconds = Math.floor((options.now ?? Date.now()) / 1000);
  if (timestamp > nowSeconds + 60 || nowSeconds - timestamp > maxAgeSeconds) return false;

  const body = `${version}.${timestampText}.${nonce}.${sessionHash}`;
  const expected = createHmac('sha256', secret).update(body).digest();
  let received: Buffer;
  try { received = Buffer.from(signature, 'base64url'); } catch { return false; }
  return expected.length === received.length && timingSafeEqual(expected, received);
}
