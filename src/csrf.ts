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

function resolveNow(now: number | undefined): number {
  const value = now ?? Date.now();
  if (!Number.isFinite(value) || value < 0) throw new RangeError('now must be a non-negative finite timestamp');
  return value;
}

export function createCsrfToken(secret: string, options: CreateCsrfTokenOptions = {}): string {
  if (typeof secret !== 'string' || secret.length < 16) throw new TypeError('CSRF secret must be at least 16 characters');
  const nonceBytes = options.nonceBytes ?? 18;
  if (!Number.isInteger(nonceBytes) || nonceBytes < 16 || nonceBytes > 64) throw new RangeError('nonceBytes must be 16-64');
  const timestamp = Math.floor(resolveNow(options.now) / 1000);
  const nonce = randomBytes(nonceBytes).toString('base64url');
  const body = `v1.${timestamp}.${nonce}.${sessionFingerprint(options.sessionId)}`;
  const signature = createHmac('sha256', secret).update(body).digest('base64url');
  return `${body}.${signature}`;
}

export function verifyCsrfToken(token: string, secret: string, options: VerifyCsrfTokenOptions = {}): boolean {
  if (typeof secret !== 'string' || secret.length < 16 || typeof token !== 'string') return false;
  const parts = token.split('.');
  if (parts.length !== 5 || parts[0] !== 'v1') return false;
  const [version, timestampText, nonce, sessionHash, signature] = parts as [string, string, string, string, string];
  if (!/^\d+$/.test(timestampText) || !/^[A-Za-z0-9_-]{20,}$/.test(nonce) || !/^[A-Za-z0-9_-]{40,50}$/.test(signature)) return false;
  if (sessionHash !== sessionFingerprint(options.sessionId)) return false;

  const timestamp = Number(timestampText);
  if (!Number.isSafeInteger(timestamp) || timestamp < 0) return false;
  const maxAgeSeconds = options.maxAgeSeconds ?? 7200;
  if (!Number.isFinite(maxAgeSeconds) || maxAgeSeconds <= 0 || maxAgeSeconds > 86_400) return false;
  let nowSeconds: number;
  try { nowSeconds = Math.floor(resolveNow(options.now) / 1000); } catch { return false; }
  if (timestamp > nowSeconds + 60 || nowSeconds - timestamp > maxAgeSeconds) return false;

  const body = `${version}.${timestampText}.${nonce}.${sessionHash}`;
  const expected = createHmac('sha256', secret).update(body).digest();
  let received: Buffer;
  try { received = Buffer.from(signature, 'base64url'); } catch { return false; }
  return expected.length === received.length && timingSafeEqual(expected, received);
}
