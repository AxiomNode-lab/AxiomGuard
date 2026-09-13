import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

export interface CreateCsrfTokenOptions {
  /**
   * Value the token is bound to, typically the session identifier or the
   * authenticated user id. Required unless `allowUnbound` is set.
   */
  sessionId?: string;
  now?: number;
  nonceBytes?: number;
  /**
   * Mint a token that is not bound to a session. Only safe with the signed
   * double-submit cookie pattern: store the token in a `__Host-` cookie and
   * require the same token in a header or form field.
   */
  allowUnbound?: boolean;
}

export interface VerifyCsrfTokenOptions {
  sessionId?: string;
  now?: number;
  /** Maximum token age. Default: 7200 seconds, maximum 86400. */
  maxAgeSeconds?: number;
  /** Accept tokens minted with `allowUnbound`. See `CreateCsrfTokenOptions.allowUnbound`. */
  allowUnbound?: boolean;
}

const MAX_TOKEN_LENGTH = 256;
const MAX_NONCE_CHARS = 86; // 64 bytes of base64url
const FORWARD_SKEW_SECONDS = 60;

function assertSecret(secret: string): void {
  if (typeof secret !== 'string' || secret.length < 16) throw new TypeError('CSRF secret must be at least 16 characters');
}

function resolveBinding(sessionId: string | undefined, allowUnbound: boolean | undefined): string {
  if (sessionId !== undefined && sessionId !== '') return createHash('sha256').update(sessionId, 'utf8').digest('base64url').slice(0, 22);
  if (allowUnbound) return '-';
  throw new TypeError('CSRF tokens must be bound to a sessionId; pass allowUnbound: true only for the signed double-submit cookie pattern');
}

function resolveNow(now: number | undefined): number {
  const value = now ?? Date.now();
  if (!Number.isFinite(value) || value < 0) throw new RangeError('now must be a non-negative finite timestamp');
  return value;
}

function resolveMaxAge(maxAgeSeconds: number | undefined): number {
  const value = maxAgeSeconds ?? 7200;
  if (!Number.isFinite(value) || value <= 0 || value > 86_400) throw new RangeError('maxAgeSeconds must be >0 and <=86400');
  return value;
}

function sign(secret: string, body: string): Buffer {
  return createHmac('sha256', secret).update(body).digest();
}

/**
 * Create a signed, expiring CSRF token: `v1.<timestamp>.<nonce>.<binding>.<signature>`.
 *
 * Bind the token to the session (`sessionId`) so a token minted in one
 * browser cannot be submitted from another. Verify it with `verifyCsrfToken`
 * using the same secret and session.
 */
export function createCsrfToken(secret: string, options: CreateCsrfTokenOptions = {}): string {
  assertSecret(secret);
  const nonceBytes = options.nonceBytes ?? 18;
  if (!Number.isInteger(nonceBytes) || nonceBytes < 16 || nonceBytes > 64) throw new RangeError('nonceBytes must be 16-64');
  const binding = resolveBinding(options.sessionId, options.allowUnbound);
  const timestamp = Math.floor(resolveNow(options.now) / 1000);
  const nonce = randomBytes(nonceBytes).toString('base64url');
  const body = `v1.${timestamp}.${nonce}.${binding}`;
  return `${body}.${sign(secret, body).toString('base64url')}`;
}

/**
 * Verify a token produced by `createCsrfToken`.
 *
 * Returns `false` for tampered, expired, unbound or foreign tokens. Throws for
 * operator errors (short secret, invalid `maxAgeSeconds`, missing binding)
 * because those would otherwise silently reject every request.
 */
export function verifyCsrfToken(token: string, secret: string, options: VerifyCsrfTokenOptions = {}): boolean {
  assertSecret(secret);
  const maxAgeSeconds = resolveMaxAge(options.maxAgeSeconds);
  const binding = resolveBinding(options.sessionId, options.allowUnbound);
  if (typeof token !== 'string' || token.length === 0 || token.length > MAX_TOKEN_LENGTH) return false;

  const parts = token.split('.');
  if (parts.length !== 5 || parts[0] !== 'v1') return false;
  const [version, timestampText, nonce, tokenBinding, signature] = parts as [string, string, string, string, string];
  if (!/^\d{1,13}$/.test(timestampText) || !/^[A-Za-z0-9_-]{20,86}$/.test(nonce) || nonce.length > MAX_NONCE_CHARS) return false;
  if (!/^[A-Za-z0-9_-]{43}$/.test(signature)) return false;

  const timestamp = Number(timestampText);
  if (!Number.isSafeInteger(timestamp) || timestamp < 0) return false;
  let nowSeconds: number;
  try { nowSeconds = Math.floor(resolveNow(options.now) / 1000); } catch { return false; }
  if (timestamp > nowSeconds + FORWARD_SKEW_SECONDS || nowSeconds - timestamp > maxAgeSeconds) return false;

  // Sign with the server-side binding rather than the token's own segment so a
  // token minted for another session fails the constant-time HMAC comparison.
  const expected = sign(secret, `${version}.${timestampText}.${nonce}.${binding}`);
  const received = Buffer.from(signature, 'base64url');
  if (received.length !== expected.length || received.toString('base64url') !== signature) return false;
  return timingSafeEqual(expected, received) && tokenBinding === binding;
}
