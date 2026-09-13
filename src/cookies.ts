export type SameSite = 'Strict' | 'Lax' | 'None';
export type CookiePriority = 'Low' | 'Medium' | 'High';

export interface CookieOptions {
  domain?: string;
  path?: string;
  expires?: Date;
  maxAge?: number;
  httpOnly?: boolean;
  secure?: boolean;
  sameSite?: SameSite;
  priority?: CookiePriority;
  partitioned?: boolean;
}

function assertCookieName(name: string): void {
  if (!/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(name)) throw new TypeError('invalid cookie name');
}

function assertSafeAttribute(value: string, label: string): void {
  if (/[\u0000-\u001F\u007F;,\s]/.test(value)) throw new TypeError(`${label} contains unsafe characters`);
}

/** Browsers must accept at least 4096 bytes per cookie (RFC 6265 §6.1); larger cookies are silently dropped. */
const MAX_COOKIE_BYTES = 4096;

/**
 * Serialize a `Set-Cookie` value with secure defaults: `Secure`, `HttpOnly`,
 * `SameSite=Lax`, `Path=/`. The value is `encodeURIComponent`-encoded, which
 * the `cookie` package, Fastify, Hono and Express decode by default; custom
 * parsers must decode it too (`parseCookies` does).
 */
export function serializeCookie(name: string, value: string, options: CookieOptions = {}): string {
  assertCookieName(name);
  if (typeof value !== 'string') throw new TypeError('cookie value must be a string');

  const secure = options.secure ?? true;
  const path = options.path ?? '/';
  const httpOnly = options.httpOnly ?? true;
  const sameSite = options.sameSite ?? 'Lax';

  if (name.startsWith('__Secure-') && !secure) throw new TypeError('__Secure- cookies must be Secure');
  if (name.startsWith('__Host-')) {
    if (!secure) throw new TypeError('__Host- cookies must be Secure');
    if (path !== '/') throw new TypeError('__Host- cookies must use Path=/');
    if (options.domain !== undefined) throw new TypeError('__Host- cookies must not set Domain');
  }
  if (sameSite === 'None' && !secure) throw new TypeError('SameSite=None requires Secure');
  if (options.partitioned && !secure) throw new TypeError('Partitioned cookies require Secure');

  assertSafeAttribute(path, 'Path');
  if (!path.startsWith('/')) throw new TypeError('Path must start with /');
  if (options.domain !== undefined) {
    assertSafeAttribute(options.domain, 'Domain');
    if (!/^\.?[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*$/.test(options.domain)) throw new TypeError('Domain must be a hostname');
  }

  const parts = [`${name}=${encodeURIComponent(value)}`, `Path=${path}`];
  if (options.domain) parts.push(`Domain=${options.domain}`);
  if (options.maxAge !== undefined) {
    if (!Number.isFinite(options.maxAge)) throw new RangeError('maxAge must be finite');
    parts.push(`Max-Age=${Math.trunc(options.maxAge)}`);
  }
  if (options.expires) {
    if (Number.isNaN(options.expires.getTime())) throw new TypeError('expires must be a valid Date');
    parts.push(`Expires=${options.expires.toUTCString()}`);
  }
  if (httpOnly) parts.push('HttpOnly');
  if (secure) parts.push('Secure');
  parts.push(`SameSite=${sameSite}`);
  if (options.priority) parts.push(`Priority=${options.priority}`);
  if (options.partitioned) parts.push('Partitioned');
  const serialized = parts.join('; ');
  if (Buffer.byteLength(serialized, 'utf8') > MAX_COOKIE_BYTES) throw new RangeError(`cookie exceeds ${MAX_COOKIE_BYTES} bytes and would be dropped by browsers`);
  return serialized;
}

/**
 * Serialize a deletion for a cookie previously set with the same attributes.
 * Path, Domain, Secure, SameSite and Partitioned must match the original or
 * browsers keep the old cookie.
 */
export function clearCookie(name: string, options: Omit<CookieOptions, 'expires' | 'maxAge'> = {}): string {
  return serializeCookie(name, '', { ...options, maxAge: 0, expires: new Date(0) });
}

/**
 * Parse a request `Cookie` header into a map. Values are percent-decoded
 * (matching `serializeCookie`); undecodable values are kept verbatim. The
 * first occurrence of a name wins, as browsers order the most specific first.
 */
export function parseCookies(header: string | undefined | null): Record<string, string> {
  const cookies: Record<string, string> = {};
  if (typeof header !== 'string' || header.length === 0) return cookies;
  if (header.length > 65_536) throw new RangeError('Cookie header is too large');
  for (const pair of header.split(';')) {
    const separator = pair.indexOf('=');
    if (separator <= 0) continue;
    const name = pair.slice(0, separator).trim();
    if (!/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(name) || Object.hasOwn(cookies, name)) continue;
    let value = pair.slice(separator + 1).trim();
    if (value.length >= 2 && value.startsWith('"') && value.endsWith('"')) value = value.slice(1, -1);
    try { value = decodeURIComponent(value); } catch { /* keep the raw value */ }
    Object.defineProperty(cookies, name, { value, enumerable: true, writable: true, configurable: true });
  }
  return cookies;
}
