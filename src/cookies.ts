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
  if (/[\u0000-\u001F\u007F;,]/.test(value)) throw new TypeError(`${label} contains unsafe characters`);
}

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
  if (options.domain !== undefined) assertSafeAttribute(options.domain, 'Domain');

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
  return parts.join('; ');
}
