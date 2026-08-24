export type CorsOriginMatcher = readonly string[] | ((origin: string) => boolean);

export interface CorsOptions {
  origins: '*' | CorsOriginMatcher;
  allowCredentials?: boolean;
  allowMethods?: readonly string[];
  allowHeaders?: readonly string[];
  exposeHeaders?: readonly string[];
  maxAge?: number;
  /** `Origin: null` is blocked by default because it can represent opaque/sandboxed origins. */
  allowNullOrigin?: boolean;
  /** Opt-in support for Private Network Access preflights. */
  allowPrivateNetwork?: boolean;
}

function joinTokens(values: readonly string[] | undefined): string | undefined {
  if (!values || values.length === 0) return undefined;
  for (const value of values) {
    if (!/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(value)) throw new TypeError(`invalid HTTP token: ${value}`);
  }
  return values.join(', ');
}

function normalizeRequestOrigin(origin: string, allowNullOrigin: boolean): string {
  if (/[\r\n]/.test(origin)) throw new TypeError('origin contains unsafe characters');
  if (origin === 'null') {
    if (!allowNullOrigin) throw new Error('opaque null origins are blocked by default');
    return origin;
  }
  let parsed: URL;
  try { parsed = new URL(origin); } catch { throw new TypeError('origin must be an absolute HTTP(S) origin'); }
  if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password || parsed.pathname !== '/' || parsed.search || parsed.hash) {
    throw new TypeError('origin must be an absolute HTTP(S) origin without credentials, path, query, or fragment');
  }
  return parsed.origin;
}

function normalizeConfiguredOrigin(origin: string, allowNullOrigin: boolean): string {
  return normalizeRequestOrigin(origin, allowNullOrigin);
}

export function createCorsHeaders(origin: string | undefined | null, options: CorsOptions): Record<string, string> | null {
  const credentials = options.allowCredentials ?? false;
  const allowNullOrigin = options.allowNullOrigin ?? false;
  if (options.origins === '*' && credentials) throw new TypeError('CORS wildcard origin cannot be combined with credentials');

  let requestOrigin: string | null = null;
  if (origin) requestOrigin = normalizeRequestOrigin(origin, allowNullOrigin);

  let allowedOrigin: string | null = null;
  if (options.origins === '*') {
    allowedOrigin = '*';
  } else if (requestOrigin) {
    const allowed = Array.isArray(options.origins)
      ? options.origins.some((candidate) => normalizeConfiguredOrigin(candidate, allowNullOrigin) === requestOrigin)
      : (options.origins as (origin: string) => boolean)(requestOrigin);
    if (allowed) allowedOrigin = requestOrigin;
  }
  if (!allowedOrigin) return null;

  const headers: Record<string, string> = { 'Access-Control-Allow-Origin': allowedOrigin };
  if (allowedOrigin !== '*') headers['Vary'] = 'Origin';
  if (credentials) headers['Access-Control-Allow-Credentials'] = 'true';

  const methods = joinTokens(options.allowMethods);
  const allowHeaders = joinTokens(options.allowHeaders);
  const exposeHeaders = joinTokens(options.exposeHeaders);
  if (methods) headers['Access-Control-Allow-Methods'] = methods;
  if (allowHeaders) headers['Access-Control-Allow-Headers'] = allowHeaders;
  if (exposeHeaders) headers['Access-Control-Expose-Headers'] = exposeHeaders;
  if (options.maxAge !== undefined) {
    if (!Number.isInteger(options.maxAge) || options.maxAge < 0) throw new RangeError('CORS maxAge must be a non-negative integer');
    headers['Access-Control-Max-Age'] = String(options.maxAge);
  }
  if (options.allowPrivateNetwork) headers['Access-Control-Allow-Private-Network'] = 'true';
  return headers;
}
