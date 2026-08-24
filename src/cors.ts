export type CorsOriginMatcher = readonly string[] | ((origin: string) => boolean);

export interface CorsOptions {
  origins: '*' | CorsOriginMatcher;
  allowCredentials?: boolean;
  allowMethods?: readonly string[];
  allowHeaders?: readonly string[];
  exposeHeaders?: readonly string[];
  maxAge?: number;
}

function joinTokens(values: readonly string[] | undefined): string | undefined {
  if (!values || values.length === 0) return undefined;
  for (const value of values) {
    if (!/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(value)) throw new TypeError(`invalid HTTP token: ${value}`);
  }
  return values.join(', ');
}

export function createCorsHeaders(origin: string | undefined | null, options: CorsOptions): Record<string, string> | null {
  const credentials = options.allowCredentials ?? false;
  if (options.origins === '*' && credentials) {
    throw new TypeError('CORS wildcard origin cannot be combined with credentials');
  }

  let allowedOrigin: string | null = null;
  if (options.origins === '*') {
    allowedOrigin = '*';
  } else if (origin) {
    const allowed = Array.isArray(options.origins)
      ? options.origins.includes(origin)
      : (options.origins as (origin: string) => boolean)(origin);
    if (allowed) allowedOrigin = origin;
  }
  if (!allowedOrigin) return null;
  if (/[\r\n]/.test(allowedOrigin)) throw new TypeError('origin contains unsafe characters');

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
  return headers;
}
