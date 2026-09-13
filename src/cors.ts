export type CorsOriginMatcher = readonly string[] | ((origin: string) => boolean);

export interface CorsOptions {
  origins: '*' | CorsOriginMatcher;
  allowCredentials?: boolean;
  allowMethods?: readonly string[];
  /** Header names allowed on preflight, or `'reflect'` to echo `Access-Control-Request-Headers`. */
  allowHeaders?: readonly string[] | 'reflect';
  exposeHeaders?: readonly string[];
  maxAge?: number;
  /** `Origin: null` is blocked by default because it can represent opaque/sandboxed origins. */
  allowNullOrigin?: boolean;
  /** Opt-in support for Private Network Access preflights. */
  allowPrivateNetwork?: boolean;
}

/** The request context CORS needs beyond the Origin header. */
export interface CorsRequestContext {
  method?: string | undefined;
  accessControlRequestMethod?: string | null | undefined;
  accessControlRequestHeaders?: string | null | undefined;
  accessControlRequestPrivateNetwork?: string | null | undefined;
}

export interface CorsDecision {
  /** Whether the request origin is allowed to read the response. */
  allowed: boolean;
  /** Whether the request is a CORS preflight (`OPTIONS` + `Access-Control-Request-Method`). */
  preflight: boolean;
  /** Headers to set. Always includes `Vary` for non-wildcard policies so caches never mix origins. */
  headers: Record<string, string>;
}

export interface CorsPolicy {
  evaluate(origin: string | undefined | null, request?: CorsRequestContext): CorsDecision;
}

const TOKEN = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f]/;

function joinTokens(values: readonly string[] | undefined, label: string): string | undefined {
  if (!values || values.length === 0) return undefined;
  for (const value of values) {
    if (!TOKEN.test(value)) throw new TypeError(`invalid HTTP token in ${label}: ${value}`);
  }
  return values.join(', ');
}

/** Parse a request-supplied Origin. Never throws: anything malformed is simply not allowed. */
function parseRequestOrigin(origin: string, allowNullOrigin: boolean): string | null {
  if (origin === 'null') return allowNullOrigin ? 'null' : null;
  if (origin.length > 2048 || CONTROL_CHARACTERS.test(origin)) return null;
  let parsed: URL;
  try { parsed = new URL(origin); } catch { return null; }
  if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password || parsed.pathname !== '/' || parsed.search || parsed.hash) return null;
  return parsed.origin;
}

function normalizeConfiguredOrigin(origin: string, allowNullOrigin: boolean): string {
  if (typeof origin !== 'string') throw new TypeError('configured origins must be strings');
  if (origin === 'null' && !allowNullOrigin) throw new TypeError("configured origin 'null' requires allowNullOrigin: true");
  const normalized = parseRequestOrigin(origin, allowNullOrigin);
  if (!normalized) throw new TypeError(`invalid configured origin: ${origin} (expected an absolute HTTP(S) origin without path, query or credentials)`);
  return normalized;
}

function isReflectAllowedHeaders(value: string | null | undefined): string | undefined {
  if (!value) return undefined;
  const names = value.split(',').map((name) => name.trim()).filter(Boolean);
  if (names.length === 0 || names.length > 64 || names.some((name) => !TOKEN.test(name))) return undefined;
  return names.join(', ');
}

/**
 * Validate a CORS configuration once and return a reusable policy. Throws for
 * operator errors (wildcard with credentials, malformed configured origins,
 * bad header tokens) at construction time rather than on the first request.
 */
export function createCorsPolicy(options: CorsOptions): CorsPolicy {
  const credentials = options.allowCredentials ?? false;
  const allowNullOrigin = options.allowNullOrigin ?? false;
  if (options.origins === '*' && credentials) throw new TypeError('CORS wildcard origin cannot be combined with credentials');
  if (allowNullOrigin && credentials) throw new TypeError('CORS null origin cannot be combined with credentials');
  if (options.maxAge !== undefined && (!Number.isInteger(options.maxAge) || options.maxAge < 0)) throw new RangeError('CORS maxAge must be a non-negative integer');

  const methods = joinTokens(options.allowMethods, 'allowMethods');
  const staticAllowHeaders = options.allowHeaders === 'reflect' ? undefined : joinTokens(options.allowHeaders, 'allowHeaders');
  const reflectHeaders = options.allowHeaders === 'reflect';
  const exposeHeaders = joinTokens(options.exposeHeaders, 'exposeHeaders');
  const maxAge = options.maxAge;
  const allowPrivateNetwork = options.allowPrivateNetwork === true;

  const configured = options.origins === '*'
    ? '*'
    : typeof options.origins === 'function'
      ? options.origins
      : new Set(options.origins.map((origin) => normalizeConfiguredOrigin(origin, allowNullOrigin)));

  const evaluate = (origin: string | undefined | null, request: CorsRequestContext = {}): CorsDecision => {
    const requestOrigin = origin ? parseRequestOrigin(origin, allowNullOrigin) : null;
    const preflight = request.method?.toUpperCase() === 'OPTIONS' && !!request.accessControlRequestMethod && requestOrigin !== null;
    const headers: Record<string, string> = {};
    if (configured !== '*') headers.Vary = preflight ? 'Origin, Access-Control-Request-Method, Access-Control-Request-Headers' : 'Origin';

    let allowedOrigin: string | null = null;
    if (configured === '*') allowedOrigin = '*';
    else if (requestOrigin !== null) {
      const allowed = configured instanceof Set ? configured.has(requestOrigin) : configured(requestOrigin);
      if (allowed) allowedOrigin = requestOrigin;
    }
    if (!allowedOrigin) return { allowed: false, preflight, headers };

    headers['Access-Control-Allow-Origin'] = allowedOrigin;
    if (credentials) headers['Access-Control-Allow-Credentials'] = 'true';
    if (exposeHeaders) headers['Access-Control-Expose-Headers'] = exposeHeaders;

    if (preflight) {
      if (methods) headers['Access-Control-Allow-Methods'] = methods;
      const allowHeaders = reflectHeaders ? isReflectAllowedHeaders(request.accessControlRequestHeaders) : staticAllowHeaders;
      if (allowHeaders) headers['Access-Control-Allow-Headers'] = allowHeaders;
      if (maxAge !== undefined) headers['Access-Control-Max-Age'] = String(maxAge);
      if (allowPrivateNetwork && request.accessControlRequestPrivateNetwork === 'true') headers['Access-Control-Allow-Private-Network'] = 'true';
    }
    return { allowed: true, preflight, headers };
  };

  return { evaluate };
}

/**
 * Convenience wrapper around `createCorsPolicy`. Returns the CORS headers for
 * an allowed origin, or `null` when the origin is not allowed. Because `null`
 * carries no headers, set `Vary: Origin` yourself on rejected responses (or
 * use `createCorsPolicy`, which always returns it).
 */
export function createCorsHeaders(origin: string | undefined | null, options: CorsOptions, request?: CorsRequestContext): Record<string, string> | null {
  const decision = createCorsPolicy(options).evaluate(origin, request);
  return decision.allowed ? decision.headers : null;
}
