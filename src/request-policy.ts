const DEFAULT_SAFE_METHODS = ['GET', 'HEAD', 'OPTIONS'] as const;
const METHOD_TOKEN = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
const FETCH_SITES = new Set(['same-origin', 'same-site', 'cross-site', 'none']);
const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f]/;

export type RequestPolicyAllowReason =
  | 'safe-method'
  | 'same-origin'
  | 'same-site'
  | 'trusted-origin'
  | 'non-browser-client';

export type RequestPolicyBlockReason =
  | 'invalid-method'
  | 'invalid-fetch-metadata'
  | 'cross-site'
  | 'same-site-not-allowed'
  | 'invalid-origin'
  | 'null-origin'
  | 'missing-origin'
  | 'untrusted-origin';

export type RequestPolicyDecision =
  | { allowed: true; reason: RequestPolicyAllowReason }
  | { allowed: false; reason: RequestPolicyBlockReason };

export interface BrowserRequestMetadata {
  method: string;
  origin?: string | null;
  secFetchSite?: string | null;
}

export interface RequestPolicyOptions {
  /**
   * Origins accepted when Fetch Metadata is absent or inconclusive, and — with
   * `allowCrossSiteFromAllowedOrigins` — when the browser reports `cross-site`.
   */
  allowedOrigins?: readonly string[];
  /** Methods assumed to be side-effect free. Defaults to GET, HEAD and OPTIONS. */
  safeMethods?: readonly string[];
  /** Treat same-site as trusted for unsafe methods. Disabled by default. */
  allowSameSite?: boolean;
  /** Allow unsafe requests that have neither Fetch Metadata nor Origin. Intended for explicit machine-to-machine endpoints only. */
  allowNoOrigin?: boolean;
  /**
   * Accept `Sec-Fetch-Site: cross-site` requests whose `Origin` header is in
   * `allowedOrigins`. Browsers set `Origin` themselves, so this is the OWASP
   * origin check for partner front-ends on other sites. Disabled by default:
   * cross-site unsafe requests are rejected outright.
   */
  allowCrossSiteFromAllowedOrigins?: boolean;
}

/** A validated, reusable policy. Create once per route or adapter. */
export interface CompiledRequestPolicy {
  evaluate(input: BrowserRequestMetadata): RequestPolicyDecision;
  assert(input: BrowserRequestMetadata): RequestPolicyDecision & { allowed: true };
}

function normalizeMethod(method: string): string | null {
  if (typeof method !== 'string') return null;
  const normalized = method.trim().toUpperCase();
  return normalized && METHOD_TOKEN.test(normalized) ? normalized : null;
}

function parseOrigin(value: string): string | null {
  if (!value || value.length > 2048 || CONTROL_CHARACTERS.test(value)) return null;
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return null;
  }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.pathname !== '/' || url.search || url.hash) return null;
  return url.origin;
}

function normalizeConfiguredOrigin(value: string): string {
  const origin = typeof value === 'string' ? parseOrigin(value) : null;
  if (!origin) throw new TypeError(`Invalid allowed origin: ${String(value)}`);
  return origin;
}

function parseOriginHeader(value: string | null | undefined):
  | { kind: 'missing' }
  | { kind: 'null' }
  | { kind: 'invalid' }
  | { kind: 'valid'; origin: string } {
  if (value === undefined || value === null || value === '') return { kind: 'missing' };
  if (value === 'null') return { kind: 'null' };
  const origin = parseOrigin(value);
  return origin ? { kind: 'valid', origin } : { kind: 'invalid' };
}

function normalizeSafeMethods(values: readonly string[] | undefined): Set<string> {
  const source = values ?? DEFAULT_SAFE_METHODS;
  const methods = new Set<string>();
  for (const value of source) {
    const method = normalizeMethod(value);
    if (!method) throw new TypeError(`Invalid safe HTTP method: ${String(value)}`);
    methods.add(method);
  }
  return methods;
}

/**
 * Validate the options once and return a policy that can evaluate many
 * requests. Configuration errors throw here, at startup, rather than on the
 * first unsafe request that reaches the affected code path.
 */
export function createRequestPolicy(options: RequestPolicyOptions = {}): CompiledRequestPolicy {
  const safeMethods = normalizeSafeMethods(options.safeMethods);
  const allowedOrigins = new Set((options.allowedOrigins ?? []).map(normalizeConfiguredOrigin));
  const allowSameSite = options.allowSameSite === true;
  const allowNoOrigin = options.allowNoOrigin === true;
  const allowCrossSite = options.allowCrossSiteFromAllowedOrigins === true;

  const evaluate = (input: BrowserRequestMetadata): RequestPolicyDecision => {
    const method = normalizeMethod(input.method);
    if (!method) return { allowed: false, reason: 'invalid-method' };
    if (safeMethods.has(method)) return { allowed: true, reason: 'safe-method' };

    const origin = parseOriginHeader(input.origin);
    let fetchSite: string | null = null;
    if (input.secFetchSite !== undefined && input.secFetchSite !== null && input.secFetchSite !== '') {
      fetchSite = input.secFetchSite.trim().toLowerCase();
      if (!FETCH_SITES.has(fetchSite)) return { allowed: false, reason: 'invalid-fetch-metadata' };
      if (fetchSite === 'same-origin') return { allowed: true, reason: 'same-origin' };
      if (fetchSite === 'same-site' && allowSameSite) return { allowed: true, reason: 'same-site' };
      if (fetchSite === 'cross-site') {
        if (allowCrossSite && origin.kind === 'valid' && allowedOrigins.has(origin.origin)) return { allowed: true, reason: 'trusted-origin' };
        return { allowed: false, reason: 'cross-site' };
      }
    }

    if (origin.kind === 'invalid') return { allowed: false, reason: 'invalid-origin' };
    if (origin.kind === 'null') return { allowed: false, reason: 'null-origin' };
    if (origin.kind === 'valid') {
      if (allowedOrigins.has(origin.origin)) return { allowed: true, reason: 'trusted-origin' };
      return { allowed: false, reason: 'untrusted-origin' };
    }

    if (fetchSite === 'same-site') return { allowed: false, reason: 'same-site-not-allowed' };
    if (allowNoOrigin) return { allowed: true, reason: 'non-browser-client' };
    return { allowed: false, reason: 'missing-origin' };
  };

  return {
    evaluate,
    assert(input) {
      const decision = evaluate(input);
      if (!decision.allowed) throw new RequestPolicyError(decision.reason);
      return decision;
    },
  };
}

/**
 * Evaluate browser request context using Fetch Metadata first and Origin as a
 * fallback for unsafe methods. This is a CSRF-oriented policy primitive, not
 * authentication or authorization. Prefer `createRequestPolicy` when the same
 * options are reused across requests.
 */
export function evaluateRequestPolicy(input: BrowserRequestMetadata, options: RequestPolicyOptions = {}): RequestPolicyDecision {
  return createRequestPolicy(options).evaluate(input);
}

export class RequestPolicyError extends Error {
  readonly reason: RequestPolicyBlockReason;

  constructor(reason: RequestPolicyBlockReason) {
    super(`Request blocked by security policy: ${reason}`);
    this.name = 'RequestPolicyError';
    this.reason = reason;
  }
}

export function assertRequestAllowed(input: BrowserRequestMetadata, options: RequestPolicyOptions = {}): RequestPolicyDecision & { allowed: true } {
  return createRequestPolicy(options).assert(input);
}
