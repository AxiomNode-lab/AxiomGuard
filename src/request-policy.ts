const DEFAULT_SAFE_METHODS = ['GET', 'HEAD', 'OPTIONS'] as const;
const METHOD_TOKEN = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
const FETCH_SITES = new Set(['same-origin', 'same-site', 'cross-site', 'none']);

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
  /** Origins accepted as a fallback when Fetch Metadata is absent or inconclusive. */
  allowedOrigins?: readonly string[];
  /** Methods assumed to be side-effect free. Defaults to GET, HEAD and OPTIONS. */
  safeMethods?: readonly string[];
  /** Treat same-site as trusted for unsafe methods. Disabled by default. */
  allowSameSite?: boolean;
  /** Allow unsafe requests that have neither Fetch Metadata nor Origin. Intended for explicit machine-to-machine endpoints only. */
  allowNoOrigin?: boolean;
}

function normalizeMethod(method: string): string | null {
  const normalized = method.trim().toUpperCase();
  return normalized && METHOD_TOKEN.test(normalized) ? normalized : null;
}

function normalizeConfiguredOrigin(value: string): string {
  if (!value || value.length > 2048 || /[\u0000-\u001f\u007f]/.test(value)) {
    throw new TypeError('allowedOrigins must contain valid HTTP(S) origins');
  }
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new TypeError(`Invalid allowed origin: ${value}`);
  }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.pathname !== '/' || url.search || url.hash) {
    throw new TypeError(`Invalid allowed origin: ${value}`);
  }
  return url.origin;
}

function parseOriginHeader(value: string | null | undefined):
  | { kind: 'missing' }
  | { kind: 'null' }
  | { kind: 'invalid' }
  | { kind: 'valid'; origin: string } {
  if (value === undefined || value === null || value === '') return { kind: 'missing' };
  if (value === 'null') return { kind: 'null' };
  if (value.length > 2048 || /[\u0000-\u001f\u007f]/.test(value)) return { kind: 'invalid' };
  try {
    const url = new URL(value);
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.pathname !== '/' || url.search || url.hash) {
      return { kind: 'invalid' };
    }
    return { kind: 'valid', origin: url.origin };
  } catch {
    return { kind: 'invalid' };
  }
}

function normalizeSafeMethods(values: readonly string[] | undefined): Set<string> {
  const source = values ?? DEFAULT_SAFE_METHODS;
  const methods = new Set<string>();
  for (const value of source) {
    const method = normalizeMethod(value);
    if (!method) throw new TypeError(`Invalid safe HTTP method: ${value}`);
    methods.add(method);
  }
  return methods;
}

/**
 * Evaluate browser request context using Fetch Metadata first and Origin as a
 * fallback for unsafe methods. This is a CSRF-oriented policy primitive, not
 * authentication or authorization.
 */
export function evaluateRequestPolicy(input: BrowserRequestMetadata, options: RequestPolicyOptions = {}): RequestPolicyDecision {
  const method = normalizeMethod(input.method);
  if (!method) return { allowed: false, reason: 'invalid-method' };

  const safeMethods = normalizeSafeMethods(options.safeMethods);
  if (safeMethods.has(method)) return { allowed: true, reason: 'safe-method' };

  let fetchSite: string | null = null;
  if (input.secFetchSite !== undefined && input.secFetchSite !== null && input.secFetchSite !== '') {
    fetchSite = input.secFetchSite.trim().toLowerCase();
    if (!FETCH_SITES.has(fetchSite)) return { allowed: false, reason: 'invalid-fetch-metadata' };
    if (fetchSite === 'cross-site') return { allowed: false, reason: 'cross-site' };
    if (fetchSite === 'same-origin') return { allowed: true, reason: 'same-origin' };
    if (fetchSite === 'same-site' && options.allowSameSite) return { allowed: true, reason: 'same-site' };
  }

  const allowedOrigins = new Set((options.allowedOrigins ?? []).map(normalizeConfiguredOrigin));
  const origin = parseOriginHeader(input.origin);
  if (origin.kind === 'invalid') return { allowed: false, reason: 'invalid-origin' };
  if (origin.kind === 'null') return { allowed: false, reason: 'null-origin' };
  if (origin.kind === 'valid') {
    if (allowedOrigins.has(origin.origin)) return { allowed: true, reason: 'trusted-origin' };
    return { allowed: false, reason: 'untrusted-origin' };
  }

  if (fetchSite === 'same-site') return { allowed: false, reason: 'same-site-not-allowed' };
  if (options.allowNoOrigin) return { allowed: true, reason: 'non-browser-client' };
  return { allowed: false, reason: 'missing-origin' };
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
  const decision = evaluateRequestPolicy(input, options);
  if (!decision.allowed) throw new RequestPolicyError(decision.reason);
  return decision;
}
