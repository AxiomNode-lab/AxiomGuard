import { createCorsPolicy, type CorsOptions, type CorsPolicy } from '../cors.js';
import { createSecurityHeaders, type SecurityHeadersOptions } from '../headers.js';
import { createRequestPolicy, type CompiledRequestPolicy, type RequestPolicyOptions } from '../request-policy.js';

/** Minimal request view shared by every adapter. `header` returns a single value or undefined. */
export interface AdapterRequest {
  method: string;
  header(name: string): string | undefined;
}

export interface SecurityAdapterOptions {
  /**
   * Defensive response headers. Pass a function to compute them per request,
   * for example to inject a CSP nonce. `false` disables them.
   */
  headers?: SecurityHeadersOptions | false | ((request: AdapterRequest) => SecurityHeadersOptions | false);
  cors?: CorsOptions | false;
  /** Answer CORS preflights (`OPTIONS` + `Access-Control-Request-Method`) directly. Default: true. */
  handlePreflight?: boolean;
  preflightStatus?: number;
  /** Optional Fetch-Metadata/Origin policy for unsafe browser requests. */
  requestPolicy?: RequestPolicyOptions | false;
  /** Status returned when requestPolicy blocks a request. Defaults to 403. */
  requestPolicyStatus?: number;
  /** Remove `X-Powered-By` when the framework exposes a way to. Default: true. */
  removePoweredBy?: boolean;
}

export type SecurityOutcome =
  | { kind: 'preflight'; status: number; headers: Record<string, string> }
  | { kind: 'blocked'; status: number; headers: Record<string, string>; reason: string }
  | { kind: 'continue'; headers: Record<string, string> };

/** A validated, reusable security pipeline shared by the framework adapters. */
export interface SecurityCore {
  evaluate(request: AdapterRequest): SecurityOutcome;
  removePoweredBy: boolean;
}

/** Collapse a possibly repeated header into one value; repeated values are treated as absent. */
export function normalizeHeaderValue(value: string | readonly string[] | undefined): string | undefined {
  if (typeof value === 'string') return value;
  if (Array.isArray(value)) return value.length === 1 ? value[0] : undefined;
  return undefined;
}

/** Merge a `Vary` value into an existing one without duplicating tokens. */
export function mergeVary(existing: string | number | readonly string[] | undefined, addition: string): string {
  const current = Array.isArray(existing) ? existing.join(', ') : existing === undefined ? '' : String(existing);
  if (current.trim() === '*') return '*';
  const tokens = new Map<string, string>();
  for (const token of `${current}, ${addition}`.split(',')) {
    const trimmed = token.trim();
    if (trimmed) tokens.set(trimmed.toLowerCase(), trimmed);
  }
  return [...tokens.values()].join(', ');
}

export function preflightStatus(options: SecurityAdapterOptions): number {
  const status = options.preflightStatus ?? 204;
  if (!Number.isInteger(status) || status < 200 || status > 299) throw new RangeError('preflightStatus must be a 2xx status code');
  return status;
}

export function blockedRequestStatus(options: SecurityAdapterOptions): number {
  const status = options.requestPolicyStatus ?? 403;
  if (!Number.isInteger(status) || status < 400 || status > 499) throw new RangeError('requestPolicyStatus must be a 4xx status code');
  return status;
}

/**
 * Validate every option once and return the pipeline the adapters run per
 * request: security headers, CORS (with preflight handling) and the optional
 * browser request policy.
 */
export function createSecurityCore(options: SecurityAdapterOptions = {}): SecurityCore {
  const status = preflightStatus(options);
  const deniedStatus = blockedRequestStatus(options);
  const handlePreflight = options.handlePreflight ?? true;
  const staticHeaders = typeof options.headers === 'function' ? null : options.headers === false ? {} : createSecurityHeaders(options.headers ?? {});
  const headerFactory = typeof options.headers === 'function' ? options.headers : null;
  const cors: CorsPolicy | null = options.cors === false || options.cors === undefined ? null : createCorsPolicy(options.cors);
  const policy: CompiledRequestPolicy | null = options.requestPolicy === false || options.requestPolicy === undefined ? null : createRequestPolicy(options.requestPolicy);

  const evaluate = (request: AdapterRequest): SecurityOutcome => {
    const securityHeaders = headerFactory
      ? (() => { const computed = headerFactory(request); return computed === false ? {} : createSecurityHeaders(computed); })()
      : staticHeaders!;
    const origin = request.header('origin');
    const corsDecision = cors?.evaluate(origin, {
      method: request.method,
      accessControlRequestMethod: request.header('access-control-request-method'),
      accessControlRequestHeaders: request.header('access-control-request-headers'),
      accessControlRequestPrivateNetwork: request.header('access-control-request-private-network'),
    });
    const headers = { ...securityHeaders, ...(corsDecision?.headers ?? {}) };

    if (corsDecision?.preflight && corsDecision.allowed && handlePreflight) return { kind: 'preflight', status, headers };

    if (policy) {
      const decision = policy.evaluate({ method: request.method, origin: origin ?? null, secFetchSite: request.header('sec-fetch-site') ?? null });
      if (!decision.allowed) return { kind: 'blocked', status: deniedStatus, headers, reason: decision.reason };
    }
    return { kind: 'continue', headers };
  };

  return { evaluate, removePoweredBy: options.removePoweredBy ?? true };
}
