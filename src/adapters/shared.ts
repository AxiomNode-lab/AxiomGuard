import { createCorsHeaders, type CorsOptions } from '../cors.js';
import { createSecurityHeaders, type SecurityHeadersOptions } from '../headers.js';
import { evaluateRequestPolicy, type BrowserRequestMetadata, type RequestPolicyDecision, type RequestPolicyOptions } from '../request-policy.js';

export interface SecurityAdapterOptions {
  headers?: SecurityHeadersOptions | false;
  cors?: CorsOptions | false;
  handlePreflight?: boolean;
  preflightStatus?: number;
  /** Optional Fetch-Metadata/Origin policy for unsafe browser requests. */
  requestPolicy?: RequestPolicyOptions | false;
  /** Status returned when requestPolicy blocks a request. Defaults to 403. */
  requestPolicyStatus?: number;
}

export function adapterSecurityHeaders(options: SecurityAdapterOptions): Record<string, string> {
  return options.headers === false ? {} : createSecurityHeaders(options.headers ?? {});
}

export function adapterCorsHeaders(origin: string | undefined, options: SecurityAdapterOptions): Record<string, string> | null {
  if (options.cors === false || options.cors === undefined) return null;
  return createCorsHeaders(origin, options.cors);
}

export function adapterRequestPolicy(input: BrowserRequestMetadata, options: SecurityAdapterOptions): RequestPolicyDecision | null {
  if (options.requestPolicy === false || options.requestPolicy === undefined) return null;
  return evaluateRequestPolicy(input, options.requestPolicy);
}

export function normalizeHeaderValue(value: string | readonly string[] | undefined): string | undefined {
  return typeof value === 'string' ? value : value?.[0];
}

export function shouldHandlePreflight(method: string | undefined, corsHeaders: Record<string, string> | null, options: SecurityAdapterOptions): boolean {
  return (options.handlePreflight ?? true) && method?.toUpperCase() === 'OPTIONS' && corsHeaders !== null;
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
