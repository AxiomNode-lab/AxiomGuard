import { createCorsHeaders, type CorsOptions } from '../cors.js';
import { createSecurityHeaders, type SecurityHeadersOptions } from '../headers.js';

export interface SecurityAdapterOptions {
  headers?: SecurityHeadersOptions | false;
  cors?: CorsOptions | false;
  handlePreflight?: boolean;
  preflightStatus?: number;
}

export function adapterSecurityHeaders(options: SecurityAdapterOptions): Record<string, string> {
  return options.headers === false ? {} : createSecurityHeaders(options.headers ?? {});
}

export function adapterCorsHeaders(origin: string | undefined, options: SecurityAdapterOptions): Record<string, string> | null {
  if (options.cors === false || options.cors === undefined) return null;
  return createCorsHeaders(origin, options.cors);
}

export function normalizeHeaderValue(value: string | readonly string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

export function shouldHandlePreflight(method: string | undefined, corsHeaders: Record<string, string> | null, options: SecurityAdapterOptions): boolean {
  return (options.handlePreflight ?? true) && method?.toUpperCase() === 'OPTIONS' && corsHeaders !== null;
}

export function preflightStatus(options: SecurityAdapterOptions): number {
  const status = options.preflightStatus ?? 204;
  if (!Number.isInteger(status) || status < 200 || status > 299) throw new RangeError('preflightStatus must be a 2xx status code');
  return status;
}
