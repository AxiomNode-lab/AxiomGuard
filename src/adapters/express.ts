import { adapterCorsHeaders, adapterSecurityHeaders, normalizeHeaderValue, preflightStatus, shouldHandlePreflight, type SecurityAdapterOptions } from './shared.js';

export interface ExpressLikeRequest {
  method?: string;
  headers: Record<string, string | readonly string[] | undefined>;
}

export interface ExpressLikeResponse {
  statusCode: number;
  setHeader(name: string, value: string): unknown;
  end(): unknown;
}

export type ExpressLikeNext = (error?: unknown) => void;
export type ExpressSecurityMiddleware = (request: ExpressLikeRequest, response: ExpressLikeResponse, next: ExpressLikeNext) => void;

export function createExpressSecurityMiddleware(options: SecurityAdapterOptions = {}): ExpressSecurityMiddleware {
  const securityHeaders = adapterSecurityHeaders(options);
  const status = preflightStatus(options);
  return (request, response, next) => {
    for (const [name, value] of Object.entries(securityHeaders)) response.setHeader(name, value);
    const origin = normalizeHeaderValue(request.headers.origin);
    const corsHeaders = adapterCorsHeaders(origin, options);
    if (corsHeaders) for (const [name, value] of Object.entries(corsHeaders)) response.setHeader(name, value);
    if (shouldHandlePreflight(request.method, corsHeaders, options)) {
      response.statusCode = status;
      response.end();
      return;
    }
    next();
  };
}

export type { SecurityAdapterOptions } from './shared.js';
