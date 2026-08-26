import { adapterCorsHeaders, adapterRequestPolicy, adapterSecurityHeaders, blockedRequestStatus, normalizeHeaderValue, preflightStatus, shouldHandlePreflight, type SecurityAdapterOptions } from './shared.js';

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
  const deniedStatus = blockedRequestStatus(options);
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

    const decision = adapterRequestPolicy({
      method: request.method ?? '',
      origin: origin ?? null,
      secFetchSite: normalizeHeaderValue(request.headers['sec-fetch-site']) ?? null,
    }, options);
    if (decision && !decision.allowed) {
      response.statusCode = deniedStatus;
      response.end();
      return;
    }
    next();
  };
}

export type { SecurityAdapterOptions } from './shared.js';
