import { createSecurityCore, mergeVary, normalizeHeaderValue, type SecurityAdapterOptions } from './shared.js';

export interface ExpressLikeRequest {
  method?: string;
  headers: Record<string, string | readonly string[] | undefined>;
}

export interface ExpressLikeResponse {
  statusCode: number;
  setHeader(name: string, value: string): unknown;
  getHeader?(name: string): string | number | readonly string[] | undefined;
  removeHeader?(name: string): unknown;
  end(): unknown;
}

export type ExpressLikeNext = (error?: unknown) => void;
export type ExpressSecurityMiddleware = (request: ExpressLikeRequest, response: ExpressLikeResponse, next: ExpressLikeNext) => void;

function applyHeaders(response: ExpressLikeResponse, headers: Record<string, string>): void {
  for (const [name, value] of Object.entries(headers)) {
    response.setHeader(name, name === 'Vary' ? mergeVary(response.getHeader?.('Vary'), value) : value);
  }
}

/**
 * Express/Connect middleware: sets defensive headers before the handler runs
 * (handlers may override them), answers CORS preflights and optionally
 * enforces the browser request policy. Client-controlled input never throws.
 */
export function createExpressSecurityMiddleware(options: SecurityAdapterOptions = {}): ExpressSecurityMiddleware {
  const core = createSecurityCore(options);
  return (request, response, next) => {
    if (core.removePoweredBy) response.removeHeader?.('X-Powered-By');
    const outcome = core.evaluate({ method: request.method ?? '', header: (name) => normalizeHeaderValue(request.headers[name]) });
    applyHeaders(response, outcome.headers);
    if (outcome.kind === 'continue') {
      next();
      return;
    }
    response.statusCode = outcome.status;
    response.end();
  };
}

export type { SecurityAdapterOptions } from './shared.js';
