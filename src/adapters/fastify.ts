import { adapterCorsHeaders, adapterSecurityHeaders, normalizeHeaderValue, preflightStatus, shouldHandlePreflight, type SecurityAdapterOptions } from './shared.js';

export interface FastifyLikeRequest {
  method?: string;
  headers: Record<string, string | readonly string[] | undefined>;
}

export interface FastifyLikeReply {
  header(name: string, value: string): FastifyLikeReply | unknown;
  code(status: number): FastifyLikeReply;
  send(payload?: unknown): unknown;
}

export type FastifySecurityHook = (request: FastifyLikeRequest, reply: FastifyLikeReply) => unknown;

export function createFastifySecurityHook(options: SecurityAdapterOptions = {}): FastifySecurityHook {
  const securityHeaders = adapterSecurityHeaders(options);
  const status = preflightStatus(options);
  return (request, reply) => {
    for (const [name, value] of Object.entries(securityHeaders)) reply.header(name, value);
    const origin = normalizeHeaderValue(request.headers.origin);
    const corsHeaders = adapterCorsHeaders(origin, options);
    if (corsHeaders) for (const [name, value] of Object.entries(corsHeaders)) reply.header(name, value);
    if (shouldHandlePreflight(request.method, corsHeaders, options)) return reply.code(status).send();
    return undefined;
  };
}

export type { SecurityAdapterOptions } from './shared.js';
