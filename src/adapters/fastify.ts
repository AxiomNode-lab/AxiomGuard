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

/**
 * Promise-style Fastify hook. Fastify treats a two-argument async hook as
 * completion-by-promise; callback-style hooks instead require a third `done`
 * argument. Returning an ordinary synchronous two-argument function can leave
 * real Fastify requests waiting for completion even though structural mocks
 * appear to work.
 */
export type FastifySecurityHook = (request: FastifyLikeRequest, reply: FastifyLikeReply) => Promise<unknown>;

export function createFastifySecurityHook(options: SecurityAdapterOptions = {}): FastifySecurityHook {
  const securityHeaders = adapterSecurityHeaders(options);
  const status = preflightStatus(options);
  return async (request, reply) => {
    for (const [name, value] of Object.entries(securityHeaders)) reply.header(name, value);
    const origin = normalizeHeaderValue(request.headers.origin);
    const corsHeaders = adapterCorsHeaders(origin, options);
    if (corsHeaders) for (const [name, value] of Object.entries(corsHeaders)) reply.header(name, value);
    if (shouldHandlePreflight(request.method, corsHeaders, options)) return reply.code(status).send();
    return undefined;
  };
}

export type { SecurityAdapterOptions } from './shared.js';
