import { createSecurityCore, mergeVary, normalizeHeaderValue, type SecurityAdapterOptions } from './shared.js';

export interface FastifyLikeRequest {
  method?: string;
  headers: Record<string, string | readonly string[] | undefined>;
}

export interface FastifyLikeReply {
  header(name: string, value: string): FastifyLikeReply | unknown;
  getHeader?(name: string): string | number | readonly string[] | undefined;
  removeHeader?(name: string): unknown;
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
  const core = createSecurityCore(options);
  return async (request, reply) => {
    if (core.removePoweredBy) reply.removeHeader?.('X-Powered-By');
    const outcome = core.evaluate({ method: request.method ?? '', header: (name) => normalizeHeaderValue(request.headers[name]) });
    for (const [name, value] of Object.entries(outcome.headers)) {
      reply.header(name, name === 'Vary' ? mergeVary(reply.getHeader?.('Vary'), value) : value);
    }
    if (outcome.kind === 'continue') return undefined;
    return reply.code(outcome.status).send();
  };
}

export type { SecurityAdapterOptions } from './shared.js';
