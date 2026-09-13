import { createSecurityCore, mergeVary, type SecurityAdapterOptions } from './shared.js';

export interface HonoLikeContext {
  req: {
    method: string;
    header(name: string): string | undefined;
  };
  res?: { headers: Headers } | undefined;
  header(name: string, value: string, options?: { append?: boolean }): void;
}

export type HonoLikeNext = () => Promise<void>;
export type HonoSecurityMiddleware = (context: HonoLikeContext, next: HonoLikeNext) => Promise<Response | void>;

/**
 * Hono middleware. Defensive headers are applied after `await next()` so the
 * adapter owns the final values; `Vary` is merged with what handlers set.
 */
export function createHonoSecurityMiddleware(options: SecurityAdapterOptions = {}): HonoSecurityMiddleware {
  const core = createSecurityCore(options);
  return async (context, next) => {
    const outcome = core.evaluate({ method: context.req.method, header: (name) => context.req.header(name) });
    if (outcome.kind !== 'continue') return new Response(null, { status: outcome.status, headers: outcome.headers });

    await next();
    for (const [name, value] of Object.entries(outcome.headers)) {
      if (name === 'Vary') context.header('Vary', mergeVary(context.res?.headers.get('Vary') ?? undefined, value));
      else context.header(name, value);
    }
    return undefined;
  };
}

export type { SecurityAdapterOptions } from './shared.js';
