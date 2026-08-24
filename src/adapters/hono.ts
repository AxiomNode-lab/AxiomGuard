import { adapterCorsHeaders, adapterSecurityHeaders, preflightStatus, shouldHandlePreflight, type SecurityAdapterOptions } from './shared.js';

export interface HonoLikeContext {
  req: {
    method: string;
    header(name: string): string | undefined;
  };
  header(name: string, value: string): void;
}

export type HonoLikeNext = () => Promise<void>;
export type HonoSecurityMiddleware = (context: HonoLikeContext, next: HonoLikeNext) => Promise<Response | void>;

export function createHonoSecurityMiddleware(options: SecurityAdapterOptions = {}): HonoSecurityMiddleware {
  const securityHeaders = adapterSecurityHeaders(options);
  const status = preflightStatus(options);
  return async (context, next) => {
    const corsHeaders = adapterCorsHeaders(context.req.header('Origin'), options);
    if (shouldHandlePreflight(context.req.method, corsHeaders, options)) {
      return new Response(null, { status, headers: { ...securityHeaders, ...(corsHeaders ?? {}) } });
    }
    await next();
    for (const [name, value] of Object.entries(securityHeaders)) context.header(name, value);
    if (corsHeaders) for (const [name, value] of Object.entries(corsHeaders)) context.header(name, value);
    return undefined;
  };
}

export type { SecurityAdapterOptions } from './shared.js';
