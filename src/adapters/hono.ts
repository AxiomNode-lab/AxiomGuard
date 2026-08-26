import { adapterCorsHeaders, adapterRequestPolicy, adapterSecurityHeaders, blockedRequestStatus, preflightStatus, shouldHandlePreflight, type SecurityAdapterOptions } from './shared.js';

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
  const deniedStatus = blockedRequestStatus(options);
  return async (context, next) => {
    const origin = context.req.header('Origin');
    const corsHeaders = adapterCorsHeaders(origin, options);
    if (shouldHandlePreflight(context.req.method, corsHeaders, options)) {
      return new Response(null, { status, headers: { ...securityHeaders, ...(corsHeaders ?? {}) } });
    }

    const decision = adapterRequestPolicy({
      method: context.req.method,
      origin: origin ?? null,
      secFetchSite: context.req.header('Sec-Fetch-Site') ?? null,
    }, options);
    if (decision && !decision.allowed) {
      return new Response(null, { status: deniedStatus, headers: { ...securityHeaders, ...(corsHeaders ?? {}) } });
    }

    await next();
    for (const [name, value] of Object.entries(securityHeaders)) context.header(name, value);
    if (corsHeaders) for (const [name, value] of Object.entries(corsHeaders)) context.header(name, value);
    return undefined;
  };
}

export type { SecurityAdapterOptions } from './shared.js';
