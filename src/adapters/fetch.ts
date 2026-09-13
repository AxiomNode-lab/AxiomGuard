import { createSecurityCore, mergeVary, type SecurityAdapterOptions } from './shared.js';

export type FetchHandler = (request: Request) => Response | Promise<Response>;
export type FetchSecurityHandler = (request: Request, next: FetchHandler) => Promise<Response>;

/**
 * Web-standard (WinterCG) wrapper for runtimes that speak `Request`/`Response`
 * directly: Next.js middleware, SvelteKit hooks, Cloudflare Workers, Deno,
 * Bun and Node's own `http` via adapters. Preflights and policy blocks are
 * answered without calling `next`; otherwise the handler's response is
 * returned with the defensive headers applied and `Vary` merged.
 */
export function createFetchSecurityHandler(options: SecurityAdapterOptions = {}): FetchSecurityHandler {
  const core = createSecurityCore(options);
  return async (request, next) => {
    const outcome = core.evaluate({ method: request.method, header: (name) => request.headers.get(name) ?? undefined });
    if (outcome.kind !== 'continue') return new Response(null, { status: outcome.status, headers: outcome.headers });

    const response = await next(request);
    const headers = new Headers(response.headers);
    for (const [name, value] of Object.entries(outcome.headers)) {
      headers.set(name, name === 'Vary' ? mergeVary(headers.get('Vary') ?? undefined, value) : value);
    }
    if (core.removePoweredBy) headers.delete('X-Powered-By');
    return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
  };
}

/** Apply the computed security/CORS headers to a `Headers` object in place (for frameworks that expose one). */
export function applySecurityHeaders(headers: Headers, request: Request, options: SecurityAdapterOptions = {}): void {
  const outcome = createSecurityCore(options).evaluate({ method: request.method, header: (name) => request.headers.get(name) ?? undefined });
  for (const [name, value] of Object.entries(outcome.headers)) {
    headers.set(name, name === 'Vary' ? mergeVary(headers.get('Vary') ?? undefined, value) : value);
  }
}

export type { SecurityAdapterOptions } from './shared.js';
