// Web-standard runtimes: Cloudflare Workers, Deno, Bun, Next.js middleware, SvelteKit.
import { createFetchSecurityHandler } from '../dist/adapters/fetch.js';

const guard = createFetchSecurityHandler({
  headers: { contentSecurityPolicy: { 'default-src': ["'self'"] } },
  cors: { origins: ['https://app.example.com'], allowMethods: ['GET', 'POST'] },
  requestPolicy: { allowedOrigins: ['https://app.example.com'] },
});

const app = (request) => new Response(`hello from ${new URL(request.url).pathname}`, { headers: { 'content-type': 'text/plain' } });
const handler = (request) => guard(request, app);

for (const [label, request] of [
  ['GET', new Request('https://api.example.com/hello')],
  ['preflight', new Request('https://api.example.com/hello', { method: 'OPTIONS', headers: { Origin: 'https://app.example.com', 'Access-Control-Request-Method': 'POST' } })],
  ['cross-site POST', new Request('https://api.example.com/hello', { method: 'POST', headers: { Origin: 'https://evil.example', 'Sec-Fetch-Site': 'cross-site' } })],
  ['trusted POST', new Request('https://api.example.com/hello', { method: 'POST', headers: { Origin: 'https://app.example.com', 'Sec-Fetch-Site': 'same-site' } })],
]) {
  const response = await handler(request);
  console.log(label, response.status, Object.fromEntries(response.headers));
}
