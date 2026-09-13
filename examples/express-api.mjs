// Express 5 API with headers, CORS, request policy, rate limiting and typed env.
import express from 'express';
import { createExpressSecurityMiddleware } from '../dist/adapters/express.js';
import { MemoryRateLimitStore, checkRateLimit, createRateLimitHeaders, getClientIp, requireEnv } from '../dist/index.js';

const env = requireEnv({ PORT: { type: 'port', default: 3000 }, CORS_ORIGINS: { type: 'list', default: ['https://app.example.com'] }, TRUSTED_PROXIES: { type: 'integer', default: 0 } });
const app = express();
const limiter = new MemoryRateLimitStore();

app.use(createExpressSecurityMiddleware({
  cors: { origins: env.CORS_ORIGINS, allowCredentials: true, allowMethods: ['GET', 'POST'] },
  requestPolicy: { allowedOrigins: env.CORS_ORIGINS },
}));

app.use(async (request, response, next) => {
  const ip = getClientIp(request.socket.remoteAddress, request.headers['x-forwarded-for'], { trustedProxyCount: env.TRUSTED_PROXIES }) ?? 'unknown';
  const result = await checkRateLimit(`ip:${ip}`, { limit: 60, windowMs: 60_000, store: limiter });
  for (const [name, value] of Object.entries(createRateLimitHeaders(result, { policyName: 'api' }))) response.setHeader(name, value);
  if (!result.allowed) return response.status(429).end();
  next();
});

app.get('/health', (_request, response) => response.json({ ok: true }));
app.post('/profile', (_request, response) => response.json({ updated: true }));

const server = app.listen(env.PORT, () => console.log(`listening on http://localhost:${env.PORT}`));
if (process.env.EXAMPLE_SMOKE) {
  const response = await fetch(`http://localhost:${env.PORT}/health`, { headers: { Origin: 'https://app.example.com' } });
  console.log(response.status, Object.fromEntries(response.headers));
  server.close();
}
