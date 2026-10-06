# AxiomGuard Beginner Guide

A practical, step-by-step introduction to using AxiomGuard in a real Node.js or TypeScript project.

This guide assumes you are new to AxiomGuard and may be new to application security. You do not need to understand every security concept before starting. Follow the sections in order, then use the individual recipes when you need a specific protection.

> **Current release status:** the repository is preparing the `0.8.0-beta.1` prerelease. The stable published release is still `0.7.1` until the beta is explicitly published. The examples in this guide describe the current API in `main`.

## 1. What AxiomGuard does

AxiomGuard is a collection of small security building blocks for backend services.

You can use it to:

- protect signed webhooks from tampering and replay
- generate and verify API keys
- reduce common SSRF mistakes when your application fetches user-controlled URLs
- apply security response headers
- configure CORS safely
- apply a CSRF-oriented browser request policy
- create and verify CSRF tokens
- prevent accidental duplicate writes with idempotency claims
- rate-limit requests
- validate environment variables
- redact secrets and mask common PII before logging
- safely serialize cookies
- keep upload paths inside an intended directory
- scan repositories for committed secrets
- run the scanner locally, in GitHub Actions, or in a container

AxiomGuard is intentionally a **toolkit**, not a complete security boundary.

It does not replace:

- authentication
- authorization
- a database transaction
- a WAF or firewall
- network egress controls
- a secrets manager
- DDoS protection
- a full SAST or malware scanner

The safest way to use AxiomGuard is to combine its application-level controls with normal infrastructure security.

---

## 2. Requirements

The current Beta line supports:

- Node.js 22 or newer
- Node.js 24 is the recommended LTS line
- Node.js 26 is also qualified in CI
- TypeScript 5.x
- ESM projects are recommended, although the package also supports `require()` on Node versions with `require(esm)`

Check your Node version:

```bash
node --version
npm --version
```

You should see Node.js 22 or newer.

---

## 3. Install AxiomGuard

For the stable published package:

```bash
npm install @axiomnode-lab/guard
```

With pnpm:

```bash
pnpm add @axiomnode-lab/guard
```

With Yarn:

```bash
yarn add @axiomnode-lab/guard
```

### Beta installation

The `0.8.0-beta.1` version is a prerelease and is not the stable channel.

After the beta is published, install it explicitly:

```bash
npm install @axiomnode-lab/guard@beta
```

Or use an exact prerelease version:

```bash
npm install @axiomnode-lab/guard@0.8.0-beta.1
```

Do not assume that `npm install @axiomnode-lab/guard` installs the beta. The stable `latest` channel remains separate.

---

## 4. Your first AxiomGuard example

Create a TypeScript file such as `src/security.ts`:

```ts
import { createSecurityHeaders } from '@axiomnode-lab/guard/headers';

const headers = createSecurityHeaders();

console.log(headers);
```

The default helper returns defensive response headers such as:

- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Referrer-Policy: no-referrer`
- `Permissions-Policy`
- cross-origin isolation related headers where configured
- `X-XSS-Protection: 0`

AxiomGuard does not automatically send these headers for you when you call this low-level helper. You must apply the returned values to your framework's response.

For Express, Fastify and Hono, the adapters make this much easier.

---

# 5. Recommended setup for a beginner

If your project is a normal HTTP API, start with the framework adapter instead of manually wiring every low-level primitive.

## Express

Install Express separately in your application:

```bash
npm install express
```

Then:

```ts
import express from 'express';
import { createExpressSecurityMiddleware } from '@axiomnode-lab/guard/adapters/express';

const app = express();

app.use(
  createExpressSecurityMiddleware({
    cors: {
      origins: ['https://app.example.com'],
      allowCredentials: true,
      allowMethods: ['GET', 'POST', 'PATCH'],
    },
    requestPolicy: {
      allowedOrigins: ['https://app.example.com'],
    },
  }),
);

app.get('/health', (_req, res) => {
  res.json({ ok: true });
});

app.post('/profile', (_req, res) => {
  res.json({ updated: true });
});

app.listen(3000);
```

This gives you a single place to apply:

- response security headers
- CORS
- browser request policy

The request policy is **not authentication**. Your application still needs normal authentication and authorization.

## Fastify

```ts
import Fastify from 'fastify';
import { createFastifySecurityHook } from '@axiomnode-lab/guard/adapters/fastify';

const app = Fastify();

app.addHook(
  'onRequest',
  createFastifySecurityHook({
    cors: {
      origins: ['https://app.example.com'],
      allowMethods: ['GET', 'POST'],
    },
    requestPolicy: {
      allowedOrigins: ['https://app.example.com'],
    },
  }),
);
```

## Hono

```ts
import { Hono } from 'hono';
import { createHonoSecurityMiddleware } from '@axiomnode-lab/guard/adapters/hono';

const app = new Hono();

app.use(
  '*',
  createHonoSecurityMiddleware({
    cors: {
      origins: ['https://app.example.com'],
      allowMethods: ['GET', 'POST'],
    },
    requestPolicy: {
      allowedOrigins: ['https://app.example.com'],
    },
  }),
);
```

## Web-standard Fetch

For Fetch-based runtimes such as Cloudflare Workers, Deno, Bun, and compatible frameworks:

```ts
import { createFetchSecurityHandler } from '@axiomnode-lab/guard/adapters/fetch';

const guard = createFetchSecurityHandler({
  cors: {
    origins: ['https://app.example.com'],
  },
  requestPolicy: {
    allowedOrigins: ['https://app.example.com'],
  },
});

export default {
  fetch: (request: Request) =>
    guard(request, (req) => app.handle(req)),
};
```

---

# 6. Using AxiomGuard with AI applications

You can also use AxiomGuard when your application talks to an AI model, agent, chatbot, RAG system, tool-calling workflow, or AI API.

The key idea is simple:

> **AxiomGuard protects the application around the AI model. It does not try to replace the model provider's safety controls.**

For example, imagine this flow:

```text
User
  |
  v
Your API / AI application
  |
  +--> AxiomGuard request policy
  +--> Authentication / API key checks
  +--> Rate limiting
  +--> Input validation
  |
  v
AI model / AI provider
  |
  +--> Tool calls / URLs / webhooks
  |
  v
AxiomGuard protected operations
```

This is useful because AI applications often make security-sensitive decisions or requests on behalf of a user.

## 6.1 Simple AI backend example

A beginner-friendly pattern is to put AxiomGuard in your backend before calling the model provider.

Example:

```ts
import { safeFetch } from '@axiomnode-lab/guard/fetch';
import {
  createApiKey,
  parseApiKey,
  verifyApiKey,
} from '@axiomnode-lab/guard/api-keys';
import {
  MemoryRateLimitStore,
  checkRateLimit,
} from '@axiomnode-lab/guard/rate-limit';

const rateStore = new MemoryRateLimitStore();

async function handleAiRequest(request: Request) {
  // 1. Authenticate the caller.
  const authorization = request.headers.get('authorization');
  const token = authorization?.startsWith('Bearer ')
    ? authorization.slice('Bearer '.length)
    : null;

  if (!token) {
    return new Response('Unauthorized', { status: 401 });
  }

  const parsed = parseApiKey(token);

  if (!parsed) {
    return new Response('Unauthorized', { status: 401 });
  }

  const record = await db.apiKeys.findById(parsed.id);

  if (!record || !verifyApiKey(token, record.digest)) {
    return new Response('Unauthorized', { status: 401 });
  }

  // 2. Rate-limit AI requests.
  const limit = await checkRateLimit(
    `ai:${parsed.id}`,
    {
      limit: 30,
      windowMs: 60_000,
      store: rateStore,
    },
  );

  if (!limit.allowed) {
    return new Response('Too Many Requests', { status: 429 });
  }

  // 3. Read and validate the application input.
  const body = await request.json();

  if (
    typeof body.prompt !== 'string' ||
    body.prompt.length === 0 ||
    body.prompt.length > 20_000
  ) {
    return new Response('Invalid prompt', { status: 400 });
  }

  // 4. Call your AI provider from the server.
  // Keep the provider secret on the server.
  const aiResponse = await fetch(process.env.AI_API_URL!, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${process.env.AI_API_KEY!}`,
      'content-type': 'application/json',
    },
    body: JSON.stringify({
      model: process.env.AI_MODEL,
      input: body.prompt,
    }),
  });

  return new Response(aiResponse.body, {
    status: aiResponse.status,
    headers: {
      'content-type':
        aiResponse.headers.get('content-type') ?? 'application/json',
    },
  });
}
```

The important part is not the exact AI provider. The security pattern is:

```text
Authenticate
   ↓
Rate limit
   ↓
Validate input
   ↓
Call AI provider from the server
   ↓
Apply security checks to any tools/network access
   ↓
Return the result
```

Never put your AI provider secret directly in browser code.

## 6.2 Protect AI agents that can access URLs

This becomes especially important for AI agents.

Suppose an agent can receive a URL and then fetch it:

```text
User prompt
    ↓
AI agent
    ↓
"Open this URL"
    ↓
Your server fetches the URL
```

That is an SSRF risk when the URL is user-controlled or model-controlled.

Instead of:

```ts
const response = await fetch(urlFromUserOrAgent);
```

use:

```ts
import { safeFetch } from '@axiomnode-lab/guard/fetch';

const response = await safeFetch(urlFromUserOrAgent, {
  protocols: ['https:'],
  allowedHosts: ['api.example.com'],
  maxRedirects: 2,
  timeoutMs: 5_000,
  maxResponseBytes: 5_000_000,
});
```

This is a particularly useful pattern for:

- AI web agents
- URL summarizers
- document fetchers
- RAG ingestion services
- browser automation backends
- webhook-driven AI workers
- tool-calling agents

Do not assume that a URL is safe just because the AI model suggested it.

## 6.3 Protect tool-calling agents

A tool-calling agent may have functions such as:

```text
searchWeb()
getDocument()
sendWebhook()
createOrder()
runJob()
```

Treat every tool as an API endpoint.

A good rule is:

```text
AI decides what to request
        ↓
Your application validates the request
        ↓
AxiomGuard applies the relevant security control
        ↓
Only then execute the tool
```

For example:

### AI wants to call an external HTTP API

Use `safeFetch()` when the destination can be influenced by the user or model.

### AI wants to call a protected internal API

Use normal authentication and authorization. AxiomGuard API keys can help with generated machine credentials, but they do not decide whether the AI is allowed to perform a business action.

### AI wants to create a resource

Use idempotency for operations that may be retried:

```ts
const fingerprint = createIdempotencyFingerprint({
  method: request.method,
  target: '/api/orders',
  contentType: request.headers.get('content-type'),
  body: rawBody,
});
```

Then claim an idempotency key before performing the write.

## 6.4 AI chatbot + browser security

For a browser-based AI chat application, you can combine:

- security headers
- CORS
- request policy
- CSRF protection
- authentication
- rate limiting

A typical flow is:

```text
Browser
  ↓
Security headers + CORS
  ↓
Request policy / CSRF checks
  ↓
Authentication
  ↓
Rate limit
  ↓
AI endpoint
  ↓
AI provider
```

CORS still does **not** authenticate the user, and AI output should not be trusted as authorization.

For example, do not do this:

```ts
if (modelOutput === 'admin approved') {
  performSensitiveAction();
}
```

The model can help make decisions, but your application must enforce authorization independently.

## 6.5 AI + webhooks

AI systems often react to provider events.

For example:

```text
Payment webhook
      ↓
Verify signature
      ↓
Check replay/freshness
      ↓
Parse event
      ↓
Queue AI job
      ↓
AI worker
```

Use AxiomGuard webhook verification **before** passing an event to the AI workflow.

The AI model should never be responsible for deciding whether a webhook signature is valid.

## 6.6 AI secrets and logs

AI applications frequently handle sensitive prompts, tokens, tool arguments, and provider credentials.

Keep secrets on the server:

```text
Browser
   X  AI_API_KEY
   X  webhook secret
   X  database credential

Server
   ✓ AI_API_KEY
   ✓ webhook secrets
   ✓ database credentials
```

Before logging tool calls or model requests, consider:

```ts
import { redactSecrets, maskPII } from '@axiomnode-lab/guard/logging';

const safeRequest = redactSecrets({
  tool: 'searchWeb',
  authorization: request.headers.get('authorization'),
  arguments: toolArguments,
});

console.log({
  request: maskPII(JSON.stringify(safeRequest)),
});
```

Do not blindly log complete prompts, tokens, authorization headers, uploaded documents, or model responses. AI applications may contain personal or confidential information even when there is no obvious password.

## 6.7 RAG / document ingestion

A RAG system often looks like:

```text
Upload document
      ↓
Validate input
      ↓
Store safely
      ↓
Extract text
      ↓
Chunk + embed
      ↓
Vector database
      ↓
Retrieve context
      ↓
AI model
```

AxiomGuard can help with the application-security parts around this pipeline:

- `safePath()` for filesystem destinations
- `sanitizeFilename()` for upload names
- `redactSecrets()` before logs
- rate limiting on upload/search endpoints
- request policy and authentication
- `safeFetch()` when documents are imported from URLs

Remember that AxiomGuard does not inspect document content for prompt injection or malware.

You still need application-level content validation and, where appropriate, dedicated malware/content scanning.

## 6.8 MCP-style or agent-tool servers

When an AI system connects to a server exposing tools, treat those tools like public API endpoints.

For each tool:

```text
1. authenticate the caller
2. authorize the requested action
3. validate every argument
4. rate-limit expensive operations
5. use safeFetch for untrusted network destinations
6. use idempotency for retryable writes
7. redact sensitive values from logs
8. fail closed on security checks
```

Do not trust a model-generated argument simply because the model produced it.

Example:

```ts
async function runTool(args: unknown) {
  const input = validateToolArguments(args);

  if (!input.ok) {
    throw new Error('Invalid tool arguments');
  }

  const response = await safeFetch(input.url, {
    protocols: ['https:'],
    allowedHosts: ['api.example.com'],
  });

  return response;
}
```

The validation function in this example is part of your application. AxiomGuard does not know your business rules.

## 6.9 Protecting AI endpoints from abuse

AI endpoints can be expensive.

A user may repeatedly send requests that trigger:

- large prompts
- expensive models
- repeated tool calls
- large document retrieval
- long-running agent loops

Use rate limiting and application quotas:

```text
user / API key
     ↓
rate limit
     ↓
request size limit
     ↓
application quota
     ↓
AI call
```

AxiomGuard provides the rate-limit primitive. Your application should define the actual quota policy, such as:

```text
Free user:
  20 requests/minute

Pro user:
  120 requests/minute

Internal worker:
  dedicated service limit
```

Also consider limiting maximum prompt size and maximum tool-call depth in the application.

## 6.10 Example: a safer AI tool workflow

A practical beginner design is:

```text
                    +-------------------+
                    |      Browser      |
                    +---------+---------+
                              |
                              v
                    +-------------------+
                    | Authentication    |
                    | CORS / CSRF       |
                    | Request Policy    |
                    +---------+---------+
                              |
                              v
                    +-------------------+
                    |   Rate Limiting   |
                    +---------+---------+
                              |
                              v
                    +-------------------+
                    |    AI Endpoint    |
                    +---------+---------+
                              |
                    +---------+---------+
                    |                   |
                    v                   v
             +-------------+     +-------------+
             | AI Provider |     | AI Tools    |
             +-------------+     +------+------+
                                      |
                              +-------+-------+
                              | AxiomGuard    |
                              | safeFetch     |
                              | API keys      |
                              | idempotency   |
                              | logging       |
                              +---------------+
```

The AI model is inside the workflow, but your application remains the security authority.

## 6.11 Beginner AI checklist

Before putting an AI feature into production, ask:

```text
[ ] Is the AI provider key server-side only?
[ ] Is the caller authenticated?
[ ] Is authorization enforced outside the model?
[ ] Is the AI endpoint rate-limited?
[ ] Are prompts and tool arguments size-limited?
[ ] Are model-controlled URLs passed through safeFetch()?
[ ] Are retryable writes protected with idempotency?
[ ] Are webhooks verified before entering the AI workflow?
[ ] Are secrets removed from logs?
[ ] Are uploads stored with safe filesystem paths?
[ ] Are external services protected with normal network egress controls?
[ ] Is there a timeout for model/tool operations?
[ ] Is there an independent content/malware/prompt-injection strategy?
```

### What AxiomGuard does not solve for AI

AxiomGuard is useful around AI applications, but it does not automatically protect against every AI-specific threat.

It does not by itself guarantee protection against:

- prompt injection
- jailbreaks
- model hallucinations
- unsafe model output
- poisoned training data
- malicious documents
- excessive agent loops
- unauthorized business decisions
- data leakage caused by your application design

For those problems, add AI-specific validation, authorization, content safety, data governance, observability, and network controls.


---

# 7. API keys

Use AxiomGuard API keys for machine-to-machine authentication where your application needs a generated credential.

## Generate a key

```ts
import { createApiKey } from '@axiomnode-lab/guard/api-keys';

const created = createApiKey({ prefix: 'svc' });

console.log(created.token);
```

The returned object contains:

- `token` — the credential you give to the client once
- `id` — the public identifier
- `digest` — what you should store instead of the plaintext token
- `fingerprint` — a short non-secret identifier

### Important rule

Do **not** store the plaintext API key in your database when you can avoid it.

A common pattern is:

```text
client receives:
    token

database stores:
    id
    digest
```

## Verify a key

```ts
import {
  parseApiKey,
  verifyApiKey,
} from '@axiomnode-lab/guard/api-keys';

const parsed = parseApiKey(presentedToken);

if (!parsed) {
  throw new Error('Invalid API key');
}

const record = await db.apiKeys.findById(parsed.id);

const valid =
  record !== null &&
  verifyApiKey(presentedToken, record.digest);

if (!valid) {
  throw new Error('Invalid API key');
}
```

The key verifier is designed for high-entropy generated credentials. It is **not** a replacement for password hashing.

For a server-held pepper:

```ts
import {
  hashApiKey,
  verifyApiKey,
} from '@axiomnode-lab/guard/api-keys';

const digest = hashApiKey(token, {
  pepper: process.env.API_KEY_PEPPER!,
});

const valid = verifyApiKey(token, digest, {
  pepper: process.env.API_KEY_PEPPER!,
});
```

Keep the pepper outside the database and outside source control.

---

# 8. Webhooks

Webhook verification is one of the most important places to use AxiomGuard correctly.

## The golden rule: verify the raw body

A provider signs exact bytes.

This is dangerous:

```ts
const json = await request.json();
const body = JSON.stringify(json);
verifyWebhook(body, signature, secret);
```

Parsing and re-serializing can change the exact bytes.

Use the raw request body that arrived from the provider.

## GitHub webhook

```ts
import {
  MemoryReplayStore,
  verifyGitHubWebhookDelivery,
} from '@axiomnode-lab/guard/webhooks';

const replayStore = new MemoryReplayStore();

const result = await verifyGitHubWebhookDelivery(
  rawBody,
  request.headers['x-hub-signature-256'],
  process.env.GITHUB_WEBHOOK_SECRET!,
  request.headers['x-github-delivery'],
  {
    replayStore,
  },
);

if (!result.ok) {
  console.error('Webhook rejected:', result.reason);
  return;
}
```

Possible reasons include:

- `invalid-signature`
- `invalid-delivery`
- `replay`

For one process, `MemoryReplayStore` is convenient.

For multiple application instances, use a Redis replay store so every instance sees the same replay claims.

## Stripe

```ts
import { verifyStripeWebhook } from '@axiomnode-lab/guard/webhooks';

const result = await verifyStripeWebhook(
  rawBody,
  request.headers['stripe-signature'],
  process.env.STRIPE_WEBHOOK_SECRET!,
  {
    replayStore,
  },
);

if (!result.ok) {
  console.error('Stripe webhook rejected:', result.reason);
}
```

The verifier checks the signed timestamp before accepting the request as fresh and can reject replays.

## Slack

```ts
import {
  MemoryReplayStore,
  verifySlackWebhook,
} from '@axiomnode-lab/guard/webhooks';

const result = await verifySlackWebhook(
  rawBody,
  request.headers['x-slack-signature'],
  request.headers['x-slack-request-timestamp'],
  process.env.SLACK_SIGNING_SECRET!,
  {
    toleranceSeconds: 300,
    replayStore: new MemoryReplayStore(),
  },
);
```

## Meta / WhatsApp

```ts
import { verifyMetaWebhook } from '@axiomnode-lab/guard/webhooks';

const valid = verifyMetaWebhook(
  rawBody,
  request.headers['x-hub-signature-256'],
  process.env.META_APP_SECRET!,
);
```

Meta event-level duplicate handling still belongs to your application.

## Standard Webhooks / Svix-compatible senders

```ts
import { verifyStandardWebhook } from '@axiomnode-lab/guard/webhooks';

const result = await verifyStandardWebhook(
  rawBody,
  {
    id: request.headers['webhook-id'],
    timestamp: request.headers['webhook-timestamp'],
    signature: request.headers['webhook-signature'],
  },
  process.env.WEBHOOK_SECRET!,
  {
    replayStore,
  },
);
```

### Webhook checklist

For every provider:

1. receive the raw body
2. verify the provider signature
3. reject invalid signatures
4. reject stale or replayed messages where supported
5. only then parse and process the payload
6. make your actual database operation idempotent when necessary

---

# 9. CSRF protection

CSRF is mainly a browser problem.

AxiomGuard provides two useful layers:

- a signed CSRF token
- a Fetch Metadata / Origin request policy

## Create a session-bound CSRF token

```ts
import {
  createCsrfToken,
  verifyCsrfToken,
} from '@axiomnode-lab/guard/csrf';

const token = createCsrfToken(
  process.env.CSRF_SECRET!,
  {
    sessionId: session.id,
  },
);

const valid = verifyCsrfToken(
  token,
  process.env.CSRF_SECRET!,
  {
    sessionId: session.id,
  },
);
```

The token is signed, expires, and is bound to the session.

Your application still decides where the token is rendered or transported.

## Use the request policy as a second layer

```ts
import { evaluateRequestPolicy } from '@axiomnode-lab/guard/request-policy';

const decision = evaluateRequestPolicy(
  {
    method: request.method,
    origin: request.headers.origin ?? null,
    secFetchSite: request.headers['sec-fetch-site'] ?? null,
  },
  {
    allowedOrigins: ['https://app.example.com'],
  },
);

if (!decision.allowed) {
  response.statusCode = 403;
  response.end();
  return;
}
```

By default, unsafe cross-site requests are rejected.

Do not set `allowNoOrigin: true` globally just to make API clients work. Restrict that option to endpoints that genuinely need machine-to-machine traffic without browser-origin metadata.

---

# 10. CORS

CORS and CSRF are **not the same thing**.

CORS controls which browser origins can read responses. It does not authenticate a caller and does not automatically stop CSRF.

## Simple allowlist

```ts
import { createCorsHeaders } from '@axiomnode-lab/guard/cors';

const headers = createCorsHeaders(
  request.headers.origin,
  {
    origins: ['https://app.example.com'],
    allowMethods: ['GET', 'POST'],
  },
);

if (headers) {
  for (const [name, value] of Object.entries(headers)) {
    response.setHeader(name, value);
  }
}
```

## Credentials

When using credentials:

```ts
{
  origins: ['https://app.example.com'],
  allowCredentials: true,
}
```

Do not combine credentialed CORS with a wildcard origin.

AxiomGuard rejects unsafe combinations such as wildcard origin + credentials and `null` origin + credentials.

## Reflecting requested headers

For some APIs you may want:

```ts
{
  origins: ['https://app.example.com'],
  allowHeaders: 'reflect',
}
```

AxiomGuard validates the requested header names before reflecting them.

---

# 11. Security headers

The low-level API is useful when you already have your own middleware.

```ts
import { createSecurityHeaders } from '@axiomnode-lab/guard/headers';

const headers = createSecurityHeaders({
  contentSecurityPolicy: {
    'default-src': ["'self'"],
    'script-src': ["'self'"],
  },
  hsts: {
    maxAge: 31_536_000,
    includeSubDomains: true,
  },
});

for (const [name, value] of Object.entries(headers)) {
  response.setHeader(name, value);
}
```

## CSP nonce

If your application needs an inline script nonce:

```ts
import {
  createCspNonce,
  cspNonceSource,
} from '@axiomnode-lab/guard/headers';

const nonce = createCspNonce();

const headers = createSecurityHeaders({
  contentSecurityPolicy: {
    'default-src': ["'self'"],
    'script-src': [
      "'self'",
      cspNonceSource(nonce),
    ],
  },
});
```

Store the nonce in request/response state so your template can put the same nonce on the script element.

---

# 12. Safe outbound requests and SSRF

SSRF happens when an attacker influences a URL and your server makes the request on their behalf.

Typical dangerous input:

```text
https://example.com/image.png
```

looks harmless, but an attacker may try:

```text
http://127.0.0.1:8080/admin
http://localhost/
http://169.254.169.254/
```

Use `safeFetch()` whenever the destination can be influenced by a user or an external system.

```ts
import { safeFetch } from '@axiomnode-lab/guard/fetch';

const response = await safeFetch(userSuppliedUrl, {
  protocols: ['https:'],
  allowedHosts: ['api.example.com'],
  maxRedirects: 2,
  timeoutMs: 5_000,
  maxResponseBytes: 5_000_000,
  headers: {
    accept: 'application/json',
  },
});

const data = await response.json();
```

AxiomGuard validates:

- the original destination
- DNS-resolved addresses
- every followed redirect
- redirect depth
- HTTPS downgrade attempts
- sensitive credentials on cross-origin redirects
- total timeout
- response size
- dangerous transport headers

## Very important: this is not magic SSRF protection

AxiomGuard documents an important limitation: application-layer DNS validation cannot guarantee that the exact DNS address checked by the library is the exact address later used by the transport connection.

For high-risk systems, also use:

- egress firewalls
- proxy controls
- cloud metadata protection
- network segmentation
- private-address routing restrictions

## Local development

A local server is intentionally blocked by default.

For development or tests only:

```ts
await safeFetch('http://127.0.0.1:3000', {
  dangerouslyAllowPrivateTargets: true,
});
```

Never enable that option for user-controlled URLs in production.

---

# 13. Idempotency

Idempotency is useful when a client may retry the same write because of a timeout.

Examples:

- creating an order
- starting a job
- submitting a payment request
- creating a resource

## Create a request fingerprint

```ts
import {
  createIdempotencyFingerprint,
} from '@axiomnode-lab/guard/idempotency';

const fingerprint = createIdempotencyFingerprint({
  method: request.method,
  target: request.url,
  contentType: request.headers['content-type'],
  body: rawBody,
});
```

## Claim the idempotency key

```ts
import {
  MemoryIdempotencyStore,
  claimIdempotencyKey,
} from '@axiomnode-lab/guard/idempotency';

const store = new MemoryIdempotencyStore();

const status = await claimIdempotencyKey(
  request.headers['idempotency-key'],
  fingerprint,
  {
    store,
    ttlMs: 86_400_000,
    scope: user.id,
  },
);
```

Handle the result:

```ts
switch (status) {
  case 'missing-key':
  case 'invalid-key':
    // Return HTTP 400.
    break;

  case 'accepted':
    // Process the operation.
    break;

  case 'replay':
    // Same key + same request semantics.
    break;

  case 'conflict':
    // Same key reused for a different request.
    break;

  case 'capacity':
    // Store is saturated. Fail closed or return a retryable response.
    break;
}
```

### Always use a scope

This is important:

```ts
scope: user.id
```

or:

```ts
scope: tenant.id
```

Without a scope, two unrelated callers can collide on the same idempotency key.

### What AxiomGuard does not do

The idempotency store remembers a **claim**.

It does not automatically:

- store your HTTP response
- make your database transaction atomic
- roll back your business operation

If clients need full response replay, store the application result in durable application storage.

---

# 14. Rate limiting

AxiomGuard provides a fixed-window rate-limit primitive.

Simple in-memory example:

```ts
import {
  MemoryRateLimitStore,
  checkRateLimit,
} from '@axiomnode-lab/guard/rate-limit';

const store = new MemoryRateLimitStore();

const result = await checkRateLimit(
  'user:123',
  {
    limit: 60,
    windowMs: 60_000,
    store,
  },
);

if (!result.allowed) {
  // Return HTTP 429.
}
```

## Rate-limit by client IP

If you are behind a proxy, do not blindly trust `X-Forwarded-For`.

Use an explicit trusted proxy count:

```ts
import { getClientIp } from '@axiomnode-lab/guard/rate-limit';

const clientIp = getClientIp(
  request.socket.remoteAddress,
  request.headers['x-forwarded-for'],
  {
    trustedProxyCount: 1,
  },
);
```

Only increase the trusted proxy count when you actually control and understand that proxy chain.

## Response headers

```ts
import {
  createRateLimitHeaders,
} from '@axiomnode-lab/guard/rate-limit';

const headers = createRateLimitHeaders(result, {
  policyName: 'api',
});
```

Apply those headers to the response.

## Multiple instances

The in-memory store belongs to one process.

For several application instances, use the Redis adapters:

```ts
import {
  createNodeRedisRateLimitStore,
} from '@axiomnode-lab/guard/adapters/redis';

const store = createNodeRedisRateLimitStore(redis);
```

---

# 15. Environment variable validation

Instead of reading everything from `process.env` and hoping it is correct:

```ts
import { requireEnv } from '@axiomnode-lab/guard/env';

const env = requireEnv({
  PORT: {
    type: 'port',
    default: 3000,
  },
  API_URL: 'url',
  CORS_ORIGINS: 'list',
  REQUEST_TIMEOUT: {
    type: 'duration',
    default: 10_000,
  },
});
```

Now the values are validated when your application starts.

Examples of supported types include:

- strings
- URLs
- ports
- durations
- lists
- JSON
- allowed values

For example:

```ts
const env = requireEnv({
  MODE: {
    type: 'string',
    allowed: ['development', 'production'],
    default: 'production',
  },
});
```

Do not put real secrets into source code just because a library example accepts a string. Use environment variables or your secret-management system.

---

# 16. Secret-safe logging

Accidentally logging credentials is a common production mistake.

AxiomGuard can redact common secret keys and provider-shaped secrets.

```ts
import { redactSecrets } from '@axiomnode-lab/guard/logging';

const safe = redactSecrets({
  user: 'alice',
  authorization: 'Bearer very-sensitive-token',
  apiKey: 'secret-value',
  nested: {
    clientSecret: 'another-secret',
  },
});

console.log(safe);
```

The result keeps structure while replacing secret-looking values.

You can also mask likely PII in free text:

```ts
import { maskPII } from '@axiomnode-lab/guard/logging';

const safeText = maskPII(
  'contact user@example.com or +1 415 555 2671',
);
```

## Important logging rule

Redaction is a safety layer, not permission to log everything.

Avoid logging:

- raw webhook request bodies
- authentication headers
- API keys
- session tokens
- passwords
- database connection strings

Prefer structured logs with only the fields you actually need.

---

# 17. Secure cookies

Use AxiomGuard when your application builds `Set-Cookie` values directly.

```ts
import { serializeCookie } from '@axiomnode-lab/guard/cookies';

const cookie = serializeCookie(
  'session',
  sessionId,
  {
    httpOnly: true,
    secure: true,
    sameSite: 'Lax',
    path: '/',
  },
);

response.setHeader('Set-Cookie', cookie);
```

AxiomGuard validates important attributes and enforces rules for prefixes such as:

- `__Host-`
- `__Secure-`

It also rejects unsafe cookie names and oversized serialized cookies.

To clear a cookie:

```ts
import { clearCookie } from '@axiomnode-lab/guard/cookies';

response.setHeader(
  'Set-Cookie',
  clearCookie('session', {
    path: '/',
    sameSite: 'Lax',
  }),
);
```

When clearing a cookie, use matching attributes so the browser removes the intended cookie.

---

# 18. Safe filesystem paths

If users can choose filenames or upload locations, never concatenate paths blindly.

Dangerous pattern:

```ts
const filePath = '/srv/uploads/' + userInput;
```

Use:

```ts
import {
  safePath,
  sanitizeFilename,
} from '@axiomnode-lab/guard/filesystem';

const filename = sanitizeFilename(userInput);
const filePath = safePath('/srv/uploads', filename);
```

`safePath()` prevents normal path traversal such as:

```text
../../etc/passwd
```

and rejects NUL bytes.

### Symlink limitation

`safePath()` does not resolve symlinks.

If the directory may contain symlinks that point outside the intended directory, resolve the path with `fs.realpath()` and apply your own filesystem policy.

---

# 19. Repository secret scanner

AxiomGuard also includes a command-line scanner.

After installing the package, run:

```bash
axiomguard scan .
```

Or:

```bash
npx axiomguard scan .
```

The scanner reports high-confidence secret-shaped findings without printing the matched credential value.

## List the available rules

```bash
axiomguard rules
```

## Scan with JSON output

```bash
axiomguard scan . --json
```

## Scan with SARIF

```bash
axiomguard scan . --sarif --output axiomguard.sarif
```

## Scan without failing the command

Useful while evaluating an existing repository:

```bash
axiomguard scan . --no-fail
```

## Exclude a narrow path

```bash
axiomguard scan . --exclude 'docs/fixtures/**'
```

Do not exclude an entire source tree just to make the scan pass.

## Create a baseline

If you have reviewed existing findings:

```bash
axiomguard scan . --write-baseline .axiomguard-baseline.json
```

Then normal scans can use the baseline:

```bash
axiomguard scan .
```

### Important baseline rule

A baseline is not approval for a real secret.

If a finding is an actual credential:

1. revoke or rotate it
2. remove it from the repository
3. investigate where it was exposed
4. only use a baseline for reviewed, non-secret findings or intentional accepted exceptions

---

# 20. GitHub Action

AxiomGuard can scan your repository in GitHub Actions.

Example:

```yaml
name: Secret scan

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write

jobs:
  secrets:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@<commit-sha>

      - id: axiomguard
        uses: AxiomNode-lab/AxiomGuard@v0.7.1
        with:
          path: .
          fail-on-findings: 'true'
          annotations: 'true'

      - name: Upload SARIF
        if: always() && steps.axiomguard.outputs.sarif != ''
        uses: github/codeql-action/upload-sarif@<commit-sha>
        with:
          sarif_file: ${{ steps.axiomguard.outputs.sarif }}
          category: axiomguard-secrets
```

For production workflows, pin third-party actions to immutable commit SHAs or another reviewed immutable reference.

See [GitHub Action documentation](GITHUB_ACTION.md) for the complete input and output reference.

---

# 21. Docker scanner

You can also use the published container:

```bash
docker run --rm \
  -v "$PWD:/workspace:ro" \
  ghcr.io/axiomnode-lab/axiomguard:0.7.1 \
  scan /workspace
```

For production automation, pin the container image to a reviewed immutable digest.

---

# 22. A simple production architecture

A beginner-friendly way to think about AxiomGuard is in layers.

```text
Browser / Client
       |
       v
+----------------------------+
| Authentication / Identity  |
+----------------------------+
       |
       v
+----------------------------+
| AxiomGuard request policy  |
| CORS + security headers    |
+----------------------------+
       |
       v
+----------------------------+
| Rate limit                 |
| API key / session checks   |
+----------------------------+
       |
       v
+----------------------------+
| Application routes         |
+----------------------------+
       |
       +------> Idempotency claim
       |
       +------> Database transaction
       |
       +------> Outbound safeFetch()
       |
       +------> Webhook verification
       |
       v
+----------------------------+
| Logging / Monitoring       |
| redactSecrets + maskPII    |
+----------------------------+
```

The important idea is that AxiomGuard provides controls **around** your application. It does not become your entire security architecture.

---

# 23. What should be configured once vs per request?

A useful beginner rule:

### Configure once at startup

Create and validate reusable policies once when practical:

- Express/Fastify/Hono security middleware
- `createRequestPolicy()`
- `createCorsPolicy()`
- environment schema
- Redis-backed stores

### Evaluate per request

Use request-specific values for:

- request metadata
- CSRF tokens
- API keys
- webhook bodies and signatures
- idempotency keys
- rate-limit identities
- user-controlled URLs

This keeps configuration errors visible early and avoids rebuilding the same policy unnecessarily.

---

# 24. Common beginner mistakes

## Mistake 1: trusting all `X-Forwarded-For`

Wrong:

```ts
const ip = request.headers['x-forwarded-for'];
```

Better:

```ts
getClientIp(
  request.socket.remoteAddress,
  request.headers['x-forwarded-for'],
  { trustedProxyCount: 1 },
);
```

Only trust headers added by infrastructure you control.

## Mistake 2: parsing a webhook before verifying it

Wrong:

```ts
const payload = await request.json();
verifyWebhook(JSON.stringify(payload), signature, secret);
```

Better:

```text
raw bytes
   ↓
verify signature
   ↓
check replay/freshness
   ↓
parse payload
   ↓
process event
```

## Mistake 3: enabling private targets in production

Never use:

```ts
dangerouslyAllowPrivateTargets: true
```

for an untrusted production URL.

## Mistake 4: using an API-key digest as a password hash

Generated API keys are high entropy.

Human passwords should use a password hashing system such as Argon2id, scrypt, or bcrypt with an appropriate password-storage design.

## Mistake 5: thinking CORS is authentication

This:

```ts
origins: ['https://app.example.com']
```

does not mean the caller is authenticated.

You still need authentication and authorization.

## Mistake 6: using an in-memory store in a multi-instance deployment

These stores are process-local:

- `MemoryReplayStore`
- `MemoryRateLimitStore`
- `MemoryIdempotencyStore`

Use the Redis adapters when state must be shared across application instances.

## Mistake 7: logging the secret because it is "only for debugging"

Debug logs become production logs surprisingly often.

Use:

```ts
redactSecrets(...)
```

and log only the minimum information you need.

---

# 25. Recommended first deployment

For a typical Express API, a sensible first setup is:

```text
1. createExpressSecurityMiddleware()
2. exact CORS origin list
3. requestPolicy with allowedOrigins
4. authentication middleware
5. application authorization
6. rate limiting
7. idempotency for retryable writes
8. webhook verification on webhook endpoints
9. safeFetch for user-controlled outbound URLs
10. redactSecrets before structured logging
11. scanner in CI
12. Redis adapters when running multiple instances
```

Do not enable every advanced feature just because it exists. Start with the protections that match your actual architecture.

---

# 26. Troubleshooting

## "My webhook signature is always invalid"

Check:

- you are using the raw body
- you are using the correct provider secret
- the header name is correct
- a middleware did not parse and rewrite the body first
- you did not convert bytes to JSON and back before verification

## "safeFetch rejects localhost during development"

That is expected.

For tests/local development:

```ts
dangerouslyAllowPrivateTargets: true
```

Keep it out of production paths.

## "My client is blocked by requestPolicy"

Inspect the returned decision:

```ts
const decision = evaluateRequestPolicy(...);

console.log(decision.reason);
```

Typical reasons include:

- `missing-origin`
- `untrusted-origin`
- `cross-site`
- `invalid-fetch-metadata`

Do not immediately disable the policy globally. First determine whether the endpoint is actually browser-facing or machine-to-machine.

## "Rate limits reset when I deploy"

An in-memory store is intentionally process-local.

Use Redis when the state must survive across instances.

## "My idempotency retry does not return the old response"

That is expected.

AxiomGuard claims idempotency state; it does not automatically persist and replay the application response.

Store durable results in the application/database layer when full response replay is required.

---

# 27. Where to go next

After this guide, use the deeper documentation:

- [API Reference](API.md) — all exports and detailed signatures
- [API Protection](API_PROTECTION.md) — request policy, CSRF-oriented browser controls and idempotency
- [Safe Fetch](SAFE_FETCH.md) — SSRF guardrails, redirects and DNS limitations
- [Scanner Guide](SCANNER.md) — scanner rules, baselines, SARIF and configuration
- [Framework Adapters](ADAPTERS.md) — Express, Fastify, Hono and Redis integration
- [GitHub Action](GITHUB_ACTION.md) — CI inputs, outputs and production usage
- [Security Policy](../SECURITY.md) — security reporting and supported-release policy
- [Threat Model](../THREAT_MODEL.md) — attacker model, trust boundaries and non-goals
- [Security Assurance](SECURITY_ASSURANCE.md) — what is tested and what still requires independent assurance

For a beginner, the most useful learning order is:

```text
This guide
   ↓
Framework adapter
   ↓
API keys / webhooks
   ↓
Request policy + CORS + CSRF
   ↓
Rate limiting + idempotency
   ↓
safeFetch
   ↓
Scanner + GitHub Action
   ↓
Threat model / security assurance
```

The project is safest when you understand not only what a function blocks, but also what it deliberately does **not** claim to block.
