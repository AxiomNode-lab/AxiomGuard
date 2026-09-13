# How AxiomGuard compares

AxiomGuard is not a replacement for a framework's ecosystem; it is a set of
primitives that can stand in for several small dependencies with one audited,
zero-dependency package. The table shows the closest popular alternative for
each control and what AxiomGuard does differently.

| Control | Common alternative | AxiomGuard | What AxiomGuard does not do |
| --- | --- | --- | --- |
| Security headers | `helmet` | `createSecurityHeaders`, presets, per-request CSP nonces, header-injection validation | Ship a default CSP for you; HSTS/COEP stay opt-in |
| CORS | `cors`, `@fastify/cors`, `hono/cors` | `createCorsPolicy` validated at startup, never throws on request input, always sets `Vary`, PNA-aware, `allowHeaders: 'reflect'` | Route-level configuration; combine with your router |
| CSRF | `csrf-csrf`, `hono/csrf`, `lusca` | Signed session-bound tokens **and** Fetch-Metadata/Origin request policy | Store sessions or render forms |
| Rate limiting | `express-rate-limit`, `rate-limiter-flexible` | Fixed-window store contract with bounded memory and atomic Redis adapters, IETF `RateLimit` headers, spoof-resistant `getClientIp` | Sliding windows, token buckets, distributed bot mitigation |
| Webhook verification | `@octokit/webhooks`, `stripe.webhooks.constructEvent`, `svix`, `@slack/bolt` | One consistent API for GitHub, Stripe, Slack, Meta and Standard Webhooks, with replay protection on a shared store | Parse or type the provider payloads |
| Idempotency keys | ad-hoc middleware | Normalised keys, request fingerprints, per-tenant scope, `accepted`/`replay`/`conflict` semantics, Redis adapters | Store the response for replay; that is application data |
| API keys | ad-hoc | Opaque parseable tokens, constant-time verification, optional pepper | Password hashing (use Argon2/scrypt/bcrypt) |
| SSRF-safe fetch | `ssrf-req-filter`, `got` hooks | `safeFetch` re-validates every redirect, bounds time and body size, strips credentials across origins, rejects downgrades | Pin DNS to the socket; you still need egress controls |
| Secret redaction | `pino` redact paths, `fast-redact` | Key, path and value-pattern redaction that keeps `Error`s intact | Replace a structured logger |
| Environment validation | `envalid`, `zod` | Typed schema with security-flavoured types (`url` without credentials, `port`, `duration`, `list`) | Arbitrary schema composition |
| Secret scanning | `gitleaks`, `trufflehog` | Conservative provider-shaped rules, baselines, SARIF, GitHub Action and container, no matched values in output | Entropy analysis, git history scanning, hundreds of rules |
| Filenames and paths | `sanitize-filename`, `path.resolve` checks | Byte-bounded Unicode-aware filenames, NUL-safe path containment | Resolve symlinks (use `fs.realpath` after `safePath`) |

Choose AxiomGuard when you want these controls to share one threat model,
one release cadence and no transitive dependencies. Keep the specialised
tools when you need their depth (a full scanner for git history, a token
bucket limiter, a provider SDK that also parses events).
