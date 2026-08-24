# AxiomGuard design research

AxiomGuard is deliberately smaller than a full web-security framework. Research is used to choose proven security boundaries, not to copy every feature from mature packages.

## Baseline reviewed for 0.2

- **Helmet** — secure-header defaults, per-header opt-outs, CSP/report-only support, COOP/CORP and conservative middleware behavior.
- **Envalid** — immutable validated configuration, richer environment types, defaults and choices.
- **Pino-style redaction** — explicit object paths and wildcards in addition to name/pattern heuristics.
- **Express `cors`** — dynamic origins, credentials, preflight behavior, exposed/allowed headers and `Vary: Origin`.
- **Cookie libraries and browser cookie rules** — `Secure`, `HttpOnly`, `SameSite`, `Partitioned`, priority and cookie-prefix constraints.
- **OWASP CSRF guidance** — signed tokens and session binding instead of trusting unsigned double-submit values.
- **GitHub webhook guidance** — raw-body HMAC-SHA256 and timing-safe comparison.
- **Stripe webhook guidance** — timestamp-bound signatures, freshness windows and replay resistance.
- **OWASP SSRF guidance** — scheme restrictions, allowlists, resolved-address validation and explicit redirect trust decisions.

That pass produced provider-aware webhook helpers, secure cookies, CORS/CSRF primitives, richer headers and environment validation, explicit redaction paths and clearer SSRF limits.

## Integration research for 0.3

The next gap was not another set of unrelated primitives; it was adoption cost.

### Express

Express middleware receives `req`, `res` and `next`, and must either end the response or call `next()`. The adapter therefore uses only `headers`, `setHeader`, `statusCode`, `end` and `next`, avoiding a hard Express dependency.

Reference: https://expressjs.com/en/5x/guide/writing-middleware/

### Fastify

Fastify request/reply hooks are lifecycle primitives. `onRequest` is early enough for header/CORS decisions and can short-circuit by sending a reply. The adapter uses a structural request/reply surface and avoids mixing callback and promise hook styles.

Reference: https://fastify.dev/docs/latest/Reference/Hooks/

### Hono

Hono middleware follows an `await next()` model and can mutate response headers after downstream handlers. The adapter applies normal-response headers after `next()` and returns a direct `Response` only for an allowed preflight short-circuit.

Reference: https://hono.dev/docs/guides/middleware

### Redis

Replay claims must be atomic. The Redis adapters use `SET ... NX PX` rather than a separate read/write sequence. Fixed-window rate limiting uses one Lua script for increment-plus-expiry so the first increment cannot lose its TTL between commands.

### SARIF and GitHub code scanning

GitHub accepts third-party SARIF through `github/codeql-action/upload-sarif`. AxiomGuard's SARIF results include rule, file and line, but never the matched secret. The GitHub Action exposes the SARIF path instead of requiring code-scanning permissions for every scan.

Reference: https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/integrate-with-existing-tools/upload-sarif-file

### npm supply-chain publishing

npm Trusted Publishing supports GitHub-hosted Actions through OIDC and can automatically create provenance for public packages from public repositories. The npmjs workflow is prepared for that model but disabled until the npm scope/package is configured.

Reference: https://docs.npmjs.com/trusted-publishers/

## Deliberate boundaries

- Framework adapters do not import or pin Express, Fastify or Hono.
- CORS remains browser policy, not authentication or authorization.
- Rate limiting is a traffic-control primitive, not abuse prevention by itself.
- The in-memory stores are single-process only.
- Redis adapters assume the supplied client is already authenticated and configured securely.
- URL validation does not replace outbound network policy.
- SARIF findings are conservative pattern matches, not proof that a credential is live.
- AxiomGuard does not implement password hashing, authorization policy, a WAF, a secrets manager or a distributed identity system.

## What makes the package distinct

The project is not trying to win by API size. Its useful niche is a dependency-free set of auditable backend security primitives with explicit failure modes, provider-aware verification where formats matter, adapters that do not force framework versions, and CI-friendly scanner output. Features are added only when they fit that boundary.
