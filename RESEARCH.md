# AxiomGuard competitive research

This document records the design pass behind the 0.2 line. The goal is not to clone established packages; it is to keep a small, auditable SDK while adopting patterns that have proved useful in mature Node.js security tooling.

## Projects and guidance reviewed

- **Helmet** — broad secure-header defaults, per-header opt-outs, CSP and report-only support, COOP/CORP and low-maintenance integration.
- **Envalid** — immutable validated configuration, richer environment types, defaults, choices, custom validation and executable configuration documentation.
- **Pino-style redaction** — explicit object paths and wildcard redaction in addition to secret-name heuristics.
- **Express `cors`** — dynamic origins, preflight settings, credentials, exposed/allowed headers, cache age and the importance of `Vary: Origin` when reflecting an origin.
- **Cookie/Cookies packages and browser cookie rules** — `Secure`, `HttpOnly`, `SameSite`, `Partitioned`, priority and cookie-prefix constraints.
- **Stateless double-submit CSRF implementations / OWASP CSRF guidance** — HMAC-signed tokens and session binding instead of trusting an unsigned cookie/token pair.
- **GitHub webhook guidance** — raw-body HMAC-SHA256 verification and timing-safe comparison.
- **Stripe webhook guidance** — timestamp included in the signed payload, bounded freshness windows and replay resistance.
- **OWASP SSRF Prevention Cheat Sheet** — prefer allowlists, restrict schemes, validate resolved addresses, treat redirects as a separate trust decision and account for metadata/private ranges.

## Gaps found in AxiomGuard 0.1

1. Header support covered CSP/HSTS basics but not the broader cross-origin isolation and legacy hardening headers commonly emitted by mature middleware.
2. Fresh webhook verification accepted a timestamp that was not cryptographically bound to the signature. That was useful only for providers whose signing format already covered time externally; it was not sufficient as a Stripe-style verifier.
3. Environment validation lacked number, port, email, JSON, defaults and numeric ranges.
4. Redaction relied on key names and token patterns but lacked explicit object paths.
5. There was no framework-neutral CORS policy helper, and therefore no central place to reject invalid origin syntax or wildcard-plus-credentials policies.
6. There was no secure cookie serializer enforcing `__Host-` / `__Secure-` invariants.
7. There was no stateless signed CSRF primitive for applications that want a small session-bound building block.
8. Package exports were modular, but the SDK still lacked dedicated modules for cookies, CORS and CSRF.
9. CI qualified Node 20/22 only and used GitHub Actions versions whose JavaScript runtime was being deprecated by hosted runners.

## 0.2 design decisions

- Keep **zero runtime dependencies**.
- Add provider-aware webhook helpers instead of pretending one generic signature format fits every provider.
- Fail closed on malformed signatures, cookie prefixes, CORS wildcard+credentials combinations, opaque `Origin: null` by default, and stale CSRF tokens.
- Validate CORS origins as exact HTTP(S) origins; do not treat CORS as authentication or authorization.
- Make Private Network Access an explicit opt-in rather than emitting it by default.
- Add explicit path/wildcard log redaction while preserving non-mutating behavior.
- Keep framework adapters out of core. Express/Fastify/Hono/Nest wrappers can live in separate packages later.
- Do not claim network isolation from URL validation; SSRF defense still requires outbound network policy for high-risk workloads.
- Preserve subpath imports so consumers only load the area they use.
- Qualify Node 20, 22 and 24 and use current GitHub Actions runtimes.

## What AxiomGuard deliberately does differently

AxiomGuard does not try to win by having the largest API. It combines a set of security primitives that are commonly needed together while keeping each module independently importable and dependency-free at runtime. Provider-specific helpers are added only where the provider's signing format materially changes the security property, as with Stripe's signed timestamp.

The project also keeps limitations next to the feature: CORS is not access control, URL validation is not a firewall, in-memory replay protection is not suitable for a multi-instance deployment, and SHA-256 API-key digests are intended for generated high-entropy keys rather than human passwords.

## Deliberately out of scope

AxiomGuard is not trying to replace Helmet, a secrets manager, a WAF, a password hashing library, a distributed rate limiter, or an authorization framework. Mature dedicated packages should remain the default when an application needs their full feature set.
