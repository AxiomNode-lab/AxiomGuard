# AxiomGuard competitive research

This document records the design pass behind the 0.2 line. The goal is not to clone established packages; it is to keep a small, auditable SDK while adopting the patterns that have proven useful in mature Node.js security tooling.

## Projects and guidance reviewed

- **Helmet** — mature secure-header defaults, per-header opt-outs, CSP support and low-dependency integration.
- **Envalid** — richer environment types, defaults, choices and executable configuration documentation.
- **Pino redaction patterns** — explicit redaction paths in addition to secret-name heuristics.
- **GitHub webhook guidance** — raw-body HMAC-SHA256 verification and timing-safe comparison.
- **Stripe webhook guidance** — timestamp included in the signed payload, bounded freshness windows and replay resistance.
- **OWASP SSRF Prevention Cheat Sheet** — prefer allowlists, restrict schemes, validate resolved addresses, treat redirects as a separate trust decision and account for metadata/private ranges.

## Gaps found in AxiomGuard 0.1

1. Header support covered CSP/HSTS basics but not the broader cross-origin isolation and legacy hardening headers commonly emitted by mature middleware.
2. Fresh webhook verification accepted a timestamp that was not cryptographically bound to the signature. That was useful only for providers whose signing format already covered time externally; it was not sufficient as a Stripe-style verifier.
3. Environment validation lacked number, port, email, JSON, defaults, numeric ranges and aliases/choices.
4. There was no framework-neutral CORS policy helper.
5. There was no secure cookie serializer enforcing `__Host-` / `__Secure-` invariants.
6. There was no stateless signed CSRF primitive for applications that want a small double-submit/session-bound building block.
7. Package exports were modular, but the SDK still lacked dedicated modules for cookies, CORS and CSRF.

## 0.2 design decisions

- Keep **zero runtime dependencies**.
- Add provider-aware webhook helpers instead of pretending one generic signature format fits every provider.
- Fail closed on malformed signatures, cookie prefixes, CORS wildcard+credentials combinations and stale CSRF tokens.
- Keep framework adapters out of core. Express/Fastify/Hono/Nest wrappers can live in separate packages later.
- Do not claim network isolation from URL validation; SSRF defense still requires outbound network policy for high-risk workloads.
- Preserve subpath imports so consumers only load the area they use.

## Deliberately out of scope

AxiomGuard is not trying to replace Helmet, a secrets manager, a WAF, a password hashing library, a distributed rate limiter, or an authorization framework. Mature dedicated packages should remain the default when an application needs their full feature set.
