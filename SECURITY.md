# Security Policy

## Supported versions

AxiomGuard is pre-1.0. Until a stable release exists, only the latest released minor version receives security fixes.

## Reporting a vulnerability

Do not open a public issue for a vulnerability that exposes credentials, private data, or a working exploit against downstream users. Use GitHub's private vulnerability reporting feature for this repository when enabled. If private reporting is unavailable, contact the repository maintainers through their GitHub profiles without posting exploit details publicly.

## Security boundaries

AxiomGuard provides application-level guardrails. It does not replace:

- network egress filtering or sandboxing;
- a dedicated secrets manager;
- authentication/authorization policy;
- dependency and container vulnerability scanning;
- a full SSRF defense at the socket/proxy layer;
- code review and threat modeling.

### URL validation

`assertSafeResolvedUrl` performs DNS lookup at validation time and rejects blocked addresses. DNS answers can change after validation. Callers should disable or explicitly validate redirects and enforce network-level egress restrictions for sensitive services.

### Webhook validation

Webhook HMAC verification must use the exact raw request body. Parsing and reserializing JSON before verification can change bytes and invalidate the security property.

### Secret scanner

The CLI is intentionally conservative and will not detect every possible secret. It reports only locations and rule names to reduce accidental secret exposure in CI logs.
