# AxiomGuard threat model

## Purpose

AxiomGuard is a defensive Node.js/TypeScript SDK and repository scanner. It reduces common implementation mistakes around credentials, signed requests, browser-facing policy, outbound HTTP, rate limiting, configuration, logging and filesystem paths. It is not an authorization system, secrets manager, network firewall, malware scanner, WAF or complete SAST platform.

## Assets

- API keys, webhook secrets, CSRF secrets and session identifiers handled by applications using the SDK.
- Integrity of webhook processing and replay decisions.
- Availability of services protected by rate limits and bounded in-memory stores.
- Confidentiality of internal network endpoints reachable by applications performing outbound fetches.
- Confidentiality of secrets that may appear in logs, repositories or CI artifacts.
- Integrity of published npm, GitHub Packages and GHCR artifacts.

## Attacker capabilities

The model assumes an attacker may control request headers, origins, URLs, redirect targets, webhook payloads/signatures, rate-limit partition keys, filenames, selected environment/configuration inputs and repository text scanned by the CLI. The attacker may issue many requests and intentionally create high-cardinality input. The attacker does not automatically control the host process, Redis server, package registry account, CI identity, DNS resolver or application secrets.

## Trust boundaries

1. **Application input -> AxiomGuard primitives.** Inputs must be treated as untrusted even when a helper validates their syntax.
2. **AxiomGuard -> operating system / Node runtime.** Node crypto, DNS, URL parsing, Fetch and filesystem semantics are trusted dependencies.
3. **AxiomGuard -> Redis.** Redis-backed stores assume an authenticated, integrity-protected Redis deployment controlled by the application operator.
4. **DNS validation -> outbound connection.** `safeFetch` validates DNS before each request and redirect but the underlying Fetch implementation can resolve DNS again at connection time. This is an explicit TOCTOU boundary.
5. **Repository -> CI / scanner output.** Repository contents are attacker-influenced on pull requests. Scanner output must not echo matched secret material.
6. **CI -> package registries.** Release workflows use least-privilege GitHub permissions and npm Trusted Publishing where configured; registry/account policy remains an external trust boundary.

## Security properties and limitations

### API keys

Generated keys use cryptographic randomness. Verification compares SHA-256 digests with constant-time equality. The digest is suitable for high-entropy generated API keys, not human passwords. Applications that expect a database compromise and want an additional server-held secret can wrap storage with a separate pepper/HMAC strategy outside AxiomGuard.

### Webhooks

HMAC helpers verify signatures before accepting payloads. Stripe-style verification binds the timestamp into the signed input, verifies the signature before reporting freshness, and can claim a replay key. GitHub signatures do not contain a timestamp; `verifyGitHubWebhookDelivery` can replay-protect the provider's delivery ID when a shared store is supplied. Multi-instance deployments must not rely on in-process replay stores.

### CSRF and browser policy

CSRF tokens are signed, expiring and optionally session-bound. They do not replace origin/method checks or application authorization. CORS controls browser read access and does not authenticate a caller. HSTS and cross-origin isolation are deployment commitments and are therefore not silently enabled by generic presets.

### SSRF and outbound fetches

URL checks reject localhost, private/link-local/multicast/reserved address families and risky IPv6 transition forms. DNS results are checked before use and redirects are revalidated. `safeFetch` strips sensitive credentials on cross-origin redirects and refuses silent request-body replay. These checks do **not** pin the validated DNS answer to the actual socket. High-risk workloads must also enforce egress firewall/proxy policy and protect cloud metadata endpoints at the network layer.

### Rate limiting

The fixed-window limiter is an abuse-control primitive, not authentication. The memory store is bounded and intended for one process. Distributed deployments require a shared store such as Redis. Redis integrity/availability failures are surfaced rather than treated as successful claims.

### Scanner and redaction

The repository scanner is intentionally conservative and can have false positives and false negatives. Findings contain rule/location/fingerprint data but not the matched credential value. Baselines suppress reviewed locations and must not be treated as proof that a credential is safe. Log redaction is defense in depth; applications should avoid collecting secrets in the first place.

## Abuse cases considered

- Alternate IPv4/IPv6 representations targeting loopback or private services.
- Redirect chains that move a request from a public endpoint to a private target.
- Cross-origin redirect credential forwarding.
- High-cardinality rate-limit or replay keys causing memory growth.
- Replayed GitHub/Stripe webhook deliveries.
- Malformed Redis script results or missing key expiry.
- Invalid schema defaults bypassing environment constraints.
- Secrets leaking into SARIF, workflow annotations or logs.
- Registry/network failures being mistaken for an unpublished package version.

## Non-goals

AxiomGuard does not claim to prevent compromise after arbitrary code execution, secure an untrusted Redis server, defeat all DNS rebinding at the application layer, validate business authorization, hash passwords, provide distributed bot mitigation, or prove an application is secure merely because the SDK is installed.
