# AxiomGuard threat model

## Purpose

AxiomGuard is a defensive Node.js/TypeScript SDK and repository scanner. It reduces common implementation mistakes around credentials, signed requests, browser-facing policy, duplicate API operations, outbound HTTP, rate limiting, configuration, logging and filesystem paths. It is not an authorization system, secrets manager, network firewall, malware scanner, WAF or complete SAST platform.

## Assets

- API keys, webhook secrets, CSRF secrets and session identifiers handled by applications using the SDK.
- Integrity of webhook processing and replay decisions.
- Integrity of idempotency claims used to prevent accidental duplicate operations.
- Availability of services protected by request policy, rate limits and bounded in-memory stores.
- Confidentiality of internal network endpoints reachable by applications performing outbound fetches.
- Confidentiality of secrets that may appear in logs, repositories or CI artifacts.
- Integrity of published npm, GitHub Packages and GHCR artifacts.

## Attacker capabilities

The model assumes an attacker may control request headers, origins, URLs, redirect targets, webhook payloads/signatures, idempotency keys, request bodies, rate-limit partition keys, filenames, selected environment/configuration inputs and repository text scanned by the CLI. The attacker may issue many requests and intentionally create high-cardinality input. The attacker does not automatically control the host process, Redis server, package registry account, CI identity, DNS resolver or application secrets.

## Trust boundaries

1. **Application input -> AxiomGuard primitives.** Inputs must be treated as untrusted even when a helper validates their syntax.
2. **Browser metadata -> request policy.** `Sec-Fetch-Site` is useful because browsers control the header, but applications/proxies can remove or alter headers before AxiomGuard sees them. Origin fallback remains part of the policy.
3. **AxiomGuard -> operating system / Node runtime.** Node crypto, DNS, URL parsing, Fetch and filesystem semantics are trusted dependencies.
4. **AxiomGuard -> Redis.** Redis-backed stores assume an authenticated, integrity-protected Redis deployment controlled by the application operator.
5. **DNS validation -> outbound connection.** `safeFetch` validates DNS before each request and redirect but the underlying Fetch implementation can resolve DNS again at connection time. This is an explicit TOCTOU boundary.
6. **Repository -> CI / scanner output.** Repository contents are attacker-influenced on pull requests. Scanner output must not echo matched secret material.
7. **CI -> package registries.** Release workflows use least-privilege GitHub permissions and npm Trusted Publishing where configured; registry/account policy remains an external trust boundary.

## Security properties and limitations

### API keys

Generated keys use cryptographic randomness. Verification compares SHA-256 digests with constant-time equality. The digest is suitable for high-entropy generated API keys, not human passwords. Applications that expect a database compromise and want an additional server-held secret can wrap storage with a separate pepper/HMAC strategy outside AxiomGuard.

### Webhooks

HMAC helpers verify signatures before accepting payloads. Stripe-style verification binds the timestamp into the signed input, verifies the signature before reporting freshness, and can claim a replay key. Slack verification similarly signs `v0:timestamp:raw-body`, checks the signature before freshness and can claim replay state. GitHub signatures do not contain a timestamp; `verifyGitHubWebhookDelivery` can replay-protect the provider's delivery ID when a shared store is supplied. Meta/WhatsApp signature verification checks `X-Hub-Signature-256` against the raw body but does not invent a universal Meta event identifier; application-specific event deduplication remains necessary. Multi-instance deployments must not rely on in-process replay stores.

### CSRF and browser request policy

CSRF tokens are signed, expiring and optionally session-bound. `evaluateRequestPolicy` can reject unsafe browser requests using Fetch Metadata and strict Origin fallback. It deliberately treats `same-site` as weaker than `same-origin` by default and rejects `Origin: null` for unsafe methods. Missing browser metadata is not automatically trusted; machine-to-machine callers require an explicit policy choice.

These controls do not replace authentication, application authorization, correct use of side-effect-free HTTP methods, or transaction-level anti-replay rules. CORS controls browser read access and does not authenticate a caller. HSTS and cross-origin isolation are deployment commitments and are therefore not silently enabled by generic presets.

### Idempotency

Idempotency helpers hash raw client keys before storage and fingerprint method, request target, normalized content type and raw body. A live key can be accepted once, recognized as a same-request replay, or rejected as conflicting reuse. The in-memory store is bounded and fails closed at capacity. Redis adapters use one atomic Lua operation with TTL.

The module does not store or replay an application response and does not make a database transaction atomic. APIs that promise deterministic replay must combine AxiomGuard's claim with durable result storage and business transaction semantics. An attacker who obtains a valid client idempotency key may still replay the same request unless authentication/authorization and application policy reject it.

### SSRF and outbound fetches

URL checks reject localhost, private/link-local/multicast/reserved address families and risky IPv6 transition forms. DNS results are checked before use and redirects are revalidated. `safeFetch` strips sensitive credentials on cross-origin redirects and refuses silent request-body replay. These checks do **not** pin the validated DNS answer to the actual socket. High-risk workloads must also enforce egress firewall/proxy policy and protect cloud metadata endpoints at the network layer.

### Rate limiting

The fixed-window limiter is an abuse-control primitive, not authentication. The memory store is bounded and intended for one process. Distributed deployments require a shared store such as Redis. Redis integrity/availability failures are surfaced rather than treated as successful claims.

### Scanner and redaction

The repository scanner is intentionally conservative and can have false positives and false negatives. Findings contain rule/location/fingerprint data but not the matched credential value. Baselines suppress reviewed locations and must not be treated as proof that a credential is safe. Log redaction is defense in depth; applications should avoid collecting secrets in the first place.

## Abuse cases considered

- Cross-site unsafe browser requests with forged ordinary headers or missing Fetch Metadata.
- `same-site` requests crossing a less-trusted sibling origin.
- Reuse of an idempotency key for a different request body or target.
- High-cardinality idempotency, rate-limit or replay keys causing memory pressure.
- Replayed GitHub/Stripe/Slack webhook deliveries.
- Invalid Meta/WhatsApp signatures or verification after JSON reserialization.
- Alternate IPv4/IPv6 representations targeting loopback or private services.
- Redirect chains that move a request from a public endpoint to a private target.
- Cross-origin redirect credential forwarding.
- Malformed Redis script results or missing key expiry.
- Invalid schema defaults bypassing environment constraints.
- Secrets leaking into SARIF, workflow annotations or logs.
- Registry/network failures being mistaken for an unpublished package version.

## Non-goals

AxiomGuard does not claim to prevent compromise after arbitrary code execution, secure an untrusted Redis server, defeat all DNS rebinding at the application layer, validate business authorization, hash passwords, provide durable idempotent result storage, provide distributed bot mitigation, or prove an application is secure merely because the SDK is installed.
