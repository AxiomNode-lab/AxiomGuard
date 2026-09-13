# AxiomGuard API reference

Every export is listed by module. The root package re-exports everything; the subpath is the recommended import in larger services. Types are exported alongside the functions that use them.

Conventions that hold across the whole SDK:

- **Operator errors throw, client input never does.** Invalid configuration (bad origins, short secrets, out-of-range TTLs) throws `TypeError`/`RangeError`, preferably at construction time. Malformed request data is reported as `false`, `null`, a reason string or a status.
- **Comparisons of secret-derived data are constant-time.**
- **Findings and logs never contain the secret value.**
- **Every `now` option is a millisecond timestamp** so you can inject your own clock (useful in test suites and replay tooling).

## `@axiomnode-lab/guard/crypto`

| Export | Purpose |
| --- | --- |
| `secureToken(bytes = 32)` | URL-safe random token (`base64url`). |
| `constantTimeCompare(left, right)` | Timing-safe equality for strings or Buffers of any length. |
| `verifyHmacWebhook(payload, signature, secret, options?)` | Generic HMAC verification. Options: `algorithm` (`sha256`/`sha512`), `prefix` (default `${algorithm}=`, `''` for bare digests), `encoding` (`hex`/`base64`), `requirePrefix`. Throws on an empty secret. |
| `signHmacWebhook(payload, secret, options?)` | Produce the signature `verifyHmacWebhook` accepts — for outbound webhooks you send, or for your own test suites. |
| `computeHmacSignature(payload, secret, options?)` | Same, returning `{ digest, signature }`. |
| `decodeDigest(text, encoding, expectedBytes)` | Strict hex/base64 decoder; `null` unless canonical and the right length. |

## `@axiomnode-lab/guard/webhooks`

| Export | Purpose |
| --- | --- |
| `verifyGitHubWebhook(payload, signature, secret)` | `X-Hub-Signature-256` (prefix required). |
| `verifyGitHubWebhookDelivery(payload, signature, secret, deliveryId, { replayStore, replayTtlSeconds?, now? })` | Signature plus `X-GitHub-Delivery` replay claim. Reasons: `invalid-signature`, `invalid-delivery`, `replay`. Redeliveries reuse the GUID and are reported as `replay` inside the TTL. |
| `verifyStripeWebhook(payload, header, secret, { toleranceSeconds?, now?, replayStore? })` | `Stripe-Signature`: literal `t=` text is signed, rotated `v1` entries accepted, `v0` ignored. Reasons: `invalid-signature`, `stale-timestamp`, `replay`. |
| `verifySlackWebhook(payload, signature, timestamp, signingSecret, options?)` | Slack v0 signing (`v0:timestamp:body`). Reasons add `invalid-timestamp`. |
| `verifyMetaWebhook(payload, signature, appSecret)` | Meta/WhatsApp `X-Hub-Signature-256`. |
| `verifyStandardWebhook(payload, { id, timestamp, signature }, secret, options?)` | [Standard Webhooks](https://www.standardwebhooks.com/) / Svix: signs `id.timestamp.payload`, `v1,<base64>` entries, `whsec_` secrets. Reasons add `invalid-id`; the id is the replay key. |
| `verifyFreshHmacWebhook({ payload, signature, secret, timestamp }, options?)` | Generic HMAC + separate timestamp header. `signedInput: 'payload'` (default) or `'timestamp.payload'`; `toleranceSeconds` (300); `replayStore`; `replayTtlSeconds` (defaults to the tolerance — raise it when the timestamp is not signed); `replayKey` override. Replay keys are derived from the canonical HMAC. |
| `createStripeSignatureHeader(payload, secret, timestamp)`, `createSlackSignature(payload, secret, timestamp)` | Build provider-format headers, for example to exercise your webhook endpoint locally. |
| `createWebhookReplayKey(signature)` | Hash an arbitrary string into a replay key. |
| `MemoryReplayStore(maxEntries = 10000)` | Bounded single-process `ReplayStore` (`claim(key, expiresAt, now?)`); fails closed at capacity; `size`, `clear()`. Use the Redis adapters across instances. |

## `@axiomnode-lab/guard/api-keys`

| Export | Purpose |
| --- | --- |
| `createApiKey({ prefix?, bytes?, idBytes? })` | `{ token, id, digest, fingerprint }`. Token layout `prefix_id_secret` with base62 `id`/`secret`. Store `id` + `digest`, show `token` once. |
| `parseApiKey(token)` | `{ prefix, id, secret }` or `null`; use `id` to look up the stored digest. |
| `hashApiKey(token, { pepper? })` | SHA-256 hex, or HMAC-SHA256 with a server-held pepper (≥ 16 chars). |
| `verifyApiKey(token, expectedDigest, { pepper? })` | Constant-time digest comparison; `false` for any malformed input. |
| `maskApiKey(token)` | `prefix_...last4`, or `[REDACTED]` for short values. |

## `@axiomnode-lab/guard/csrf`

| Export | Purpose |
| --- | --- |
| `createCsrfToken(secret, { sessionId, now?, nonceBytes?, allowUnbound? })` | Signed, expiring token `v1.ts.nonce.binding.sig`. `sessionId` (or `allowUnbound: true` for the signed double-submit cookie pattern) is required. |
| `verifyCsrfToken(token, secret, { sessionId, now?, maxAgeSeconds?, allowUnbound? })` | `false` for tampered/expired/foreign tokens; throws for operator errors (short secret, invalid `maxAgeSeconds`, missing binding). 60 s forward clock skew is tolerated. |

## `@axiomnode-lab/guard/request-policy`

| Export | Purpose |
| --- | --- |
| `createRequestPolicy(options)` | Validate once; returns `{ evaluate(input), assert(input) }`. Options: `allowedOrigins`, `safeMethods` (GET/HEAD/OPTIONS), `allowSameSite`, `allowNoOrigin`, `allowCrossSiteFromAllowedOrigins`. |
| `evaluateRequestPolicy(input, options?)` | One-shot evaluation. Input: `{ method, origin?, secFetchSite? }`. Returns `{ allowed, reason }` — see [API_PROTECTION.md](API_PROTECTION.md) for the decision matrix. |
| `assertRequestAllowed(input, options?)` | Throws `RequestPolicyError` (with `.reason`) when blocked. |

## `@axiomnode-lab/guard/idempotency`

| Export | Purpose |
| --- | --- |
| `createIdempotencyFingerprint({ method, target, body?, contentType? })` | SHA-256 over the exact request semantics (query order and content-type parameters included). |
| `claimIdempotencyKey(headerValue, fingerprint, { store, ttlMs?, now?, scope? })` | Accepts the raw header (string, array, undefined). Returns `accepted`, `replay`, `conflict`, `capacity`, `missing-key` or `invalid-key`. Always pass `scope` (user/tenant). |
| `normalizeIdempotencyKey(value)`, `createIdempotencyStoreKey(key, scope?)` | Header normalisation and the hashed store key. |
| `MemoryIdempotencyStore(maxEntries = 10000)` | Bounded single-process store; fails closed with `capacity`. |

## `@axiomnode-lab/guard/web` and `@axiomnode-lab/guard/fetch`

| Export | Purpose |
| --- | --- |
| `assertSafeUrl(input, options?)` | Sync checks: scheme, credentials, literal localhost/private addresses, `allowedHosts` (exact or `*.example.com`). Throws `SafeUrlError` with a `code`. |
| `assertSafeResolvedUrl(input, options?)` | `assertSafeUrl` plus DNS resolution of every address. |
| `isPrivateIPAddress(ip)` | Loopback, private, link-local, multicast, reserved, documentation, transition and NAT64 ranges (IPv4 and IPv6). |
| `normalizeHostname(hostname)` | Lower-case, strip brackets and trailing dots. |
| `validateRedirect(target, allowedOrigins, { base? })` | Open-redirect guard; resolves relative targets against `base`, rejects protocol-relative and backslash tricks. Redirect to the returned `href`. |
| `safeFetch(input, options?)` | Guarded `fetch`: `maxRedirects` (3), `timeoutMs` (10 s, covers the body), `maxResponseBytes`, `redirect: 'follow' \| 'manual'`, `allowInsecureRedirectDowngrade`, `stripSensitiveHeadersOnCrossOriginRedirect`, `dangerouslyAllowPrivateTargets`, `fetchImpl`, plus `SafeUrlOptions` and `RequestInit`. Throws `SafeFetchError` (`code`, `status`, `location`). |
| `SafeUrlError`, `SafeFetchError` | Typed errors with stable `code` values. |

## `@axiomnode-lab/guard/filesystem`

| Export | Purpose |
| --- | --- |
| `safePath(baseDirectory, candidate)` | Resolve inside a base directory or throw; rejects NUL bytes. Does not resolve symlinks. |
| `sanitizeFilename(input, { maxBytes?, allowLeadingDot?, fallback? })` | Single safe filename component; strips separators, control/format characters and Windows-reserved names; byte-bounded without splitting code points. |

## `@axiomnode-lab/guard/headers` and `/presets`

| Export | Purpose |
| --- | --- |
| `createSecurityHeaders(options?)` | `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, COOP/CORP/COEP, `Origin-Agent-Cluster`, `X-DNS-Prefetch-Control`, `X-XSS-Protection: 0`, optional CSP and HSTS. Values are validated against header injection. |
| `buildContentSecurityPolicy(directives)` | Deterministic CSP string; `true`/`''`/`[]` emit a valueless directive. |
| `createCspNonce(bytes = 18)`, `cspNonceSource(nonce)` | Per-response nonce and its `'nonce-…'` source expression. |
| `getSecurityHeaderPreset(name)`, `createPresetSecurityHeaders(name, overrides?)` | `api`, `web`, `isolated` presets. HSTS and cross-origin isolation are deployment commitments and stay opt-in. |

## `@axiomnode-lab/guard/cookies`

| Export | Purpose |
| --- | --- |
| `serializeCookie(name, value, options?)` | Secure defaults (`Secure`, `HttpOnly`, `SameSite=Lax`, `Path=/`), `__Host-`/`__Secure-` invariants, `Partitioned`, `Priority`, 4096-byte cap. Values are `encodeURIComponent`-encoded. |
| `parseCookies(header)` | Parse a `Cookie` header into a prototype-safe object, decoding values. |
| `clearCookie(name, options?)` | Deletion with matching attributes. |

## `@axiomnode-lab/guard/cors`

| Export | Purpose |
| --- | --- |
| `createCorsPolicy(options)` | Validate once; `evaluate(origin, requestContext?)` returns `{ allowed, preflight, headers }`. Options: `origins` (`'*'`, list or predicate), `allowCredentials`, `allowMethods`, `allowHeaders` (list or `'reflect'`), `exposeHeaders`, `maxAge`, `allowNullOrigin`, `allowPrivateNetwork`. `Vary` is always included for non-wildcard policies. |
| `createCorsHeaders(origin, options, requestContext?)` | Convenience wrapper; `null` when not allowed. |

## `@axiomnode-lab/guard/rate-limit`

| Export | Purpose |
| --- | --- |
| `checkRateLimit(key, { limit, windowMs, store, now? })` | Fixed-window check; `{ allowed, remaining, retryAfterSeconds, resetAt, … }`. |
| `createRateLimitHeaders(result, options?)` | IETF `RateLimit`/`RateLimit-Policy` (draft-11 shape), legacy `RateLimit-*` fields, `Retry-After`. |
| `getClientIp(remoteAddress, forwardedFor, { trustedProxyCount? })` | Spoof-resistant client IP; the header is ignored unless proxies are trusted. |
| `rateLimitBucketForIp(ip)` | IPv6 addresses bucketed by /64. |
| `MemoryRateLimitStore(maxEntries = 10000)` | Bounded single-process store; saturates unknown identities at capacity instead of evicting live ones. |

## `@axiomnode-lab/guard/env`

| Export | Purpose |
| --- | --- |
| `requireEnv(schema, source?)` | Typed, frozen values (`InferEnv<S>`); throws with every error listed. Types: `string`, `url`, `integer`, `number`, `boolean`, `email`, `port`, `json`, `list`, `duration`. Rules: `required`, `default`, `min`/`max`, `minLength`/`maxLength`, `pattern`, `allowed`, `allowCredentials`. |
| `validateEnv(schema, source?)` | `{ ok, errors, values }` without throwing. |

## `@axiomnode-lab/guard/logging`

| Export | Purpose |
| --- | --- |
| `redactSecrets(value, { replacement?, extraKeys?, paths?, maxDepth? })` | Deep, non-mutating redaction by key (any casing), by path (`users.*.token`) and by value pattern (provider keys, JWTs, `Bearer`/`Basic`, URL passwords, PEM). Preserves `Error`s, `Date`s, `Map`s, `Set`s; summarises binary data. |
| `maskPII(text, { emails?, phones?, ipv4?, ipv6? })` | Best-effort masking in free text; leaves timestamps, epochs and UUIDs intact. |

## `@axiomnode-lab/guard/scanner`

| Export | Purpose |
| --- | --- |
| `scanSecrets(target, { ignoreDirectories?, ignoreFiles?, maxFileBytes?, baselineFingerprints?, concurrency? })` | Scan a directory or file; findings are `{ file, line, rule, fingerprint }`. |
| `listSecretRules()` | Rule names, descriptions and severities. |
| `findingsToSarif(findings)` | SARIF 2.1.0 with `partialFingerprints`, rule metadata and severities. |
| `createSecretScanBaseline`, `parseSecretScanBaseline`, `parseSecretScannerConfig`, `createFindingFingerprint` | Baseline and config plumbing used by the CLI. |

## `@axiomnode-lab/guard/adapters/*`

| Export | Purpose |
| --- | --- |
| `createExpressSecurityMiddleware(options)` | Express/Connect middleware. |
| `createFastifySecurityHook(options)` | Fastify `onRequest` hook. |
| `createHonoSecurityMiddleware(options)` | Hono middleware (headers applied after `next`). |
| `createFetchSecurityHandler(options)`, `applySecurityHeaders(headers, request, options)` | Web-standard `Request`/`Response` runtimes. |
| `createSecurityCore(options)` | The shared pipeline (`evaluate(request)` → `preflight`/`blocked`/`continue`) for writing your own adapter. |
| `createNodeRedis*Store`, `createIORedis*Store` | Replay, rate-limit and idempotency stores on node-redis or ioredis, each one atomic Lua/`SET NX PX` operation. |

Adapter options: `headers` (object, `false`, or a per-request function), `cors`, `handlePreflight`, `preflightStatus`, `requestPolicy`, `requestPolicyStatus`, `removePoweredBy`. See [ADAPTERS.md](ADAPTERS.md).
