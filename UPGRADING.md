# Upgrading

## 0.8.0-beta.1 → 0.8.0-beta.2

### Added

The beta now includes a model-agnostic CI/AI integration surface:

- `@axiomnode-lab/guard/agent` exposes `scanForAgent()` and `createAgentSecurityReport()`.
- `axiomguard ci` emits a stable `ci-agent` JSON report.
- `--format agent` and `--agent-output` support CI orchestrators and AI coding agents without exposing matched values.
- The GitHub Action exposes an `agent-report` output alongside SARIF.
- The package can be installed with npm, pnpm, Yarn or Bun and run one-off with npx, `pnpm dlx`, `yarn dlx`, `bunx` or `npm exec`.

### Migration

No migration is required for existing scanner users. Existing `scan`, JSON, SARIF and GitHub Action behavior remains supported.

For AI-assisted CI/CD, prefer:

```bash
axiomguard ci . --no-fail --output axiomguard-agent.json
```

or the library API:

```ts
import { scanForAgent } from '@axiomnode-lab/guard/agent';

const report = await scanForAgent('.');
```

## 0.7.1 → 0.8.0-beta.1

### Breaking

The 0.8.0 beta is a prerelease. It raises the supported Node.js baseline from 20 to 22 because Node.js 20 is end-of-life. Node.js 22, 24 and 26 are qualified in CI.

The beta also includes the unreleased security and release-pipeline hardening prepared during the prior release-candidate cycle. No application migration is required for the normal security APIs beyond the stricter runtime validation already described below.

### Beta channel

The beta is intentionally separate from the stable channel. After publication, install it explicitly with `npm install @axiomnode-lab/guard@beta` or an exact prerelease version. Do not treat the beta channel as the stable `latest` channel.

AxiomGuard is pre-1.0: prereleases may change security defaults, APIs or supported runtimes before stable. Every such change is listed here with the migration.

## 0.7.0 → 0.7.1

### Changed

This patch release does not change the runtime API. It fixes the published package surface, documentation consistency and package-shape qualification. No application code changes are required.

## 0.6 → 0.7

### Breaking

**CSRF tokens must be bound.** `createCsrfToken(secret)` without `sessionId`
now throws. Bind the token to the session or user, or opt into the signed
double-submit cookie pattern explicitly:

```ts
createCsrfToken(secret, { sessionId: session.id });
verifyCsrfToken(token, secret, { sessionId: session.id });

// Double-submit cookie (token stored in a __Host- cookie and echoed in a header):
createCsrfToken(secret, { allowUnbound: true });
verifyCsrfToken(token, secret, { allowUnbound: true });
```

`verifyCsrfToken` also throws (instead of returning `false`) for operator
errors: a secret shorter than 16 characters, or `maxAgeSeconds` outside
`(0, 86400]`.

**Empty webhook secrets throw.** `verifyHmacWebhook`, `verifyStripeWebhook`,
`verifySlackWebhook` and friends throw `TypeError` when `secret` is empty
instead of silently rejecting every webhook. Check the environment variable
is set at startup (`requireEnv`) rather than catching this.

**`verifyGitHubWebhook` and `verifyMetaWebhook` require the `sha256=` prefix.**
A bare hex digest is no longer accepted for these provider helpers. The
generic `verifyHmacWebhook` still accepts either form unless
`requirePrefix: true` is set.

**`allowedHosts` matches exactly.** `assertSafeUrl`/`safeFetch` with
`allowedHosts: ['example.com']` no longer accepts `evil.example.com`. Use
`'*.example.com'` for subdomains (it does not match the apex).

**`safeFetch` rejects https→http redirects.** Set
`allowInsecureRedirectDowngrade: true` to restore the old behaviour. The
timeout and caller `signal` now also cancel a response body that is still
streaming, and `x-api-key`/`x-auth-token` are stripped on cross-origin
redirects.

**`sanitizeFilename` signature and defaults.** The second argument is an
options object (`{ maxBytes, allowLeadingDot, fallback }`); a number is still
accepted as `maxBytes`. Length is now measured in UTF-8 bytes, leading dots
become `_` unless `allowLeadingDot: true`, and DEL/C1/format characters are
stripped. Windows drive prefixes are removed (`C:\\a\\b.txt` → `b.txt`).

**`safePath` rejects NUL bytes** with an error instead of returning a path.

**CORS never throws on request input.** `createCorsHeaders('null', …)` and
malformed origins now return `null` (not allowed) instead of throwing; only
misconfiguration throws. Preflight-only headers (`Access-Control-Allow-Methods`,
`-Headers`, `-Max-Age`, `-Private-Network`) are emitted only on a real
preflight (`OPTIONS` with `Access-Control-Request-Method`); pass the request
context as the third argument or use `createCorsPolicy`. `allowNullOrigin`
combined with `allowCredentials` throws.

**Adapters only short-circuit real preflights.** An `OPTIONS` request without
`Access-Control-Request-Method` now reaches your handlers. Adapters remove
`X-Powered-By` (set `removePoweredBy: false` to keep it) and merge `Vary`.

**`claimIdempotencyKey` returns `'missing-key'`/`'invalid-key'`** instead of
throwing for a missing or malformed `Idempotency-Key` header. Map them to a
400 response. It also accepts the raw header value (string, array or
undefined).

**`createApiKey` tokens use a base62 alphabet** for `id` and `secret`. Tokens
issued by 0.6 remain verifiable (`verifyApiKey` hashes the whole token), but
`parseApiKey` only parses the new format. `maskApiKey` returns `[REDACTED]`
for values shorter than 12 characters.

**`requireEnv` is typed.** `env.PORT` is now `number`, not `unknown`. Existing
code that cast the result keeps working; code that relied on `unknown` may
need the casts removed. `'url'` values are returned as supplied (previously
normalised by `URL.toString()`) and URLs with embedded credentials are
rejected unless `allowCredentials: true`.

**Security headers add `X-XSS-Protection: 0`** (disable with
`xssProtection: false`). HSTS `preload: true` now requires
`includeSubDomains: true` and `maxAge >= 31536000`. The `web` and `isolated`
presets add `form-action 'self'`, `script-src-attr 'none'` and
`upgrade-insecure-requests` to their CSP.

**`serializeCookie` validates more.** `path` must start with `/`, `domain`
must be a hostname, and a serialized cookie over 4096 bytes throws.

**Scanner output streams.** The CLI writes the report to stdout in every
format (text used to go to stderr when findings existed) and workflow
annotations to stderr, as `::error` unless `--no-fail`. `--write-baseline`
resolves relative paths against the scan root, like `--baseline`. The
scanner now reads many more file types (`.pem`, `.key`, `id_rsa`,
`Dockerfile`, `.npmrc`, `.tf`, …), so expect new findings; review them and
regenerate baselines deliberately.

**`redactSecrets` changes shape for some values.** `Date` → ISO string,
`Buffer`/typed arrays → `[binary N bytes]`, `Map` → object, `Set` → array,
`Error` → `{ name, message, stack, cause, …ownProps }`, `bigint` → string.
`Bearer`/`Basic` credentials keep the scheme: `Bearer [REDACTED]`.

**`maskPII` phone heuristics changed**: bare digit runs are only masked at
national length (10–11 digits) and grouped numbers with a 5+ digit group are
left alone, so timestamps, epochs and UUIDs survive. IPv6 addresses are masked.

**Source maps are no longer shipped** in the package.

### Added

See [CHANGELOG.md](CHANGELOG.md#070) for the full list: Standard Webhooks
(Svix) verification, base64 signatures, `signHmacWebhook`, Stripe/Slack
signature builders, `parseApiKey`, peppered API-key hashes, idempotency
`scope`, `createRequestPolicy`, `allowCrossSiteFromAllowedOrigins`,
`createCorsPolicy`, `createFetchSecurityHandler`, per-request header
functions (CSP nonces), `getClientIp`, `parseCookies`/`clearCookie`, typed
`requireEnv` with `list`/`duration`, `validateRedirect` bases,
`maxResponseBytes`, `redirect: 'manual'`, `dangerouslyAllowPrivateTargets`,
20 new scanner rules and CLI flags.
