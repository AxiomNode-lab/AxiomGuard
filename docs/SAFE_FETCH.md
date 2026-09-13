# Safe outbound fetches

`safeFetch()` is a defensive wrapper around the Node.js Fetch API for applications that accept a URL from an untrusted or semi-trusted source.

It is designed to reduce common SSRF mistakes without pretending that application-layer URL validation can replace network isolation.

## What it does

Before the first request, and before every redirect that it follows, AxiomGuard:

- allows only configured HTTP(S) protocols
- blocks URL credentials unless explicitly enabled
- blocks `localhost` (including `localhost.` and `*.localhost`)
- blocks literal private, loopback, link-local, multicast, reserved, documentation, NAT64 and transition IP ranges (IPv4 and IPv6, including mapped/translated forms)
- resolves hostnames and rejects blocked resolved addresses
- applies an optional hostname allowlist (`api.example.com` exact, `*.example.com` for subdomains)
- follows redirects manually and re-validates every redirect target
- rejects https→http downgrades unless `allowInsecureRedirectDowngrade: true`
- strips `Authorization`, `Cookie`, `Proxy-Authorization`, `X-Api-Key` and `X-Auth-Token` on cross-origin redirects by default
- limits redirect depth
- applies one timeout across the whole redirect chain **and** the response body
- caps the response body with `maxResponseBytes` (aborts the stream instead of buffering)
- refuses user overrides for transport authority/framing headers such as `Host`, `Content-Length`, and `Transfer-Encoding`
- refuses to replay a request body across redirects that preserve the request method

## Example

```ts
import { safeFetch } from '@axiomnode-lab/guard/fetch';

const response = await safeFetch(userSuppliedUrl, {
  protocols: ['https:'],
  allowedHosts: ['api.example.com'],
  maxRedirects: 2,
  timeoutMs: 5_000,
  headers: {
    accept: 'application/json',
  },
});

if (!response.ok) {
  throw new Error(`upstream returned ${response.status}`);
}
```

## Errors

Policy decisions throw `SafeUrlError` (URL/DNS checks) or `SafeFetchError` (redirect, timeout, size and header decisions). Both carry a stable `code` — for example `private-address`, `host-not-allowed`, `timeout`, `too-many-redirects`, `insecure-downgrade`, `body-replay`, `response-too-large` — and `SafeFetchError` includes the redirect `status` and validated `location` when relevant, so you can branch without matching messages.

## Manual redirects

`redirect: 'manual'` validates the first redirect target and returns the 3xx response untouched so the caller decides (the right approach for redirected writes). `maxRedirects: 0` in the default `follow` mode throws `too-many-redirects` instead.

## Local development

Every private-address check applies to `127.0.0.1`, so a local service cannot be fetched through `safeFetch` by default. Set `dangerouslyAllowPrivateTargets: true` in development and tests only; never for URLs a user can influence.

## Redirect credentials

Cross-origin redirects remove sensitive credential headers by default. This avoids accidentally forwarding an API credential to a different origin after a redirect.

If you deliberately disable this behavior, the caller owns that risk:

```ts
await safeFetch(url, {
  stripSensitiveHeadersOnCrossOriginRedirect: false,
});
```

Prefer a strict `allowedHosts` list instead of disabling credential stripping.

## Request bodies

AxiomGuard does not automatically replay a body when a redirect requires preserving the method and body. Streams and other bodies may be one-shot, and silently replaying authenticated writes can be unsafe.

For redirected writes, handle the redirect explicitly after validating the target and deciding whether repeating the operation is safe.

## Important boundary: DNS rebinding / TOCTOU

`safeFetch()` validates DNS resolution before each request, but the Node.js fetch transport performs its own connection-time resolution. The library cannot guarantee that the address validated by AxiomGuard is the exact address used by the connection.

For high-risk URL fetchers, combine application checks with infrastructure controls such as:

- outbound firewall/egress allowlists
- cloud metadata endpoint protection
- network namespaces or dedicated fetch services
- private-address routing restrictions
- proxy policy that validates the actual destination

Treat `safeFetch()` as one layer, not as a complete SSRF boundary.
