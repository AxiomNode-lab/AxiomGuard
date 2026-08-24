# Safe outbound fetches

`safeFetch()` is a defensive wrapper around the Node.js Fetch API for applications that accept a URL from an untrusted or semi-trusted source.

It is designed to reduce common SSRF mistakes without pretending that application-layer URL validation can replace network isolation.

## What it does

Before the first request, and before every redirect that it follows, AxiomGuard:

- allows only configured HTTP(S) protocols
- blocks URL credentials unless explicitly enabled
- blocks `localhost`
- blocks literal private, loopback, link-local, multicast and reserved IP ranges
- resolves hostnames and rejects blocked resolved addresses
- applies an optional hostname allowlist
- follows redirects manually and re-validates every redirect target
- strips `Authorization`, `Cookie`, and `Proxy-Authorization` on cross-origin redirects by default
- limits redirect depth
- applies one timeout across the whole redirect chain
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
