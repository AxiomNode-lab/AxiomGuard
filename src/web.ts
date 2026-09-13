import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';

export type SafeUrlErrorCode =
  | 'blocked-protocol'
  | 'credentials'
  | 'localhost'
  | 'private-address'
  | 'host-not-allowed'
  | 'unresolved-host'
  | 'resolved-private-address'
  | 'redirect-origin'
  | 'redirect-protocol'
  | 'redirect-credentials'
  | 'redirect-path';

/** Error thrown by the URL guards. `code` is stable; messages may change. */
export class SafeUrlError extends Error {
  readonly code: SafeUrlErrorCode;

  constructor(code: SafeUrlErrorCode, message: string) {
    super(message);
    this.name = 'SafeUrlError';
    this.code = code;
  }
}

export interface SafeUrlOptions {
  /** Accepted URL schemes. Default: https and http. */
  protocols?: readonly ('http:' | 'https:')[];
  /**
   * Hostname allowlist. Entries match exactly; `*.example.com` matches any
   * subdomain (but not `example.com` itself). Trailing dots are ignored.
   */
  allowedHosts?: readonly string[];
  /** Accept `user:pass@host` URLs. Default: false. */
  allowCredentials?: boolean;
  /**
   * Skip the localhost/private/reserved address checks. For local development
   * and tests only; never enable this for URLs influenced by users.
   */
  dangerouslyAllowPrivateTargets?: boolean;
}

function isPrivateIPv4(ip: string): boolean {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some((part) => part < 0 || part > 255 || !Number.isInteger(part))) return true;
  const [a, b, c] = parts as [number, number, number, number];
  return (
    a === 0 ||
    a === 10 ||
    a === 127 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 0 && c === 0) ||
    (a === 192 && b === 0 && c === 2) ||
    (a === 192 && b === 88 && c === 99) ||
    (a === 192 && b === 168) ||
    (a === 198 && (b === 18 || b === 19)) ||
    (a === 198 && b === 51 && c === 100) ||
    (a === 203 && b === 0 && c === 113) ||
    a >= 224
  );
}

function parseIpv6Words(ip: string): number[] | null {
  const normalized = ip.toLowerCase().split('%', 1)[0]!;
  const pieces = normalized.split('::');
  if (pieces.length > 2) return null;

  const parseSide = (side: string): number[] | null => {
    if (!side) return [];
    const tokens = side.split(':');
    const words: number[] = [];
    for (let index = 0; index < tokens.length; index += 1) {
      const token = tokens[index]!;
      if (token.includes('.')) {
        if (index !== tokens.length - 1 || isIP(token) !== 4) return null;
        const bytes = token.split('.').map(Number);
        words.push((bytes[0]! << 8) | bytes[1]!, (bytes[2]! << 8) | bytes[3]!);
        continue;
      }
      if (!/^[0-9a-f]{1,4}$/.test(token)) return null;
      words.push(Number.parseInt(token, 16));
    }
    return words;
  };

  const left = parseSide(pieces[0]!);
  const right = parseSide(pieces[1] ?? '');
  if (!left || !right) return null;
  const missing = 8 - left.length - right.length;
  if (pieces.length === 1) return missing === 0 ? left : null;
  if (missing < 1) return null;
  return [...left, ...Array.from({ length: missing }, () => 0), ...right];
}

function embeddedIPv4(words: readonly number[]): string {
  return `${words[6]! >> 8}.${words[6]! & 0xff}.${words[7]! >> 8}.${words[7]! & 0xff}`;
}

function isPrivateIPv6(ip: string): boolean {
  const words = parseIpv6Words(ip);
  if (words?.length !== 8) return true;

  const allZero = words.every((word) => word === 0);
  const loopback = words.slice(0, 7).every((word) => word === 0) && words[7] === 1;
  if (allZero || loopback) return true;

  // IPv4-mapped IPv6 (::ffff:a.b.c.d or ::ffff:7f00:1).
  if (words.slice(0, 5).every((word) => word === 0) && words[5] === 0xffff) return isPrivateIPv4(embeddedIPv4(words));
  // IPv4-translated (::ffff:0:a.b.c.d, RFC 2765) carries an IPv4 destination too.
  if (words.slice(0, 4).every((word) => word === 0) && words[4] === 0xffff && words[5] === 0) return isPrivateIPv4(embeddedIPv4(words));

  // Deprecated IPv4-compatible IPv6. Block conservatively rather than let an
  // alternate representation bypass IPv4 policy.
  if (words.slice(0, 6).every((word) => word === 0)) return true;

  const first = words[0]!;
  const second = words[1]!;
  if ((first & 0xfe00) === 0xfc00) return true; // fc00::/7 unique-local
  if ((first & 0xffc0) === 0xfe80) return true; // fe80::/10 link-local
  if ((first & 0xffc0) === 0xfec0) return true; // fec0::/10 deprecated site-local
  if ((first & 0xff00) === 0xff00) return true; // ff00::/8 multicast
  if (first === 0x0100 && words.slice(1, 4).every((word) => word === 0)) return true; // 100::/64 discard-only
  if (first === 0x2001 && second === 0x0db8) return true; // 2001:db8::/32 documentation
  if (first === 0x2001 && second === 0x0002 && words[2] === 0) return true; // 2001:2::/48 benchmarking
  if ((first & 0xfff0) === 0x3ff0) return true; // 3fff::/20 documentation (RFC 9637)

  // Transition/tunneling prefixes can encode an IPv4 destination or relay and
  // undermine an IPv4-only SSRF policy. Treat them as unsafe by default.
  if (first === 0x2002) return true; // 6to4
  if (first === 0x2001 && second === 0x0000) return true; // Teredo
  if (first === 0x0064 && second === 0xff9b && words[2] === 0 && words.slice(3, 6).every((word) => word === 0)) return true; // NAT64 well-known prefix
  if (first === 0x0064 && second === 0xff9b && words[2] === 1) return true; // 64:ff9b:1::/48 local-use NAT64 (RFC 8215)

  return false;
}

/** True for loopback, private, link-local, multicast, reserved, documentation and transition addresses, and for anything unparsable. */
export function isPrivateIPAddress(ip: string): boolean {
  const family = isIP(ip);
  if (family === 4) return isPrivateIPv4(ip);
  if (family === 6) return isPrivateIPv6(ip);
  return true;
}

/** Lower-case a hostname, strip IPv6 brackets and any trailing dots. */
export function normalizeHostname(hostname: string): string {
  return hostname.replace(/^\[|\]$/g, '').replace(/\.+$/, '').toLowerCase();
}

function hostMatches(hostname: string, allowedHosts: readonly string[]): boolean {
  return allowedHosts.some((allowed) => {
    const candidate = normalizeHostname(allowed);
    if (candidate.startsWith('*.')) {
      const suffix = candidate.slice(1);
      return hostname.length > suffix.length && hostname.endsWith(suffix);
    }
    return hostname === candidate;
  });
}

/**
 * Parse and validate an outbound URL without touching the network: scheme,
 * credentials, literal localhost/private addresses and the host allowlist.
 * Hostnames are not resolved; use `assertSafeResolvedUrl` for that.
 */
export function assertSafeUrl(input: string | URL, options: SafeUrlOptions = {}): URL {
  const url = input instanceof URL ? new URL(input.toString()) : new URL(input);
  const protocols = options.protocols ?? ['https:', 'http:'];

  if (!protocols.includes(url.protocol as 'http:' | 'https:')) {
    throw new SafeUrlError('blocked-protocol', `Blocked URL protocol: ${url.protocol}`);
  }
  if (!options.allowCredentials && (url.username || url.password)) {
    throw new SafeUrlError('credentials', 'URLs containing credentials are blocked');
  }

  const hostname = normalizeHostname(url.hostname);
  if (!options.dangerouslyAllowPrivateTargets) {
    if (hostname === 'localhost' || hostname.endsWith('.localhost')) {
      throw new SafeUrlError('localhost', 'Localhost URLs are blocked');
    }
    if (isIP(hostname) && isPrivateIPAddress(hostname)) {
      throw new SafeUrlError('private-address', 'Private, loopback, link-local, multicast, transition, or reserved IP addresses are blocked');
    }
  }
  if (options.allowedHosts && !hostMatches(hostname, options.allowedHosts)) {
    throw new SafeUrlError('host-not-allowed', 'URL host is not in the allowlist');
  }

  return url;
}

/**
 * `assertSafeUrl` plus DNS resolution: every address the hostname resolves to
 * must pass the private-address policy. DNS can change between this check and
 * the connection; see docs/SAFE_FETCH.md.
 */
export async function assertSafeResolvedUrl(input: string | URL, options: SafeUrlOptions = {}): Promise<URL> {
  const url = assertSafeUrl(input, options);
  const hostname = normalizeHostname(url.hostname);
  if (isIP(hostname) || options.dangerouslyAllowPrivateTargets) return url;

  const addresses = await lookup(hostname, { all: true, order: 'verbatim' });
  if (addresses.length === 0) throw new SafeUrlError('unresolved-host', 'URL host did not resolve');
  for (const address of addresses) {
    if (isPrivateIPAddress(address.address)) {
      throw new SafeUrlError('resolved-private-address', `URL resolved to a blocked address (${address.family === 6 ? 'IPv6' : 'IPv4'})`);
    }
  }
  return url;
}

export interface ValidateRedirectOptions {
  /** Base used to resolve relative targets such as `/dashboard`. */
  base?: string | URL;
}

/**
 * Validate a post-login/return-to redirect target against an origin allowlist.
 * Relative targets are resolved against `base`; protocol-relative and
 * backslash-prefixed paths are rejected. Always redirect to the returned
 * `URL.href`, never to the raw input.
 */
export function validateRedirect(target: string | URL, allowedOrigins: readonly string[], options: ValidateRedirectOptions = {}): URL {
  const allowed = new Set(allowedOrigins.map((origin) => {
    let parsed: URL;
    try { parsed = new URL(origin); } catch { throw new TypeError(`Invalid allowed origin: ${origin}`); }
    if (!['http:', 'https:'].includes(parsed.protocol) || parsed.pathname !== '/' || parsed.search || parsed.hash) throw new TypeError(`Invalid allowed origin: ${origin}`);
    return parsed.origin;
  }));

  if (typeof target === 'string') {
    if (/[\u0000-\u001f\u007f]/.test(target)) throw new SafeUrlError('redirect-path', 'Redirect target contains control characters');
    const trimmed = target.trimStart();
    if (trimmed.startsWith('//') || trimmed.startsWith('/\\') || trimmed.startsWith('\\')) {
      throw new SafeUrlError('redirect-path', 'Protocol-relative redirect targets are blocked');
    }
  }

  let url: URL;
  try {
    url = target instanceof URL ? new URL(target.toString()) : new URL(target, options.base);
  } catch {
    throw new SafeUrlError('redirect-path', 'Redirect target is not a valid URL');
  }
  if (!['http:', 'https:'].includes(url.protocol)) throw new SafeUrlError('redirect-protocol', 'Redirect protocol is not allowed');
  if (!allowed.has(url.origin)) throw new SafeUrlError('redirect-origin', 'Redirect origin is not allowed');
  if (url.username || url.password) throw new SafeUrlError('redirect-credentials', 'Redirect URLs containing credentials are blocked');
  if (url.pathname.startsWith('//') || url.pathname.startsWith('/\\')) throw new SafeUrlError('redirect-path', 'Redirect path must not be protocol-relative');
  return url;
}
