import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';

export interface SafeUrlOptions {
  protocols?: readonly ('http:' | 'https:')[];
  allowedHosts?: readonly string[];
  allowCredentials?: boolean;
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

function isPrivateIPv6(ip: string): boolean {
  const words = parseIpv6Words(ip);
  if (!words || words.length !== 8) return true;

  const allZero = words.every((word) => word === 0);
  const loopback = words.slice(0, 7).every((word) => word === 0) && words[7] === 1;
  if (allZero || loopback) return true;

  // IPv4-mapped IPv6 (::ffff:a.b.c.d or ::ffff:7f00:1).
  if (words.slice(0, 5).every((word) => word === 0) && words[5] === 0xffff) {
    const mapped = `${words[6]! >> 8}.${words[6]! & 0xff}.${words[7]! >> 8}.${words[7]! & 0xff}`;
    return isPrivateIPv4(mapped);
  }

  // Deprecated IPv4-compatible IPv6. Block conservatively rather than let an
  // alternate representation bypass IPv4 policy.
  if (words.slice(0, 6).every((word) => word === 0)) return true;

  const first = words[0]!;
  if ((first & 0xfe00) === 0xfc00) return true; // fc00::/7 unique-local
  if ((first & 0xffc0) === 0xfe80) return true; // fe80::/10 link-local
  if ((first & 0xffc0) === 0xfec0) return true; // fec0::/10 deprecated site-local
  if ((first & 0xff00) === 0xff00) return true; // ff00::/8 multicast
  if (first === 0x2001 && words[1] === 0x0db8) return true; // documentation

  // Transition/tunneling prefixes can encode an IPv4 destination or relay and
  // undermine an IPv4-only SSRF policy. Treat them as unsafe by default.
  if (first === 0x2002) return true; // 6to4
  if (first === 0x2001 && words[1] === 0x0000) return true; // Teredo
  if (first === 0x0064 && words[1] === 0xff9b && words.slice(2, 6).every((word) => word === 0)) return true; // NAT64 WKP

  return false;
}

export function isPrivateIPAddress(ip: string): boolean {
  const family = isIP(ip);
  if (family === 4) return isPrivateIPv4(ip);
  if (family === 6) return isPrivateIPv6(ip);
  return true;
}

function hostMatches(hostname: string, allowedHosts: readonly string[]): boolean {
  const normalized = hostname.toLowerCase();
  return allowedHosts.some((allowed) => {
    const candidate = allowed.toLowerCase();
    return normalized === candidate || normalized.endsWith(`.${candidate}`);
  });
}

export function assertSafeUrl(input: string | URL, options: SafeUrlOptions = {}): URL {
  const url = input instanceof URL ? new URL(input.toString()) : new URL(input);
  const protocols = options.protocols ?? ['https:', 'http:'];

  if (!protocols.includes(url.protocol as 'http:' | 'https:')) {
    throw new Error(`Blocked URL protocol: ${url.protocol}`);
  }
  if (!options.allowCredentials && (url.username || url.password)) {
    throw new Error('URLs containing credentials are blocked');
  }

  const hostname = url.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (hostname === 'localhost' || hostname.endsWith('.localhost')) {
    throw new Error('Localhost URLs are blocked');
  }
  if (isIP(hostname) && isPrivateIPAddress(hostname)) {
    throw new Error('Private, loopback, link-local, multicast, transition, or reserved IP addresses are blocked');
  }
  if (options.allowedHosts && !hostMatches(hostname, options.allowedHosts)) {
    throw new Error('URL host is not in the allowlist');
  }

  return url;
}

export async function assertSafeResolvedUrl(input: string | URL, options: SafeUrlOptions = {}): Promise<URL> {
  const url = assertSafeUrl(input, options);
  const hostname = url.hostname.replace(/^\[|\]$/g, '');
  if (isIP(hostname)) return url;

  const addresses = await lookup(hostname, { all: true, verbatim: true });
  if (addresses.length === 0) throw new Error('URL host did not resolve');
  for (const address of addresses) {
    if (isPrivateIPAddress(address.address)) {
      throw new Error(`URL resolved to a blocked address (${address.family === 6 ? 'IPv6' : 'IPv4'})`);
    }
  }
  return url;
}

export function validateRedirect(target: string | URL, allowedOrigins: readonly string[]): URL {
  const url = target instanceof URL ? new URL(target.toString()) : new URL(target);
  const allowed = new Set(allowedOrigins.map((origin) => new URL(origin).origin));
  if (!allowed.has(url.origin)) throw new Error('Redirect origin is not allowed');
  if (!['http:', 'https:'].includes(url.protocol)) throw new Error('Redirect protocol is not allowed');
  if (url.username || url.password) throw new Error('Redirect URLs containing credentials are blocked');
  return url;
}
