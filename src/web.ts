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
  const [a, b] = parts as [number, number, number, number];
  return (
    a === 0 ||
    a === 10 ||
    a === 127 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 198 && (b === 18 || b === 19)) ||
    a >= 224
  );
}

function isPrivateIPv6(ip: string): boolean {
  const normalized = ip.toLowerCase();
  if (normalized === '::' || normalized === '::1') return true;
  if (normalized.startsWith('fc') || normalized.startsWith('fd')) return true;
  if (/^fe[89ab]/.test(normalized)) return true;
  if (normalized.startsWith('ff')) return true;
  if (normalized.startsWith('2001:db8:')) return true;
  const mapped = normalized.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  return mapped ? isPrivateIPv4(mapped[1]!) : false;
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
    throw new Error('Private, loopback, link-local, multicast, or reserved IP addresses are blocked');
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
