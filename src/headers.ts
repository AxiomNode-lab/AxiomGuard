import { randomBytes } from 'node:crypto';

export type ContentSecurityPolicyValue = string | readonly string[] | false | undefined;
export type ContentSecurityPolicyDirectives = Record<string, ContentSecurityPolicyValue>;

function assertHeaderSafe(value: string): void {
  if (/[\r\n]/.test(value)) throw new TypeError('header values must not contain CR or LF characters');
}

function normalizeDirectiveValue(value: Exclude<ContentSecurityPolicyValue, false | undefined>): string {
  const values = typeof value === 'string' ? [value] : value;
  for (const item of values) if (/[;\r\n]/.test(item)) throw new TypeError('CSP directive values must not contain semicolons or newlines');
  return values.join(' ').trim();
}

export function createCspNonce(bytes = 18): string {
  if (!Number.isInteger(bytes) || bytes < 16 || bytes > 64) throw new RangeError('CSP nonce bytes must be 16-64');
  return randomBytes(bytes).toString('base64');
}

export function buildContentSecurityPolicy(directives: ContentSecurityPolicyDirectives): string {
  const parts: string[] = [];
  for (const [name, value] of Object.entries(directives).sort(([a], [b]) => a.localeCompare(b))) {
    if (value === false || value === undefined) continue;
    if (!/^[a-z][a-z0-9-]*$/i.test(name)) throw new TypeError(`invalid CSP directive name: ${name}`);
    const normalized = normalizeDirectiveValue(value);
    parts.push(normalized ? `${name} ${normalized}` : name);
  }
  return parts.join('; ');
}

export interface HstsOptions { maxAge?: number; includeSubDomains?: boolean; preload?: boolean; }
export interface SecurityHeadersOptions {
  contentSecurityPolicy?: ContentSecurityPolicyDirectives | string | false;
  contentSecurityPolicyReportOnly?: boolean;
  referrerPolicy?: string | false;
  frameOptions?: 'DENY' | 'SAMEORIGIN' | false;
  permissionsPolicy?: string | false;
  hsts?: HstsOptions | false;
  crossOriginOpenerPolicy?: 'same-origin' | 'same-origin-allow-popups' | 'unsafe-none' | false;
  crossOriginResourcePolicy?: 'same-origin' | 'same-site' | 'cross-origin' | false;
  crossOriginEmbedderPolicy?: 'require-corp' | 'credentialless' | 'unsafe-none' | false;
  originAgentCluster?: boolean;
  dnsPrefetchControl?: 'on' | 'off' | false;
}

export function createSecurityHeaders(options: SecurityHeadersOptions = {}): Record<string, string> {
  const headers: Record<string, string> = {
    'X-Content-Type-Options': 'nosniff',
    'X-Download-Options': 'noopen',
    'X-Permitted-Cross-Domain-Policies': 'none',
  };

  const referrer = options.referrerPolicy === undefined ? 'no-referrer' : options.referrerPolicy;
  if (referrer !== false) headers['Referrer-Policy'] = referrer;
  const frame = options.frameOptions === undefined ? 'DENY' : options.frameOptions;
  if (frame !== false) headers['X-Frame-Options'] = frame;
  const permissions = options.permissionsPolicy === undefined ? 'camera=(), microphone=(), geolocation=()' : options.permissionsPolicy;
  if (permissions !== false) headers['Permissions-Policy'] = permissions;

  const coop = options.crossOriginOpenerPolicy === undefined ? 'same-origin' : options.crossOriginOpenerPolicy;
  if (coop !== false) headers['Cross-Origin-Opener-Policy'] = coop;
  const corp = options.crossOriginResourcePolicy === undefined ? 'same-origin' : options.crossOriginResourcePolicy;
  if (corp !== false) headers['Cross-Origin-Resource-Policy'] = corp;
  const coep = options.crossOriginEmbedderPolicy;
  if (coep !== undefined && coep !== false) headers['Cross-Origin-Embedder-Policy'] = coep;
  if (options.originAgentCluster ?? true) headers['Origin-Agent-Cluster'] = '?1';
  const dns = options.dnsPrefetchControl === undefined ? 'off' : options.dnsPrefetchControl;
  if (dns !== false) headers['X-DNS-Prefetch-Control'] = dns;

  const csp = options.contentSecurityPolicy;
  if (csp !== false && csp !== undefined) {
    const name = options.contentSecurityPolicyReportOnly ? 'Content-Security-Policy-Report-Only' : 'Content-Security-Policy';
    headers[name] = typeof csp === 'string' ? csp : buildContentSecurityPolicy(csp);
  }

  if (options.hsts !== false && options.hsts !== undefined) {
    const maxAge = options.hsts.maxAge ?? 31_536_000;
    if (!Number.isInteger(maxAge) || maxAge < 0) throw new RangeError('HSTS maxAge must be a non-negative integer');
    let value = `max-age=${maxAge}`;
    if (options.hsts.includeSubDomains) value += '; includeSubDomains';
    if (options.hsts.preload) value += '; preload';
    headers['Strict-Transport-Security'] = value;
  }
  for (const value of Object.values(headers)) assertHeaderSafe(value);
  return headers;
}
