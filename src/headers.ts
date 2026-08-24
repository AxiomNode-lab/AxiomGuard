export type ContentSecurityPolicyValue = string | readonly string[] | false | undefined;
export type ContentSecurityPolicyDirectives = Record<string, ContentSecurityPolicyValue>;

function assertHeaderSafe(value: string): void {
  if (/[\r\n]/.test(value)) throw new TypeError('header values must not contain CR or LF characters');
}

function normalizeDirectiveValue(value: Exclude<ContentSecurityPolicyValue, false | undefined>): string {
  const values = typeof value === 'string' ? [value] : value;
  for (const item of values) {
    if (/[;\r\n]/.test(item)) throw new TypeError('CSP directive values must not contain semicolons or newlines');
  }
  return values.join(' ').trim();
}

export function buildContentSecurityPolicy(directives: ContentSecurityPolicyDirectives): string {
  const parts: string[] = [];
  for (const [name, value] of Object.entries(directives).sort(([left], [right]) => left.localeCompare(right))) {
    if (value === false || value === undefined) continue;
    if (!/^[a-z][a-z0-9-]*$/i.test(name)) throw new TypeError(`invalid CSP directive name: ${name}`);
    const normalized = normalizeDirectiveValue(value);
    parts.push(normalized ? `${name} ${normalized}` : name);
  }
  return parts.join('; ');
}

export interface HstsOptions {
  maxAge?: number;
  includeSubDomains?: boolean;
  preload?: boolean;
}

export interface SecurityHeadersOptions {
  contentSecurityPolicy?: ContentSecurityPolicyDirectives | string | false;
  referrerPolicy?: string;
  frameOptions?: 'DENY' | 'SAMEORIGIN' | false;
  permissionsPolicy?: string | false;
  hsts?: HstsOptions | false;
}

export function createSecurityHeaders(options: SecurityHeadersOptions = {}): Record<string, string> {
  const headers: Record<string, string> = {
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': options.referrerPolicy ?? 'no-referrer',
  };

  const frameOptions = options.frameOptions === undefined ? 'DENY' : options.frameOptions;
  if (frameOptions !== false) headers['X-Frame-Options'] = frameOptions;

  const permissions = options.permissionsPolicy === undefined
    ? 'camera=(), microphone=(), geolocation=()'
    : options.permissionsPolicy;
  if (permissions !== false) headers['Permissions-Policy'] = permissions;

  const csp = options.contentSecurityPolicy;
  if (csp !== false && csp !== undefined) {
    headers['Content-Security-Policy'] = typeof csp === 'string' ? csp : buildContentSecurityPolicy(csp);
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
