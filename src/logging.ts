const DEFAULT_SECRET_KEYS = [
  'password', 'password_hash', 'password_digest', 'passwd', 'pwd', 'secret', 'secret_key', 'secret_hash', 'token', 'access_token', 'refresh_token', 'id_token', 'jwt', 'api_key', 'apikey',
  'authorization', 'cookie', 'set_cookie', 'private_key', 'signing_key', 'encryption_key', 'client_secret', 'credentials', 'session_id',
  'otp', 'cvv', 'ssn', 'card_number',
];

const SECRET_PATTERNS: RegExp[] = [
  /\bgh[pousr]_[A-Za-z0-9_]{20,}\b/g,
  /\bgithub_pat_[A-Za-z0-9_]{20,}\b/g,
  /\bgl(?:pat|rt|dt|ptt|soat|oas)-[A-Za-z0-9_-]{20,}\b/g,
  /\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/g,
  /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b/g,
  /\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20}T3BlbkFJ[A-Za-z0-9_-]{20}\b|\bsk-proj-[A-Za-z0-9_-]{60,}\b/g,
  /\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{80,}\b/g,
  /\bAIza[0-9A-Za-z_-]{35}\b/g,
  /\bnpm_[A-Za-z0-9]{36}\b/g,
  /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g,
  /\bhf_[A-Za-z0-9]{34}\b/g,
  /\bxox(?:[bpasr]|e\.xox[bp])-[A-Za-z0-9-]{20,}\b/g,
  /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]{6,}\/B[A-Z0-9]{6,}\/[A-Za-z0-9]{20,}/g,
  /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
  /\bBearer\s+[A-Za-z0-9._~+/=-]{12,}\b/gi,
  /\bBasic\s+[A-Za-z0-9+/]{8,}={0,2}(?![A-Za-z0-9+/=])/g,
  /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?|mssql|clickhouse|https?|ftp):\/\/[^:/\s@]+:[^@/\s]+@/gi,
  /-----BEGIN(?: [A-Z0-9]+)* PRIVATE KEY(?: BLOCK)?-----[\s\S]*?-----END(?: [A-Z0-9]+)* PRIVATE KEY(?: BLOCK)?-----/g,
];

/** `accessToken`, `x-api-key`, `Set Cookie` and `access_token` all normalise to snake_case. */
function normalizeKey(key: string): string {
  return key.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase().replace(/[\s-]+/g, '_');
}

function isSecretKey(normalized: string, secretKeys: readonly string[]): boolean {
  return secretKeys.some((secretKey) => normalized === secretKey || normalized.endsWith(`_${secretKey}`));
}

function redactString(value: string, replacement: string): string {
  let output = value;
  for (const pattern of SECRET_PATTERNS) {
    pattern.lastIndex = 0;
    output = output.replace(pattern, (match) => {
      // Keep the auth scheme so logs still show *what* was redacted.
      const scheme = /^(Bearer|Basic)(\s+)/i.exec(match);
      return scheme ? `${scheme[1]}${scheme[2]}${replacement}` : replacement;
    });
  }
  return output;
}

function pathMatches(path: readonly string[], pattern: string): boolean {
  const expected = pattern.split('.').filter(Boolean);
  if (expected.length !== path.length) return false;
  return expected.every((segment, index) => segment === '*' || segment === path[index]);
}

function isArrayBufferView(value: object): value is ArrayBufferView {
  return ArrayBuffer.isView(value);
}

export interface RedactSecretsOptions {
  replacement?: string;
  /** Additional key names (any casing or separator style) to redact. */
  extraKeys?: readonly string[];
  /** Exact dot paths or single-segment wildcards, e.g. `req.headers.authorization` or `users.*.token`. */
  paths?: readonly string[];
  maxDepth?: number;
}

/**
 * Return a deep copy of `input` with secret-looking keys and values replaced.
 * Errors keep name/message/stack/cause, Dates and binary data are summarised
 * rather than dumped, Maps/Sets become plain objects/arrays, and circular
 * references are marked. The original value is never mutated.
 */
export function redactSecrets<T>(input: T, options: RedactSecretsOptions = {}): T {
  const replacement = options.replacement ?? '[REDACTED]';
  const secretKeys = [...DEFAULT_SECRET_KEYS, ...(options.extraKeys ?? []).map(normalizeKey)];
  const explicitPaths = options.paths ?? [];
  const maxDepth = options.maxDepth ?? 20;
  if (!Number.isInteger(maxDepth) || maxDepth < 0 || maxDepth > 100) throw new RangeError('maxDepth must be an integer between 0 and 100');
  const seen = new WeakMap<object, unknown>();

  const define = (target: Record<string, unknown>, key: string, value: unknown): void => {
    // defineProperty keeps a "__proto__" key as data instead of re-parenting the clone.
    Object.defineProperty(target, key, { value, enumerable: true, writable: true, configurable: true });
  };

  const visit = (value: unknown, depth: number, currentPath: string[]): unknown => {
    if (explicitPaths.some((pattern) => pathMatches(currentPath, pattern))) return replacement;
    if (typeof value === 'string') return redactString(value, replacement);
    if (value === null || typeof value !== 'object') return typeof value === 'bigint' ? value.toString() : value;
    if (depth > maxDepth) return '[MAX_DEPTH]';
    if (seen.has(value)) return '[CIRCULAR]';

    if (value instanceof Date) return Number.isNaN(value.getTime()) ? '[Invalid Date]' : value.toISOString();
    if (value instanceof RegExp) return String(value);
    if (value instanceof URL) {
      if (!value.password) return value.href;
      return value.href.replace(`:${value.password}@`, `:${replacement}@`);
    }
    if (isArrayBufferView(value) || value instanceof ArrayBuffer) return `[binary ${value.byteLength} bytes]`;

    if (Array.isArray(value)) {
      const clone: unknown[] = [];
      seen.set(value, clone);
      for (let index = 0; index < value.length; index += 1) clone.push(visit(value[index], depth + 1, [...currentPath, String(index)]));
      return clone;
    }

    if (value instanceof Map) {
      const entries = Object.fromEntries([...value.entries()].map(([key, entry]) => [String(key), entry]));
      seen.set(value, entries);
      return visit(entries, depth, currentPath);
    }
    if (value instanceof Set) {
      const items = [...value.values()];
      seen.set(value, items);
      return visit(items, depth, currentPath);
    }

    const clone: Record<string, unknown> = {};
    seen.set(value, clone);
    if (value instanceof Error) {
      define(clone, 'name', value.name);
      define(clone, 'message', redactString(value.message, replacement));
      if (typeof value.stack === 'string') define(clone, 'stack', redactString(value.stack, replacement));
      if ('cause' in value && value.cause !== undefined) define(clone, 'cause', visit(value.cause, depth + 1, [...currentPath, 'cause']));
    } else if (typeof (value as { toJSON?: unknown }).toJSON === 'function' && !(value instanceof Error)) {
      return visit((value as { toJSON(): unknown }).toJSON(), depth + 1, currentPath);
    }
    for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
      const nextPath = [...currentPath, key];
      define(clone, key, isSecretKey(normalizeKey(key), secretKeys) || explicitPaths.some((pattern) => pathMatches(nextPath, pattern))
        ? replacement
        : visit(child, depth + 1, nextPath));
    }
    return clone;
  };

  return visit(input, 0, []) as T;
}

export interface MaskPIIOptions { emails?: boolean; phones?: boolean; ipv4?: boolean; ipv6?: boolean; }

const PHONE = /(?<![\w.:/-])(?!(?:\d{1,3}\.){3}\d{1,3}(?![\w.:/-]))(\+?\(?\d{1,4}\)?[\s.-]?\(?\d{2,4}\)?[\s.-]?\d{3,4}(?:[\s.-]?\d{2,4}){0,2})(?![\w.:/-])/g;
const IPV6 = /(?<![\w:])(?:[0-9a-f]{1,4}:){2,7}(?::?[0-9a-f]{1,4}){1,6}(?![\w:])|(?<![\w:])::(?:[0-9a-f]{1,4}:){0,6}[0-9a-f]{1,4}(?![\w:])/gi;

/**
 * Best-effort masking of emails, phone numbers and IP addresses in free text.
 * Timestamps, UUIDs and other digit runs that do not look like phone numbers
 * are left intact.
 */
export function maskPII(value: string, options: MaskPIIOptions = {}): string {
  const emails = options.emails ?? true;
  const phones = options.phones ?? true;
  const ipv4 = options.ipv4 ?? true;
  const ipv6 = options.ipv6 ?? true;
  let output = value;
  if (emails) output = output.replace(/\b([A-Z0-9._%+-])[A-Z0-9._%+-]*@([A-Z0-9.-]+\.[A-Z]{2,})\b/gi, '$1***@$2');
  if (ipv4) output = output.replace(/\b(25[0-5]|2[0-4]\d|1?\d?\d)\.(25[0-5]|2[0-4]\d|1?\d?\d)\.(25[0-5]|2[0-4]\d|1?\d?\d)\.(25[0-5]|2[0-4]\d|1?\d?\d)\b/g, '$1.$2.*.*');
  if (ipv6) {
    output = output.replace(IPV6, (match) => {
      const groups = match.split(':');
      return groups.length < 3 ? match : `${groups.slice(0, 2).join(':')}:****`;
    });
  }
  if (phones) {
    output = output.replace(PHONE, (match) => {
      const digits = match.replace(/\D/g, '');
      if (digits.length < 8 || digits.length > 15) return match;
      if (!match.startsWith('+')) {
        // Without a country code, only national-length bare runs or 2-4 digit groupings look like phones;
        // dates (20260912), epochs and coordinates (48.856614) do not.
        if (/^\d+$/.test(match)) return digits.length === 10 || digits.length === 11 ? `${match.slice(0, 2)}***${match.slice(-2)}` : match;
        if (/\d{5,}/.test(match)) return match;
      }
      return `${match.slice(0, 2)}***${match.slice(-2)}`;
    });
  }
  return output;
}
