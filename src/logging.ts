const DEFAULT_SECRET_KEYS = [
  'password',
  'passwd',
  'secret',
  'token',
  'api_key',
  'apikey',
  'authorization',
  'cookie',
  'set-cookie',
  'private_key',
  'client_secret',
];

const SECRET_PATTERNS: RegExp[] = [
  /\bgh[pousr]_[A-Za-z0-9_]{20,}\b/g,
  /\bgithub_pat_[A-Za-z0-9_]{20,}\b/g,
  /\bAKIA[0-9A-Z]{16}\b/g,
  /\bBearer\s+[A-Za-z0-9._~+/=-]{12,}\b/gi,
  /-----BEGIN(?: [A-Z]+)? PRIVATE KEY-----[\s\S]*?-----END(?: [A-Z]+)? PRIVATE KEY-----/g,
];

function isSecretKey(key: string, extraKeys: readonly string[]): boolean {
  const normalized = key.toLowerCase().replace(/[\s-]/g, '_');
  return [...DEFAULT_SECRET_KEYS, ...extraKeys.map((item) => item.toLowerCase())]
    .some((secretKey) => normalized === secretKey || normalized.endsWith(`_${secretKey}`));
}

function redactString(value: string, replacement: string): string {
  let output = value;
  for (const pattern of SECRET_PATTERNS) {
    output = output.replace(pattern, replacement);
  }
  return output;
}

export interface RedactSecretsOptions {
  replacement?: string;
  extraKeys?: readonly string[];
  maxDepth?: number;
}

export function redactSecrets<T>(input: T, options: RedactSecretsOptions = {}): T {
  const replacement = options.replacement ?? '[REDACTED]';
  const extraKeys = options.extraKeys ?? [];
  const maxDepth = options.maxDepth ?? 20;
  const seen = new WeakMap<object, unknown>();

  const visit = (value: unknown, depth: number): unknown => {
    if (typeof value === 'string') return redactString(value, replacement);
    if (value === null || typeof value !== 'object') return value;
    if (depth > maxDepth) return '[MAX_DEPTH]';
    if (seen.has(value)) return '[CIRCULAR]';

    if (Array.isArray(value)) {
      const clone: unknown[] = [];
      seen.set(value, clone);
      for (const item of value) clone.push(visit(item, depth + 1));
      return clone;
    }

    const clone: Record<string, unknown> = {};
    seen.set(value, clone);
    for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
      clone[key] = isSecretKey(key, extraKeys) ? replacement : visit(child, depth + 1);
    }
    return clone;
  };

  return visit(input, 0) as T;
}

export interface MaskPIIOptions {
  emails?: boolean;
  phones?: boolean;
  ipv4?: boolean;
}

export function maskPII(value: string, options: MaskPIIOptions = {}): string {
  const emails = options.emails ?? true;
  const phones = options.phones ?? true;
  const ipv4 = options.ipv4 ?? true;
  let output = value;

  if (emails) {
    output = output.replace(/\b([A-Z0-9._%+-])[A-Z0-9._%+-]*@([A-Z0-9.-]+\.[A-Z]{2,})\b/gi, '$1***@$2');
  }
  if (ipv4) {
    output = output.replace(/\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b/g, '$1.$2.*.*');
  }
  if (phones) {
    output = output.replace(/(?<!\d)(\+?\d[\d\s().-]{6,}\d)(?!\d)/g, (match) => {
      const digits = match.replace(/\D/g, '');
      if (digits.length < 8 || digits.length > 15) return match;
      return `${match.slice(0, 2)}***${match.slice(-2)}`;
    });
  }

  return output;
}
