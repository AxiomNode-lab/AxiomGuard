export type EnvType = 'string' | 'url' | 'integer' | 'number' | 'boolean' | 'email' | 'port' | 'json' | 'list' | 'duration';

export interface EnvRule {
  type?: EnvType;
  /** Default: true. Optional variables without a default resolve to `undefined`. */
  required?: boolean;
  default?: string | number | boolean | readonly string[] | unknown;
  minLength?: number;
  maxLength?: number;
  min?: number;
  max?: number;
  pattern?: RegExp;
  allowed?: readonly (string | number | boolean)[];
  /** `url` only: accept `user:pass@host` URLs. Default: false. */
  allowCredentials?: boolean;
}

export type EnvSchema = Record<string, EnvType | EnvRule>;

type EnvTypeOf<R> = R extends EnvType ? R : R extends { type: infer T extends EnvType } ? T : 'string';
type EnvValueOf<T extends EnvType> =
  T extends 'port' | 'integer' | 'number' | 'duration' ? number
    : T extends 'boolean' ? boolean
      : T extends 'json' ? unknown
        : T extends 'list' ? string[]
          : string;
type IsOptional<R> = R extends { required: false } ? (R extends { default: unknown } ? false : true) : false;

/** The value object `requireEnv` returns for a schema, with per-variable types. */
export type InferEnv<S extends EnvSchema> = {
  readonly [K in keyof S]: IsOptional<S[K]> extends true ? EnvValueOf<EnvTypeOf<S[K]>> | undefined : EnvValueOf<EnvTypeOf<S[K]>>;
};

export interface EnvValidationResult<S extends EnvSchema = EnvSchema> {
  ok: boolean;
  errors: string[];
  values: Partial<InferEnv<S>>;
}

const DURATION = /^(\d+(?:\.\d+)?)\s*(ms|s|m|h|d)?$/i;
const DURATION_MS: Record<string, number> = { ms: 1, s: 1_000, m: 60_000, h: 3_600_000, d: 86_400_000 };

function normalizeRule(rule: EnvType | EnvRule): EnvRule { return typeof rule === 'string' ? { type: rule } : rule; }
function parseBoolean(value: string): boolean | undefined { if (/^(true|1|yes|on)$/i.test(value)) return true; if (/^(false|0|no|off)$/i.test(value)) return false; return undefined; }

function parseValue(name: string, input: unknown, rule: EnvRule, errors: string[], fromDefault: boolean): unknown {
  const type = rule.type ?? 'string';
  if (fromDefault) {
    if (type === 'json' && typeof input !== 'string') return input;
    if (type === 'boolean' && typeof input === 'boolean') return input;
    if (type === 'list' && Array.isArray(input)) {
      if (input.some((item) => typeof item !== 'string')) { errors.push(`${name} default must be a list of strings`); return undefined; }
      return [...input];
    }
    if ((type === 'integer' || type === 'number' || type === 'port' || type === 'duration') && typeof input === 'number') {
      if (!Number.isFinite(input)) { errors.push(`${name} default must be finite`); return undefined; }
      if ((type === 'integer' || type === 'duration') && !Number.isSafeInteger(input)) { errors.push(`${name} default must be a safe integer`); return undefined; }
      if (type === 'port' && (!Number.isInteger(input) || input < 1 || input > 65535)) { errors.push(`${name} default must be a TCP port between 1 and 65535`); return undefined; }
      return input;
    }
  }
  if (typeof input !== 'string') {
    errors.push(`${name}${fromDefault ? ' default' : ''} must be a string for type ${type}`);
    return undefined;
  }

  const raw = input;
  switch (type) {
    case 'string': return raw;
    case 'url': {
      let url: URL;
      try { url = new URL(raw); } catch { errors.push(`${name} must be a valid HTTP(S) URL`); return undefined; }
      if (!['http:', 'https:'].includes(url.protocol)) { errors.push(`${name} must be a valid HTTP(S) URL`); return undefined; }
      if (!rule.allowCredentials && (url.username || url.password)) { errors.push(`${name} must not embed credentials`); return undefined; }
      return raw;
    }
    case 'integer': if (!/^-?\d+$/.test(raw) || !Number.isSafeInteger(Number(raw))) { errors.push(`${name} must be a safe integer`); return undefined; } return Number(raw);
    case 'number': { const parsed = Number(raw); if (raw.trim() === '' || !Number.isFinite(parsed)) { errors.push(`${name} must be a finite number`); return undefined; } return parsed; }
    case 'boolean': { const parsed = parseBoolean(raw); if (parsed === undefined) { errors.push(`${name} must be a boolean`); return undefined; } return parsed; }
    case 'email': if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(raw) || raw.length > 254) { errors.push(`${name} must be an email address`); return undefined; } return raw;
    case 'port': if (!/^\d+$/.test(raw) || Number(raw) < 1 || Number(raw) > 65535) { errors.push(`${name} must be a TCP port between 1 and 65535`); return undefined; } return Number(raw);
    case 'json': try { return JSON.parse(raw); } catch { errors.push(`${name} must be valid JSON`); return undefined; }
    case 'list': return raw.split(',').map((item) => item.trim()).filter((item) => item.length > 0);
    case 'duration': {
      const match = DURATION.exec(raw.trim());
      if (!match) { errors.push(`${name} must be a duration such as 500ms, 30s, 5m, 2h or 1d`); return undefined; }
      const value = Number(match[1]) * (DURATION_MS[(match[2] ?? 'ms').toLowerCase()] ?? 1);
      if (!Number.isSafeInteger(value)) { errors.push(`${name} must be a whole number of milliseconds`); return undefined; }
      return value;
    }
    default: errors.push(`${name} has an unsupported type`); return undefined;
  }
}

function validateConstraints(name: string, parsed: unknown, rule: EnvRule, errors: string[]): boolean {
  const before = errors.length;
  if (typeof parsed === 'string') {
    if (rule.minLength !== undefined && parsed.length < rule.minLength) errors.push(`${name} must be at least ${rule.minLength} characters`);
    if (rule.maxLength !== undefined && parsed.length > rule.maxLength) errors.push(`${name} must be at most ${rule.maxLength} characters`);
    if (rule.pattern) {
      rule.pattern.lastIndex = 0;
      if (!rule.pattern.test(parsed)) errors.push(`${name} does not match the required pattern`);
    }
  }
  if (typeof parsed === 'number') {
    if (rule.min !== undefined && parsed < rule.min) errors.push(`${name} must be >= ${rule.min}`);
    if (rule.max !== undefined && parsed > rule.max) errors.push(`${name} must be <= ${rule.max}`);
  }
  if (Array.isArray(parsed)) {
    if (rule.minLength !== undefined && parsed.length < rule.minLength) errors.push(`${name} must have at least ${rule.minLength} items`);
    if (rule.maxLength !== undefined && parsed.length > rule.maxLength) errors.push(`${name} must have at most ${rule.maxLength} items`);
    if (rule.allowed && parsed.some((item) => !rule.allowed!.some((candidate) => Object.is(candidate, item)))) errors.push(`${name} items must be among the allowed values`);
  } else if (rule.allowed && !rule.allowed.some((candidate) => Object.is(candidate, parsed))) errors.push(`${name} must be one of the allowed values`);
  return errors.length === before;
}

/**
 * Validate environment variables against a schema. Empty strings count as
 * unset. Only values that pass every check appear in `values`.
 */
export function validateEnv<const S extends EnvSchema>(schema: S, source: NodeJS.ProcessEnv | Record<string, string | undefined> = process.env): EnvValidationResult<S> {
  const errors: string[] = [];
  const values: Record<string, unknown> = {};
  for (const [name, rawRule] of Object.entries(schema)) {
    const rule = normalizeRule(rawRule);
    const raw = Object.hasOwn(source, name) ? source[name] : undefined;
    const fromDefault = raw === undefined || raw === '';
    if (fromDefault && rule.default === undefined) {
      if (rule.required ?? true) errors.push(`${name} is required`);
      continue;
    }

    const parsed = parseValue(name, fromDefault ? rule.default : raw, rule, errors, fromDefault);
    if (parsed === undefined) continue;
    if (!validateConstraints(name, parsed, rule, errors)) continue;
    values[name] = parsed;
  }
  return { ok: errors.length === 0, errors, values: values as Partial<InferEnv<S>> };
}

/** Like `validateEnv` but throws a single descriptive error and returns a frozen, typed object. */
export function requireEnv<const S extends EnvSchema>(schema: S, source: NodeJS.ProcessEnv | Record<string, string | undefined> = process.env): InferEnv<S> {
  const result = validateEnv(schema, source);
  if (!result.ok) throw new Error(`Environment validation failed:\n- ${result.errors.join('\n- ')}`);
  return Object.freeze({ ...result.values }) as InferEnv<S>;
}
