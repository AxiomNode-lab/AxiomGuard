export type EnvType = 'string' | 'url' | 'integer' | 'number' | 'boolean' | 'email' | 'port' | 'json';
export interface EnvRule {
  type?: EnvType; required?: boolean; default?: string | number | boolean | unknown; minLength?: number; maxLength?: number;
  min?: number; max?: number; pattern?: RegExp; allowed?: readonly (string | number | boolean)[];
}
export type EnvSchema = Record<string, EnvType | EnvRule>;
export interface EnvValidationResult { ok: boolean; errors: string[]; values: Record<string, unknown>; }
function normalizeRule(rule: EnvType | EnvRule): EnvRule { return typeof rule === 'string' ? { type: rule } : rule; }
function parseBoolean(value: string): boolean | undefined { if (/^(true|1|yes|on)$/i.test(value)) return true; if (/^(false|0|no|off)$/i.test(value)) return false; return undefined; }

function parseValue(name: string, input: unknown, rule: EnvRule, errors: string[], fromDefault: boolean): unknown {
  const type = rule.type ?? 'string';
  if (type === 'json' && fromDefault && typeof input !== 'string') return input;
  if (type === 'boolean' && fromDefault && typeof input === 'boolean') return input;
  if ((type === 'integer' || type === 'number' || type === 'port') && fromDefault && typeof input === 'number') {
    if (!Number.isFinite(input)) { errors.push(`${name} default must be finite`); return undefined; }
    if (type === 'integer' && !Number.isSafeInteger(input)) { errors.push(`${name} default must be a safe integer`); return undefined; }
    if (type === 'port' && (!Number.isInteger(input) || input < 1 || input > 65535)) { errors.push(`${name} default must be a TCP port between 1 and 65535`); return undefined; }
    return input;
  }
  if (typeof input !== 'string') {
    errors.push(`${name}${fromDefault ? ' default' : ''} must be a string for type ${type}`);
    return undefined;
  }

  const raw = input;
  switch (type) {
    case 'string': return raw;
    case 'url': {
      try { const url = new URL(raw); if (!['http:', 'https:'].includes(url.protocol)) throw new Error(); return url.toString(); }
      catch { errors.push(`${name} must be a valid HTTP(S) URL`); return undefined; }
    }
    case 'integer': if (!/^-?\d+$/.test(raw) || !Number.isSafeInteger(Number(raw))) { errors.push(`${name} must be a safe integer`); return undefined; } return Number(raw);
    case 'number': { const parsed = Number(raw); if (!Number.isFinite(parsed)) { errors.push(`${name} must be a finite number`); return undefined; } return parsed; }
    case 'boolean': { const parsed = parseBoolean(raw); if (parsed === undefined) { errors.push(`${name} must be a boolean`); return undefined; } return parsed; }
    case 'email': if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(raw) || raw.length > 254) { errors.push(`${name} must be an email address`); return undefined; } return raw;
    case 'port': if (!/^\d+$/.test(raw) || Number(raw) < 1 || Number(raw) > 65535) { errors.push(`${name} must be a TCP port between 1 and 65535`); return undefined; } return Number(raw);
    case 'json': try { return JSON.parse(raw); } catch { errors.push(`${name} must be valid JSON`); return undefined; }
    default: errors.push(`${name} has an unsupported type`); return undefined;
  }
}

function validateConstraints(name: string, parsed: unknown, rule: EnvRule, errors: string[]): void {
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
  if (rule.allowed && !rule.allowed.some((candidate) => Object.is(candidate, parsed))) errors.push(`${name} must be one of the allowed values`);
}

export function validateEnv(schema: EnvSchema, source: NodeJS.ProcessEnv | Record<string, string | undefined> = process.env): EnvValidationResult {
  const errors: string[] = [];
  const values: Record<string, unknown> = {};
  for (const [name, rawRule] of Object.entries(schema)) {
    const rule = normalizeRule(rawRule);
    const raw = source[name];
    const fromDefault = raw === undefined || raw === '';
    if (fromDefault && rule.default === undefined) {
      if (rule.required ?? true) errors.push(`${name} is required`);
      continue;
    }

    const parsed = parseValue(name, fromDefault ? rule.default : raw, rule, errors, fromDefault);
    if (parsed === undefined && (fromDefault ? rule.default !== undefined : true)) continue;
    validateConstraints(name, parsed, rule, errors);
    values[name] = parsed;
  }
  return { ok: errors.length === 0, errors, values };
}

export function requireEnv(schema: EnvSchema, source: NodeJS.ProcessEnv | Record<string, string | undefined> = process.env): Record<string, unknown> {
  const result = validateEnv(schema, source);
  if (!result.ok) throw new Error(`Environment validation failed:\n- ${result.errors.join('\n- ')}`);
  return Object.freeze({ ...result.values });
}
