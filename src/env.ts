export type EnvType = 'string' | 'url' | 'integer' | 'boolean';

export interface EnvRule {
  type?: EnvType;
  required?: boolean;
  minLength?: number;
  maxLength?: number;
  pattern?: RegExp;
  allowed?: readonly string[];
}

export type EnvSchema = Record<string, EnvType | EnvRule>;

export interface EnvValidationResult {
  ok: boolean;
  errors: string[];
  values: Record<string, string | number | boolean>;
}

function normalizeRule(rule: EnvType | EnvRule): EnvRule {
  return typeof rule === 'string' ? { type: rule } : rule;
}

function parseBoolean(value: string): boolean | undefined {
  if (/^(true|1|yes|on)$/i.test(value)) return true;
  if (/^(false|0|no|off)$/i.test(value)) return false;
  return undefined;
}

export function validateEnv(
  schema: EnvSchema,
  source: NodeJS.ProcessEnv | Record<string, string | undefined> = process.env,
): EnvValidationResult {
  const errors: string[] = [];
  const values: Record<string, string | number | boolean> = {};

  for (const [name, rawRule] of Object.entries(schema)) {
    const rule = normalizeRule(rawRule);
    const required = rule.required ?? true;
    const raw = source[name];

    if (raw === undefined || raw === '') {
      if (required) errors.push(`${name} is required`);
      continue;
    }

    if (rule.minLength !== undefined && raw.length < rule.minLength) {
      errors.push(`${name} must be at least ${rule.minLength} characters`);
    }
    if (rule.maxLength !== undefined && raw.length > rule.maxLength) {
      errors.push(`${name} must be at most ${rule.maxLength} characters`);
    }
    if (rule.pattern && !rule.pattern.test(raw)) {
      errors.push(`${name} does not match the required pattern`);
    }
    if (rule.allowed && !rule.allowed.includes(raw)) {
      errors.push(`${name} must be one of: ${rule.allowed.join(', ')}`);
    }

    switch (rule.type ?? 'string') {
      case 'string':
        values[name] = raw;
        break;
      case 'url': {
        try {
          const parsed = new URL(raw);
          if (!['http:', 'https:'].includes(parsed.protocol)) {
            errors.push(`${name} must use http or https`);
          } else {
            values[name] = parsed.toString();
          }
        } catch {
          errors.push(`${name} must be a valid URL`);
        }
        break;
      }
      case 'integer': {
        if (!/^-?\d+$/.test(raw)) {
          errors.push(`${name} must be an integer`);
          break;
        }
        const parsed = Number(raw);
        if (!Number.isSafeInteger(parsed)) {
          errors.push(`${name} must be a safe integer`);
          break;
        }
        values[name] = parsed;
        break;
      }
      case 'boolean': {
        const parsed = parseBoolean(raw);
        if (parsed === undefined) {
          errors.push(`${name} must be a boolean`);
          break;
        }
        values[name] = parsed;
        break;
      }
      default:
        errors.push(`${name} has an unsupported type`);
    }
  }

  return { ok: errors.length === 0, errors, values };
}

export function requireEnv(
  schema: EnvSchema,
  source: NodeJS.ProcessEnv | Record<string, string | undefined> = process.env,
): Record<string, string | number | boolean> {
  const result = validateEnv(schema, source);
  if (!result.ok) {
    throw new Error(`Environment validation failed:\n- ${result.errors.join('\n- ')}`);
  }
  return result.values;
}
