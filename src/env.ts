export type EnvType = 'string' | 'url' | 'integer' | 'number' | 'boolean' | 'email' | 'port' | 'json';
export interface EnvRule {
  type?: EnvType; required?: boolean; default?: string | number | boolean | unknown; minLength?: number; maxLength?: number;
  min?: number; max?: number; pattern?: RegExp; allowed?: readonly (string | number | boolean)[];
}
export type EnvSchema = Record<string, EnvType | EnvRule>;
export interface EnvValidationResult { ok: boolean; errors: string[]; values: Record<string, unknown>; }
function normalizeRule(rule: EnvType | EnvRule): EnvRule { return typeof rule === 'string' ? { type: rule } : rule; }
function parseBoolean(value: string): boolean | undefined { if (/^(true|1|yes|on)$/i.test(value)) return true; if (/^(false|0|no|off)$/i.test(value)) return false; return undefined; }

export function validateEnv(schema: EnvSchema, source: NodeJS.ProcessEnv | Record<string, string | undefined> = process.env): EnvValidationResult {
  const errors: string[] = []; const values: Record<string, unknown> = {};
  for (const [name, rawRule] of Object.entries(schema)) {
    const rule = normalizeRule(rawRule); const raw = source[name];
    if (raw === undefined || raw === '') {
      if (rule.default !== undefined) values[name] = rule.default;
      else if (rule.required ?? true) errors.push(`${name} is required`);
      continue;
    }
    if (rule.minLength !== undefined && raw.length < rule.minLength) errors.push(`${name} must be at least ${rule.minLength} characters`);
    if (rule.maxLength !== undefined && raw.length > rule.maxLength) errors.push(`${name} must be at most ${rule.maxLength} characters`);
    if (rule.pattern && !rule.pattern.test(raw)) errors.push(`${name} does not match the required pattern`);

    let parsed: unknown = raw;
    switch (rule.type ?? 'string') {
      case 'string': parsed = raw; break;
      case 'url': try { const url = new URL(raw); if (!['http:', 'https:'].includes(url.protocol)) throw new Error(); parsed = url.toString(); } catch { errors.push(`${name} must be a valid HTTP(S) URL`); continue; }
      case 'integer': if (!/^-?\d+$/.test(raw) || !Number.isSafeInteger(Number(raw))) { errors.push(`${name} must be a safe integer`); continue; } parsed = Number(raw); break;
      case 'number': parsed = Number(raw); if (!Number.isFinite(parsed)) { errors.push(`${name} must be a finite number`); continue; } break;
      case 'boolean': parsed = parseBoolean(raw); if (parsed === undefined) { errors.push(`${name} must be a boolean`); continue; } break;
      case 'email': if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(raw) || raw.length > 254) { errors.push(`${name} must be an email address`); continue; } parsed = raw; break;
      case 'port': if (!/^\d+$/.test(raw) || Number(raw) < 1 || Number(raw) > 65535) { errors.push(`${name} must be a TCP port between 1 and 65535`); continue; } parsed = Number(raw); break;
      case 'json': try { parsed = JSON.parse(raw); } catch { errors.push(`${name} must be valid JSON`); continue; } break;
      default: errors.push(`${name} has an unsupported type`); continue;
    }
    if (typeof parsed === 'number') {
      if (rule.min !== undefined && parsed < rule.min) errors.push(`${name} must be >= ${rule.min}`);
      if (rule.max !== undefined && parsed > rule.max) errors.push(`${name} must be <= ${rule.max}`);
    }
    if (rule.allowed && !rule.allowed.some((candidate) => Object.is(candidate, parsed))) errors.push(`${name} must be one of the allowed values`);
    values[name] = parsed;
  }
  return { ok: errors.length === 0, errors, values };
}
export function requireEnv(schema: EnvSchema, source: NodeJS.ProcessEnv | Record<string, string | undefined> = process.env): Record<string, unknown> {
  const result = validateEnv(schema, source); if (!result.ok) throw new Error(`Environment validation failed:\n- ${result.errors.join('\n- ')}`); return Object.freeze({ ...result.values });
}
