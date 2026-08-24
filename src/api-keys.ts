import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

export interface CreateApiKeyOptions {
  prefix?: string;
  bytes?: number;
  idBytes?: number;
}

export interface CreatedApiKey {
  token: string;
  id: string;
  digest: string;
  fingerprint: string;
}

function assertPrefix(prefix: string): void {
  if (!/^[A-Za-z][A-Za-z0-9_-]{1,15}$/.test(prefix)) {
    throw new TypeError('prefix must start with a letter and contain 2-16 safe characters');
  }
}

export function hashApiKey(token: string): string {
  if (typeof token !== 'string' || token.length < 16) {
    throw new TypeError('token must be a non-empty API key string');
  }
  return createHash('sha256').update(token, 'utf8').digest('hex');
}

export function createApiKey(options: CreateApiKeyOptions = {}): CreatedApiKey {
  const prefix = options.prefix ?? 'axg';
  const bytes = options.bytes ?? 32;
  const idBytes = options.idBytes ?? 6;
  assertPrefix(prefix);
  if (!Number.isInteger(bytes) || bytes < 24 || bytes > 128) {
    throw new RangeError('bytes must be an integer between 24 and 128');
  }
  if (!Number.isInteger(idBytes) || idBytes < 4 || idBytes > 16) {
    throw new RangeError('idBytes must be an integer between 4 and 16');
  }

  const id = randomBytes(idBytes).toString('base64url');
  const secret = randomBytes(bytes).toString('base64url');
  const token = `${prefix}_${id}_${secret}`;
  const digest = hashApiKey(token);
  return { token, id, digest, fingerprint: digest.slice(0, 12) };
}

export function verifyApiKey(token: string, expectedDigest: string): boolean {
  if (!/^[a-fA-F0-9]{64}$/.test(expectedDigest)) return false;
  let actualDigest: string;
  try {
    actualDigest = hashApiKey(token);
  } catch {
    return false;
  }
  const actual = Buffer.from(actualDigest, 'hex');
  const expected = Buffer.from(expectedDigest, 'hex');
  return timingSafeEqual(actual, expected);
}

export function maskApiKey(token: string): string {
  if (typeof token !== 'string' || token.length === 0) return '[REDACTED]';
  const marker = token.indexOf('_');
  const prefix = marker > 0 ? token.slice(0, marker) : 'key';
  const suffix = token.length >= 4 ? token.slice(-4) : '****';
  return `${prefix}_...${suffix}`;
}
