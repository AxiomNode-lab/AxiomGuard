import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import { computeHmacSignature, decodeDigest, verifyHmacWebhook, type VerifyHmacWebhookOptions } from './crypto.js';

export interface ReplayStore { claim(key: string, expiresAt: number, now?: number): boolean | Promise<boolean>; }

/**
 * Bounded single-process replay store. Multi-instance deployments must share
 * replay state through one of the Redis adapters instead.
 */
export class MemoryReplayStore implements ReplayStore {
  private readonly entries = new Map<string, number>();
  private operations = 0;
  private nextExpiry = Number.POSITIVE_INFINITY;

  constructor(private readonly maxEntries = 10_000) {
    if (!Number.isInteger(maxEntries) || maxEntries < 1 || maxEntries > 1_000_000) throw new RangeError('maxEntries must be an integer between 1 and 1000000');
  }

  private sweepExpired(now: number): void {
    let next = Number.POSITIVE_INFINITY;
    for (const [candidate, expiry] of this.entries) {
      if (expiry <= now) this.entries.delete(candidate);
      else if (expiry < next) next = expiry;
    }
    this.nextExpiry = next;
  }

  claim(key: string, expiresAt: number, now = Date.now()): boolean {
    if (!Number.isFinite(now) || now < 0) throw new RangeError('now must be a non-negative finite timestamp');
    if (!Number.isFinite(expiresAt) || expiresAt <= now) return false;
    this.operations += 1;
    // Only pay for a full sweep when something can actually have expired; a
    // saturated store must not turn every claim into an O(n) scan.
    if ((this.operations % 256 === 0 || this.entries.size >= this.maxEntries) && this.nextExpiry <= now) this.sweepExpired(now);

    const existing = this.entries.get(key);
    if (existing !== undefined && existing > now) return false;
    if (existing !== undefined) this.entries.delete(key);

    if (this.entries.size >= this.maxEntries) return false;

    this.entries.set(key, expiresAt);
    if (expiresAt < this.nextExpiry) this.nextExpiry = expiresAt;
    return true;
  }

  clear(): void {
    this.entries.clear();
    this.operations = 0;
    this.nextExpiry = Number.POSITIVE_INFINITY;
  }

  get size(): number {
    return this.entries.size;
  }
}

export type FreshWebhookFailureReason = 'invalid-signature' | 'invalid-timestamp' | 'stale-timestamp' | 'replay';
export type FreshWebhookResult = { ok: true } | { ok: false; reason: FreshWebhookFailureReason };
export interface VerifyFreshHmacWebhookInput { payload: string | Buffer; signature: string | undefined | null; secret: string; timestamp: string | number; }
export interface VerifyFreshHmacWebhookOptions extends VerifyHmacWebhookOptions {
  /** Maximum clock difference between `timestamp` and `now`. Default: 300 seconds. */
  toleranceSeconds?: number;
  now?: number;
  replayStore?: ReplayStore;
  /** Override the replay key. Defaults to a hash of the canonical computed HMAC. */
  replayKey?: string;
  /**
   * How long a replay claim is remembered. Defaults to `toleranceSeconds`.
   * Raise it when `signedInput` is `payload`, because a captured signature stays
   * valid under any future timestamp once the claim expires.
   */
  replayTtlSeconds?: number;
  /**
   * Which bytes the provider signed. `payload` (default) verifies the HMAC over
   * the body only, so `timestamp` is merely a freshness hint. `timestamp.payload`
   * verifies the HMAC over `${timestamp}.${payload}`, binding freshness into the
   * signature like Stripe and Slack do.
   */
  signedInput?: 'payload' | 'timestamp.payload';
}

export type GitHubWebhookFailureReason = 'invalid-signature' | 'invalid-delivery' | 'replay';
export type GitHubWebhookResult = { ok: true } | { ok: false; reason: GitHubWebhookFailureReason };
export interface VerifyGitHubWebhookDeliveryOptions {
  replayStore: ReplayStore;
  replayTtlSeconds?: number;
  now?: number;
}

export interface VerifySlackWebhookOptions {
  toleranceSeconds?: number;
  now?: number;
  replayStore?: ReplayStore;
}

const TIMESTAMP_TEXT = /^\d{1,13}$/;

function assertSecret(secret: string): void {
  if (typeof secret !== 'string' || secret.length === 0) throw new TypeError('secret must be a non-empty string');
}

function resolveNow(now: number | undefined): number {
  const value = now ?? Date.now();
  if (!Number.isFinite(value) || value < 0) throw new RangeError('now must be a non-negative finite timestamp');
  return value;
}

function resolveTolerance(toleranceSeconds: number | undefined): number {
  const tolerance = toleranceSeconds ?? 300;
  if (!Number.isFinite(tolerance) || tolerance <= 0 || tolerance > 86_400) throw new RangeError('toleranceSeconds must be >0 and <=86400');
  return tolerance;
}

function resolveReplayTtl(replayTtlSeconds: number | undefined, fallback: number): number {
  const ttl = replayTtlSeconds ?? fallback;
  if (!Number.isFinite(ttl) || ttl <= 0 || ttl > 604_800) throw new RangeError('replayTtlSeconds must be >0 and <=604800');
  return ttl;
}

function replayKeyFor(scope: string, ...parts: readonly string[]): string {
  const hash = createHash('sha256').update(scope, 'utf8');
  for (const part of parts) hash.update('\0', 'utf8').update(part, 'utf8');
  return hash.digest('hex');
}

function toBuffer(payload: string | Buffer): Buffer {
  return Buffer.isBuffer(payload) ? payload : Buffer.from(payload, 'utf8');
}

/** Derive a stable non-secret replay key from a signature string. Prefer the canonical keys the provider helpers compute. */
export function createWebhookReplayKey(signature: string): string { return createHash('sha256').update(signature, 'utf8').digest('hex'); }

/** Verify GitHub's `X-Hub-Signature-256` header against the raw request body. */
export function verifyGitHubWebhook(payload: string | Buffer, signature: string | undefined | null, secret: string): boolean {
  return verifyHmacWebhook(payload, signature, secret, { algorithm: 'sha256', prefix: 'sha256=', requirePrefix: true });
}

/** Verify Meta/WhatsApp-style X-Hub-Signature-256 against the raw request body. */
export function verifyMetaWebhook(payload: string | Buffer, signature: string | undefined | null, appSecret: string): boolean {
  return verifyHmacWebhook(payload, signature, appSecret, { algorithm: 'sha256', prefix: 'sha256=', requirePrefix: true });
}

/**
 * Verify a GitHub webhook and claim its `X-GitHub-Delivery` identifier so the
 * same delivery is processed once per `replayTtlSeconds` (default 24 hours).
 * GitHub redeliveries reuse the delivery GUID and are therefore reported as
 * `replay` inside that window.
 */
export async function verifyGitHubWebhookDelivery(
  payload: string | Buffer,
  signature: string | undefined | null,
  secret: string,
  deliveryId: string | undefined | null,
  options: VerifyGitHubWebhookDeliveryOptions,
): Promise<GitHubWebhookResult> {
  if (!verifyGitHubWebhook(payload, signature, secret)) return { ok: false, reason: 'invalid-signature' };
  if (!deliveryId || deliveryId.length > 200 || /[\u0000-\u001f\u007f]/.test(deliveryId)) return { ok: false, reason: 'invalid-delivery' };
  const replayTtlSeconds = options.replayTtlSeconds ?? 86_400;
  if (!Number.isInteger(replayTtlSeconds) || replayTtlSeconds < 1 || replayTtlSeconds > 604_800) throw new RangeError('replayTtlSeconds must be an integer between 1 and 604800');
  const now = resolveNow(options.now);
  if (!await options.replayStore.claim(replayKeyFor('github-delivery', deliveryId), now + replayTtlSeconds * 1000, now)) return { ok: false, reason: 'replay' };
  return { ok: true };
}

/**
 * Verify a generic HMAC webhook that carries a separate timestamp header.
 *
 * The signature is verified first, then freshness, then (optionally) a replay
 * claim keyed on the canonical computed HMAC so re-encoding the signature
 * cannot produce a fresh replay key.
 */
export async function verifyFreshHmacWebhook(input: VerifyFreshHmacWebhookInput, options: VerifyFreshHmacWebhookOptions = {}): Promise<FreshWebhookResult> {
  const { toleranceSeconds, now: nowOption, replayStore, replayKey, replayTtlSeconds, signedInput, ...hmacOptions } = options;
  const timestampText = typeof input.timestamp === 'number' ? String(input.timestamp) : input.timestamp.trim();
  const signed = signedInput === 'timestamp.payload'
    ? Buffer.concat([Buffer.from(`${timestampText}.`, 'utf8'), toBuffer(input.payload)])
    : input.payload;
  if (!verifyHmacWebhook(signed, input.signature, input.secret, hmacOptions)) return { ok: false, reason: 'invalid-signature' };

  const timestamp = Number(timestampText);
  if (!TIMESTAMP_TEXT.test(timestampText) || !Number.isSafeInteger(timestamp) || timestamp <= 0) return { ok: false, reason: 'invalid-timestamp' };
  const tolerance = resolveTolerance(toleranceSeconds);
  const now = resolveNow(nowOption);
  if (Math.abs(now - timestamp * 1000) > tolerance * 1000) return { ok: false, reason: 'stale-timestamp' };

  if (replayStore) {
    const ttl = resolveReplayTtl(replayTtlSeconds, tolerance);
    const key = replayKey ?? replayKeyFor('fresh-hmac', computeHmacSignature(signed, input.secret, hmacOptions).digest.toString('hex'));
    if (!await replayStore.claim(key, now + ttl * 1000, now)) return { ok: false, reason: 'replay' };
  }
  return { ok: true };
}

export interface VerifyStripeWebhookOptions { toleranceSeconds?: number; now?: number; replayStore?: ReplayStore; }

function parseStripeSignature(header: string): { timestampText: string; timestamp: number; signatures: string[] } | null {
  let timestampText: string | undefined;
  const signatures: string[] = [];
  for (const item of header.split(',')) {
    const separator = item.indexOf('=');
    if (separator < 0) continue;
    const key = item.slice(0, separator);
    const value = item.slice(separator + 1);
    if (key === 't' && TIMESTAMP_TEXT.test(value)) timestampText = value;
    if (key === 'v1' && /^[a-fA-F0-9]{64}$/.test(value)) signatures.push(value.toLowerCase());
  }
  if (timestampText === undefined || signatures.length === 0) return null;
  const timestamp = Number(timestampText);
  return Number.isSafeInteger(timestamp) && timestamp > 0 ? { timestampText, timestamp, signatures } : null;
}

/** Build a `Stripe-Signature` header value for tests and fixtures. */
export function createStripeSignatureHeader(payload: string | Buffer, secret: string, timestamp: number): string {
  assertSecret(secret);
  if (!Number.isSafeInteger(timestamp) || timestamp <= 0) throw new RangeError('timestamp must be a positive integer of seconds');
  const signed = Buffer.concat([Buffer.from(`${timestamp}.`, 'utf8'), toBuffer(payload)]);
  return `t=${timestamp},v1=${createHmac('sha256', secret).update(signed).digest('hex')}`;
}

/**
 * Verify Stripe's `Stripe-Signature` header. The literal `t=` text is signed
 * together with the raw body, the signature is checked before freshness, and
 * rotated `v1` entries are accepted while `v0` entries are ignored.
 */
export async function verifyStripeWebhook(payload: string | Buffer, signatureHeader: string | undefined | null, secret: string, options: VerifyStripeWebhookOptions = {}): Promise<FreshWebhookResult> {
  assertSecret(secret);
  if (typeof signatureHeader !== 'string' || signatureHeader.length === 0 || signatureHeader.length > 4096) return { ok: false, reason: 'invalid-signature' };
  const parsed = parseStripeSignature(signatureHeader);
  if (!parsed) return { ok: false, reason: 'invalid-signature' };
  const tolerance = resolveTolerance(options.toleranceSeconds);

  const signed = Buffer.concat([Buffer.from(`${parsed.timestampText}.`, 'utf8'), toBuffer(payload)]);
  const expected = createHmac('sha256', secret).update(signed).digest();
  const valid = parsed.signatures.some((candidate) => {
    const received = Buffer.from(candidate, 'hex');
    return received.length === expected.length && timingSafeEqual(received, expected);
  });
  if (!valid) return { ok: false, reason: 'invalid-signature' };

  const now = resolveNow(options.now);
  if (Math.abs(now - parsed.timestamp * 1000) > tolerance * 1000) return { ok: false, reason: 'stale-timestamp' };
  if (options.replayStore) {
    const key = replayKeyFor('stripe', parsed.timestampText, expected.toString('hex'));
    if (!await options.replayStore.claim(key, now + tolerance * 1000, now)) return { ok: false, reason: 'replay' };
  }
  return { ok: true };
}

/** Build a Slack `X-Slack-Signature` value for tests and fixtures. */
export function createSlackSignature(payload: string | Buffer, signingSecret: string, timestamp: number | string): string {
  assertSecret(signingSecret);
  const text = String(timestamp);
  if (!TIMESTAMP_TEXT.test(text)) throw new RangeError('timestamp must be a positive integer of seconds');
  const signed = Buffer.concat([Buffer.from(`v0:${text}:`, 'utf8'), toBuffer(payload)]);
  return `v0=${createHmac('sha256', signingSecret).update(signed).digest('hex')}`;
}

/** Verify Slack's v0 signature, signed timestamp freshness and optional replay claim. */
export async function verifySlackWebhook(
  payload: string | Buffer,
  signature: string | undefined | null,
  timestamp: string | number | undefined | null,
  signingSecret: string,
  options: VerifySlackWebhookOptions = {},
): Promise<FreshWebhookResult> {
  assertSecret(signingSecret);
  if (timestamp === undefined || timestamp === null || timestamp === '') return { ok: false, reason: 'invalid-timestamp' };
  const rawTimestamp = String(timestamp);
  if (!TIMESTAMP_TEXT.test(rawTimestamp)) return { ok: false, reason: 'invalid-timestamp' };
  if (!signature?.startsWith('v0=')) return { ok: false, reason: 'invalid-signature' };
  const signed = Buffer.concat([Buffer.from(`v0:${rawTimestamp}:`, 'utf8'), toBuffer(payload)]);
  if (!verifyHmacWebhook(signed, signature, signingSecret, { algorithm: 'sha256', prefix: 'v0=', requirePrefix: true })) {
    return { ok: false, reason: 'invalid-signature' };
  }

  const parsedTimestamp = Number(rawTimestamp);
  if (!Number.isSafeInteger(parsedTimestamp) || parsedTimestamp <= 0) return { ok: false, reason: 'invalid-timestamp' };
  const tolerance = resolveTolerance(options.toleranceSeconds);
  const now = resolveNow(options.now);
  if (Math.abs(now - parsedTimestamp * 1000) > tolerance * 1000) return { ok: false, reason: 'stale-timestamp' };

  if (options.replayStore) {
    const expected = createHmac('sha256', signingSecret).update(signed).digest('hex');
    if (!await options.replayStore.claim(replayKeyFor('slack', rawTimestamp, expected), now + tolerance * 1000, now)) return { ok: false, reason: 'replay' };
  }
  return { ok: true };
}

export type StandardWebhookFailureReason = FreshWebhookFailureReason | 'invalid-id';
export type StandardWebhookResult = { ok: true } | { ok: false; reason: StandardWebhookFailureReason };
export interface StandardWebhookHeaders {
  /** `webhook-id` header. */
  id: string | undefined | null;
  /** `webhook-timestamp` header (seconds). */
  timestamp: string | number | undefined | null;
  /** `webhook-signature` header: space-separated `v1,<base64>` entries. */
  signature: string | undefined | null;
}
export interface VerifyStandardWebhookOptions { toleranceSeconds?: number; now?: number; replayStore?: ReplayStore; }

function decodeStandardWebhookSecret(secret: string): Buffer {
  assertSecret(secret);
  const encoded = secret.startsWith('whsec_') ? secret.slice('whsec_'.length) : secret;
  if (!/^[A-Za-z0-9+/=]+$/.test(encoded)) throw new TypeError('Standard Webhooks secret must be base64, optionally prefixed with whsec_');
  const decoded = Buffer.from(encoded, 'base64');
  if (decoded.length < 16) throw new TypeError('Standard Webhooks secret must decode to at least 16 bytes');
  return decoded;
}

/**
 * Verify a Standard Webhooks (Svix-compatible) signature. The signed content is
 * `${id}.${timestamp}.${payload}`, so freshness is part of the signature and the
 * message id doubles as the replay key.
 */
export async function verifyStandardWebhook(
  payload: string | Buffer,
  headers: StandardWebhookHeaders,
  secret: string,
  options: VerifyStandardWebhookOptions = {},
): Promise<StandardWebhookResult> {
  const key = decodeStandardWebhookSecret(secret);
  const id = headers.id;
  if (typeof id !== 'string' || id.length === 0 || id.length > 256 || /[\u0000-\u0020\u007f]/.test(id)) return { ok: false, reason: 'invalid-id' };
  if (headers.timestamp === undefined || headers.timestamp === null || headers.timestamp === '') return { ok: false, reason: 'invalid-timestamp' };
  const timestampText = String(headers.timestamp);
  if (!TIMESTAMP_TEXT.test(timestampText)) return { ok: false, reason: 'invalid-timestamp' };
  if (typeof headers.signature !== 'string' || headers.signature.length === 0 || headers.signature.length > 4096) return { ok: false, reason: 'invalid-signature' };

  const signed = Buffer.concat([Buffer.from(`${id}.${timestampText}.`, 'utf8'), toBuffer(payload)]);
  const expected = createHmac('sha256', key).update(signed).digest();
  const valid = headers.signature.split(' ').some((entry) => {
    if (!entry.startsWith('v1,')) return false;
    const received = decodeDigest(entry.slice(3), 'base64', expected.length);
    return received !== null && timingSafeEqual(received, expected);
  });
  if (!valid) return { ok: false, reason: 'invalid-signature' };

  const timestamp = Number(timestampText);
  const tolerance = resolveTolerance(options.toleranceSeconds);
  const now = resolveNow(options.now);
  if (Math.abs(now - timestamp * 1000) > tolerance * 1000) return { ok: false, reason: 'stale-timestamp' };
  if (options.replayStore) {
    if (!await options.replayStore.claim(replayKeyFor('standard-webhook', id), now + tolerance * 1000, now)) return { ok: false, reason: 'replay' };
  }
  return { ok: true };
}
