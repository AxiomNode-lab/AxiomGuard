import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import { verifyHmacWebhook, type VerifyHmacWebhookOptions } from './crypto.js';

export interface ReplayStore { claim(key: string, expiresAt: number, now?: number): boolean | Promise<boolean>; }
export class MemoryReplayStore implements ReplayStore {
  private readonly entries = new Map<string, number>();
  private operations = 0;

  constructor(private readonly maxEntries = 10_000) {
    if (!Number.isInteger(maxEntries) || maxEntries < 1 || maxEntries > 1_000_000) throw new RangeError('maxEntries must be an integer between 1 and 1000000');
  }

  private sweepExpired(now: number): void {
    for (const [candidate, expiry] of this.entries) if (expiry <= now) this.entries.delete(candidate);
  }

  claim(key: string, expiresAt: number, now = Date.now()): boolean {
    if (!Number.isFinite(now) || now < 0) throw new RangeError('now must be a non-negative finite timestamp');
    if (!Number.isFinite(expiresAt) || expiresAt <= now) return false;
    this.operations += 1;
    if (this.operations % 256 === 0 || this.entries.size >= this.maxEntries) this.sweepExpired(now);

    const existing = this.entries.get(key);
    if (existing !== undefined && existing > now) return false;
    if (existing !== undefined) this.entries.delete(key);
    while (this.entries.size >= this.maxEntries) {
      const oldest = this.entries.keys().next().value as string | undefined;
      if (oldest === undefined) break;
      this.entries.delete(oldest);
    }
    this.entries.set(key, expiresAt);
    return true;
  }

  clear(): void {
    this.entries.clear();
    this.operations = 0;
  }
}

export type FreshWebhookFailureReason = 'invalid-signature' | 'invalid-timestamp' | 'stale-timestamp' | 'replay';
export type FreshWebhookResult = { ok: true } | { ok: false; reason: FreshWebhookFailureReason };
export interface VerifyFreshHmacWebhookInput { payload: string | Buffer; signature: string | undefined | null; secret: string; timestamp: string | number; }
export interface VerifyFreshHmacWebhookOptions extends VerifyHmacWebhookOptions { toleranceSeconds?: number; now?: number; replayStore?: ReplayStore; replayKey?: string; }

export type GitHubWebhookFailureReason = 'invalid-signature' | 'invalid-delivery' | 'replay';
export type GitHubWebhookResult = { ok: true } | { ok: false; reason: GitHubWebhookFailureReason };
export interface VerifyGitHubWebhookDeliveryOptions {
  replayStore: ReplayStore;
  replayTtlSeconds?: number;
  now?: number;
}

function resolveNow(now: number | undefined): number {
  const value = now ?? Date.now();
  if (!Number.isFinite(value) || value < 0) throw new RangeError('now must be a non-negative finite timestamp');
  return value;
}

export function createWebhookReplayKey(signature: string): string { return createHash('sha256').update(signature, 'utf8').digest('hex'); }
export function verifyGitHubWebhook(payload: string | Buffer, signature: string | undefined | null, secret: string): boolean {
  return verifyHmacWebhook(payload, signature, secret, { algorithm: 'sha256', prefix: 'sha256=' });
}

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
  const replayKey = createHash('sha256').update(`github-delivery\0${deliveryId}`, 'utf8').digest('hex');
  if (!await options.replayStore.claim(replayKey, now + replayTtlSeconds * 1000, now)) return { ok: false, reason: 'replay' };
  return { ok: true };
}

export async function verifyFreshHmacWebhook(input: VerifyFreshHmacWebhookInput, options: VerifyFreshHmacWebhookOptions = {}): Promise<FreshWebhookResult> {
  if (!verifyHmacWebhook(input.payload, input.signature, input.secret, options)) return { ok: false, reason: 'invalid-signature' };
  const timestamp = typeof input.timestamp === 'number' ? input.timestamp : Number(input.timestamp);
  if (!Number.isFinite(timestamp) || timestamp <= 0) return { ok: false, reason: 'invalid-timestamp' };
  const toleranceSeconds = options.toleranceSeconds ?? 300;
  if (!Number.isFinite(toleranceSeconds) || toleranceSeconds <= 0 || toleranceSeconds > 86_400) throw new RangeError('toleranceSeconds must be >0 and <=86400');
  const now = resolveNow(options.now);
  if (Math.abs(now - timestamp * 1000) > toleranceSeconds * 1000) return { ok: false, reason: 'stale-timestamp' };
  if (options.replayStore) {
    const key = options.replayKey ?? createWebhookReplayKey(input.signature ?? '');
    if (!await options.replayStore.claim(key, now + toleranceSeconds * 1000, now)) return { ok: false, reason: 'replay' };
  }
  return { ok: true };
}

export interface VerifyStripeWebhookOptions { toleranceSeconds?: number; now?: number; replayStore?: ReplayStore; }
function parseStripeSignature(header: string): { timestamp: number; signatures: string[] } | null {
  let timestamp: number | undefined;
  const signatures: string[] = [];
  for (const item of header.split(',')) {
    const [key, value] = item.split('=', 2);
    if (key === 't' && value && /^\d+$/.test(value)) timestamp = Number(value);
    if (key === 'v1' && value && /^[a-fA-F0-9]{64}$/.test(value)) signatures.push(value.toLowerCase());
  }
  return timestamp && Number.isSafeInteger(timestamp) && signatures.length ? { timestamp, signatures } : null;
}

export async function verifyStripeWebhook(payload: string | Buffer, signatureHeader: string | undefined | null, secret: string, options: VerifyStripeWebhookOptions = {}): Promise<FreshWebhookResult> {
  if (!signatureHeader || !secret) return { ok: false, reason: 'invalid-signature' };
  const parsed = parseStripeSignature(signatureHeader);
  if (!parsed) return { ok: false, reason: 'invalid-signature' };
  const tolerance = options.toleranceSeconds ?? 300;
  if (!Number.isFinite(tolerance) || tolerance <= 0 || tolerance > 86_400) throw new RangeError('toleranceSeconds must be >0 and <=86400');

  const body = Buffer.isBuffer(payload) ? payload : Buffer.from(payload, 'utf8');
  const signed = Buffer.concat([Buffer.from(`${parsed.timestamp}.`, 'utf8'), body]);
  const expected = createHmac('sha256', secret).update(signed).digest();
  const valid = parsed.signatures.some((candidate) => {
    const received = Buffer.from(candidate, 'hex');
    return received.length === expected.length && timingSafeEqual(received, expected);
  });
  if (!valid) return { ok: false, reason: 'invalid-signature' };

  const now = resolveNow(options.now);
  if (Math.abs(now - parsed.timestamp * 1000) > tolerance * 1000) return { ok: false, reason: 'stale-timestamp' };
  if (options.replayStore) {
    const key = createWebhookReplayKey(signatureHeader);
    if (!await options.replayStore.claim(key, now + tolerance * 1000, now)) return { ok: false, reason: 'replay' };
  }
  return { ok: true };
}
