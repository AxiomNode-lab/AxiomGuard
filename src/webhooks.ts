import { createHash } from 'node:crypto';
import { verifyHmacWebhook, type VerifyHmacWebhookOptions } from './crypto.js';

export interface ReplayStore {
  /** Atomically reserves a replay key. Returns false when the key already exists and is still live. */
  claim(key: string, expiresAt: number): boolean | Promise<boolean>;
}

export class MemoryReplayStore implements ReplayStore {
  private readonly entries = new Map<string, number>();

  constructor(private readonly maxEntries = 10_000) {
    if (!Number.isInteger(maxEntries) || maxEntries < 1) {
      throw new RangeError('maxEntries must be a positive integer');
    }
  }

  claim(key: string, expiresAt: number): boolean {
    const now = Date.now();
    for (const [candidate, expiry] of this.entries) {
      if (expiry <= now) this.entries.delete(candidate);
    }
    const existing = this.entries.get(key);
    if (existing !== undefined && existing > now) return false;

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
  }
}

export type FreshWebhookFailureReason =
  | 'invalid-signature'
  | 'invalid-timestamp'
  | 'stale-timestamp'
  | 'replay';

export type FreshWebhookResult =
  | { ok: true }
  | { ok: false; reason: FreshWebhookFailureReason };

export interface VerifyFreshHmacWebhookInput {
  payload: string | Buffer;
  signature: string | undefined | null;
  secret: string;
  /** Unix timestamp in seconds supplied by the provider. */
  timestamp: string | number;
}

export interface VerifyFreshHmacWebhookOptions extends VerifyHmacWebhookOptions {
  toleranceSeconds?: number;
  now?: number;
  replayStore?: ReplayStore;
  replayKey?: string;
}

export function createWebhookReplayKey(signature: string): string {
  return createHash('sha256').update(signature, 'utf8').digest('hex');
}

export async function verifyFreshHmacWebhook(
  input: VerifyFreshHmacWebhookInput,
  options: VerifyFreshHmacWebhookOptions = {},
): Promise<FreshWebhookResult> {
  if (!verifyHmacWebhook(input.payload, input.signature, input.secret, options)) {
    return { ok: false, reason: 'invalid-signature' };
  }

  const timestamp = typeof input.timestamp === 'number' ? input.timestamp : Number(input.timestamp);
  if (!Number.isFinite(timestamp) || timestamp <= 0) {
    return { ok: false, reason: 'invalid-timestamp' };
  }

  const toleranceSeconds = options.toleranceSeconds ?? 300;
  if (!Number.isFinite(toleranceSeconds) || toleranceSeconds <= 0 || toleranceSeconds > 86_400) {
    throw new RangeError('toleranceSeconds must be greater than 0 and at most 86400');
  }

  const now = options.now ?? Date.now();
  const timestampMs = timestamp * 1000;
  if (Math.abs(now - timestampMs) > toleranceSeconds * 1000) {
    return { ok: false, reason: 'stale-timestamp' };
  }

  if (options.replayStore) {
    const signature = input.signature ?? '';
    const replayKey = options.replayKey ?? createWebhookReplayKey(signature);
    const claimed = await options.replayStore.claim(replayKey, now + toleranceSeconds * 1000);
    if (!claimed) return { ok: false, reason: 'replay' };
  }

  return { ok: true };
}
