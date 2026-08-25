import { performance } from 'node:perf_hooks';
import { createHmac } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import {
  MemoryRateLimitStore,
  createApiKey,
  hashApiKey,
  redactSecrets,
  scanSecrets,
  secureToken,
  verifyApiKey,
  verifyHmacWebhook,
} from '../dist/index.js';

function measure(name, iterations, operation) {
  for (let index = 0; index < Math.min(iterations, 1000); index += 1) operation(index);
  const start = performance.now();
  for (let index = 0; index < iterations; index += 1) operation(index);
  const elapsedMs = performance.now() - start;
  return {
    name,
    iterations,
    elapsedMs: Number(elapsedMs.toFixed(3)),
    operationsPerSecond: Number(((iterations / elapsedMs) * 1000).toFixed(0)),
  };
}

const results = [];
results.push(measure('secureToken(32)', 20_000, () => secureToken(32)));

const apiKey = createApiKey();
results.push(measure('hashApiKey', 30_000, () => hashApiKey(apiKey.token)));
results.push(measure('verifyApiKey', 30_000, () => verifyApiKey(apiKey.token, apiKey.digest)));

const payload = Buffer.from('{"benchmark":true}');
const webhookSecret = 'benchmark-secret';
const signature = `sha256=${createHmac('sha256', webhookSecret).update(payload).digest('hex')}`;
results.push(measure('verifyHmacWebhook', 30_000, () => verifyHmacWebhook(payload, signature, webhookSecret)));

const logFixture = {
  request: {
    authorization: 'Bearer abcdefghijklmnopqrstuvwxyz123456',
    nested: Array.from({ length: 5 }, (_, index) => ({ index, token: `value-${index}` })),
  },
};
results.push(measure('redactSecrets', 10_000, () => redactSecrets(logFixture)));

const limiter = new MemoryRateLimitStore(10_000);
results.push(measure('MemoryRateLimitStore.consume same key', 50_000, () => limiter.consume('client', 60_000, 1_000)));

const highCardinalityLimiter = new MemoryRateLimitStore(10_000);
results.push(measure('MemoryRateLimitStore.consume unique keys', 20_000, (index) => highCardinalityLimiter.consume(`client:${index}`, 60_000, 1_000)));

const directory = await mkdtemp(path.join(tmpdir(), 'axiomguard-bench-'));
try {
  const body = 'export const value = "placeholder";\n'.repeat(50);
  await Promise.all(Array.from({ length: 200 }, (_, index) => writeFile(path.join(directory, `file-${index}.ts`), body, 'utf8')));
  const start = performance.now();
  const findings = await scanSecrets(directory);
  const elapsedMs = performance.now() - start;
  results.push({
    name: 'scanSecrets 200x50-line files',
    iterations: 1,
    elapsedMs: Number(elapsedMs.toFixed(3)),
    operationsPerSecond: null,
    findings: findings.length,
  });
} finally {
  await rm(directory, { recursive: true, force: true });
}

console.log(JSON.stringify({
  node: process.version,
  platform: process.platform,
  arch: process.arch,
  note: 'Informational benchmark only; CI does not enforce machine-dependent throughput thresholds.',
  results,
}, null, 2));
