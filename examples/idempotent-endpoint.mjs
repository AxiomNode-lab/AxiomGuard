// A create endpoint that survives client retries.
import { MemoryIdempotencyStore, claimIdempotencyKey, createIdempotencyFingerprint } from '../dist/index.js';

const store = new MemoryIdempotencyStore();

async function handle(request) {
  const fingerprint = createIdempotencyFingerprint({ method: request.method, target: request.url, contentType: request.headers['content-type'], body: request.body });
  const status = await claimIdempotencyKey(request.headers['idempotency-key'], fingerprint, { store, ttlMs: 86_400_000, scope: request.user });
  switch (status) {
    case 'missing-key':
    case 'invalid-key':
      return { status: 400, body: 'Idempotency-Key header is required' };
    case 'accepted':
      return { status: 201, body: 'created' };
    case 'replay':
      return { status: 200, body: 'already created (same request)' };
    case 'conflict':
      return { status: 409, body: 'key reused for a different request' };
    case 'capacity':
      return { status: 503, body: 'try again later' };
  }
}

const base = { method: 'POST', url: '/orders', headers: { 'content-type': 'application/json', 'idempotency-key': 'order-42' }, user: 'alice' };
console.log(await handle({ ...base, body: '{"sku":"a"}' }));
console.log(await handle({ ...base, body: '{"sku":"a"}' }));
console.log(await handle({ ...base, body: '{"sku":"b"}' }));
console.log(await handle({ ...base, body: '{"sku":"a"}', user: 'bob' }));
console.log(await handle({ ...base, headers: { 'content-type': 'application/json' }, body: '{"sku":"a"}' }));
