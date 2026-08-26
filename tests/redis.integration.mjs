import test from 'node:test';
import assert from 'node:assert/strict';
import { createClient } from 'redis';
import Redis from 'ioredis';
import {
  createIORedisRateLimitStore,
  createIORedisReplayStore,
  createNodeRedisRateLimitStore,
  createNodeRedisReplayStore,
} from '../dist/adapters/redis.js';

const url = process.env.AXIOMGUARD_REDIS_URL ?? 'redis://127.0.0.1:6379';

test('node-redis adapters use Redis atomically with expiry', async () => {
  const client = createClient({ url });
  await client.connect();
  try {
    await client.flushDb();
    const replay = createNodeRedisReplayStore(client, 'it:node:replay:');
    const expiresAt = Date.now() + 5000;
    assert.equal(await replay.claim('delivery', expiresAt), true);
    assert.equal(await replay.claim('delivery', expiresAt), false);

    const limiter = createNodeRedisRateLimitStore(client, 'it:node:rate:');
    const first = await limiter.consume('client', 5000);
    const second = await limiter.consume('client', 5000);
    assert.equal(first.count, 1);
    assert.equal(second.count, 2);
    const ttl = await client.pTTL('it:node:rate:client');
    assert.ok(ttl > 0 && ttl <= 5000);
  } finally {
    await client.quit();
  }
});

test('ioredis adapters use Redis atomically with expiry', async () => {
  const client = new Redis(url, { lazyConnect: true, maxRetriesPerRequest: 1 });
  await client.connect();
  try {
    await client.flushdb();
    const replay = createIORedisReplayStore(client, 'it:io:replay:');
    const expiresAt = Date.now() + 5000;
    assert.equal(await replay.claim('delivery', expiresAt), true);
    assert.equal(await replay.claim('delivery', expiresAt), false);

    const limiter = createIORedisRateLimitStore(client, 'it:io:rate:');
    const first = await limiter.consume('client', 5000);
    const second = await limiter.consume('client', 5000);
    assert.equal(first.count, 1);
    assert.equal(second.count, 2);
    const ttl = await client.pttl('it:io:rate:client');
    assert.ok(ttl > 0 && ttl <= 5000);
  } finally {
    await client.quit();
  }
});
