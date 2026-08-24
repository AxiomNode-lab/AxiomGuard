import test from 'node:test';
import assert from 'node:assert/strict';
import {
  MemoryRateLimitStore,
  checkRateLimit,
  createRateLimitHeaders,
  safeFetch,
} from '../dist/index.js';

test('safeFetch revalidates redirects and strips credentials across origins', async () => {
  const calls = [];
  const fetchImpl = async (url, init) => {
    const headers = Object.fromEntries(new Headers(init.headers).entries());
    calls.push({ url: String(url), headers, method: init.method });
    if (calls.length === 1) {
      return new Response(null, { status: 302, headers: { location: 'https://1.1.1.1/next' } });
    }
    return new Response('ok', { status: 200 });
  };

  const response = await safeFetch('https://8.8.8.8/start', {
    fetchImpl,
    headers: {
      authorization: 'Bearer test-token',
      cookie: 'session=test',
      'x-client': 'axiomguard',
    },
  });

  assert.equal(response.status, 200);
  assert.equal(calls.length, 2);
  assert.equal(calls[0].headers.authorization, 'Bearer test-token');
  assert.equal(calls[1].headers.authorization, undefined);
  assert.equal(calls[1].headers.cookie, undefined);
  assert.equal(calls[1].headers['x-client'], 'axiomguard');
});

test('safeFetch blocks a redirect to a private target before a second request', async () => {
  let calls = 0;
  const fetchImpl = async () => {
    calls += 1;
    return new Response(null, { status: 302, headers: { location: 'http://127.0.0.1/admin' } });
  };

  await assert.rejects(
    safeFetch('https://8.8.8.8/start', { fetchImpl }),
    /Private, loopback, link-local, multicast, or reserved IP addresses are blocked/,
  );
  assert.equal(calls, 1);
});

test('safeFetch refuses transport authority header overrides', async () => {
  await assert.rejects(
    safeFetch('https://8.8.8.8/start', {
      headers: { host: 'internal.example' },
      fetchImpl: async () => new Response('never'),
    }),
    /does not allow overriding transport header/,
  );
});

test('rate-limit results produce draft and compatibility response fields', async () => {
  const store = new MemoryRateLimitStore();
  const now = 1_000_000;
  await checkRateLimit('client:1', { limit: 1, windowMs: 60_000, store, now });
  const blocked = await checkRateLimit('client:1', { limit: 1, windowMs: 60_000, store, now });
  const headers = createRateLimitHeaders(blocked, { now, policyName: 'api' });

  assert.equal(blocked.allowed, false);
  assert.equal(headers['RateLimit-Policy'], '"api";q=1;w=60');
  assert.equal(headers.RateLimit, '"api";r=0;t=60');
  assert.equal(headers['RateLimit-Limit'], '1');
  assert.equal(headers['RateLimit-Remaining'], '0');
  assert.equal(headers['RateLimit-Reset'], '60');
  assert.equal(headers['Retry-After'], '60');
});
