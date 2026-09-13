import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { once } from 'node:events';
import {
  SafeFetchError,
  SafeUrlError,
  assertSafeUrl,
  isPrivateIPAddress,
  safeFetch,
  safePath,
  sanitizeFilename,
  validateRedirect,
} from '../dist/index.js';

async function withServer(handler, run) {
  const server = createServer(handler);
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const { port } = server.address();
  try {
    await run(`http://127.0.0.1:${port}`);
  } finally {
    server.closeAllConnections?.();
    await new Promise((resolve) => server.close(resolve));
  }
}

test('assertSafeUrl blocks trailing-dot localhost variants and normalises hostnames', () => {
  for (const url of ['http://localhost.', 'http://LOCALHOST.', 'http://foo.localhost.', 'http://[::1]', 'http://0x7f000001', 'http://127.1', 'http://2130706433']) {
    assert.throws(() => assertSafeUrl(url), SafeUrlError, url);
  }
  assert.throws(() => assertSafeUrl('http://localhost'), (error) => error instanceof SafeUrlError && error.code === 'localhost');
  assert.throws(() => assertSafeUrl('http://10.0.0.1'), (error) => error.code === 'private-address');
  assert.throws(() => assertSafeUrl('ftp://example.com'), (error) => error.code === 'blocked-protocol');
  assert.throws(() => assertSafeUrl('https://user:pw@example.com'), (error) => error.code === 'credentials');
  assert.equal(assertSafeUrl('https://Example.COM./x', { allowedHosts: ['example.com'] }).hostname, 'example.com.');
  assert.equal(assertSafeUrl('http://127.0.0.1:8080/', { dangerouslyAllowPrivateTargets: true }).port, '8080');
});

test('allowedHosts matches exactly unless a wildcard subdomain entry is used', () => {
  assert.ok(assertSafeUrl('https://api.example.com', { allowedHosts: ['api.example.com'] }));
  assert.throws(() => assertSafeUrl('https://evil.example.com', { allowedHosts: ['example.com'] }), (error) => error.code === 'host-not-allowed');
  assert.ok(assertSafeUrl('https://evil.example.com', { allowedHosts: ['*.example.com'] }));
  assert.throws(() => assertSafeUrl('https://example.com', { allowedHosts: ['*.example.com'] }), (error) => error.code === 'host-not-allowed');
  assert.throws(() => assertSafeUrl('https://notexample.com', { allowedHosts: ['*.example.com'] }), (error) => error.code === 'host-not-allowed');
});

test('isPrivateIPAddress blocks IPv4-translated, local-use NAT64, discard and documentation prefixes', () => {
  for (const ip of ['::ffff:0:7f00:1', '::ffff:0:127.0.0.1', '64:ff9b:1::7f00:1', '100::1', '3fff::1', '2001:2::1', '2001:db8::1']) {
    assert.equal(isPrivateIPAddress(ip), true, ip);
  }
  assert.equal(isPrivateIPAddress('::ffff:0:8.8.8.8'), false);
  assert.equal(isPrivateIPAddress('2606:4700::1111'), false);
});

test('safeFetch timeout and caller signal keep applying while the body streams', async () => {
  await withServer((_request, response) => {
    response.writeHead(200, { 'content-type': 'text/plain' });
    response.write('partial');
    // Never end: simulate a stalled body.
  }, async (base) => {
    const response = await safeFetch(`${base}/slow`, { dangerouslyAllowPrivateTargets: true, timeoutMs: 100 });
    assert.equal(response.status, 200);
    assert.equal(response.url, `${base}/slow`);
    await assert.rejects(response.text(), (error) => error instanceof SafeFetchError && error.code === 'timeout');

    const controller = new AbortController();
    const second = await safeFetch(`${base}/slow`, { dangerouslyAllowPrivateTargets: true, timeoutMs: 5_000, signal: controller.signal });
    const reading = second.text();
    controller.abort();
    await assert.rejects(reading, (error) => error.name === 'AbortError');
  });
});

test('safeFetch enforces maxResponseBytes without buffering the whole body', async () => {
  await withServer((_request, response) => {
    response.writeHead(200);
    response.end('x'.repeat(10_000));
  }, async (base) => {
    const response = await safeFetch(`${base}/big`, { dangerouslyAllowPrivateTargets: true, maxResponseBytes: 1_000 });
    await assert.rejects(response.text(), (error) => error.code === 'response-too-large');
    const small = await safeFetch(`${base}/big`, { dangerouslyAllowPrivateTargets: true, maxResponseBytes: 20_000 });
    assert.equal((await small.text()).length, 10_000);
  });
});

test('safeFetch rejects https to http downgrade by default and cancels rejected redirect bodies', async () => {
  let cancelled = false;
  const stalled = new ReadableStream({ cancel() { cancelled = true; } });
  const fetchImpl = async () => new Response(stalled, { status: 302, headers: { location: 'http://8.8.8.8/plain' } });
  await assert.rejects(safeFetch('https://8.8.8.8/start', { fetchImpl }), (error) => error instanceof SafeFetchError && error.code === 'insecure-downgrade' && error.location === 'http://8.8.8.8/plain');
  assert.equal(cancelled, true, 'the 302 body must be cancelled before throwing');

  let calls = 0;
  const downgrade = async () => {
    calls += 1;
    return calls === 1 ? new Response(null, { status: 302, headers: { location: 'http://8.8.8.8/plain' } }) : new Response('ok');
  };
  const response = await safeFetch('https://8.8.8.8/start', { fetchImpl: downgrade, allowInsecureRedirectDowngrade: true });
  assert.equal(await response.text(), 'ok');

  let privateCancelled = false;
  const privateBody = new ReadableStream({ cancel() { privateCancelled = true; } });
  await assert.rejects(
    safeFetch('https://8.8.8.8/start', { fetchImpl: async () => new Response(privateBody, { status: 302, headers: { location: 'http://127.0.0.1/' } }) }),
    (error) => error instanceof SafeUrlError && error.code === 'private-address',
  );
  assert.equal(privateCancelled, true);
});

test('safeFetch redirect: manual returns the validated 3xx and typed errors carry redirect details', async () => {
  const fetchImpl = async () => new Response(null, { status: 307, headers: { location: 'https://1.1.1.1/next' } });
  const manual = await safeFetch('https://8.8.8.8/start', { fetchImpl, redirect: 'manual' });
  assert.equal(manual.status, 307);
  assert.equal(manual.headers.get('location'), 'https://1.1.1.1/next');

  await assert.rejects(
    safeFetch('https://8.8.8.8/start', { fetchImpl, method: 'PUT', body: 'payload' }),
    (error) => error instanceof SafeFetchError && error.code === 'body-replay' && error.status === 307 && error.location === 'https://1.1.1.1/next',
  );
  await assert.rejects(
    safeFetch('https://8.8.8.8/start', { fetchImpl, maxRedirects: 0 }),
    (error) => error.code === 'too-many-redirects' && error.location === 'https://1.1.1.1/next',
  );
  await assert.rejects(
    safeFetch('https://8.8.8.8/start', { fetchImpl: async () => new Response(null, { status: 302, headers: { location: 'http://[' } }) }),
    (error) => error.code === 'invalid-redirect',
  );
  await assert.rejects(
    safeFetch('https://8.8.8.8/start', { fetchImpl: async () => new Response(null, { status: 302, headers: { location: 'https://127.0.0.1/x' } }), redirect: 'manual' }),
    (error) => error instanceof SafeUrlError,
    'manual mode still validates the redirect target',
  );
});

test('safeFetch strips API-key style headers on cross-origin redirects', async () => {
  const calls = [];
  const fetchImpl = async (_url, init) => {
    calls.push(Object.fromEntries(new Headers(init.headers).entries()));
    return calls.length === 1 ? new Response(null, { status: 302, headers: { location: 'https://1.1.1.1/next' } }) : new Response('ok');
  };
  await safeFetch('https://8.8.8.8/start', { fetchImpl, headers: { 'x-api-key': 'k', 'x-auth-token': 't', accept: 'text/plain' } });
  assert.equal(calls[1]['x-api-key'], undefined);
  assert.equal(calls[1]['x-auth-token'], undefined);
  assert.equal(calls[1].accept, 'text/plain');
});

test('validateRedirect resolves relative targets against base and rejects protocol-relative tricks', () => {
  const allowed = ['https://app.example.com'];
  const base = 'https://app.example.com/login';
  assert.equal(validateRedirect('/dashboard', allowed, { base }).href, 'https://app.example.com/dashboard');
  assert.equal(validateRedirect('settings?tab=1', allowed, { base }).href, 'https://app.example.com/settings?tab=1');
  assert.equal(validateRedirect('https:evil.com', allowed, { base }).href, 'https://app.example.com/evil.com', 'scheme-only targets stay on the base origin');
  for (const target of ['//evil.com', '/\\evil.com', '\\\\evil.com', '/.//evil.com', ' //evil.com', 'https://evil.com/', '/x\r\nSet-Cookie: a=b']) {
    assert.throws(() => validateRedirect(target, allowed, { base }), SafeUrlError, target);
  }
  assert.throws(() => validateRedirect('/dashboard', allowed), (error) => error.code === 'redirect-path', 'relative targets need a base');
  assert.throws(() => validateRedirect('https://app.example.com/x', ['app.example.com']), /Invalid allowed origin/);
});

test('safePath rejects NUL bytes and sanitizeFilename produces well-formed bounded names', () => {
  assert.throws(() => safePath('/srv/app/uploads', 'a\u0000.txt'), /NUL/);
  assert.equal(sanitizeFilename('evil\u202egnp.exe'), 'evil_gnp.exe');
  assert.equal(sanitizeFilename('a\u007fb\u0085c\u200b.txt'), 'a_b_c_.txt');
  assert.equal(sanitizeFilename('.htaccess'), '_htaccess');
  assert.equal(sanitizeFilename('.htaccess', { allowLeadingDot: true }), '.htaccess');
  assert.equal(sanitizeFilename('..'), 'file');
  assert.equal(sanitizeFilename('...', { fallback: 'upload' }), 'upload');
  assert.equal(sanitizeFilename('C:\\Users\\me\\report.pdf'), 'report.pdf');

  const emoji = sanitizeFilename(`a${'😀'.repeat(100)}.png`);
  assert.ok(Buffer.byteLength(emoji) <= 180, String(Buffer.byteLength(emoji)));
  assert.equal(emoji.isWellFormed(), true);
  assert.ok(emoji.endsWith('.png'));
  const accents = sanitizeFilename(`${'é'.repeat(200)}.txt`, { maxBytes: 255 });
  assert.ok(Buffer.byteLength(accents) <= 255);
  assert.equal(sanitizeFilename('résumé.pdf', 20), 'résumé.pdf');
  assert.throws(() => sanitizeFilename('x', { maxBytes: 300 }), RangeError);
});
