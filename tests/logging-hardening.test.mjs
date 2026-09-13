import test from 'node:test';
import assert from 'node:assert/strict';
import { maskPII, redactSecrets } from '../dist/index.js';

test('redactSecrets preserves Errors, Dates, Maps, Sets and summarises binary data', () => {
  const error = new Error('boom with password=hunter2', { cause: new Error('root') });
  error.code = 'E1';
  error.password = 'p';
  const out = redactSecrets({ error, when: new Date('2026-09-12T10:00:00Z'), buf: Buffer.from('secret'), map: new Map([['token', 't'], ['x', 1]]), set: new Set([1, 2]), url: new URL('https://u:p@h/'), re: /x/g, big: 10n });
  assert.equal(out.error.name, 'Error');
  assert.equal(out.error.message, 'boom with password=hunter2', 'message text is kept unless it matches a credential pattern');
  assert.match(out.error.stack, /boom/);
  assert.equal(out.error.cause.message, 'root');
  assert.equal(out.error.code, 'E1');
  assert.equal(out.error.password, '[REDACTED]');
  assert.equal(out.when, '2026-09-12T10:00:00.000Z');
  assert.equal(out.buf, '[binary 6 bytes]');
  assert.deepEqual(out.map, { token: '[REDACTED]', x: 1 });
  assert.deepEqual(out.set, [1, 2]);
  assert.equal(out.url, 'https://u:[REDACTED]@h/');
  assert.equal(out.re, '/x/g');
  assert.equal(out.big, '10');
});

test('redactSecrets redacts camelCase, hyphenated and extra keys and keeps __proto__ as data', () => {
  const input = {
    accessToken: 'a', passwordHash: 'b', jwt: 'c', privateKey: 'd', clientSecret: 'e', sessionId: 'f', ssn: 'g', 'x-api-key': 'h', 'Set-Cookie': 'i',
    refresh_token: 'j', Authorization: 'k', apiKeyId: 'not-secret', tokens: 'not-secret-either', 'x-custom-secret-key': 'l', myCustom: 'm', safe: 'value',
  };
  const out = redactSecrets(input, { extraKeys: ['x-custom-secret-key', 'my_custom'] });
  for (const key of ['accessToken', 'passwordHash', 'jwt', 'privateKey', 'clientSecret', 'sessionId', 'ssn', 'x-api-key', 'Set-Cookie', 'refresh_token', 'Authorization', 'x-custom-secret-key', 'myCustom']) {
    assert.equal(out[key], '[REDACTED]', key);
  }
  assert.equal(out.apiKeyId, 'not-secret');
  assert.equal(out.tokens, 'not-secret-either');
  assert.equal(out.safe, 'value');

  const polluted = redactSecrets(JSON.parse('{"__proto__":{"polluted":1},"a":1}'));
  assert.equal(Object.getPrototypeOf(polluted), Object.prototype);
  assert.equal(polluted.polluted, undefined);
  assert.deepEqual(Object.keys(polluted).sort(), ['__proto__', 'a']);
});

test('redactSecrets string patterns cover JWTs, provider keys, basic auth and connection strings', () => {
  const jwt = ['eyJhbGciOiJIUzI1NiJ9', 'eyJzdWIiOiIxMjM0NTY3ODkwIn0', 'SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'].join('.');
  const text = [`jwt=${jwt}`, `openai=${['sk-', 'a'.repeat(20), 'T3BlbkFJ', 'b'.repeat(20)].join('')}`, `google=${['AIza', 'x'.repeat(35)].join('')}`, 'basic=Basic dXNlcjpwYXNz', ['db=postgres://app:', 'P4ssw0rd', '@db/app'].join(''), 'hdr=Bearer abcdefghijklmnop'].join(' ');
  const out = redactSecrets({ text }).text;
  assert.equal(out, 'jwt=[REDACTED] openai=[REDACTED] google=[REDACTED] basic=Basic [REDACTED] db=[REDACTED]db/app hdr=Bearer [REDACTED]');
});

test('maskPII leaves timestamps, epochs and UUIDs intact while masking phones and IPv6', () => {
  const text = 'at 2026-01-02T12:34:56Z ts=1757700000000 id=123e4567-e89b-12d3-a456-426614174000 req 20260912-191515 lat 48.856614 call +1 415 555 2671 or 0044 20 7946 0958 from 2001:db8:85a3::8a2e:370:7334 and 10.0.0.7';
  const out = maskPII(text);
  assert.match(out, /2026-01-02T12:34:56Z/);
  assert.match(out, /ts=1757700000000/);
  assert.match(out, /123e4567-e89b-12d3-a456-426614174000/);
  assert.match(out, /20260912-191515/);
  assert.match(out, /48\.856614/);
  assert.match(out, /\+1\*\*\*71/);
  assert.match(out, /00\*\*\*58/);
  assert.match(out, /2001:db8:\*\*\*\*/);
  assert.match(out, /10\.0\.\*\.\*/);
  assert.equal(maskPII('999.999.999.999'), '999.999.999.999', 'invalid IPv4 octets are neither addresses nor phones');
  assert.equal(maskPII('call 5551234567'), 'call 55***67', 'ten-digit national numbers are masked');
});
