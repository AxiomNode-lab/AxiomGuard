import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import {
  assertSafeUrl,
  constantTimeCompare,
  isPrivateIPAddress,
  maskPII,
  redactSecrets,
  safePath,
  sanitizeFilename,
  secureToken,
  validateEnv,
  validateRedirect,
  verifyHmacWebhook,
} from '../dist/index.js';

test('redactSecrets redacts sensitive keys without mutating input', () => {
  const input = { user: 'imed', password: 'secret123', nested: { api_key: 'abc' } };
  const result = redactSecrets(input);
  assert.equal(result.password, '[REDACTED]');
  assert.equal(result.nested.api_key, '[REDACTED]');
  assert.equal(input.password, 'secret123');
});

test('maskPII masks email and IPv4', () => {
  const value = maskPII('mail user@example.com from 192.168.1.15');
  assert.match(value, /u\*\*\*@example\.com/);
  assert.match(value, /192\.168\.\*\.\*/);
});

test('validateEnv parses typed values', () => {
  const result = validateEnv(
    { PORT: 'integer', ENABLED: 'boolean', API_URL: 'url', SECRET: { type: 'string', minLength: 8 } },
    { PORT: '3000', ENABLED: 'true', API_URL: 'https://example.com', SECRET: 'abcdefgh' },
  );
  assert.equal(result.ok, true);
  assert.equal(result.values.PORT, 3000);
  assert.equal(result.values.ENABLED, true);
});

test('verifyHmacWebhook validates a SHA-256 signature', () => {
  const payload = Buffer.from('{"ok":true}');
  const secret = 'test-secret';
  const signature = `sha256=${createHmac('sha256', secret).update(payload).digest('hex')}`;
  assert.equal(verifyHmacWebhook(payload, signature, secret), true);
  assert.equal(verifyHmacWebhook(payload, `${signature}00`, secret), false);
});

test('secureToken returns URL-safe random token', () => {
  const token = secureToken(32);
  assert.match(token, /^[A-Za-z0-9_-]+$/);
  assert.ok(token.length >= 40);
});

test('constantTimeCompare compares values', () => {
  assert.equal(constantTimeCompare('abc', 'abc'), true);
  assert.equal(constantTimeCompare('abc', 'abd'), false);
  assert.equal(constantTimeCompare('abc', 'abc0'), false);
});

test('assertSafeUrl blocks local and private targets', () => {
  assert.throws(() => assertSafeUrl('http://127.0.0.1/admin'));
  assert.throws(() => assertSafeUrl('http://localhost:3000'));
  assert.throws(() => assertSafeUrl('http://10.0.0.1'));
  assert.equal(assertSafeUrl('https://example.com/path').hostname, 'example.com');
});

test('isPrivateIPAddress detects common private ranges', () => {
  assert.equal(isPrivateIPAddress('192.168.1.1'), true);
  assert.equal(isPrivateIPAddress('8.8.8.8'), false);
  assert.equal(isPrivateIPAddress('::1'), true);
});

test('validateRedirect requires an allowed origin', () => {
  assert.equal(validateRedirect('https://app.example.com/callback', ['https://app.example.com']).pathname, '/callback');
  assert.throws(() => validateRedirect('https://evil.example/callback', ['https://app.example.com']));
});

test('safePath prevents traversal', () => {
  assert.match(safePath('/tmp/workspace', 'uploads/a.txt'), /uploads\/a\.txt$/);
  assert.throws(() => safePath('/tmp/workspace', '../../etc/passwd'));
});

test('sanitizeFilename removes path and reserved characters', () => {
  assert.equal(sanitizeFilename('../../bad:name?.txt'), 'bad_name_.txt');
  assert.equal(sanitizeFilename('CON'), '_CON');
});
