import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import test from 'node:test';
import assert from 'node:assert/strict';

const execFileAsync = promisify(execFile);
const script = 'scripts/check-release-tag.mjs';

function envFor(tag, prerelease) {
  return {
    ...process.env,
    RELEASE_TAG: tag,
    RELEASE_PRERELEASE: prerelease ? 'true' : 'false',
  };
}

test('release tag validator accepts stable and prerelease metadata', async () => {
  await execFileAsync(process.execPath, [script], { env: envFor('v0.8.0', false) });
  await execFileAsync(process.execPath, [script], { env: envFor('v0.8.0-beta.1', true) });
});

test('release tag validator rejects mismatched prerelease metadata', async () => {
  await assert.rejects(
    execFileAsync(process.execPath, [script], { env: envFor('v0.8.0-beta.1', false) }),
    /prerelease flag does not match/,
  );
  await assert.rejects(
    execFileAsync(process.execPath, [script], { env: envFor('v0.8.0', true) }),
    /prerelease flag does not match/,
  );
});

test('release tag validator rejects malformed tags', async () => {
  await assert.rejects(
    execFileAsync(process.execPath, [script], { env: envFor('0.8.0-beta.1', true) }),
    /invalid release tag/,
  );
});
