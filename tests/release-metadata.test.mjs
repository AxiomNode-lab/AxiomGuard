import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { join } from 'node:path';
import test from 'node:test';
import assert from 'node:assert/strict';

const execFileAsync = promisify(execFile);

test('published release metadata guard rejects Unreleased and accepts a dated entry', async () => {
  const tempDir = await mkdtemp(join(process.env.RUNNER_TEMP ?? process.env.TMPDIR ?? '/tmp', 'axiomguard-release-check-'));

  try {
    await mkdir(join(tempDir, 'scripts'), { recursive: true });

    for (const file of ['package.json', 'package-lock.json', 'scripts/check-published-release.mjs']) {
      const source = join(process.cwd(), file);
      const target = join(tempDir, file);
      await cp(source, target, { recursive: false });
    }

    const changelogSource = await readFile('CHANGELOG.md', 'utf8');
    const changelogTarget = join(tempDir, 'CHANGELOG.md');
    await writeFile(changelogTarget, changelogSource, 'utf8');

    await assert.rejects(
      execFileAsync(process.execPath, [join(tempDir, 'scripts/check-published-release.mjs')], {
        cwd: tempDir,
      }),
      (error) => error?.stderr?.includes('CHANGELOG.md entry') && error.stderr.includes('YYYY-MM-DD'),
    );

    const datedChangelog = changelogSource.replace(
      /^## \[(\d+\.\d+\.\d+)\] - Unreleased$/m,
      '## [$1] - 2000-01-01',
    );
    await writeFile(changelogTarget, datedChangelog, 'utf8');

    await execFileAsync(process.execPath, [join(tempDir, 'scripts/check-published-release.mjs')], {
      cwd: tempDir,
    });
  } finally {
    await rm(tempDir, { recursive: true, force: true });
  }
});
