import { spawnSync } from 'node:child_process';
import { access, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import process from 'node:process';

const root = process.cwd();
const packageJson = JSON.parse(await readFile(path.join(root, 'package.json'), 'utf8'));
const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';

function run(command, args, cwd = root) {
  const result = spawnSync(command, args, { cwd, encoding: 'utf8', env: process.env, shell: process.platform === 'win32' });
  if (result.status !== 0) {
    process.stderr.write(result.stdout ?? '');
    process.stderr.write(result.stderr ?? '');
    throw new Error(`${command} ${args.join(' ')} failed with exit code ${result.status}`);
  }
  return result.stdout;
}

const packOutput = run(npm, ['pack', '--json', '--ignore-scripts']);
const packResult = JSON.parse(packOutput);
if (!Array.isArray(packResult) || packResult.length !== 1 || typeof packResult[0]?.filename !== 'string') {
  throw new Error('npm pack did not return one package archive');
}

const archive = path.join(root, packResult[0].filename);
const workspace = await mkdtemp(path.join(tmpdir(), 'axiomguard-package-'));

try {
  run(npm, ['init', '-y'], workspace);
  run(npm, ['install', '--ignore-scripts', '--no-audit', '--no-fund', archive], workspace);

  const subpaths = Object.keys(packageJson.exports).filter((key) => key !== '.' && key !== './package.json').map((key) => key.slice(2));
  const consumer = `
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const subpaths = ${JSON.stringify(subpaths)};
const root = await import('@axiomnode-lab/guard');
if (typeof root.secureToken !== 'function' || typeof root.safeFetch !== 'function') throw new Error('root export is incomplete');
if (typeof root.evaluateRequestPolicy !== 'function' || typeof root.claimIdempotencyKey !== 'function') throw new Error('API protection exports are incomplete');
if (typeof root.verifyMetaWebhook !== 'function' || typeof root.verifyStandardWebhook !== 'function') throw new Error('provider webhook exports are incomplete');
if (typeof require('@axiomnode-lab/guard').safeFetch !== 'function') throw new Error('require() of the root export failed');
if (require('@axiomnode-lab/guard/package.json').version !== ${JSON.stringify(packageJson.version)}) throw new Error('package.json export mismatch');
for (const subpath of subpaths) {
  const module = await import('@axiomnode-lab/guard/' + subpath);
  if (Object.keys(module).length === 0) throw new Error('empty subpath export: ' + subpath);
  if (Object.keys(require('@axiomnode-lab/guard/' + subpath)).length !== Object.keys(module).length) throw new Error('require() surface differs: ' + subpath);
}
`;
  await writeFile(path.join(workspace, 'verify.mjs'), consumer, 'utf8');
  run(process.execPath, ['verify.mjs'], workspace);

  const typeConsumer = `
import { claimIdempotencyKey, evaluateRequestPolicy, requireEnv, secureToken, safeFetch, verifyMetaWebhook } from '@axiomnode-lab/guard';
import { MemoryIdempotencyStore } from '@axiomnode-lab/guard/idempotency';
import { verifyGitHubWebhookDelivery } from '@axiomnode-lab/guard/webhooks';
import { createFetchSecurityHandler } from '@axiomnode-lab/guard/adapters/fetch';
const token: string = secureToken();
const store = new MemoryIdempotencyStore();
const env = requireEnv({ PORT: { type: 'port', default: 3000 } }, {});
const port: number = env.PORT;
void token;
void store;
void port;
void safeFetch;
void claimIdempotencyKey;
void evaluateRequestPolicy;
void verifyMetaWebhook;
void verifyGitHubWebhookDelivery;
void createFetchSecurityHandler;
`;
  await writeFile(path.join(workspace, 'consumer.ts'), typeConsumer, 'utf8');
  const tsc = path.join(root, 'node_modules', 'typescript', 'bin', 'tsc');
  run(process.execPath, [tsc, '--module', 'NodeNext', '--moduleResolution', 'NodeNext', '--target', 'ES2022', '--strict', '--skipLibCheck', '--noEmit', '--typeRoots', path.join(root, 'node_modules', '@types'), 'consumer.ts'], workspace);

  const installedPackage = JSON.parse(await readFile(path.join(workspace, 'node_modules', '@axiomnode-lab', 'guard', 'package.json'), 'utf8'));
  if (installedPackage.version !== packResult[0].version) throw new Error('installed tarball version does not match npm pack metadata');
  if (installedPackage.bin?.axiomguard !== 'dist/cli.js') throw new Error('published package metadata does not expose the axiomguard CLI');

  const shim = path.join(workspace, 'node_modules', '.bin', process.platform === 'win32' ? 'axiomguard.cmd' : 'axiomguard');
  await access(shim);
  run(npm, ['exec', '--', 'axiomguard', '--help'], workspace);
  run(process.execPath, [path.join(workspace, 'node_modules', '@axiomnode-lab', 'guard', 'dist', 'cli.js'), 'scan', workspace, '--no-fail'], workspace);

  console.log(`Verified clean-room install of @axiomnode-lab/guard@${installedPackage.version}, including the CLI shim`);
} finally {
  await rm(workspace, { recursive: true, force: true });
  await rm(archive, { force: true });
}
