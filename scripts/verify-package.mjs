import { spawnSync } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

const root = process.cwd();

function run(command, args, cwd = root) {
  const result = spawnSync(command, args, { cwd, encoding: 'utf8', env: process.env });
  if (result.status !== 0) {
    process.stderr.write(result.stdout ?? '');
    process.stderr.write(result.stderr ?? '');
    throw new Error(`${command} ${args.join(' ')} failed with exit code ${result.status}`);
  }
  return result.stdout;
}

const packOutput = run('npm', ['pack', '--json', '--ignore-scripts']);
const packResult = JSON.parse(packOutput);
if (!Array.isArray(packResult) || packResult.length !== 1 || typeof packResult[0]?.filename !== 'string') {
  throw new Error('npm pack did not return one package archive');
}

const archive = path.join(root, packResult[0].filename);
const workspace = await mkdtemp(path.join(tmpdir(), 'axiomguard-package-'));

try {
  run('npm', ['init', '-y'], workspace);
  run('npm', ['install', '--ignore-scripts', '--no-audit', '--no-fund', archive], workspace);

  const consumer = `
const subpaths = [
  'api-keys','cookies','cors','crypto','csrf','env','fetch','filesystem','headers','idempotency','logging','presets','rate-limit','request-policy','scanner','web','webhooks',
  'adapters','adapters/express','adapters/fastify','adapters/hono','adapters/redis'
];
const root = await import('@axiomnode-lab/guard');
if (typeof root.secureToken !== 'function' || typeof root.safeFetch !== 'function') throw new Error('root export is incomplete');
if (typeof root.evaluateRequestPolicy !== 'function' || typeof root.claimIdempotencyKey !== 'function') throw new Error('API protection exports are incomplete');
if (typeof root.verifyMetaWebhook !== 'function' || typeof root.verifySlackWebhook !== 'function') throw new Error('provider webhook exports are incomplete');
for (const subpath of subpaths) {
  const module = await import('@axiomnode-lab/guard/' + subpath);
  if (Object.keys(module).length === 0) throw new Error('empty subpath export: ' + subpath);
}
`;
  await writeFile(path.join(workspace, 'verify.mjs'), consumer, 'utf8');
  run(process.execPath, ['verify.mjs'], workspace);

  const typeConsumer = `
import { claimIdempotencyKey, evaluateRequestPolicy, secureToken, safeFetch, verifyMetaWebhook } from '@axiomnode-lab/guard';
import { MemoryIdempotencyStore } from '@axiomnode-lab/guard/idempotency';
import { verifyGitHubWebhookDelivery } from '@axiomnode-lab/guard/webhooks';
const token: string = secureToken();
const store = new MemoryIdempotencyStore();
void token;
void store;
void safeFetch;
void claimIdempotencyKey;
void evaluateRequestPolicy;
void verifyMetaWebhook;
void verifyGitHubWebhookDelivery;
`;
  await writeFile(path.join(workspace, 'consumer.ts'), typeConsumer, 'utf8');
  const tsc = path.join(root, 'node_modules', 'typescript', 'bin', 'tsc');
  run(process.execPath, [tsc, '--module', 'NodeNext', '--moduleResolution', 'NodeNext', '--target', 'ES2022', '--strict', '--skipLibCheck', '--noEmit', '--typeRoots', path.join(root, 'node_modules', '@types'), 'consumer.ts'], workspace);

  const installedPackage = JSON.parse(await readFile(path.join(workspace, 'node_modules', '@axiomnode-lab', 'guard', 'package.json'), 'utf8'));
  if (installedPackage.version !== packResult[0].version) throw new Error('installed tarball version does not match npm pack metadata');
  run(process.execPath, [path.join(workspace, 'node_modules', '@axiomnode-lab', 'guard', 'dist', 'cli.js'), 'scan', workspace, '--no-fail'], workspace);

  console.log(`Verified clean-room install of @axiomnode-lab/guard@${installedPackage.version}`);
} finally {
  await rm(workspace, { recursive: true, force: true });
  await rm(archive, { force: true });
}
