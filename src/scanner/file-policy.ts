import path from 'node:path';

export const DEFAULT_IGNORE_DIRECTORIES = Object.freeze([
  '.git',
  'node_modules',
  'dist',
  'build',
  'coverage',
  '.next',
  '.cache',
  '.axiomguard',
  'vendor',
  '.venv',
  'venv',
  '__pycache__',
  'target',
]);
export const DEFAULT_MAX_FILE_BYTES = 1_000_000;
export const DEFAULT_FILESYSTEM_CONCURRENCY = 16;

const TEXT_EXTENSIONS = new Set([
  '.js', '.mjs', '.cjs', '.ts', '.mts', '.cts', '.tsx', '.jsx', '.vue', '.svelte', '.astro',
  '.json', '.json5', '.jsonc', '.yml', '.yaml', '.toml', '.ini', '.conf', '.cfg', '.properties', '.xml', '.plist',
  '.env', '.txt', '.md', '.mdx', '.rst', '.adoc',
  '.sh', '.bash', '.zsh', '.fish', '.ps1', '.bat', '.cmd',
  '.py', '.rb', '.go', '.rs', '.java', '.kt', '.kts', '.scala', '.groovy', '.gradle', '.php', '.cs', '.fs', '.swift', '.dart', '.ex', '.exs', '.erl', '.hs', '.lua', '.pl', '.pm', '.r', '.c', '.h', '.cc', '.cpp', '.hpp', '.m', '.mm',
  '.html', '.htm', '.css', '.scss', '.less',
  '.sql', '.graphql', '.gql', '.proto', '.tf', '.tfvars', '.hcl', '.nomad', '.dockerfile', '.ipynb', '.csv', '.tsv',
  '.pem', '.key', '.crt', '.cer', '.p8', '.ppk', '.asc', '.gpg',
]);

const TEXT_BASENAMES = new Set([
  'dockerfile', 'containerfile', 'makefile', 'gnumakefile', 'rakefile', 'gemfile', 'procfile', 'vagrantfile', 'jenkinsfile', 'brewfile', 'justfile',
  '.npmrc', '.yarnrc', '.pypirc', '.netrc', '.htpasswd', '.git-credentials', '.pgpass', '.my.cnf', '.boto', '.s3cfg', '.dockercfg',
  'id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519', 'credentials', 'config', 'secrets', 'known_hosts',
]);

export function normalizePathSeparators(filePath: string): string {
  return filePath.split(path.sep).join('/');
}

export function compareStrings(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function escapeRegExp(value: string): string {
  return value.replace(/[|\\{}()[\]^$+?.]/g, '\\$&');
}

export function globToRegExp(pattern: string): RegExp {
  const normalized = normalizePathSeparators(pattern).replace(/^\.\//, '');
  let source = '^';
  for (let index = 0; index < normalized.length; index += 1) {
    const char = normalized[index]!;
    if (char === '*') {
      if (normalized[index + 1] === '*') {
        if (normalized[index + 2] === '/') {
          source += '(?:.*/)?';
          index += 2;
        } else {
          source += '.*';
          index += 1;
        }
      } else {
        source += '[^/]*';
      }
    } else if (char === '?') {
      source += '[^/]';
    } else {
      source += escapeRegExp(char);
    }
  }
  return new RegExp(`${source}$`);
}

export function isSupportedTextPath(filePath: string): boolean {
  const base = path.basename(filePath).toLowerCase();
  if (TEXT_BASENAMES.has(base) || base === '.env' || base.startsWith('.env.') || base.endsWith('.env')) return true;
  return TEXT_EXTENSIONS.has(path.extname(base));
}

export async function mapWithConcurrency<T, R>(items: readonly T[], limit: number, worker: (item: T) => Promise<R>): Promise<R[]> {
  const results: R[] = new Array<R>(items.length);
  let next = 0;
  const runners = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const index = next;
      next += 1;
      results[index] = await worker(items[index]!);
    }
  });
  await Promise.all(runners);
  return results;
}
