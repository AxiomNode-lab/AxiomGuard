// Compile-only type assertions. Run via `npm run test:types`.
import { requireEnv, validateEnv, type InferEnv } from '../../dist/index.js';

const env = requireEnv({
  PORT: { type: 'port', default: 3000 },
  API_URL: 'url',
  DEBUG: 'boolean',
  TAGS: 'list',
  TIMEOUT: 'duration',
  RAW: 'json',
  OPTIONAL: { type: 'string', required: false },
  MODE: { type: 'string', allowed: ['development', 'production'] },
}, {});

const port: number = env.PORT;
const url: string = env.API_URL;
const debug: boolean = env.DEBUG;
const tags: string[] = env.TAGS;
const timeout: number = env.TIMEOUT;
const raw: unknown = env.RAW;
const optional: string | undefined = env.OPTIONAL;
const mode: string = env.MODE;

// @ts-expect-error PORT is a number, not a string.
const wrongPort: string = env.PORT;
// @ts-expect-error OPTIONAL may be undefined.
const wrongOptional: string = env.OPTIONAL;
// @ts-expect-error the result is frozen.
env.PORT = 4000;

type Inferred = InferEnv<{ A: 'integer'; B: { type: 'boolean'; required: false } }>;
const inferred: Inferred = { A: 1, B: undefined };
const partial = validateEnv({ A: 'integer' }, {}).values;
const maybe: number | undefined = partial.A;

void [port, url, debug, tags, timeout, raw, optional, mode, wrongPort, wrongOptional, inferred, maybe];
