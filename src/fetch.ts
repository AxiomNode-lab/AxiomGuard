import { assertSafeResolvedUrl, type SafeUrlOptions } from './web.js';

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);
const SENSITIVE_REDIRECT_HEADERS = ['authorization', 'cookie', 'proxy-authorization'] as const;
const FORBIDDEN_AUTHORITY_HEADERS = new Set(['host', 'connection', 'transfer-encoding', 'content-length', 'upgrade']);

export interface SafeFetchOptions extends SafeUrlOptions, Omit<RequestInit, 'redirect' | 'signal'> {
  /** Maximum number of redirects followed after re-validating every target. Default: 3. */
  maxRedirects?: number;
  /** Total timeout for the complete redirect chain. Default: 10 seconds. */
  timeoutMs?: number;
  /** Optional caller cancellation signal. */
  signal?: AbortSignal;
  /** Remove Authorization/Cookie/Proxy-Authorization when an allowed redirect changes origin. Default: true. */
  stripSensitiveHeadersOnCrossOriginRedirect?: boolean;
  /** Injectable fetch implementation for testing or controlled runtimes. */
  fetchImpl?: typeof fetch;
}

function validateSafeFetchOptions(options: SafeFetchOptions): void {
  const maxRedirects = options.maxRedirects ?? 3;
  if (!Number.isInteger(maxRedirects) || maxRedirects < 0 || maxRedirects > 10) {
    throw new RangeError('maxRedirects must be an integer between 0 and 10');
  }

  const timeoutMs = options.timeoutMs ?? 10_000;
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 120_000) {
    throw new RangeError('timeoutMs must be an integer between 1 and 120000');
  }
}

function validateRequestHeaders(headers: Headers): void {
  for (const name of headers.keys()) {
    if (FORBIDDEN_AUTHORITY_HEADERS.has(name.toLowerCase())) {
      throw new Error(`safeFetch does not allow overriding transport header: ${name}`);
    }
  }
}

function shouldRewriteRedirectToGet(status: number, method: string): boolean {
  if (status === 303 && method !== 'HEAD') return true;
  return (status === 301 || status === 302) && method === 'POST';
}

function stripCrossOriginCredentials(headers: Headers): void {
  for (const header of SENSITIVE_REDIRECT_HEADERS) headers.delete(header);
}

async function cancelResponseBody(response: Response): Promise<void> {
  try {
    await response.body?.cancel();
  } catch {
    // Best-effort cleanup only. A redirect target is validated independently.
  }
}

/**
 * Fetch a public HTTP(S) resource while applying AxiomGuard URL checks before
 * the first request and before every followed redirect.
 *
 * This reduces common SSRF and credential-forwarding mistakes but cannot pin
 * DNS resolution to the connection used by the underlying fetch transport.
 * High-risk environments still need egress/network controls.
 */
export async function safeFetch(input: string | URL, options: SafeFetchOptions = {}): Promise<Response> {
  validateSafeFetchOptions(options);

  const {
    protocols,
    allowedHosts,
    allowCredentials,
    maxRedirects = 3,
    timeoutMs = 10_000,
    stripSensitiveHeadersOnCrossOriginRedirect = true,
    fetchImpl,
    signal: callerSignal,
    method: initialMethod,
    headers: initialHeaders,
    body: initialBody,
    ...requestInit
  } = options;

  const urlOptions: SafeUrlOptions = {
    ...(protocols ? { protocols } : {}),
    ...(allowedHosts ? { allowedHosts } : {}),
    ...(allowCredentials !== undefined ? { allowCredentials } : {}),
  };

  const fetcher = fetchImpl ?? globalThis.fetch;
  if (typeof fetcher !== 'function') throw new Error('safeFetch requires a Fetch API implementation');

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(new Error(`safeFetch timed out after ${timeoutMs}ms`)), timeoutMs);
  timeout.unref?.();

  const relayAbort = (): void => controller.abort(callerSignal?.reason);
  if (callerSignal?.aborted) relayAbort();
  else callerSignal?.addEventListener('abort', relayAbort, { once: true });

  try {
    let currentUrl = await assertSafeResolvedUrl(input, urlOptions);
    let method = (initialMethod ?? 'GET').toUpperCase();
    let body = initialBody;
    let headers = new Headers(initialHeaders);
    validateRequestHeaders(headers);

    for (let redirects = 0; ; redirects += 1) {
      const init: RequestInit = {
        ...requestInit,
        method,
        headers,
        redirect: 'manual',
        signal: controller.signal,
      };
      if (body !== undefined) init.body = body;

      const response = await fetcher(currentUrl, init);
      if (!REDIRECT_STATUSES.has(response.status)) return response;

      const location = response.headers.get('location');
      if (!location) return response;
      if (redirects >= maxRedirects) {
        await cancelResponseBody(response);
        throw new Error(`safeFetch exceeded maxRedirects (${maxRedirects})`);
      }

      const nextCandidate = new URL(location, currentUrl);
      const nextUrl = await assertSafeResolvedUrl(nextCandidate, urlOptions);
      const originChanged = nextUrl.origin !== currentUrl.origin;

      if (originChanged && stripSensitiveHeadersOnCrossOriginRedirect) {
        headers = new Headers(headers);
        stripCrossOriginCredentials(headers);
      }

      if (shouldRewriteRedirectToGet(response.status, method)) {
        method = 'GET';
        body = undefined;
        headers = new Headers(headers);
        headers.delete('content-type');
      } else if (body !== undefined) {
        await cancelResponseBody(response);
        throw new Error('safeFetch refuses to replay a request body across a redirect; handle the redirect explicitly');
      }

      await cancelResponseBody(response);
      currentUrl = nextUrl;
    }
  } finally {
    clearTimeout(timeout);
    callerSignal?.removeEventListener('abort', relayAbort);
  }
}
