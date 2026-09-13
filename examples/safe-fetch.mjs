// Fetch a user-supplied URL without exposing internal services.
import { SafeFetchError, SafeUrlError, safeFetch } from '../dist/index.js';

async function attempt(url, options = {}) {
  try {
    const response = await safeFetch(url, { timeoutMs: 5_000, maxRedirects: 2, maxResponseBytes: 1_000_000, ...options });
    console.log('ok', url, response.status, response.url);
  } catch (error) {
    if (error instanceof SafeUrlError || error instanceof SafeFetchError) console.log('blocked', url, error.code, error.message);
    else console.log('failed', url, error.message);
  }
}

await attempt('http://127.0.0.1:8080/admin');
await attempt('http://169.254.169.254/latest/meta-data/');
await attempt('http://localhost./');
await attempt('https://example.com/', { allowedHosts: ['*.example.org'] });
await attempt('https://example.com/');
