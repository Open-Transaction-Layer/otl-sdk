/**
 * Guarded HTTPS fetching.
 *
 * Everything this module retrieves is named by a counterparty and served from
 * infrastructure they control, so a resolver is a request-forgery primitive
 * unless it is constrained. The guards, and why each is here:
 *
 *  - **HTTPS only.** Every endpoint the Identity layer defines is HTTPS
 *    (spec 2, 4.4, 5.2), and plaintext would let a network attacker rewrite
 *    a DID document in transit.
 *  - **Response size cap.** A status list is at minimum 131,072 bits (spec 5.2)
 *    but decompresses from a few hundred bytes; without a cap, a hostile
 *    endpoint can stream indefinitely, or serve a compression bomb.
 *  - **Timeout.** An endpoint that accepts a connection and never responds
 *    would otherwise stall validation forever.
 *  - **No cross-origin redirects.** Following one lets a counterparty's domain
 *    redirect a resolver at an internal host, which is the classic SSRF shape.
 *  - **Optional private-address refusal.** Off by default because local
 *    development needs `localhost`, but it must be on for any server-side
 *    deployment resolving arbitrary counterparty DIDs. It matches hostname
 *    literals only and does not resolve DNS.
 */

export class FetchError extends Error {
  readonly url: string;
  readonly status?: number;
  constructor(message: string, url: string, options?: { status?: number; cause?: unknown }) {
    super(message, options);
    this.name = 'FetchError';
    this.url = url;
    if (options?.status !== undefined) this.status = options.status;
  }
}

export interface FetchOptions {
  /** Milliseconds before the request is abandoned. */
  readonly timeoutMs?: number;
  /** Maximum bytes accepted before the response is abandoned. */
  readonly maxBytes?: number;
  /**
   * Refuse URLs whose hostname is a loopback, link-local or private-range
   * literal (for example `localhost`, `127.0.0.1` or `10.0.0.1`). Off by
   * default so local development works, and it must be turned on for any
   * server resolving arbitrary DIDs.
   *
   * This filters hostname literals only and does not resolve DNS, so it does
   * not stop a public DNS name that resolves to a private address. A server
   * that needs that protection must also constrain outbound traffic at the
   * network layer or supply a `fetch` that checks resolved addresses.
   */
  readonly blockPrivateAddresses?: boolean;
  /** Injected for tests. */
  readonly fetch?: typeof globalThis.fetch;
}

export const DEFAULT_TIMEOUT_MS = 10_000;
/** Comfortably above a realistic log or status list, far below a denial of service. */
export const DEFAULT_MAX_BYTES = 5 * 1024 * 1024;

/** Hosts that should never be reachable from a counterparty-supplied identifier. */
const PRIVATE_HOST_PATTERNS = [
  /^localhost$/i,
  /^127\./,
  /^0\.0\.0\.0$/,
  /^10\./,
  /^192\.168\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^169\.254\./, // link-local, including cloud metadata at 169.254.169.254
  /^\[?::1\]?$/,
  /^\[?f[cd][0-9a-f]{2}:/i, // unique local addresses
];

export function assertFetchableUrl(url: string, options: FetchOptions = {}): URL {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch (cause) {
    throw new FetchError(`"${url}" is not a valid URL`, url, { cause });
  }

  if (parsed.protocol !== 'https:') {
    throw new FetchError(`Refusing to fetch "${url}": the Identity layer requires HTTPS`, url);
  }

  if (options.blockPrivateAddresses === true) {
    const host = parsed.hostname;
    if (PRIVATE_HOST_PATTERNS.some((pattern) => pattern.test(host))) {
      throw new FetchError(
        `Refusing to fetch "${url}": "${host}" is a loopback, link-local or private address`,
        url,
      );
    }
  }

  return parsed;
}

/** Fetch text under the guards above. */
export async function fetchText(url: string, options: FetchOptions = {}): Promise<string> {
  const {
    timeoutMs = DEFAULT_TIMEOUT_MS,
    maxBytes = DEFAULT_MAX_BYTES,
    fetch: doFetch = globalThis.fetch,
  } = options;

  const target = assertFetchableUrl(url, options);
  const controller = new AbortController();
  const timer = setTimeout(() => {
    controller.abort();
  }, timeoutMs);

  try {
    const response = await doFetch(target, {
      // A cross-origin redirect is how a counterparty would aim a resolver at
      // an internal host, so redirects are surfaced rather than followed.
      redirect: 'manual',
      signal: controller.signal,
      headers: { Accept: 'application/json, application/jsonl, application/vp, text/plain' },
    });

    if (response.status >= 300 && response.status < 400) {
      throw new FetchError(
        `Refusing to follow a redirect from "${url}" to "${response.headers.get('location') ?? 'an unspecified location'}"`,
        url,
        { status: response.status },
      );
    }
    if (!response.ok) {
      throw new FetchError(`HTTP ${response.status} fetching "${url}"`, url, { status: response.status });
    }

    return await readCapped(response, url, maxBytes);
  } catch (error) {
    if (error instanceof FetchError) throw error;
    if ((error as { name?: string } | null | undefined)?.name === 'AbortError') {
      throw new FetchError(`Timed out after ${timeoutMs}ms fetching "${url}"`, url, { cause: error });
    }
    throw new FetchError(`Could not fetch "${url}": ${(error as Error).message}`, url, { cause: error });
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Read the body, abandoning it once the cap is exceeded.
 *
 * Checking `Content-Length` alone would not do: it is supplied by the same
 * party serving the body, and a chunked response need not declare one at all.
 */
async function readCapped(response: Response, url: string, maxBytes: number): Promise<string> {
  const declared = Number(response.headers.get('content-length'));
  if (Number.isFinite(declared) && declared > maxBytes) {
    throw new FetchError(`"${url}" declares ${declared} bytes, above the ${maxBytes}-byte limit`, url);
  }

  const body = response.body;
  if (!body) return '';

  // The runtime types the stream's chunks as `any`; a fetch body is bytes.
  const reader = body.getReader() as ReadableStreamDefaultReader<Uint8Array>;
  const chunks: Uint8Array[] = [];
  let total = 0;

  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        throw new FetchError(`"${url}" exceeded the ${maxBytes}-byte limit`, url);
      }
      chunks.push(value);
    }
  } finally {
    await reader.cancel().catch(() => undefined);
  }

  return new TextDecoder().decode(concat(chunks, total));
}

function concat(chunks: readonly Uint8Array[], total: number): Uint8Array {
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return out;
}

/** Fetch and parse JSON under the same guards. */
export async function fetchJson<T = unknown>(url: string, options: FetchOptions = {}): Promise<T> {
  const text = await fetchText(url, options);
  try {
    return JSON.parse(text) as T;
  } catch (cause) {
    throw new FetchError(`"${url}" did not return valid JSON`, url, { cause });
  }
}
