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
 *  - **Private-address refusal.** On by default, because a server resolving arbitrary counterparty DIDs is
 *    the common case; local development opts out to reach `localhost`. It is enforced on the
 *    address actually connected to, not the hostname text: a counterparty
 *    controls their DNS, so a name that looks public can resolve to an
 *    internal address. The name is resolved once, every answer is checked, and
 *    the connection is made to that checked answer, so a second lookup cannot
 *    return something different (DNS rebinding).
 */

import { isPrivateAddress } from './address.ts';

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
   * Refuse loopback, link-local, private and other non-public addresses, both
   * when written into the URL and when a hostname resolves to one. On by
   * default, so a server resolving arbitrary DIDs is protected unless it opts
   * out; set `false` for local development against `localhost`.
   *
   * The resolved-address check needs to control the connection, so it applies
   * only to the built-in transport. A caller-supplied `fetch` is responsible
   * for its own network policy and only gets the literal-address check.
   */
  readonly blockPrivateAddresses?: boolean;
  /** Resolve a hostname to every address it maps to. Injected for tests. */
  readonly lookup?: (hostname: string) => Promise<readonly ResolvedAddress[]>;
  /** Replaces the transport entirely. Injected for tests. */
  readonly fetch?: typeof globalThis.fetch;
}

export const DEFAULT_TIMEOUT_MS = 10_000;
/** Comfortably above a realistic log or status list, far below a denial of service. */
export const DEFAULT_MAX_BYTES = 5 * 1024 * 1024;

export interface ResolvedAddress {
  readonly address: string;
  readonly family: number;
}

/** Names that mean "this machine" whatever DNS says. */
const LOCAL_NAMES = /^localhost$|\.localhost$/i;

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

  if (options.blockPrivateAddresses !== false) {
    const host = parsed.hostname;
    if (LOCAL_NAMES.test(host) || isPrivateAddress(host)) {
      throw new FetchError(
        `Refusing to fetch "${url}": "${host}" is a loopback, link-local or private address`,
        url,
      );
    }
  }

  return parsed;
}

/**
 * A `fetch` that resolves the host itself, refuses if any answer is
 * non-public, and connects to the address it checked.
 *
 * Node's `fetch` offers no hook between resolution and connection, so this
 * uses `node:https`, whose `lookup` option is exactly that hook. Certificate
 * and hostname verification are unchanged: TLS still validates against the
 * name in the URL, only the address dialled is pinned.
 */
function guardedFetch(url: string, resolve?: FetchOptions['lookup']): typeof globalThis.fetch {
  return async (input, init) => {
    const [{ request }, { lookup: dnsLookup }, { Readable }] = await Promise.all([
      import('node:https'),
      import('node:dns/promises'),
      import('node:stream'),
    ]);
    const target = input instanceof URL ? input : new URL(input instanceof Request ? input.url : input);
    const resolveAll = resolve ?? ((hostname: string) => dnsLookup(hostname, { all: true }));

    return new Promise<Response>((fulfil, reject) => {
      const req = request(
        {
          protocol: target.protocol,
          hostname: target.hostname.replace(/^\[|\]$/g, ''),
          port: target.port === '' ? 443 : Number(target.port),
          path: `${target.pathname}${target.search}`,
          method: 'GET',
          headers: Object.fromEntries(new Headers(init?.headers).entries()),
          ...(init?.signal ? { signal: init.signal } : {}),
          lookup: (hostname, options, callback) => {
            resolveAll(hostname).then(
              (answers) => {
                const blocked = answers.find((answer) => isPrivateAddress(answer.address));
                if (answers.length === 0 || blocked) {
                  const why = blocked
                    ? `"${hostname}" resolves to ${blocked.address}, a loopback, link-local or private address`
                    : `"${hostname}" did not resolve to any address`;
                  callback(new FetchError(`Refusing to fetch "${url}": ${why}`, url), '', 0);
                  return;
                }
                if (options.all === true) {
                  (callback as (error: null, all: ResolvedAddress[]) => void)(null, [...answers]);
                } else {
                  const [first] = answers as [ResolvedAddress];
                  callback(null, first.address, first.family);
                }
              },
              (error: unknown) => {
                callback(error as NodeJS.ErrnoException, '', 0);
              },
            );
          },
        },
        (res) => {
          // This runs on a counterparty-controlled response, and an exception in
          // an event callback is uncaught, so any failure becomes a rejection.
          try {
            const status = res.statusCode ?? 0;
            if (status < 200 || status > 599) {
              throw new FetchError(`"${url}" returned an unusable status ${status}`, url, { status });
            }
            const headers = new Headers();
            for (const [name, value] of Object.entries(res.headers)) {
              for (const item of Array.isArray(value) ? value : value === undefined ? [] : [value]) {
                headers.append(name, item);
              }
            }
            const bodyless = status === 204 || status === 205 || status === 304;
            if (bodyless) res.resume();
            fulfil(
              new Response(bodyless ? null : (Readable.toWeb(res) as ReadableStream<Uint8Array>), {
                status,
                headers,
              }),
            );
          } catch (error) {
            res.destroy();
            reject(error instanceof Error ? error : new Error(String(error)));
          }
        },
      );
      req.on('error', reject);
      req.end();
    });
  };
}

/** Fetch text under the guards above. */
export async function fetchText(url: string, options: FetchOptions = {}): Promise<string> {
  const { timeoutMs = DEFAULT_TIMEOUT_MS, maxBytes = DEFAULT_MAX_BYTES } = options;

  const target = assertFetchableUrl(url, options);
  const doFetch =
    options.fetch ??
    (options.blockPrivateAddresses !== false ? guardedFetch(url, options.lookup) : globalThis.fetch);
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
