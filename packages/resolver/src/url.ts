/**
 * did:webvh identifier to HTTPS URL (OTL spec 2.3).
 *
 * The transformation follows did:web for the domain portion, with two
 * did:webvh-specific points:
 *
 *  - the SCID is stripped: it authenticates the log, it does not address it;
 *  - the artifacts are `did.jsonl` (the version log) and `did.json` (the
 *    resolved document), rather than did:web's `did.json` alone.
 *
 * | DID                                    | Log URL                                        |
 * |----------------------------------------|------------------------------------------------|
 * | `did:webvh:{scid}:example.com`         | `https://example.com/.well-known/did.jsonl`    |
 * | `did:webvh:{scid}:example.com:a:b`     | `https://example.com/a/b/did.jsonl`            |
 *
 * Note the asymmetry: `.well-known` is used only when there is no path.
 */

export class InvalidDidError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'InvalidDidError';
  }
}

export interface ParsedDid {
  readonly did: string;
  readonly scid: string;
  /** Host, percent-decoded, so a port survives as `example.com:8443`. */
  readonly host: string;
  /** Path segments after the host; empty when the DID addresses a bare domain. */
  readonly pathSegments: readonly string[];
  /** Origin the artifacts are served from. */
  readonly origin: string;
}

const SCID_PATTERN = /^[1-9A-HJ-NP-Za-km-z]{20,}$/; // base58btc, no 0OIl

/** Percent-decode one DID component, reporting malformed escapes as an invalid DID. */
function decodeSegment(did: string, segment: string): string {
  try {
    return decodeURIComponent(segment);
  } catch {
    throw new InvalidDidError(`"${did}" contains a malformed percent-encoding`);
  }
}

export function parseDid(did: string): ParsedDid {
  if (!did.startsWith('did:webvh:')) {
    throw new InvalidDidError(`"${did}" is not a did:webvh identifier`);
  }

  const parts = did.slice('did:webvh:'.length).split(':');
  const scid = parts[0];
  if (scid === undefined || !SCID_PATTERN.test(scid)) {
    throw new InvalidDidError(
      `"${did}" has no SCID component. The format is did:webvh:{SCID}:{domain} — ` +
        `the specification's examples omit the SCID for brevity, but did:webvh ` +
        `requires it (OTL spec 2.2).`,
    );
  }

  const rest = parts.slice(1);
  if (rest.length === 0 || rest[0] === undefined || rest[0] === '') {
    throw new InvalidDidError(`"${did}" has no domain component`);
  }

  // did:web percent-encodes a port's colon, so decode before use.
  const host = decodeSegment(did, rest[0]);
  if (!/^[A-Za-z0-9.-]+(:\d{1,5})?$/.test(host)) {
    throw new InvalidDidError(`"${host}" is not a valid host`);
  }

  const pathSegments = rest.slice(1).map((segment) => decodeSegment(did, segment));
  if (pathSegments.some((segment) => segment === '' || segment === '.' || segment === '..')) {
    throw new InvalidDidError(`"${did}" contains an empty or relative path segment`);
  }

  return { did, scid, host, pathSegments, origin: `https://${host}` };
}

const basePath = (parsed: ParsedDid): string =>
  parsed.pathSegments.length === 0 ? '/.well-known' : `/${parsed.pathSegments.join('/')}`;

/** `GET https://{domain}/.well-known/did.jsonl` — the version log (spec 2.3). */
export const didLogUrl = (did: string | ParsedDid): string => {
  const parsed = typeof did === 'string' ? parseDid(did) : did;
  return `${parsed.origin}${basePath(parsed)}/did.jsonl`;
};

/** `GET https://{domain}/.well-known/did.json` — the resolved document (spec 3). */
export const didDocumentUrl = (did: string | ParsedDid): string => {
  const parsed = typeof did === 'string' ? parseDid(did) : did;
  return `${parsed.origin}${basePath(parsed)}/did.json`;
};

/** `GET https://{domain}/.well-known/whois.vp` — the presentation (spec 4.4). */
export const whoisUrl = (did: string | ParsedDid): string => {
  const parsed = typeof did === 'string' ? parseDid(did) : did;
  return `${parsed.origin}${basePath(parsed)}/whois.vp`;
};

/** `GET https://{domain}/.well-known/status-lists/{listId}` (spec 5.2). */
export const statusListUrl = (did: string | ParsedDid, listId: string | number = 1): string => {
  const parsed = typeof did === 'string' ? parseDid(did) : did;
  return `${parsed.origin}${basePath(parsed)}/status-lists/${encodeURIComponent(String(listId))}`;
};
