/**
 * SCID derivation, entry hashing, and pre-rotation key commitments.
 *
 * All three are `base58btc(multihash(JCS(x), sha2-256))` over different inputs.
 * Getting the input wrong is the failure mode here, so each function documents
 * precisely what it hashes.
 */

import { InvalidDocumentError } from '../errors.ts';
import { canonicalizeToBytes } from '../jcs.ts';
import { hashStringToBase58, hashToBase58 } from '../multihash.ts';
import { SCID_PLACEHOLDER, type DidLogEntry } from './types.ts';

/** Strip `proof` — never part of any hash input. */
function withoutProof(entry: DidLogEntry): Record<string, unknown> {
  const { proof: _proof, ...rest } = entry as unknown as Record<string, unknown>;
  return rest;
}

/**
 * Derive the SCID from a preliminary genesis entry.
 *
 * The entry passed in must already carry `{SCID}` everywhere the SCID will
 * eventually appear — in `versionId`, in `parameters.scid`, and inside `state`
 * (the DID document `id`, and every `verificationMethod` id and controller).
 *
 * `SCID = base58btc(multihash(JCS(preliminary entry), sha2-256))`
 */
export function deriveScid(preliminaryEntry: DidLogEntry): string {
  return hashToBase58(canonicalizeToBytes(withoutProof(preliminaryEntry)));
}

/**
 * Hash a log entry, for the `{versionNumber}-{entryHash}` versionId.
 *
 * The entry is hashed with its `versionId` replaced by the *previous* entry's
 * versionId — or, for entry 1, by the bare SCID. That substitution is what
 * chains each entry to its predecessor.
 *
 * `entryHash = base58btc(multihash(JCS(entry with substituted versionId), sha2-256))`
 */
export function deriveEntryHash(entry: DidLogEntry, previousVersionId: string): string {
  return hashToBase58(canonicalizeToBytes({ ...withoutProof(entry), versionId: previousVersionId }));
}

/** `{versionNumber}-{entryHash}`. */
export const formatVersionId = (versionNumber: number, entryHash: string): string =>
  `${versionNumber}-${entryHash}`;

/**
 * Split a versionId, or throw if it is malformed.
 *
 * The version number is a positive decimal integer without leading zeros, so
 * `01-…`, `+1-…` and `1e0-…` are refused rather than read as version 1.
 *
 * @throws {InvalidDocumentError} when `versionId` is not `{versionNumber}-{entryHash}`.
 */
export function parseVersionId(versionId: unknown): { versionNumber: number; entryHash: string } {
  // A log line is parsed JSON, so the declared type is not trusted here.
  const match = typeof versionId === 'string' ? /^([1-9]\d*)-(.+)$/.exec(versionId) : null;
  const digits = match?.[1];
  const entryHash = match?.[2];
  if (digits === undefined || entryHash === undefined) {
    throw new InvalidDocumentError(
      `Malformed versionId "${String(versionId)}"; expected {versionNumber}-{entryHash} ` +
        `with a positive integer version number`,
    );
  }
  const versionNumber = Number(digits);
  if (!Number.isSafeInteger(versionNumber)) {
    throw new InvalidDocumentError(
      `Malformed versionId "${String(versionId)}"; version number is out of range`,
    );
  }
  return { versionNumber, entryHash };
}

/**
 * Pre-rotation commitment for one update key.
 *
 * Hashes the multikey *string* (`z6Mk…`) as UTF-8, not the decoded key bytes.
 *
 * The did:webvh 1.0 text defers this to a section that does not spell out the
 * input encoding; hashing the multikey string is what the reference
 * implementations do. Confirmed against the didwebvh-test-suite vectors
 * (test/vectors).
 */
export const deriveKeyHash = (multikey: string): string => hashStringToBase58(multikey);

/** Substitute `{SCID}` throughout a structure. Used both to build and to verify. */
export function replaceScid<T>(value: T, from: string, to: string): T {
  if (typeof value === 'string') return value.split(from).join(to) as unknown as T;
  if (Array.isArray(value)) return (value as unknown[]).map((v) => replaceScid(v, from, to)) as unknown as T;
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>).map(([k, v]) => [
        k.split(from).join(to),
        replaceScid(v, from, to),
      ]),
    ) as unknown as T;
  }
  return value;
}

/** Replace a derived SCID with the placeholder, for verification. */
export const toPlaceholders = <T>(value: T, scid: string): T => replaceScid(value, scid, SCID_PLACEHOLDER);

/** Replace the placeholder with a derived SCID, for construction. */
export const fromPlaceholders = <T>(value: T, scid: string): T => replaceScid(value, SCID_PLACEHOLDER, scid);
