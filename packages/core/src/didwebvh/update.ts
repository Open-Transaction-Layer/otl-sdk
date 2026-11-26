/**
 * Appending log entries — key rotation, adding keys and services, deactivation
 * (OTL spec 3.2.2, 3.3).
 *
 * ## Rotation policy
 *
 * This implementation keeps did:webvh pre-rotation permanently active by
 * default, so every entry carries a non-empty `nextKeyHashes` commitment, and
 * did:webvh requires every key in an entry's `updateKeys` to have been
 * committed in the previous entry's `nextKeyHashes`. Both are satisfiable in
 * more than one way, and the choice determines what the commitment is worth:
 *
 * - `rotate-every-entry` — each entry is signed by the key the previous entry
 *   committed to, and commits to a fresh offline key. This is the only policy
 *   under which the committed key can genuinely be kept offline and
 *   unreachable by any live application, because a key that signs entries is
 *   by definition reachable. Cost: adding a service endpoint also rotates the
 *   DID Management Key.
 *
 * - `retain-until-rotation` — an entry may re-commit to the key it is already
 *   using, so ordinary updates leave the management key in place. Operationally
 *   lighter, but the commitment then names a live key, and an attacker holding
 *   that key can retain it and publish a commitment of their own choosing —
 *   which is the takeover pre-rotation exists to prevent.
 *
 * Both are conformant with did:webvh, and the choice is a question of the
 * operator's own security posture, so it is a parameter rather than a
 * baked-in choice.
 */

import {
  fromPublicKeyJwk,
  fromPublicKeyMultibase,
  toPublicKeyMultibase,
  type KeyInfo,
  type KeyProvider,
  type PublicKey,
} from '@open-transaction-layer/keys';
import { InvalidDocumentError } from '../errors.ts';
import { createProof } from '../proof.ts';
import { buildDidDocument, type DocumentKey } from './document.ts';
import { deriveEntryHash, deriveKeyHash, formatVersionId, parseVersionId } from './hashing.ts';
import { DIDWEBVH_1_0_PROFILE, explainCurveRejection, type MethodProfile } from './profile.ts';
import type { DidDocument, DidLogEntry, DidLogParameters, ServiceEntry } from './types.ts';

export type RotationPolicy = 'rotate-every-entry' | 'retain-until-rotation';

export const DEFAULT_ROTATION_POLICY: RotationPolicy = 'rotate-every-entry';

export interface AppendEntryOptions {
  /** The entry this one follows. Its `nextKeyHashes` gates what may sign here. */
  readonly previousEntry: DidLogEntry;
  /** The document state for the new version. */
  readonly state: DidDocument;
  readonly provider: KeyProvider;
  /**
   * Label of the key that signs this entry. Its multikey goes into
   * `updateKeys`, and must have been committed by the previous entry.
   */
  readonly signingKeyLabel: string;
  /** Label of the key committed to for the *next* entry. */
  readonly nextKeyLabel: string;
  /** UTC ISO 8601. */
  readonly versionTime: string;
  /** Set `deactivated: true` (spec 3.2.2). */
  readonly deactivate?: boolean;
  /** Permitted log-proof algorithms. Defaults to stock did:webvh 1.0. */
  readonly profile?: MethodProfile;
}

/**
 * Append a signed entry to a DID log.
 *
 * Enforces the invariants that make a log verifiable, at construction time,
 * so a malformed log is never published:
 *
 *  - version numbers increment by one and chain to the previous entry;
 *  - `scid` appears in entry 1 only;
 *  - `updateKeys` and `nextKeyHashes` are explicit and non-empty;
 *  - every key in `updateKeys` was committed by the previous `nextKeyHashes`;
 *  - the signing key's curve is permitted by `profile`, and the key is
 *    present in `updateKeys`;
 *  - the previous entry has not deactivated the DID.
 */
export async function appendEntry(options: AppendEntryOptions): Promise<DidLogEntry> {
  const {
    previousEntry,
    state,
    provider,
    signingKeyLabel,
    nextKeyLabel,
    versionTime,
    deactivate,
    profile = DIDWEBVH_1_0_PROFILE,
  } = options;

  const { versionNumber: previousVersion } = parseVersionId(previousEntry.versionId);
  if (previousEntry.parameters.deactivated === true) {
    throw new InvalidDocumentError(
      `Previous entry ${previousEntry.versionId} deactivated the DID; a deactivated log cannot be extended`,
    );
  }

  const signingKey = await provider.getKey(signingKeyLabel);
  const nextKey = await provider.getKey(nextKeyLabel);
  assertCurvePermitted(profile, signingKey, signingKeyLabel, 'signing key');
  assertCurvePermitted(profile, nextKey, nextKeyLabel, 'next-key commitment');

  const signingMultikey = toPublicKeyMultibase(signingKey.publicKey);
  assertCommittedByPreviousEntry(signingMultikey, previousEntry);

  const parameters: DidLogParameters = {
    // `scid` is entry-1-only and deliberately absent.
    // `method` is inherited from entry 1.
    updateKeys: [signingMultikey],
    nextKeyHashes: [deriveKeyHash(toPublicKeyMultibase(nextKey.publicKey))],
    ...(deactivate ? { deactivated: true } : {}),
  };

  const unhashed: DidLogEntry = {
    versionId: previousEntry.versionId, // placeholder; replaced below
    versionTime,
    parameters,
    state,
  };

  // The entry hash is taken with versionId set to the *previous* entry's
  // versionId — that substitution is what chains this entry to its predecessor.
  const entryHash = deriveEntryHash(unhashed, previousEntry.versionId);
  const unsigned: DidLogEntry = {
    ...unhashed,
    versionId: formatVersionId(previousVersion + 1, entryHash),
  };

  return (await createProof({
    document: unsigned as unknown as Record<string, unknown>,
    provider,
    keyLabel: signingKeyLabel,
    verificationMethod: `did:key:${signingMultikey}#${signingMultikey}`,
    proofPurpose: 'assertionMethod',
    // Spec 3.2.2 shows log-entry proofs as an array, and at least one
    // reference implementation rejects a bare object outright.
    proofFormat: 'array',
  })) as unknown as DidLogEntry;
}

function assertCurvePermitted(profile: MethodProfile, key: KeyInfo, label: string, role: string): void {
  const problem = explainCurveRejection(profile, key.curve, `${role} ("${label}")`);
  if (problem !== undefined) throw new InvalidDocumentError(problem);
}

/**
 * did:webvh pre-rotation: "every multikey in the current entry's updateKeys
 * (not only those that appear new) MUST have its hash in the previous entry's
 * nextKeyHashes."
 *
 * This is the check that makes a rotation provably pre-planned. Failing it
 * means either the log is being forked by someone holding a key they were not
 * committed, or the operator has lost track of which key comes next.
 */
function assertCommittedByPreviousEntry(multikey: string, previousEntry: DidLogEntry): void {
  const committed = previousEntry.parameters.nextKeyHashes ?? [];
  if (committed.length === 0) {
    throw new InvalidDocumentError(
      `Previous entry ${previousEntry.versionId} carries no nextKeyHashes. This implementation ` +
        `keeps pre-rotation permanently active, so this log cannot be extended.`,
    );
  }
  if (!committed.includes(deriveKeyHash(multikey))) {
    throw new InvalidDocumentError(
      `The signing key is not committed by the previous entry's nextKeyHashes. ` +
        `Under pre-rotation, only the key committed in advance may sign the next entry.`,
    );
  }
}

// ---------------------------------------------------------------------------
// Document-level operations
// ---------------------------------------------------------------------------

export interface UpdateOperationOptions extends Omit<AppendEntryOptions, 'state' | 'deactivate'> {
  readonly did: string;
}

/**
 * Refuse an operation whose `did` is not the DID the previous entry describes.
 *
 * The document-level operations rebuild every verification method id and
 * controller from `did`, so a mismatch would publish a version whose ids point
 * at another DID.
 */
function assertSameDid(did: string, previousEntry: DidLogEntry): void {
  if (did !== previousEntry.state.id) {
    throw new InvalidDocumentError(
      `did "${did}" does not match the previous entry's DID "${previousEntry.state.id}"`,
    );
  }
}

/** Add a verification method to the document, producing a new version (spec 3.3). */
export async function addKey(
  options: UpdateOperationOptions & { readonly keys: readonly DocumentKey[] },
): Promise<DidLogEntry> {
  const { did, keys, ...rest } = options;
  assertSameDid(did, options.previousEntry);
  const existing = documentKeysOf(options.previousEntry.state);
  const state = buildDidDocument({
    did,
    keys: [...existing, ...keys],
    ...(options.previousEntry.state.service ? { service: options.previousEntry.state.service } : {}),
  });
  return appendEntry({ ...rest, state });
}

/** Add a service entry to the document, producing a new version. */
export async function addService(
  options: UpdateOperationOptions & { readonly service: ServiceEntry },
): Promise<DidLogEntry> {
  const { did, service, ...rest } = options;
  assertSameDid(did, options.previousEntry);
  const previous = options.previousEntry.state;
  const existing = (previous.service ?? []) as ServiceEntry[];

  validateServiceEntry(service, did);
  if (existing.some((s) => s.id === service.id)) {
    throw new InvalidDocumentError(`Service "${service.id}" already exists in the document`);
  }

  const state = buildDidDocument({
    did,
    keys: documentKeysOf(previous),
    service: [...existing, service],
  });
  return appendEntry({ ...rest, state });
}

/** Deactivate the DID (spec 3.2.2). */
export async function deactivate(options: UpdateOperationOptions): Promise<DidLogEntry> {
  const { did, ...rest } = options;
  assertSameDid(did, options.previousEntry);
  return appendEntry({
    ...rest,
    state: buildDidDocument({ did, keys: documentKeysOf(options.previousEntry.state) }),
    deactivate: true,
  });
}

/**
 * Validate a service entry before it is published.
 *
 * A malformed service entry cannot be removed without another log entry, so it
 * is worth rejecting up front. HTTPS is required because every endpoint the
 * Identity layer defines is fetched over HTTPS (spec 2.1, 4.4, 5.2).
 */
export function validateServiceEntry(service: ServiceEntry, did: string): void {
  if (typeof service.id !== 'string' || service.id.length === 0) {
    throw new InvalidDocumentError('Service entry requires a non-empty string "id"');
  }
  if (!service.id.startsWith('#') && !service.id.startsWith(`${did}#`)) {
    throw new InvalidDocumentError(
      `Service id "${service.id}" must be a fragment ("#whois") or absolute within this DID`,
    );
  }
  const types = Array.isArray(service.type) ? service.type : [service.type];
  if (types.length === 0 || types.some((t) => typeof t !== 'string' || t.length === 0)) {
    throw new InvalidDocumentError('Service entry requires "type" as a non-empty string or array');
  }
  assertHttpsEndpoint(service.serviceEndpoint);
}

function assertHttpsEndpoint(endpoint: unknown): void {
  if (typeof endpoint === 'string') {
    let url: URL;
    try {
      url = new URL(endpoint);
    } catch {
      throw new InvalidDocumentError(`serviceEndpoint "${endpoint}" is not a valid URL`);
    }
    if (url.protocol !== 'https:') {
      throw new InvalidDocumentError(
        `serviceEndpoint "${endpoint}" must use https; the Identity layer fetches every endpoint over HTTPS`,
      );
    }
    return;
  }
  if (Array.isArray(endpoint)) {
    if (endpoint.length === 0) throw new InvalidDocumentError('serviceEndpoint array must not be empty');
    endpoint.forEach(assertHttpsEndpoint);
    return;
  }
  if (endpoint !== null && typeof endpoint === 'object') {
    const values = Object.values(endpoint as Record<string, unknown>);
    if (values.length === 0) throw new InvalidDocumentError('serviceEndpoint object must not be empty');
    values.forEach(assertHttpsEndpoint);
    return;
  }
  throw new InvalidDocumentError('serviceEndpoint must be an https URL, or an array or object of them');
}

/**
 * Recover the document keys from a published document, so an update can rebuild
 * it without the caller re-supplying every existing key.
 */
export function documentKeysOf(document: DidDocument): DocumentKey[] {
  const methods = document.verificationMethod ?? [];
  const purposesOf = (id: string) =>
    (['authentication', 'assertionMethod', 'keyAgreement'] as const).filter((purpose) =>
      ((document[purpose] as string[] | undefined) ?? []).includes(id),
    );

  return methods.map((method) => ({
    fragment: method.id.slice(method.id.lastIndexOf('#') + 1),
    publicKey: publicKeyOf(method),
    purposes: purposesOf(method.id),
  }));
}

function publicKeyOf(method: {
  id: string;
  type: string;
  publicKeyMultibase?: string;
  publicKeyJwk?: Record<string, string>;
}): PublicKey {
  const multibase = method.publicKeyMultibase;
  if (multibase !== undefined && multibase !== '') return fromPublicKeyMultibase(multibase);
  if (method.publicKeyJwk) return fromPublicKeyJwk(method.publicKeyJwk);
  throw new InvalidDocumentError(
    `Verification method "${method.id}" of type "${method.type}" carries neither ` +
      `publicKeyMultibase nor publicKeyJwk`,
  );
}
