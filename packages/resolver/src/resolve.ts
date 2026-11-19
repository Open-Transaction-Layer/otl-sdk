/**
 * DID resolution (OTL spec 2.3, 3, 5.3).
 *
 * Two operations the CLI keeps deliberately separate, because conflating them
 * is how a verifier ends up trusting an unvalidated document:
 *
 *  - `resolve` fetches the DID document and performs **no** validation.
 *  - `validate` fetches the whole version log and verifies it to genesis.
 *
 * `resolve` is for inspection. Nothing that makes a trust decision should call
 * it — every function here that feeds the credential chain uses `validate`.
 */

import {
  parseDidLog,
  validateDidLog,
  type DidDocument,
  type DidLogEntry,
  type ValidationResult,
} from '@otl/core';
import { fromPublicKeyJwk, fromPublicKeyMultibase, type PublicKey } from '@otl/keys';
import { fetchJson, fetchText, type FetchOptions } from './http.ts';
import type { DidHeadMemory } from './memory.ts';
import { didDocumentUrl, didLogUrl, parseDid } from './url.ts';

export class ResolutionError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = 'ResolutionError';
  }
}

/**
 * Fetch a DID document without validating it.
 *
 * The returned document proves nothing: it is whatever the domain served. Use
 * {@link validateDid} before relying on any of it.
 */
export async function resolveDid(did: string, options: FetchOptions = {}): Promise<DidDocument> {
  const document = await fetchJson<DidDocument | null>(didDocumentUrl(did), options);
  if (document?.id !== did) {
    throw new ResolutionError(
      `Document at ${didDocumentUrl(did)} declares id "${String(document?.id)}", not "${did}"`,
    );
  }
  return document;
}

export interface ValidatedDid extends ValidationResult {
  readonly entries: readonly DidLogEntry[];
}

/** Options shared by everything that validates a DID log. */
export type DidValidationOptions = FetchOptions & {
  readonly requirePreRotation?: boolean;
  /**
   * The newest log version already validated for each DID. When supplied, a
   * log that does not extend it is refused (rollback or fork), and the head of
   * every log that validates is recorded. Omitted, every resolution starts
   * with no history and a rolled-back log cannot be recognised.
   */
  readonly didHeadMemory?: DidHeadMemory;
};

/**
 * Fetch the version log and verify it to genesis (spec 2.3).
 *
 * With a `didHeadMemory` the log must also extend the newest version already
 * validated for this DID. A storage failure in the memory rejects the call
 * rather than skipping the check.
 */
export async function validateDid(did: string, options: DidValidationOptions = {}): Promise<ValidatedDid> {
  const { scid } = parseDid(did); // also fails fast on a malformed identifier
  const memory = options.didHeadMemory;

  const jsonl = await fetchText(didLogUrl(did), options);

  let entries: DidLogEntry[];
  try {
    entries = parseDidLog(jsonl);
  } catch (cause) {
    throw new ResolutionError(`Could not parse the DID log at ${didLogUrl(did)}`, { cause });
  }

  const known = memory ? await memory.lastAccepted(scid) : undefined;

  const result = await validateDidLog(entries, {
    expectedDid: did,
    ...(options.requirePreRotation !== undefined ? { requirePreRotation: options.requirePreRotation } : {}),
    ...(known !== undefined ? { known } : {}),
  });

  // Recorded only once the log has validated and extended what we knew, so an
  // invalid or conflicting log can never become the history later logs are
  // measured against.
  if (memory && result.valid && result.head) await memory.record(result.head);

  return { ...result, entries };
}

/** A DID document verification relationship (spec 3.3). */
export type VerificationRelationship = 'assertionMethod' | 'authentication' | 'keyAgreement';

/**
 * Normalize a fragment or full reference to the fully-qualified form.
 *
 * A reference that names a different DID is refused rather than accepted:
 * spec 3.2.1 scopes a credential's signing key to the issuer's own document,
 * and a key belonging to someone else is never the key we were asked for.
 */
function referenceFor(did: string, fragmentOrReference: string): string {
  if (fragmentOrReference.startsWith('did:')) {
    if (!fragmentOrReference.startsWith(`${did}#`)) {
      throw new ResolutionError(`Verification method "${fragmentOrReference}" does not belong to "${did}"`);
    }
    return fragmentOrReference;
  }
  return `${did}${fragmentOrReference.startsWith('#') ? '' : '#'}${fragmentOrReference}`;
}

/** The references a relationship holds, as strings (DID Core permits embedded methods). */
function relationshipReferences(document: DidDocument, relationship: VerificationRelationship): string[] {
  const entries = document[relationship];
  if (!Array.isArray(entries)) return [];
  return entries.map((entry) => (typeof entry === 'string' ? entry : ((entry as { id?: string }).id ?? '')));
}

/**
 * Resolve a verification method to a public key, after validating the log.
 *
 * `fragmentOrReference` accepts `#vc-key-1` or the fully-qualified form, and is
 * matched against verification method ids **exactly**. A suffix match would let
 * an entry whose id ends in the same characters stand in for the one asked for.
 *
 * Pass `relationship` to require that the DID designated the key for that
 * purpose. Spec 3.2.1: a credential proof is acceptable "only if the proof's
 * `verificationMethod` resolves to a key referenced in the `assertionMethod` of
 * the issuer's DID document" — being present in `verificationMethod` is not
 * enough, because that array is an inventory, not a grant of authority.
 */
export async function resolveVerificationKey(
  did: string,
  fragmentOrReference: string,
  options: DidValidationOptions & {
    readonly relationship?: VerificationRelationship;
  } = {},
): Promise<PublicKey> {
  const validated = await validateDid(did, options);

  if (!validated.valid) {
    // An invalid log is a failure, never a fallback to the served document.
    throw new ResolutionError(
      `DID log for "${did}" failed validation:\n  - ${validated.issues.map((i) => i.message).join('\n  - ')}`,
    );
  }
  if (validated.deactivated) {
    throw new ResolutionError(`DID "${did}" has been deactivated`);
  }

  const document = validated.document;
  const wanted = referenceFor(did, fragmentOrReference);

  if (options.relationship !== undefined && document !== undefined) {
    const references = relationshipReferences(document, options.relationship);
    if (!references.includes(wanted)) {
      throw new ResolutionError(
        `DID "${did}" does not reference "${wanted}" under ${options.relationship} (spec 3.2.1). ` +
          `A key must be designated for its purpose, not merely present in the document.`,
      );
    }
  }

  const method = (document?.verificationMethod ?? []).find((m) => m.id === wanted);
  if (!method) {
    throw new ResolutionError(`DID "${did}" has no verification method "${wanted}"`);
  }
  if ((method.controller as string | undefined) !== undefined && method.controller !== did) {
    throw new ResolutionError(
      `Verification method "${method.id}" is controlled by "${method.controller}", not "${did}"`,
    );
  }

  const multibase = method.publicKeyMultibase;
  if (multibase !== undefined && multibase !== '') return fromPublicKeyMultibase(multibase);
  if (method.publicKeyJwk) return fromPublicKeyJwk(method.publicKeyJwk);
  throw new ResolutionError(
    `Verification method "${method.id}" carries neither publicKeyMultibase nor publicKeyJwk`,
  );
}

/**
 * Resolve the credential signing key a proof names (spec 3.2.1).
 *
 * Supplied to the credential validation chain as its `resolveAssertionKey`. The
 * fragment is the issuer's choice — the spec fixes no id — so the reference
 * comes from the proof being verified, and the guarantee that it is the right
 * key comes from `assertionMethod` membership rather than from its name.
 */
export const resolveAssertionKey =
  (options: DidValidationOptions = {}) =>
  (issuerDid: string, verificationMethod: string): Promise<PublicKey> =>
    resolveVerificationKey(issuerDid, verificationMethod, {
      ...options,
      relationship: 'assertionMethod',
    });

/** Locate a service endpoint by fragment (spec 3, 4.4). */
export function serviceEndpointOf(document: DidDocument, fragment: string): string | undefined {
  const wanted = `${document.id}${fragment.startsWith('#') ? '' : '#'}${fragment}`;
  const service = (document.service ?? []).find((s) => s.id === wanted);
  const endpoint = service?.serviceEndpoint;
  return typeof endpoint === 'string' ? endpoint : undefined;
}
