/**
 * DID document construction (OTL spec 3).
 */

import {
  toPublicKeyJwk,
  toPublicKeyMultibase,
  type KeyInfo,
  type PublicKey,
} from '@open-transaction-layer/keys';
import { InvalidDocumentError } from '../errors.ts';
import { CONTEXT, type DidDocument, type ServiceEntry, type VerificationMethod } from './types.ts';

export type KeyPurpose = 'authentication' | 'assertionMethod' | 'keyAgreement';

export interface DocumentKey {
  /** Fragment without the leading `#`, e.g. `credential-issuance-key`. */
  readonly fragment: string;
  readonly publicKey: PublicKey;
  readonly purposes: readonly KeyPurpose[];
}

export const keyFromKeyInfo = (
  fragment: string,
  key: KeyInfo,
  purposes: readonly KeyPurpose[],
): DocumentKey => ({ fragment, publicKey: key.publicKey, purposes });

/**
 * Build a verification method entry.
 *
 * Type follows from the curve (OTL spec 3.1): Ed25519 and X25519 use their
 * dedicated 2020 suites and carry `publicKeyMultibase`; P-256 uses
 * `JsonWebKey2020` and carries `publicKeyJwk`.
 */
export function verificationMethodFor(controller: string, key: DocumentKey): VerificationMethod {
  const id = `${controller}#${key.fragment}`;
  switch (key.publicKey.curve) {
    case 'Ed25519':
      return {
        id,
        type: 'Ed25519VerificationKey2020',
        controller,
        publicKeyMultibase: toPublicKeyMultibase(key.publicKey),
      };
    case 'X25519':
      return {
        id,
        type: 'X25519KeyAgreementKey2020',
        controller,
        publicKeyMultibase: toPublicKeyMultibase(key.publicKey),
      };
    case 'P-256':
      return {
        id,
        type: 'JsonWebKey2020',
        controller,
        publicKeyJwk: toPublicKeyJwk(key.publicKey),
      };
  }
}

/**
 * The `@context` entries OTL spec 3.1 requires, given the keys present.
 *
 * The DID Core context is always required; each suite context is added only
 * when a key actually uses it, so a document never claims vocabulary it does
 * not use.
 */
export function contextsFor(keys: readonly DocumentKey[]): string[] {
  const contexts: string[] = [CONTEXT.did];
  const curves = new Set(keys.map((k) => k.publicKey.curve));

  // Any X25519 key is published as an X25519KeyAgreementKey2020 verification
  // method, whatever purposes it is listed under, so its context is needed
  // whenever one is present.
  if (curves.has('Ed25519')) contexts.push(CONTEXT.ed25519);
  if (curves.has('P-256')) contexts.push(CONTEXT.jws);
  if (curves.has('X25519')) contexts.push(CONTEXT.x25519);
  return contexts;
}

export interface BuildDocumentOptions {
  readonly did: string;
  readonly keys: readonly DocumentKey[];
  readonly service?: readonly ServiceEntry[];
}

/** Assemble a DID document from its keys and services. */
export function buildDidDocument(options: BuildDocumentOptions): DidDocument {
  const { did, keys, service } = options;

  assertUniqueFragments(keys);
  for (const key of keys) assertPurposesValidForCurve(key);

  const reference = (key: DocumentKey) => `${did}#${key.fragment}`;
  const withPurpose = (purpose: KeyPurpose) =>
    keys.filter((k) => k.purposes.includes(purpose)).map(reference);

  const document: Record<string, unknown> = {
    '@context': contextsFor(keys),
    id: did,
    verificationMethod: keys.map((k) => verificationMethodFor(did, k)),
  };

  // Omit empty purpose arrays rather than emitting `[]` — an absent purpose and
  // an empty one mean the same thing, and one form keeps documents comparable.
  for (const purpose of ['authentication', 'assertionMethod', 'keyAgreement'] as const) {
    const references = withPurpose(purpose);
    if (references.length > 0) document[purpose] = references;
  }
  if (service && service.length > 0) document['service'] = service;

  return document as unknown as DidDocument;
}

function assertUniqueFragments(keys: readonly DocumentKey[]): void {
  const seen = new Set<string>();
  for (const key of keys) {
    if (seen.has(key.fragment)) {
      throw new InvalidDocumentError(`Duplicate verification method fragment "#${key.fragment}"`);
    }
    seen.add(key.fragment);
  }
}

/**
 * A signing curve cannot serve `keyAgreement`, and X25519 cannot sign.
 * Catching this here keeps an unusable document from ever being published.
 */
function assertPurposesValidForCurve(key: DocumentKey): void {
  const isKeyAgreementCurve = key.publicKey.curve === 'X25519' || key.publicKey.curve === 'P-256';
  const isSigningCurve = key.publicKey.curve !== 'X25519';

  for (const purpose of key.purposes) {
    if (purpose === 'keyAgreement' && !isKeyAgreementCurve) {
      throw new InvalidDocumentError(
        `Key "#${key.fragment}" uses ${key.publicKey.curve}, which cannot be used for keyAgreement`,
      );
    }
    if (purpose !== 'keyAgreement' && !isSigningCurve) {
      throw new InvalidDocumentError(
        `Key "#${key.fragment}" uses X25519, which cannot be used for ${purpose}`,
      );
    }
  }
}
