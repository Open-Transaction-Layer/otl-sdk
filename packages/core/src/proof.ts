/**
 * W3C Data Integrity proofs over JCS-canonicalized documents.
 *
 * Used for every signature in the Identity layer: DID log entries (spec 3.2.2),
 * verifiable credentials (4.3), verifiable presentations (4.4) and status list
 * credentials (5.2).
 *
 * ## Signature input (spec 6.3)
 *
 * This module implements the construction that spec 6.3 and the W3C
 * cryptosuites it names (`eddsa-jcs-2022` and `ecdsa-jcs-2019`) define:
 *
 *     hashData = SHA-256(JCS(proofConfig)) || SHA-256(JCS(unsecuredDocument))
 *
 * where `proofConfig` is the proof object without `proofValue`, carrying the
 * document's `@context`. Hashing the proof configuration binds the proof's own
 * metadata into the signature, which is what stops an attacker lifting a valid
 * signature onto a proof block that claims a different `verificationMethod`,
 * `proofPurpose`, `created`, `domain` or `challenge`.
 */

import { createHash } from 'node:crypto';
import {
  toMultibaseBase58,
  fromMultibaseBase58,
  verifySignature,
  type KeyProvider,
  type PublicKey,
} from '@otl/keys';
import { assertCryptosuiteMatchesCurve, cryptosuiteForCurve, type CryptosuiteName } from './cryptosuite.ts';
import { InvalidDocumentError, ProofError } from './errors.ts';
import { canonicalizeToBytes } from './jcs.ts';

/**
 * A proof before its signature is attached — the shape that gets canonicalized
 * and hashed as the proof configuration.
 *
 * Spelled out rather than derived with `Omit<DataIntegrityProof, 'proofValue'>`:
 * `Omit` over a type carrying an index signature collapses to just the index
 * signature and silently drops every named member.
 */
export interface UnsignedProof {
  readonly type: 'DataIntegrityProof';
  readonly cryptosuite: CryptosuiteName;
  readonly created?: string;
  readonly verificationMethod: string;
  readonly proofPurpose: string;
  readonly [key: string]: unknown;
}

export interface DataIntegrityProof extends UnsignedProof {
  readonly proofValue: string;
}

/** A JSON document, with or without a proof attached. */
export type Document = Record<string, unknown>;

export interface CreateProofOptions {
  /** The document to secure. Any existing `proof` is preserved, not replaced. */
  readonly document: Document;
  readonly provider: KeyProvider;
  /** Label of the signing key within the provider. */
  readonly keyLabel: string;
  /** Key reference written into the proof, e.g. `did:webvh:…#credential-issuance-key`. */
  readonly verificationMethod: string;
  /** Spec 6.3: always `assertionMethod` for credentials and log entries. */
  readonly proofPurpose?: string;
  /** ISO 8601. Omitted from the proof entirely when not supplied. */
  readonly created?: string;
  /** Additional proof members (e.g. `domain`, `challenge`) bound into the signature. */
  readonly additionalProperties?: Readonly<Record<string, unknown>>;
  /**
   * Shape of the `proof` member when the document has none yet.
   *
   * The spec uses both, in different places, and at least one third-party
   * did:webvh implementation rejects the wrong one outright:
   *
   *  - `'array'`  — did:webvh log entries (spec 3.2.2 shows `"proof": [{…}]`).
   *  - `'single'` — verifiable credentials and presentations (spec 4.10, 5.2.1
   *    show a bare object).
   *
   * Defaults to `'single'`. Appending to a document that already carries a
   * proof always produces an array, whatever this says.
   */
  readonly proofFormat?: 'single' | 'array';
}

const SHA256 = (bytes: Uint8Array): Uint8Array => new Uint8Array(createHash('sha256').update(bytes).digest());

/**
 * Build the proof configuration that gets hashed.
 *
 * Per the Data Integrity specification the document's `@context`, when present,
 * is copied into the configuration so that the proof is bound to the context
 * the document was interpreted under. It is deliberately *not* emitted in the
 * resulting proof object — a verifier reconstructs it the same way.
 */
function buildProofConfig(document: Document, proof: UnsignedProof): Record<string, unknown> {
  const { proofValue: _ignored, ...withoutValue } = proof as Record<string, unknown>;
  const config: Record<string, unknown> = { ...withoutValue };
  if (document['@context'] !== undefined) config['@context'] = document['@context'];
  return config;
}

/**
 * `SHA-256(JCS(proofConfig)) || SHA-256(JCS(document))`.
 *
 * Proof configuration first — the order is normative, and reversing it produces
 * signatures that verify nowhere.
 */
function hashData(document: Document, proofConfig: Record<string, unknown>): Uint8Array {
  const { proof: _existingProof, ...unsecured } = document;
  return Uint8Array.from([
    ...SHA256(canonicalizeToBytes(proofConfig)),
    ...SHA256(canonicalizeToBytes(unsecured)),
  ]);
}

/**
 * Sign `document` and return a copy with the proof attached.
 *
 * The input document is not mutated. If it already carries one or more proofs,
 * the new proof is appended rather than replacing them — did:webvh log entries
 * and multi-signed credentials both rely on this.
 */
export async function createProof(options: CreateProofOptions): Promise<Document> {
  const {
    document,
    provider,
    keyLabel,
    verificationMethod,
    proofPurpose = 'assertionMethod',
    created,
    additionalProperties,
    proofFormat = 'single',
  } = options;

  const key = await provider.getKey(keyLabel);
  const cryptosuite = cryptosuiteForCurve(key.curve);

  // `additionalProperties` is spread first so that it can add members such as
  // `domain` or `challenge` but can never override the members that identify
  // the key, the suite or the purpose.
  const unsignedProof = {
    ...additionalProperties,
    type: 'DataIntegrityProof',
    cryptosuite,
    ...(created !== undefined ? { created } : {}),
    verificationMethod,
    proofPurpose,
  } satisfies UnsignedProof;

  const proofConfig = buildProofConfig(document, unsignedProof);
  const signature = await provider.sign(keyLabel, hashData(document, proofConfig));

  const proof: DataIntegrityProof = {
    ...unsignedProof,
    proofValue: toMultibaseBase58(signature),
  };

  return { ...document, proof: appendProof(document['proof'], proof, proofFormat) };
}

function appendProof(existing: unknown, proof: DataIntegrityProof, format: 'single' | 'array'): unknown {
  if (existing === undefined) return format === 'array' ? [proof] : proof;
  return Array.isArray(existing) ? [...(existing as unknown[]), proof] : [existing, proof];
}

export interface VerificationResult {
  readonly verified: boolean;
  /** Present when `verified` is false. Safe to surface to an operator. */
  readonly reason?: string;
  /** The proof that was checked, when one could be selected. */
  readonly proof?: DataIntegrityProof;
}

export interface VerifyProofOptions {
  /** Document including its `proof` member. */
  readonly document: Document;
  /** Public key to verify against — resolved by the caller from the DID document. */
  readonly publicKey: PublicKey;
  /**
   * Which proof to check when the document carries several. Defaults to the
   * only proof present; with multiple proofs and no selector, verification
   * fails rather than silently picking one.
   */
  readonly verificationMethod?: string;
  /** Require this `proofPurpose`. Defaults to `assertionMethod` (spec 6.3). */
  readonly expectedProofPurpose?: string | null;
  /** The time `expires` is checked against. Defaults to now. */
  readonly now?: Date;
}

/**
 * Verify one Data Integrity proof on a document.
 *
 * Returns a result rather than throwing on a bad signature: an invalid proof is
 * an expected outcome of validation, not an exceptional condition. Structural
 * problems that make verification impossible are also reported this way, so a
 * caller can render one consistent failure reason.
 *
 * The signature is asynchronous even though nothing here awaits yet: that lets
 * verification backed by an HSM or a remote service be added without a breaking
 * change, and it means every caller is already obliged to `await` the result.
 */
// eslint-disable-next-line @typescript-eslint/require-await -- async by contract, see above
export async function verifyProof(options: VerifyProofOptions): Promise<VerificationResult> {
  const { document, publicKey, verificationMethod, expectedProofPurpose = 'assertionMethod' } = options;

  let proof: DataIntegrityProof;
  try {
    proof = selectProof(document, verificationMethod);
  } catch (error) {
    return { verified: false, reason: (error as Error).message };
  }

  // The proof comes from the document under verification, so its `type` is
  // attacker-controlled whatever the declared type says; compare it as a string.
  const declaredType: string = proof.type;
  if (declaredType !== 'DataIntegrityProof') {
    return { verified: false, reason: `Unsupported proof type "${declaredType}"`, proof };
  }

  if (expectedProofPurpose !== null && proof.proofPurpose !== expectedProofPurpose) {
    return {
      verified: false,
      reason: `Proof purpose is "${proof.proofPurpose}" but "${expectedProofPurpose}" was required`,
      proof,
    };
  }

  // `expires` is optional in Data Integrity, but once present it is part of the
  // signed proof configuration and a verifier must not accept the proof after
  // it. A value that is not a date fails closed rather than being ignored.
  const expires: unknown = (proof as unknown as Record<string, unknown>)['expires'];
  if (expires !== undefined) {
    const expiresMs = typeof expires === 'string' ? Date.parse(expires) : Number.NaN;
    if (Number.isNaN(expiresMs)) {
      return { verified: false, reason: 'Proof expires is not a valid date-time', proof };
    }
    if (expiresMs <= (options.now ?? new Date()).getTime()) {
      return { verified: false, reason: `Proof expired at ${JSON.stringify(expires)}`, proof };
    }
  }

  try {
    assertCryptosuiteMatchesCurve(proof.cryptosuite, publicKey.curve);
  } catch (error) {
    return { verified: false, reason: (error as Error).message, proof };
  }

  let signature: Uint8Array;
  try {
    signature = fromMultibaseBase58(proof.proofValue);
  } catch (error) {
    return { verified: false, reason: `Malformed proofValue: ${(error as Error).message}`, proof };
  }

  // Verify against the same document that was signed: this proof removed, and
  // any *other* proofs removed too, since they were not part of its input.
  const unsecured = { ...document };
  delete unsecured['proof'];

  try {
    const verified = verifySignature(
      publicKey,
      hashData(unsecured, buildProofConfig(document, proof)),
      signature,
    );
    return verified
      ? { verified: true, proof }
      : { verified: false, reason: 'Signature does not verify against the supplied key', proof };
  } catch (error) {
    return { verified: false, reason: `Verification failed: ${(error as Error).message}`, proof };
  }
}

/**
 * All proofs on a document, normalized to an array.
 *
 * The `proof` member comes from the document under verification, so its
 * elements are not guaranteed to be objects. Callers that read members from
 * them should check each one with {@link isProofObject} first.
 */
export function proofsOf(document: Document): DataIntegrityProof[] {
  const proof = document['proof'];
  if (proof === undefined) return [];
  return (Array.isArray(proof) ? proof : [proof]) as DataIntegrityProof[];
}

/** True when a proof entry is a non-null, non-array object whose members can be read. */
export function isProofObject(proof: unknown): proof is DataIntegrityProof {
  return typeof proof === 'object' && proof !== null && !Array.isArray(proof);
}

function selectProof(document: Document, verificationMethod?: string): DataIntegrityProof {
  const proofs = proofsOf(document);
  if (!proofs.every(isProofObject)) throw new InvalidDocumentError('Proof entry is not an object');
  const [first] = proofs;
  if (first === undefined) throw new InvalidDocumentError('Document carries no proof');

  if (verificationMethod === undefined) {
    if (proofs.length > 1) {
      throw new ProofError(
        `Document carries ${proofs.length} proofs; specify verificationMethod to choose one`,
      );
    }
    return first;
  }

  const matches = proofs.filter((p) => p.verificationMethod === verificationMethod);
  const [match] = matches;
  if (match === undefined) {
    throw new ProofError(`No proof found with verificationMethod "${verificationMethod}"`);
  }
  if (matches.length > 1) {
    throw new ProofError(`Multiple proofs share verificationMethod "${verificationMethod}"`);
  }
  return match;
}
