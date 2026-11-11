/**
 * did:webvh 1.0 log entry and DID document types, profiled for OTL.
 *
 * @see https://identity.foundation/didwebvh/v1.0/
 */

/** The only method version this implementation supports. */
export const DIDWEBVH_METHOD = 'did:webvh:1.0';

/**
 * The only Data Integrity cryptosuite did:webvh 1.0 permits for log-entry
 * proofs: "Permitted Data Integrity cryptosuites for both log-entry proofs and
 * witness proofs: exactly `eddsa-jcs-2022`".
 *
 * This constrains the DID Management Key to Ed25519 regardless of what OTL
 * spec 3.1.1 says about cryptographic agility — that agility governs
 * `verificationMethod` and `keyAgreement` entries *inside* the document, not
 * the method-level proof over the log entry itself.
 */
export const DIDWEBVH_CRYPTOSUITE = 'eddsa-jcs-2022';

/** The literal placeholder substituted during SCID derivation. */
export const SCID_PLACEHOLDER = '{SCID}';

export interface DidLogParameters {
  /** Required in entry 1. */
  readonly method?: string;
  /** Required in entry 1 only; MUST NOT appear in later entries. */
  readonly scid?: string;
  /** Multikey-formatted keys authorized to sign the next entry. */
  readonly updateKeys?: readonly string[];
  /** Hashes committing to the next `updateKeys`. Non-empty activates pre-rotation. */
  readonly nextKeyHashes?: readonly string[];
  /** Entry 1 only. */
  readonly portable?: boolean;
  readonly witness?: Record<string, unknown>;
  readonly watchers?: readonly string[];
  readonly deactivated?: boolean;
  readonly ttl?: number;
}

export interface DidLogEntry {
  /** `{SCID}` while deriving, then `{versionNumber}-{entryHash}`. */
  readonly versionId: string;
  /** UTC ISO 8601. */
  readonly versionTime: string;
  readonly parameters: DidLogParameters;
  /** The resolved DID document for this version. */
  readonly state: DidDocument;
  readonly proof?: unknown;
}

export interface VerificationMethod {
  readonly id: string;
  readonly type: 'Ed25519VerificationKey2020' | 'X25519KeyAgreementKey2020' | 'JsonWebKey2020';
  readonly controller: string;
  readonly publicKeyMultibase?: string;
  readonly publicKeyJwk?: Record<string, string>;
}

export interface ServiceEntry {
  readonly id: string;
  readonly type: string | readonly string[];
  readonly serviceEndpoint: unknown;
  readonly [key: string]: unknown;
}

export interface DidDocument {
  readonly '@context': readonly string[];
  readonly id: string;
  readonly verificationMethod?: readonly VerificationMethod[];
  readonly authentication?: readonly string[];
  readonly assertionMethod?: readonly string[];
  readonly keyAgreement?: readonly string[];
  readonly service?: readonly ServiceEntry[];
  readonly [key: string]: unknown;
}

/** Context URIs required per OTL spec 3.1, keyed by what makes them required. */
export const CONTEXT = {
  did: 'https://www.w3.org/ns/did/v1',
  ed25519: 'https://w3id.org/security/suites/ed25519-2020/v1',
  jws: 'https://w3id.org/security/suites/jws-2020/v1',
  x25519: 'https://w3id.org/security/suites/x25519-2020/v1',
} as const;
