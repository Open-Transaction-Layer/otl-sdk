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
  /**
   * Optional OTL extension: verificationMethod fragments designated
   * genesis-bound, written into `parameters`. Entry 1 only.
   *
   * **Non-conformant placement.** did:webvh requires that "the `parameters`
   * object MUST only include properties defined in the version of the
   * `did:webvh` DID Method specification being used", and its parameter set is
   * closed. Tested against the reference implementations: didwebvh-dart
   * rejects a log carrying this (reporting a misleading `SCID verification
   * failed`), and didwebvh-ts accepts but drops it from resolved metadata, so a
   * verifier built on it applies none of the genesis-bound rules and fails
   * open.
   *
   * Validation reads this form so that a log using it is still checked, and
   * `createDid` can emit it for comparison. Prefer
   * {@link GENESIS_BOUND_KEYS_PROPERTY} in the genesis document.
   */
  readonly genesisBoundKeys?: readonly string[];
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

/**
 * Property carrying the genesis-bound designation in the genesis DID document.
 *
 * Genesis-bound keys are an optional OTL extension that the Identity layer
 * specification does not define or require. A DID that designates a key
 * genesis-bound commits, in its first version, that the key's material never
 * changes and that the key is never removed. A verifier reads the designation
 * from version 1 only, because the current document cannot be trusted to
 * self-report it, and rejects a log whose current document drops or replaces a
 * designated key.
 *
 * The designation lives in the DID document rather than in `parameters`. DID
 * Core supports document extension by design (DID 1.1 §4.1), where did:webvh's
 * `parameters` object explicitly forbids it: "The parameters object MUST only
 * include properties defined in the version of the did:webvh DID Method
 * specification being used." Tested against two reference implementations,
 * the `parameters` placement is rejected by one and silently dropped by the
 * other, and the document placement is accepted and preserved by both.
 *
 * The SCID commits to the whole genesis entry, document included, so the
 * designation is tamper-evident in either placement.
 */
export const GENESIS_BOUND_KEYS_PROPERTY = 'genesisBoundKeys';

/**
 * Context defining {@link GENESIS_BOUND_KEYS_PROPERTY}.
 *
 * This URL MUST resolve to a context that actually defines the term. DID 1.1
 * §6.2.3: "Conforming consumers that process a JSON-LD representation SHOULD
 * drop all terms from a DID document that are not defined via the `@context`."
 * A placeholder URI would reintroduce the exact silent-drop failure this
 * placement exists to avoid.
 */
export const OTL_IDENTITY_CONTEXT = 'https://otl.network/contexts/identity/v1';

/** Where the genesis-bound designation is written. */
export type GenesisBoundPlacement = 'document' | 'parameters';

/** Context URIs required per OTL spec 3.1, keyed by what makes them required. */
export const CONTEXT = {
  did: 'https://www.w3.org/ns/did/v1',
  ed25519: 'https://w3id.org/security/suites/ed25519-2020/v1',
  jws: 'https://w3id.org/security/suites/jws-2020/v1',
  x25519: 'https://w3id.org/security/suites/x25519-2020/v1',
} as const;
