/**
 * Core value types for the OTL key layer.
 *
 * These types are shared between `@otl/core` and every KeyProvider
 * implementation, including bridges written by consumers of this SDK.
 * They are deliberately free of any backend-specific concepts.
 */

/**
 * Curves the OTL Identity layer permits (spec 3.1.1, "cryptographic agility").
 *
 *  - `Ed25519` signing, via the `eddsa-jcs-2022` cryptosuite.
 *  - `P-256`   signing, via the `ecdsa-jcs-2019` cryptosuite.
 *  - `X25519`  key agreement only. It can never sign.
 *
 * P-256 is also usable for ECDH key agreement (RFC 7518), so it is the one
 * curve that appears in both the signing and key-agreement capability lists.
 */
export type Curve = 'Ed25519' | 'P-256' | 'X25519';

export const SIGNING_CURVES: readonly Curve[] = ['Ed25519', 'P-256'];
export const KEY_AGREEMENT_CURVES: readonly Curve[] = ['X25519', 'P-256'];

export const isSigningCurve = (c: Curve): boolean => SIGNING_CURVES.includes(c);
export const isKeyAgreementCurve = (c: Curve): boolean => KEY_AGREEMENT_CURVES.includes(c);

/**
 * A reference to a key held by some provider.
 *
 * `label` is the stable logical name the caller chose (e.g. `did-management`).
 * `providerRef` is opaque to `@otl/core`: a bridge may store a KMS key ARN,
 * a Key Vault key URL, a PKCS#11 CKA_ID, or a file path there. Core code MUST
 * NOT parse or interpret it.
 */
export interface KeyHandle {
  readonly label: string;
  readonly providerRef?: string;
}

/**
 * A public key in its canonical raw form.
 *
 * Byte encodings are fixed so that every provider agrees:
 *  - `Ed25519` / `X25519` — 32 bytes, the raw curve point.
 *  - `P-256`             — 65 bytes, SEC1 *uncompressed* (leading `0x04`).
 *
 * P-256 is held uncompressed because that form is unambiguous and is what
 * every backend can produce. Compression to the 33-byte form required by
 * Multikey encoding happens in `encoding.ts`, not in providers.
 */
export interface PublicKey {
  readonly curve: Curve;
  readonly bytes: Uint8Array;
}

/** Expected raw public-key length in bytes, by curve. */
export const PUBLIC_KEY_LENGTH: Readonly<Record<Curve, number>> = {
  Ed25519: 32,
  X25519: 32,
  'P-256': 65,
};

/**
 * Expected raw signature length in bytes, by curve.
 *
 * Both are 64: Ed25519 is R‖S, P-256 is r‖s in IEEE P1363 form. Notably this
 * is NOT the DER form that AWS KMS, Azure Key Vault and most PKCS#11 modules
 * return by default — converting is the bridge's responsibility. See
 * `KeyProvider.sign`.
 */
export const SIGNATURE_LENGTH: Readonly<Partial<Record<Curve, number>>> = {
  Ed25519: 64,
  'P-256': 64,
};

export interface KeyInfo {
  readonly handle: KeyHandle;
  readonly curve: Curve;
  readonly publicKey: PublicKey;
  /** ISO 8601. Optional: some backends do not expose a creation time. */
  readonly createdAt?: string;
}

/**
 * What a provider can actually do.
 *
 * Declared up front so that commands can fail during argument parsing rather
 * than halfway through a multi-step operation such as a DID rotation. The
 * conformance kit asserts that declared capabilities match observed behaviour.
 */
export interface ProviderCapabilities {
  /** Curves this provider can sign with. */
  readonly signing: readonly Curve[];
  /** Curves this provider can perform ECDH with. Empty is legitimate — Azure
   *  Key Vault, for example, exposes no key-agreement operation at all. */
  readonly keyAgreement: readonly Curve[];
  /** False when keys are provisioned out-of-band by a governed process and the
   *  application holds only sign rights. This is the normal shape of a
   *  production KMS/HSM deployment, not a degraded mode. */
  readonly canGenerate: boolean;
  /** True only for non-production providers. No HSM or KMS can export. */
  readonly canExportPrivateKey: boolean;
}
