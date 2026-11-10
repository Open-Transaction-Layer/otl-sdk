/**
 * The OTL key-provider contract.
 *
 * This module ships an abstraction and nothing else. Bridging to AWS KMS,
 * Azure Key Vault, a PKCS#11 HSM or an internal signing service is the
 * responsibility of whoever consumes this SDK; the only implementations in
 * this package are the non-production file and in-memory ones used for
 * development and tests.
 *
 * The contract is split into one mandatory base class and three optional
 * capability interfaces. The mandatory set is exactly what *every* backend can
 * do. Generation, key agreement and export are not universal — folding them
 * into the base would force every bridge to stub out methods it cannot honour.
 *
 * @see `@otl/keys/conformance` — the test kit a bridge should run in its own CI.
 */

import type { Curve, KeyInfo, ProviderCapabilities, PublicKey } from './types.ts';

/**
 * The mandatory contract. Every backend can satisfy all four members.
 */
export abstract class KeyProvider {
  /** Stable identifier for this provider, for logs and error messages. */
  abstract readonly id: string;

  /**
   * What this provider can do. Callers check this *before* starting an
   * operation, so that an unsupported combination fails at argument-parsing
   * time rather than midway through something stateful such as a rotation.
   *
   * Implementations MUST return values consistent with actual behaviour; the
   * conformance kit verifies this.
   */
  abstract capabilities(): ProviderCapabilities;

  /** @throws {KeyNotFoundError} when no key exists under `label`. */
  abstract getKey(label: string): Promise<KeyInfo>;

  abstract listKeys(): Promise<readonly KeyInfo[]>;

  /**
   * Sign `message` — the FULL message, never a pre-computed digest.
   *
   * Ed25519 is not a pre-hash scheme (Ed25519ph is a distinct algorithm), so
   * the contract cannot pass a digest and remain valid for both curves. A
   * P-256 implementation hashes with SHA-256 internally; an Ed25519 one passes
   * the message through untouched.
   *
   * Implementations MUST return a raw, fixed-width signature:
   *   - Ed25519 -> 64 bytes, R‖S
   *   - P-256   -> 64 bytes, r‖s (IEEE P1363). **Not DER.**
   *
   * That last point is the single most likely defect in a bridge: AWS KMS,
   * Azure Key Vault and most PKCS#11 modules return DER-encoded ECDSA
   * signatures by default. Converting DER to r‖s is the bridge's job, and the
   * conformance kit tests for it explicitly.
   *
   * @throws {KeyNotFoundError} when no key exists under `label`.
   * @throws {UnsupportedOperationError} when the key's curve cannot sign.
   */
  abstract sign(label: string, message: Uint8Array): Promise<Uint8Array>;
}

/**
 * Optional: create new keys.
 *
 * Many production deployments provision keys out-of-band through a governed
 * process and grant the application sign-only rights. A provider that can only
 * *reference* pre-provisioned keys is a first-class citizen — callers check
 * {@link supportsGeneration} and fall back to requiring explicit key labels.
 */
export interface GeneratesKeys {
  /** @throws {KeyAlreadyExistsError} if `label` is taken. Never overwrites. */
  generateKey(label: string, curve: Curve): Promise<KeyInfo>;
}

/**
 * Optional: ECDH key agreement, required only for `otl encrypt` / `otl decrypt`.
 *
 * Returns the raw shared secret Z. Key derivation (Concat KDF, RFC 7518 §4.6.2)
 * and the JWE envelope
 * live in `@otl/jwe`, not here, so that every backend produces the same
 * ciphertext for the same inputs.
 *
 * Not every backend has this: Azure Key Vault exposes no key-agreement
 * operation at all, so an AKV bridge legitimately omits this interface and the
 * encryption commands are simply unavailable to that consumer.
 */
export interface DerivesSharedSecrets {
  deriveSharedSecret(label: string, peerPublicKey: PublicKey): Promise<Uint8Array>;
}

/**
 * Optional, and non-production by definition.
 *
 * No HSM or KMS implements this — that is the entire point of those products.
 * It exists so the file and in-memory providers can support development
 * workflows such as backing up a throwaway DID.
 *
 * Nothing in `@otl/core`, `@otl/credentials`, `@otl/resolver` or the CLI
 * calls it, and a KMS or HSM bridge should never implement it.
 */
export interface ExportsPrivateKeys {
  exportPrivateKey(label: string): Promise<Uint8Array>;
}

export const supportsGeneration = (p: KeyProvider): p is KeyProvider & GeneratesKeys =>
  p.capabilities().canGenerate;

export const supportsKeyAgreement = (p: KeyProvider): p is KeyProvider & DerivesSharedSecrets =>
  p.capabilities().keyAgreement.length > 0;

export const supportsPrivateKeyExport = (p: KeyProvider): p is KeyProvider & ExportsPrivateKeys =>
  p.capabilities().canExportPrivateKey;
