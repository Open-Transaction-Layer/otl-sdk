/**
 * `@open-transaction-layer/keys/node` — Node.js cryptographic helpers for provider authors.
 *
 * A {@link KeyProvider} implementation that holds key material in a KMS, an
 * HSM or a Key Vault does not need any of this, because the remote service
 * performs the operations. A provider that handles `KeyObject`s locally —
 * the development providers in `@open-transaction-layer/keys-dev`, or a bridge that unwraps a
 * key before use — needs the same encoding and signing primitives the
 * reference providers use, and reimplementing them is the likeliest place
 * for a conformance defect to appear.
 *
 * These helpers are therefore a supported extension point rather than
 * internals. The invariants they preserve are the two the conformance kit
 * checks hardest: `signWith` takes the full message and never a digest,
 * because Ed25519 cannot pre-hash, and it returns raw fixed-width `r‖s`
 * rather than DER.
 *
 * @see `@open-transaction-layer/keys/conformance` to validate an implementation built on these.
 */

export {
  deriveSharedSecretWith,
  exportPkcs8,
  generateKeyObject,
  importPkcs8,
  importPublicKey,
  publicKeyFrom,
  signWith,
  verifyWith,
} from './nodecrypto.ts';
