/**
 * `@otl/keys` — the OTL Identity layer key-provider contract.
 *
 * This package ships the abstraction and nothing that holds private key
 * material. It deliberately contains no KMS, Key Vault or HSM bridge: those
 * are written by the consumer against {@link KeyProvider}, with the Node
 * primitives in `@otl/keys/node` if the bridge handles keys locally, and
 * validated with the conformance kit in `@otl/keys/conformance`.
 *
 * The development providers that do hold private keys on disk or in memory
 * live in `@otl/keys-dev`, which is a separate package so that installing
 * this one never places file-backed key handling in a production dependency
 * tree.
 */

export * from './types.ts';
export * from './errors.ts';
export * from './provider.ts';
export {
  base58btcDecode,
  base58btcEncode,
  bytesEqual,
  compressP256,
  decompressP256,
  fromMultibaseBase58,
  fromMultibaseBase64url,
  fromPublicKeyJwk,
  fromPublicKeyMultibase,
  toMultibaseBase58,
  toMultibaseBase64url,
  toPublicKeyJwk,
  toPublicKeyMultibase,
} from './encoding.ts';
export { verifyWith as verifySignature } from './nodecrypto.ts';
export { agreeEphemeral, type EphemeralAgreement } from './ephemeral.ts';
