/**
 * `@open-transaction-layer/keys-dev` — NON-PRODUCTION `KeyProvider` implementations.
 *
 * Both providers in this package hold raw private key material in the
 * process, and {@link FileKeyProvider} additionally writes it to disk. They
 * exist so that the CLI, the test suite and the examples can run without a
 * key management service, and they are published separately from `@open-transaction-layer/keys`
 * precisely so that depending on the contract never drags private key
 * handling into a production dependency tree.
 *
 * Do not use either provider to hold a key that protects anything real.
 * A production deployment implements `KeyProvider` against a KMS, an
 * HSM or a Key Vault, and validates that implementation with the conformance
 * kit in `@open-transaction-layer/keys/conformance`.
 */

export { FileKeyProvider, type FileKeyProviderOptions } from './file.ts';
export { InMemoryKeyProvider } from './in-memory.ts';
