---
"@open-transaction-layer/credentials": minor
"@open-transaction-layer/keys-dev": minor
"@open-transaction-layer/resolver": minor
"@open-transaction-layer/core": minor
"@open-transaction-layer/keys": minor
"@open-transaction-layer/jwe": minor
"@open-transaction-layer/cli": minor
---

First public release of the OTL Identity layer SDK and command line tool,
implementing the OTL Identity Layer Technical Specification v0.6.

The SDK issues and verifies the `OtlLeiCredential` and `OtlHostingCredential`
types, detects a forked or rolled-back DID log through `DidHeadMemory` in
`@open-transaction-layer/resolver`, and caps a decoded status list at 64 times the specification's
minimum size so that a small hostile payload cannot exhaust a verifier's
memory. `@open-transaction-layer/jwe` provides a JWE Compact envelope using ECDH-ES and A256GCM,
which is provisional because the specification defines key-agreement key types
but no encryption envelope.

The packages are versioned together and released together, so an SDK version
can be matched against a specification version without consulting a table. The
version is below 1.0, so no stability promise is made about any interface.

`@open-transaction-layer/keys-dev` and `@open-transaction-layer/cli` are explicitly not production-ready, because
both hold private key material. A production deployment implements
`KeyProvider` from `@open-transaction-layer/keys` against a KMS, an HSM or a Key Vault, and
validates that implementation with the conformance kit at
`@open-transaction-layer/keys/conformance`.
