---
"@otl/credentials": minor
"@otl/keys-dev": minor
"@otl/resolver": minor
"@otl/core": minor
"@otl/keys": minor
"@otl/jwe": minor
"@otl/cli": minor
---

First public release of the OTL Identity layer SDK and command line tool,
implementing the OTL Identity Layer Technical Specification v0.6.

The SDK issues and verifies the `OtlLeiCredential` and `OtlHostingCredential`
types, detects a forked or rolled-back DID log through `DidHeadMemory` in
`@otl/resolver`, and caps a decoded status list at 64 times the specification's
minimum size so that a small hostile payload cannot exhaust a verifier's
memory. `@otl/jwe` provides a JWE Compact envelope using ECDH-ES and A256GCM,
which is provisional because the specification defines key-agreement key types
but no encryption envelope.

The packages are versioned together and released together, so an SDK version
can be matched against a specification version without consulting a table. The
version is below 1.0, so no stability promise is made about any interface.

`@otl/keys-dev` and `@otl/cli` are explicitly not production-ready, because
both hold private key material. A production deployment implements
`KeyProvider` from `@otl/keys` against a KMS, an HSM or a Key Vault, and
validates that implementation with the conformance kit at
`@otl/keys/conformance`.
