# @open-transaction-layer/core

## 0.2.0

### Minor Changes

- [`1746e50`](https://github.com/Open-Transaction-Layer/otl-sdk/commit/1746e50fd933e570f48efffff8a20e91b81162bf) Thanks [@mfoyle-otl](https://github.com/mfoyle-otl)! - First public release of the OTL Identity layer SDK and command line tool, implementing the OTL Identity Layer Technical Specification v0.6.

  The SDK issues and verifies the `OtlLeiCredential` and `OtlHostingCredential` types and validates `did:webvh` logs, including the pre-rotation commitments that bind each key update to the keys announced before it. It detects a forked or rolled-back DID log through `DidHeadMemory` in `@open-transaction-layer/resolver`, and it caps a decoded status list at 64 times the specification's minimum size so that a small hostile payload cannot exhaust a verifier's memory. `@open-transaction-layer/jwe` provides a JWE Compact envelope using ECDH-ES and A256GCM, which is provisional because the specification defines key-agreement key types but no encryption envelope.

  Verification is strict by default. Presentations are signed and verified with `proofPurpose: "authentication"` as the specification requires, a proof whose `expires` has passed or is not a date-time is rejected, and JCS canonicalization refuses input that is not valid I-JSON. The resolver refuses to fetch from a loopback, link-local, private or otherwise non-public address, and it checks the address a name actually resolves to and connects to the address it checked. Pass `blockPrivateAddresses: false` to the resolver functions, or `--allow-private-addresses` on the command line, to reach `localhost` during development.

  `@open-transaction-layer/credentials` exports `OTL_IDENTITY_CONTEXT`, which is `https://www.otl.network/contexts/identity/v1`, and the bundled context keeps every `OtlLeiCredential` field in RDF as well as in expansion and defines the terms of `OtlHostingCredential`. Credentials carry `credentials/v2` alone until the published URL resolves.

  The command line tool adds `otl credential refresh-status`, which re-signs a status list before its 1-hour validity runs out, and `otl credential status-list` shows when the list expires. `otl credential fetch` exits with code 2 when the presentation or any recognised credential fails validation, and `otl verify` accepts only a key listed under `assertionMethod`, or under `authentication` when `--relationship authentication` is given.

  The packages are versioned together and released together, so an SDK version can be matched against a specification version without consulting a table. The version is below 1.0, so no stability promise is made about any interface.

  `@open-transaction-layer/keys-dev` and `@open-transaction-layer/cli` are explicitly not production-ready, because both hold private key material. A production deployment implements `KeyProvider` from `@open-transaction-layer/keys` against a KMS, an HSM or a Key Vault, and validates that implementation with the conformance kit at `@open-transaction-layer/keys/conformance`.

### Patch Changes

- Updated dependencies [[`1746e50`](https://github.com/Open-Transaction-Layer/otl-sdk/commit/1746e50fd933e570f48efffff8a20e91b81162bf)]:
  - @open-transaction-layer/keys@0.2.0
