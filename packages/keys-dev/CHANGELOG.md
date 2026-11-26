# @open-transaction-layer/keys-dev

## 0.2.0

### Minor Changes

- [`1746e50`](https://github.com/Open-Transaction-Layer/otl-sdk/commit/1746e50fd933e570f48efffff8a20e91b81162bf) Thanks [@mfoyle-otl](https://github.com/mfoyle-otl)! - First public release of the OTL Identity layer SDK and command line tool,
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

- [`1746e50`](https://github.com/Open-Transaction-Layer/otl-sdk/commit/1746e50fd933e570f48efffff8a20e91b81162bf) Thanks [@mfoyle-otl](https://github.com/mfoyle-otl)! - **Security:** DID log validation no longer lets an entry with an empty `updateKeys` list sidestep pre-rotation. Such an entry used to be authorized by the keys before it and was exempt from the commitment check, so whoever held only the current update key could empty the list and then append an entry naming keys of their own choosing. While pre-rotation is active an empty `updateKeys` list is now refused, no entry may follow one with an empty list, and an entry that omits `nextKeyHashes` keeps the earlier commitment in force rather than switching the check off. A later entry that changes `method` is refused as unsupported.

  **Breaking:** whois presentations are now signed and verified with `proofPurpose: "authentication"`, as spec 6.3 requires, so a presentation signed with `assertionMethod` is rejected. Re-run `otl whois publish` to re-sign an existing presentation.

  `verifyProof` now rejects a proof whose `expires` has passed or is not a date-time, and it accepts a `now` option. JCS canonicalization refuses sparse arrays and strings with lone surrogates instead of emitting output that is not valid I-JSON. Credential verification refuses a revocation status entry whose `statusSize` is not 1. The resolver refuses a DID whose path segments decode to `/`, `?`, `#`, a backslash or a control character.

  `FileKeyProvider.getKey` and `listKeys` now check that the public key recorded in a key file belongs to its private key and that the file's label matches its name, so they need the correct passphrase.

  The CLI adds `otl credential refresh-status`, which re-signs a status list before its 1-hour validity runs out, and `otl credential status-list` now shows when the list expires. `otl credential fetch` exits with code 2 when the presentation or any recognised credential fails validation. `otl verify` accepts only a key listed under `assertionMethod`, or under `authentication` when `--relationship authentication` is given.

### Patch Changes

- Updated dependencies [[`1746e50`](https://github.com/Open-Transaction-Layer/otl-sdk/commit/1746e50fd933e570f48efffff8a20e91b81162bf)]:
  - @open-transaction-layer/keys@0.2.0
