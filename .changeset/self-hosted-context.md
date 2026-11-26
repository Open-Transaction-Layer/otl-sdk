---
"@open-transaction-layer/core": minor
"@open-transaction-layer/credentials": minor
"@open-transaction-layer/cli": minor
---

**Breaking:** the `genesisBoundKeys` extension is removed, because the specification dropped the section that defined it in v0.4 and the term was the only reason a DID document ever referenced the OTL context. `createDid` no longer accepts `genesisBoundKeys` or `genesisBoundPlacement`, `OTL_IDENTITY_CONTEXT`, `GENESIS_BOUND_KEYS_PROPERTY` and `GenesisBoundPlacement` are gone from `@open-transaction-layer/core`, validation no longer applies any genesis-bound rule, and `did create` no longer takes `--genesis-bound`.

`@open-transaction-layer/credentials` now exports `OTL_IDENTITY_CONTEXT`, which is `https://www.otl.network/contexts/identity/v1`, and the bundled context now keeps every `OtlLeiCredential` field in RDF as well as in expansion. `legalForm` and `registeredAt` carry their codes as the literals `elfCode` and `registrationAuthorityCode` instead of relative IRIs that vanished without a base IRI, and the context defines the terms of `OtlHostingCredential`. Credentials still carry `credentials/v2` alone until the published URL resolves, so existing credentials are unaffected.
