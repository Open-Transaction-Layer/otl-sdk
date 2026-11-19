# JSON-LD contexts

`otl-identity-v1.jsonld` defines the terms that `OtlLeiCredential` (§4.9) and
`OtlHostingCredential` (§4.14) use. Each watcher URL expands as an IRI.

## Why it is needed

VC 2.0 is a JSON-LD data model, and its rule is that a conforming consumer
**drops any term the `@context` does not define**. OTL spec §4.9 defines
14 `credentialSubject` fields, but W3C's `credentials/v2` context defines none
of them and §4.10's example carries no other context.

As a result, an `OtlLeiCredential` built exactly as §4.10 shows expands to

```json
"credentialSubject": [{ "@id": "did:webvh:…" }]
```

Every claim, including the LEI, legal name, addresses, jurisdiction and
managing LOU, is discarded. **The signature still verifies**, because
`eddsa-jcs-2022` canonicalizes raw JSON and never sees the expanded form, so
the failure is silent. A consumer that reads the credential as plain JSON sees
every field, while one that processes it as JSON-LD, as the standard says to,
sees none of them.

With this context all 14 LEI fields and both hosting fields survive, which
`packages/core/test/jsonld.test.ts` verifies.

## Status

The identifier is `https://www.otl.network/contexts/identity/v1`, and the term
namespace is `https://www.otl.network/ns/identity#`. The published copy lives in the
separate `otl-contexts` repository, served from GitHub Pages, and a test in
`packages/credentials/test/context.test.ts` pins this file's SHA-384 so the two
copies cannot drift apart unnoticed. The `www.otl.network` routes that point at it
are not in place yet, and a credential that referenced a URL returning 404
would fail to expand at all, so the issuer emits `credentials/v2` only.

To emit this context once the URL resolves, add `OTL_IDENTITY_CONTEXT` to
`additionalContexts` on `OtlLeiCredentialType` and `OtlHostingCredentialType`,
and update the first group in `packages/core/test/jsonld.test.ts`, which is
written to start failing on that day.

The SDK bundles this file (`@otl/credentials/context`) so that verification
never fetches it. Fetching it would make every verification of an OTL
credential depend on OTL's server, and would disclose the verifier's IP address
and timing for every counterparty check.

Credentials issued before the URL resolves are disposable proof of concept
artefacts, so moving to another identifier later costs a reissue and nothing
more. The context and its terms must be treated as immutable once a credential
has been signed against them, and changes must be additive only, because
`@protected` turns a changed definition into a hard error.

## An authoring trap

The subject's terms sit on the `credentialSubject` node, while the
`OtlLeiCredential` type sits on the credential node. Scoping `lei`, `entity`
and `registration` inside the type's own `@context` therefore looks correct
but **silently does nothing**, because the type expands and every field still
drops. The terms must be defined at the top level.
