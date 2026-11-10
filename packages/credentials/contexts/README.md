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

`https://otl.network/contexts/identity/v1` does not resolve yet. A credential
that referenced a URL returning 404 would fail to expand at all, so the issuer
emits `credentials/v2` only. To emit this context, add `OTL_IDENTITY_CONTEXT`
to a credential type's `additionalContexts`.

The SDK bundles this file (`@otl/credentials/context`) so that verification
never fetches it. Fetching it would make every verification of an OTL
credential depend on OTL's server, and would disclose the verifier's IP address
and timing for every counterparty check.

## Hosting requirements

- Serve the file at a stable HTTPS URL with `Content-Type: application/ld+json`
  and `Access-Control-Allow-Origin: *`, because browser-based verifiers need
  the CORS header.
- A `https://w3id.org/otl/identity/v1` identifier is preferable to an
  `otl.network` path, because w3id is a redirect service and the identifier
  survives the domain lapsing.
- Treat the URL as immutable and make additive changes only, because
  `@protected` turns a changed definition into a hard error.
- Publish a human-readable page defining the terms, and register the context
  in the W3C extensions registry for cross-representation interoperability.

## An authoring trap

The subject's terms sit on the `credentialSubject` node, while the
`OtlLeiCredential` type sits on the credential node. Scoping `lei`, `entity`
and `registration` inside the type's own `@context` therefore looks correct
but **silently does nothing**, because the type expands and every field still
drops. The terms must be defined at the top level.
