# `@otl/credentials`

Verifiable credentials for the OTL Identity layer: a pluggable credential-type
registry, the LEI and hosting credential types, the local trust perimeter and
the validation chain.

## Credential types are pluggable

Each credential type is a registered plugin rather than something hard-coded,
so adding a type does not require changing the issuance or verification paths.
`defaultRegistry()` registers `OtlLeiCredentialType` (§4.6 to §4.11) and
`OtlHostingCredentialType` (§4.14). The bundled JSON-LD context defines the terms
of both types, as [contexts/README.md](contexts/README.md) describes.

## Trust is local, always

There is no protocol-defined root of trust. Every trust decision is made by the
verifier against its own perimeter, nothing is trusted by default, and an empty
perimeter means nothing validates. That is the specification's design rather
than an omission in this implementation.

## The JSON-LD context

VC 2.0 is a JSON-LD data model, and a conforming consumer drops every term its
`@context` does not define. A verifier that cannot resolve the OTL context
therefore sees an `OtlLeiCredential` reduced to a bare subject identifier with
all of its claims gone, and the signature still verifies in that state, because
`eddsa-jcs-2022` canonicalizes the raw JSON rather than the expanded form.

This package ships the context as an asset and resolves it from disk:

```ts
import jsonld from 'jsonld';
import { bundledDocumentLoader } from '@otl/credentials/context';

const documentLoader = bundledDocumentLoader({ fallback: yourW3cLoader });
await jsonld.expand(credential, { documentLoader });
```

Resolution is from disk rather than the network on purpose, because fetching
would make verification fail whenever the host is unreachable, and it would
disclose to whoever hosts the context which credentials a verifier is
processing and when. The loader carries the OTL context only, since the W3C
contexts are someone else's documents to redistribute and the ecosystem already
packages them, so supply those through `fallback`.

Licensed under Apache-2.0.
