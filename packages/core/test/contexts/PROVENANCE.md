# Vendored: W3C Verifiable Credentials v2 JSON-LD context

Source: https://www.w3.org/ns/credentials/v2
Retrieved: 2026-10-29
Licence: W3C Software and Document License
(https://www.w3.org/copyright/software-license-2023/)

`credentials-v2.jsonld` is the JSON-LD context that every Verifiable
Credentials Data Model v2.0 credential names in its `@context`, and it is
redistributed here byte for byte as the W3C serves it.[^identical]

It is vendored so that `packages/core/test/jsonld.test.ts` can expand
credentials through an in-memory document loader and so the suite stays
reproducible offline, because fetching a context over the network during a test
would make a passing result depend on the availability of a server we do not
control. It is deliberately not shipped in any published package: the `files`
field of each package does not list `test/`, and the tarballs were checked to
confirm that, so consumers resolve this context through their own loader.

Refresh it deliberately and re-read the diff, because a change in this file is
a change in how every v2 credential is interpreted.

[^identical]: The file is 10131 bytes with a SHA-256 of
`59955ced6697d61e03f2b2556febe5308ab16842846f5b586d7f1f7adec92734`, and the
`@context` object has 31 top-level keys. Both figures were taken on 2026-10-29
by requesting `https://www.w3.org/ns/credentials/v2` with an
`Accept: application/ld+json` header, which returned HTTP 200 with 10131 bytes
that `cmp` reported as identical to the vendored file, so the 31 keys are the
same 31 in both. The count is of keys directly under `@context`, which includes
the `@protected` flag and the `id` and `type` aliases as well as the vocabulary
terms.
