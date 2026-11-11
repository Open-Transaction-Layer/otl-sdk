# `@otl/resolver`

`did:webvh` resolution over HTTPS, `whois` presentations and status-list
fetching for the OTL Identity layer.

This is the only package in the SDK that performs network I/O, which is why it
is separate: a verifier doing offline verification against logs it already
holds can depend on [`@otl/core`](../core) and never pull this in.

## What it does

`resolveDid` fetches the DID document a domain serves at `did.json` and checks
only that its `id` matches the DID asked for. It performs no cryptographic
validation, so the document it returns is whatever the domain served and is
suitable for inspection but not for a trust decision.

`validateDid` fetches the version log at `did.jsonl`, verifies the hash chain
and every entry's proof back to genesis and checks that the self-certifying
identifier matches, so the document it returns has been proven rather than
merely retrieved. `resolveVerificationKey` and `resolveAssertionKey` build on
`validateDid` and also require the key to be referenced under the expected
verification relationship. When given a `DidHeadMemory`, validation also
refuses a log that does not extend the newest version previously accepted for
that DID.

`verifyWhois` fetches the presentation a DID publishes about itself, verifies
the presentation proof against a key listed in the holder's `authentication`,
and runs every credential inside it through the verification chain. The
status-list path fetches the bitstring a credential points at so that
revocation can be checked.

All fetching requires HTTPS, caps response size, applies a timeout and refuses
redirects, and TLS verification is never disabled. The `blockPrivateAddresses`
option refuses loopback, link-local, private-range and other non-public
addresses, both when one is written into the URL and when a hostname resolves
to one. It is on by default, and the built-in transport resolves the name once,
checks every address returned and connects to the address it checked, so a
public-looking name that points at a private address is refused. Set it to
`false` for local development against `localhost`. A `fetch` you supply
replaces that transport, so it only gets the literal-address check and is
responsible for its own network policy.

Licensed under Apache-2.0.
