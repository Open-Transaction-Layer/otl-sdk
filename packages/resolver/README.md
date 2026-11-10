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
option, which refuses loopback, link-local and private-range hostnames, is off
by default so that local development against `localhost` works, and it must be
enabled for any server-side use that resolves counterparty DIDs. It inspects
hostname literals only and does not resolve DNS, so a server also needs
network-level egress controls to stop a public name that points at a private
address.

Licensed under Apache-2.0.
