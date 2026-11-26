# OTL Identity

A reference implementation of the **OTL (Open Transaction Layer) Identity
layer** — `did:webvh` identities, W3C Verifiable Credentials, Bitstring Status
List revocation, and a local trust perimeter — as an SDK and a command line
tool.

Built against the *OTL Identity Layer Technical Specification*, which lives in
the [`otl-specifications`](https://github.com/Open-Transaction-Layer/otl-specifications/blob/main/identity/identity-spec.md)
repository. Section references throughout the source (§3.2.1, §5.3, …) point
at that document.

> **did:web is not supported.** The specification permits both methods; this
> implementation resolves `did:webvh` only. `did:web` identifiers are rejected
> rather than partially handled.

> **Non-production.** File-backed private keys are a development affordance,
> and they live in [`@open-transaction-layer/keys-dev`](packages/keys-dev/README.md) so that
> depending on the `KeyProvider` contract never places private key handling in
> a production dependency tree. Production deployments bridge `KeyProvider` to
> a KMS or HSM instead and validate that bridge with `@open-transaction-layer/keys/conformance`.
> The CLI says so on every command that touches the local keystore, and the
> warning is not suppressible.

## What it does

The Identity layer answers two questions a counterparty needs before
transacting:

| Question | Mechanism |
|---|---|
| *Are you the same party as before, and has anyone tampered with your record?* | `did:webvh` — a self-certifying identifier plus a hash-chained, signed version log |
| *And who are you in the real world?* | Verifiable Credentials from issuers **you** have chosen to trust |

There is no protocol-defined root of trust. Every trust decision is local
(§4.6, §6.1) — nothing is trusted by default, and the CLI says so when your
perimeter is empty.

## Try it

```bash
examples/two-party-walkthrough.sh
```

Runs the full flow locally over real HTTPS with three separate parties: an LOU
issues an LEI credential to a VASP, the VASP publishes it, a counterparty
validates the DID to genesis, fetches the credential, rejects it (empty trust
perimeter), then accepts it after choosing to trust the issuer — and rejects it
again once revoked.

No network access needed; the GLEIF record is supplied from a local fixture.

## Layout

| Package | Contents | Production |
|---|---|---|
| [`@open-transaction-layer/keys`](packages/keys/README.md) | The abstract `KeyProvider` contract, plus a conformance kit for validating a KMS or HSM bridge | yes |
| [`@open-transaction-layer/keys-dev`](packages/keys-dev/README.md) | File-backed and in-memory providers that hold real private keys | **no** |
| [`@open-transaction-layer/core`](packages/core/README.md) | JCS canonicalization, Data Integrity proofs, `did:webvh`, status lists | yes |
| [`@open-transaction-layer/jwe`](packages/jwe/README.md) | JWE Compact encryption (ECDH-ES with A256GCM); the envelope is provisional and not sender-authenticated | yes |
| [`@open-transaction-layer/credentials`](packages/credentials/README.md) | Pluggable credential-type registry, LEI/GLEIF, trust perimeter, the §5.3 validation chain, the JSON-LD context | yes |
| [`@open-transaction-layer/resolver`](packages/resolver/README.md) | Guarded HTTPS retrieval, whois presentations, status-list fetching | yes |
| [`@open-transaction-layer/cli`](packages/cli/README.md) | The `otl` command | **no** |

Zero runtime dependencies anywhere, since everything is built on `node:crypto`.

The [API reference](https://open-transaction-layer.github.io/otl-sdk/) is
generated from the source on every merge to `main` and documents every exported
function, class and type with its inputs, outputs and errors.

## Installing

```bash
npm install @open-transaction-layer/core @open-transaction-layer/credentials @open-transaction-layer/resolver @open-transaction-layer/keys
```

Bridge `KeyProvider` to your own key management, and validate the bridge:

```ts
import { runKeyProviderConformance } from '@open-transaction-layer/keys/conformance';
runKeyProviderConformance('MyKmsProvider', () => new MyKmsProvider());
```

Requires Node 22.12 or later, which is the oldest Node line still receiving
security updates.

## Verifying a release

Every release is published to npm by this repository's release workflow, which
starts only when a maintainer publishes a GitHub release for a commit on `main`
and publishes only after a reviewer approves it, and npm records a provenance
attestation that names the repository, the workflow and the commit the package
was built from. The packages are published without any long-lived
npm credential, because npm accepts only the workflow's short-lived identity.

To check the packages in your own project, run this from the project root after
installing:

```bash
npm audit signatures
```

It verifies the registry signature of every installed package and the
provenance attestation of each package that has one, and it reports any package
whose signature or attestation does not verify. The npm page of a package also
shows a provenance badge that links to the attestation and from there to the
exact commit and workflow run. Each release is a GitHub release whose tag is `v`
followed by the version, such as `v0.2.0`, so the published contents can be
compared with the source at that tag.

Version 0.0.1 of each package is an empty placeholder that reserves the name and
was not built by the release workflow, so it carries no provenance and contains
no code.

## Developing

```bash
npm install
npm run check
```

`npm run check` runs the build, typecheck, lint, format check and the full test
suite, which is the same set of steps CI runs.

The workspace runs straight off TypeScript with no build step, through a custom
`otl-source` export condition, so the test loop needs nothing compiled first.
The build exists to produce what gets published. See
[CONTRIBUTING.md](CONTRIBUTING.md).

## Design decisions worth knowing

**Key management is an interface, not an implementation.** `@open-transaction-layer/keys` ships an
abstract class and two development providers, and no KMS/HSM bridge at all.
Generation, key agreement and private-key export are *optional* capability
interfaces, because none of them is universal — Azure Key Vault has no
key-agreement primitive, no HSM can export, and production KMS deployments are
often sign-only. A conformance kit ships alongside so a bridge author can prove
theirs is correct.

**Bridges never canonicalize.** JCS, hashing and proof assembly stay in
`@open-transaction-layer/core`, so two backends cannot drift on how a signature input is built.

**`resolve` and `validate` are separate, and the boundary is load-bearing.**
`resolve` fetches without validating and is for inspection only; nothing that
makes a trust decision calls it.

**Failing closed.** An unreachable status list invalidates a credential (§5.3) —
"I could not check" never becomes "it is fine". A log using a feature we do not
verify (witnesses) is refused rather than accepted, and reported as
*unverifiable* rather than *invalid*, because the remedy differs.

## Conformance

Three independent checks, because our own tests can only prove we agree with
ourselves:

- **Published vectors** — RFC 8785 (JCS), RFC 7518 Appendix C (Concat KDF), and
  the worked status list from spec §5.2.1.
- **The official [`didwebvh-test-suite`](https://github.com/decentralized-identity/didwebvh-test-suite)** —
  98 signed logs from six implementations across 33 scenarios.
- **Cross-resolution** against `didwebvh-ts` in CI, and `didwebvh-dart`
  manually — see [`docs/interop.md`](docs/interop.md), which also records that
  `didwebvh-ts` is the *lenient* oracle and what it fails to catch.

## Known gaps

The ones that affect use:

- **The presentation signing key is provisional.** §6.3 requires the key that
  signs a presentation to be listed in the holder's `authentication`, and the
  resolver refuses any other key, but the choice of key is left to another
  layer. `whois publish` signs with `#assertion-key` by default, which
  `did create` lists under `authentication`, and says so.
- **The encryption envelope is provisional.** §3.1.1 defines key-agreement key
  types but no envelope, so two conformant implementations cannot interoperate.
  We implement JWE Compact with ECDH-ES + A256GCM. Note it is confidential but
  **not sender-authenticated**.
- **The JSON-LD context is not published at its URL.** `@open-transaction-layer/credentials`
  ships it and resolves it from disk, which is what makes expansion work, but
  `https://www.otl.network/contexts/identity/v1` does not resolve. A verifier that
  does not use the bundled loader will therefore drop every term the context
  defines, and because `eddsa-jcs-2022` canonicalizes the raw JSON the
  signature will still verify, so that failure is silent. The URL is hashed
  into the proof configuration and therefore covered by the signature, so this
  cannot be retrofitted to credentials already issued.

## Contributing and licence

See [CONTRIBUTING.md](CONTRIBUTING.md), the
[code of conduct](CODE_OF_CONDUCT.md) and the
[security policy](SECURITY.md).

The code in this repository is licensed under [Apache-2.0](LICENSE). See
[NOTICE](NOTICE) for third-party attribution. The specification lives in its
own repository, [`otl-specifications`](https://github.com/Open-Transaction-Layer/otl-specifications),
under the Community Specification License 1.0, as described on the
[OTL licence page](https://www.otl.network/license.html).
