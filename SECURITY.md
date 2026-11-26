# Security policy

## Reporting a vulnerability

Please report security issues privately through GitHub's private vulnerability
reporting on this repository, under **Security → Report a vulnerability**. That
is the only reporting channel because it needs no shared mailbox and it keeps
the report and the fix in one place.

Please do not open a public issue for a security problem, and please do not
disclose it publicly until a fix is available.

We aim to acknowledge a report within 3 working days and to agree a disclosure
timeline with the reporter.

## Scope

This repository implements an identity layer, so the findings that matter most
are the ones that let an attacker be believed when they should not be. In
particular we want to hear about anything that lets a party forge or replay a
signature or proof, have a tampered or forked version log accepted, have a
revoked or expired credential accepted as valid, bypass the local trust
perimeter, be verified under an issuer they do not control, or cause a
verifier to report a document as valid when it cannot actually verify it.

Defects that cause a verifier to **fail closed** are bugs and belong in the
issue tracker rather than here. Defects that cause it to **fail open** are
security issues and belong here.

## What is deliberately not production-ready

`@open-transaction-layer/keys-dev` and `@open-transaction-layer/cli` hold private key material in the process and on
disk. This is stated in their manifests and their READMEs, and the CLI prints it on
every command that touches the local keystore.
Reports that those packages expose private keys to someone who already has the
relevant filesystem or process access are describing their documented design
rather than a vulnerability.

A production deployment implements `KeyProvider` from `@open-transaction-layer/keys` against a
KMS, an HSM or a Key Vault, and validates that implementation with
`@open-transaction-layer/keys/conformance`.

## Supported versions

Fixes land on the latest release only, and there are no maintained release
branches.
