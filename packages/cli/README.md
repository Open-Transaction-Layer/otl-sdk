# `@open-transaction-layer/cli`

**Non-production** command line tool for the OTL Identity layer.

> ⚠️ This CLI stores private keys on disk through
> [`@open-transaction-layer/keys-dev`](../keys-dev). It prints that warning on every command that
> touches the local keystore, and the warning is not suppressible. Do not use it to hold a key that protects
> anything real.

The CLI is the reference consumer of the SDK rather than a layer of it. Every
protocol rule it enforces lives in the libraries underneath, and what the CLI
adds on top is the local filesystem layout it writes artefacts into, so
anything you can do here you can do by calling the SDK directly.

## Usage

```bash
npx @open-transaction-layer/cli --help
```

It covers creating and updating a DID, rotating and adding keys, publishing the
version log and status lists, issuing and revoking credentials, managing the
trust perimeter, and resolving and validating an external DID.

## Walkthrough

`examples/two-party-walkthrough.sh` in the repository runs the whole flow over
real HTTPS, with a Local Operating Unit issuing a credential, a participant
publishing it, and a counterparty validating it, rejecting an untrusted issuer,
accepting a trusted one and rejecting again once the credential is revoked.

Licensed under Apache-2.0.
