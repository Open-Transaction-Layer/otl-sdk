# `@open-transaction-layer/keys-dev`

**Non-production** `KeyProvider` implementations for the OTL Identity layer.

> ⚠️ Both providers in this package hold raw private key material in the
> process, and `FileKeyProvider` additionally writes it to disk. Do not use
> either of them to hold a key that protects anything real.

This package exists so that the CLI, the test suite and the examples can run
without a key management service standing behind them. It is published
separately from [`@open-transaction-layer/keys`](../keys) precisely so that depending on the
`KeyProvider` contract never drags private key handling into a production
dependency tree, and so that a dependency listing makes the distinction
visible to anyone reviewing it.

A production deployment implements `KeyProvider` against a KMS, an HSM or a
Key Vault and validates that implementation with `@open-transaction-layer/keys/conformance`.

## Providers

| Provider | Key material | Intended use |
|---|---|---|
| `InMemoryKeyProvider` | Held in process, lost on exit | Tests and examples |
| `FileKeyProvider` | Written to disk, encrypted under a passphrase | Local CLI development |

`FileKeyProvider` derives its wrapping key with PBKDF2-SHA256 at 600,000
iterations and encrypts with AES-256-GCM under a fresh salt and nonce per
write, which makes a stolen key file useless without the passphrase. That is a meaningful protection against a copied laptop and it is
not a substitute for a key management service, because the plaintext key still
exists in process memory whenever the provider signs.

## Usage

```ts
import { InMemoryKeyProvider } from '@open-transaction-layer/keys-dev';

const keys = new InMemoryKeyProvider();
await keys.generateKey('did-update-key', 'Ed25519');
```

Licensed under Apache-2.0.
