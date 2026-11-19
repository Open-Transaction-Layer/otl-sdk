# `@otl/keys`

The key-provider contract for the OTL Identity layer.

This package ships **the abstraction and nothing that holds private key material**. It contains no AWS KMS, Azure Key Vault or HSM bridge, because those are written by whoever consumes this SDK against `KeyProvider` and validated with the conformance kit shipped alongside it.

The development providers that do hold private keys, on disk or in memory, live in [`@otl/keys-dev`](../keys-dev) instead. They are a separate package so that depending on this contract never places file-backed key handling in a production dependency tree.

Zero runtime dependencies. Everything is built on `node:crypto`.

---

## The contract

One mandatory base class, three optional capability interfaces. The mandatory set is exactly what *every* backend can do; folding generation, key agreement or export into the base would force every bridge to stub out methods it cannot honour.

```ts
abstract class KeyProvider {
  abstract readonly id: string;
  abstract capabilities(): ProviderCapabilities;
  abstract getKey(label: string): Promise<KeyInfo>;
  abstract listKeys(): Promise<readonly KeyInfo[]>;
  abstract sign(label: string, message: Uint8Array): Promise<Uint8Array>;
}

interface GeneratesKeys        { generateKey(label, curve): Promise<KeyInfo> }
interface DerivesSharedSecrets { deriveSharedSecret(label, peerPublicKey): Promise<Uint8Array> }
interface ExportsPrivateKeys   { exportPrivateKey(label): Promise<Uint8Array> }  // non-production only
```

Use the type guards rather than `instanceof` or duck-typing:

```ts
import { supportsGeneration, supportsKeyAgreement } from '@otl/keys';

if (!supportsKeyAgreement(provider)) {
  throw new Error(`Provider ${provider.id} cannot encrypt — no key-agreement primitive`);
}
```

---

## Writing a bridge

Four rules. The first two are where bridges actually go wrong.

### 1. `sign()` returns a raw fixed-width signature — never DER

- Ed25519 → 64 bytes, R‖S
- P-256 → 64 bytes, r‖s (IEEE P1363)

**AWS KMS, Azure Key Vault and most PKCS#11 modules return DER-encoded ECDSA by default.** Converting is your job. A DER signature is `0x30 <len> 0x02 <rlen> r 0x02 <slen> s`, typically 70–72 bytes for P-256; strip the wrapper and left-pad each of `r` and `s` to exactly 32 bytes.

### 2. `sign()` receives the full message, never a digest

Ed25519 is not a pre-hash scheme — Ed25519ph is a different algorithm — so the contract cannot pass a digest and stay valid for both curves. A P-256 bridge hashes with SHA-256 internally. If your backend needs a digest (KMS `MessageType: DIGEST`), compute it inside the bridge.

### 3. Translate backend errors into the typed ones

A missing key must raise `KeyNotFoundError`, not `AccessDeniedException`. Callers branch on these without knowing which backend is in play.

### 4. Declare capabilities honestly

`capabilities()` is checked before an operation starts, so that an unsupported combination fails at argument-parsing time rather than midway through something stateful like a DID rotation. The conformance kit verifies declarations against behaviour.

### Backend reality

| | Ed25519 sign | P-256 sign | ECDH | Generate | Export |
|---|---|---|---|---|---|
| AWS KMS | ✓ (`ECC_NIST_EDWARDS25519`) | ✓ (DER) | ✓ NIST only, **not** Ed25519 | ✓ | ✗ |
| Azure Key Vault | ✓ (Managed HSM) | ✓ | **✗ none** | ✓ | ✗ |
| PKCS#11 HSM | vendor-dependent | ✓ (usually DER) | ✓ | ✓ | ✗ |
| File / in-memory | ✓ | ✓ | ✓ | ✓ | ✓ |

Two consequences:

- **Azure Key Vault has no key-agreement operation at all.** An AKV bridge legitimately omits `DerivesSharedSecrets`, and `otl encrypt`/`decrypt` are unavailable to that consumer. That is why key agreement is optional rather than a base-class method.
- **AWS KMS supports Ed25519 for signing** (`ECC_NIST_EDWARDS25519`), but **not for key agreement**. A KMS bridge can sign with either curve, but must use P-256 for `DerivesSharedSecrets`. KMS has no X25519 key spec at all, so there is no Curve25519 key-agreement route.

  Watch the naming here. The spec is called `ECC_NIST_EDWARDS25519`, and the `DeriveSharedSecret` API page says only that you need "an asymmetric NIST-standard elliptic curve (ECC) or SM2 KMS key pair" — which reads as though Edwards25519 qualifies. It does not. The key spec reference is explicit: *"use one of the NIST-standard elliptic curve key specs (except `ECC_SECG_P256K1` and `ECC_NIST_EDWARDS25519`)"*, and lists Edwards25519 as *"signing and verification only"*. Reading only the API page would produce a bridge that declares key-agreement support and fails at runtime.
- **KMS Ed25519 signing requires `MessageType: RAW`** for `ED25519_SHA_512`, which matches this contract — `sign()` receives the full message, never a digest. Note KMS caps `RAW` messages at 4096 bytes; Data Integrity proofs sign a 64-byte hash so are unaffected, but a bridge should reject oversized raw-signing requests explicitly rather than letting KMS fail.

**Key generation is optional on purpose.** Many production deployments provision keys out-of-band through a governed process and grant the application sign-only rights. A provider that can only *reference* pre-provisioned keys is a first-class citizen, not a degraded mode — declare `canGenerate: false` and callers will require explicit key labels instead.

---

## Conformance kit

If the SDK ships an abstraction and no real implementation, correctness lives in code we do not write. So we ship the suite that defines correct. Run it in your own CI:

```ts
import { runKeyProviderConformance } from '@otl/keys/conformance';

runKeyProviderConformance('our KMS bridge', () => new OurKmsKeyProvider(config));
```

It exercises only what you declare in `capabilities()`, and separately checks those declarations against observed behaviour. On a different test runner, use `keyProviderConformanceCases()` to get the cases as plain data and adapt them.

The kit's own negative controls live in [`packages/keys-dev/test/conformance-negative.test.ts`](../keys-dev/test/conformance-negative.test.ts): three deliberately-broken providers that make the DER, lying-capabilities and untranslated-error mistakes, asserting the kit rejects each. A test kit that passes everything is worthless.

---

## Development providers (in `@otl/keys-dev`) — both NON-PRODUCTION

| | Purpose | Storage |
|---|---|---|
| `InMemoryKeyProvider` | Tests, throwaway runs | Process memory; lost on exit |
| `FileKeyProvider` | Local CLI development | PKCS#8 DER, AES-256-GCM under PBKDF2-SHA256 (600k iterations), files 0600 / directory 0700 |

`FileKeyProvider` requires a passphrase and will not write an unencrypted private key. It is still a private key on a disk: appropriate for exercising the protocol end to end, not a custody solution.

```ts
import { FileKeyProvider } from '@otl/keys-dev';

const provider = new FileKeyProvider({
  directory: `${process.env.HOME}/.otl/dids/<scid>/keys`,
  passphrase: process.env.OTL_KEYSTORE_PASSPHRASE!,
});
```

---

## Canonical encodings

Fixed here so two bridges can never disagree.

| | Form |
|---|---|
| Ed25519 / X25519 public key | 32 raw bytes |
| P-256 public key | 65 bytes, SEC1 uncompressed (`0x04` prefix) |
| Signature (both curves) | 64 raw bytes |
| `publicKeyMultibase` | multicodec prefix + multibase base58btc (`z…`); P-256 compressed to 33 bytes per Multikey |

Bridges never canonicalize. JCS, hashing and proof assembly stay in `@otl/core` so that proof construction cannot drift between backends.
