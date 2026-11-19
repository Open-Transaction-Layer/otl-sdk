# `@otl/core`

Protocol logic for the OTL Identity layer: canonicalization, hashing and proof construction.

Canonicalization and proof assembly live here rather than in a key provider, so that two backends can never drift on how a signature input is built. A `KeyProvider` bridge only signs bytes.

---

## Subpath imports

The root `@otl/core` entry point re-exports everything the package offers. Two of the areas are large enough to be worth importing on their own, which keeps a consumer's imports narrow and makes it obvious from an import line which concern a file depends on.

| Import                 | Use it when you need                                                                     | Typical symbols                                           |
| ---------------------- | ---------------------------------------------------------------------------------------- | --------------------------------------------------------- |
| `@otl/core/didwebvh`   | to create, update or validate a `did:webvh` log, without the proof or credential helpers | `createDid`, `appendEntry`, `validateDidLog`              |
| `@otl/core/statuslist` | to build or read Bitstring Status List credentials                                       | `Bitstring`, `buildStatusListCredential`, `allocateIndex` |

```ts
// Narrow imports: each resolves only the module it names.
import { buildStatusListCredential } from '@otl/core/statuslist';
import { createDid } from '@otl/core/didwebvh';

// The root entry point exports every symbol in the package.
import { canonicalize, createProof } from '@otl/core';
```

Prefer a subpath when you only use one of these areas, and use the root import when you work across both or need JCS canonicalization, Data Integrity proofs or multihash helpers, which are only available from the root. Each symbol is the same implementation whichever way you import it.

---

## JCS canonicalization (RFC 8785)

```ts
import { canonicalize, canonicalizeToBytes } from '@otl/core';

canonicalize({ b: 2, a: 1 }); // '{"a":1,"b":2}'
```

**Why this is hand-written rather than sort-then-`JSON.stringify`.** ECMAScript orders integer-like own properties numerically and ahead of all string keys, regardless of insertion order:

```js
const o = {};
o['9'] = 1;
o['10'] = 2;
JSON.stringify(o); // {"9":1,"10":2}
```

RFC 8785 sorts by UTF-16 code unit, which puts `"10"` before `"9"`. Any document with numeric-looking keys would canonicalize differently from every conforming implementation, and the only symptom would be an unhelpful "invalid signature". So the serializer emits the string itself and never relies on property enumeration order.

Scalars delegate to `JSON.stringify`, which is correct by construction: RFC 8785 defines its number format as ECMAScript `Number::toString` and its string escaping as ES2019 well-formed `JSON.stringify`.

Verified against RFC 8785 Appendix B.

---

## Data Integrity proofs

```ts
import { createProof, verifyProof } from '@otl/core';

const secured = await createProof({
  document: credential,
  provider,
  keyLabel: 'issuance',
  verificationMethod: 'did:webvh:{scid}:lou.example.org#credential-issuance-key',
});

const result = await verifyProof({ document: secured, publicKey });
if (!result.verified) console.error(result.reason);
```

`verifyProof` returns a result rather than throwing: an invalid proof is an expected outcome of validation, not an exceptional condition. Structural problems are reported the same way so callers render one consistent failure reason.

The cryptosuite follows from the signing key's curve — `Ed25519` → `eddsa-jcs-2022`, `P-256` → `ecdsa-jcs-2019` — and verification rejects a proof whose declared cryptosuite disagrees with the key it is being checked against.

### Signature input (§6.3)

The signature is computed over the concatenation of two SHA-256 digests, as spec §6.3 and the `eddsa-jcs-2022` and `ecdsa-jcs-2019` cryptosuites define:

```
hashData = SHA-256(JCS(proofConfig)) || SHA-256(JCS(unsecuredDocument))
```

Here `unsecuredDocument` is the document with its `proof` member removed, and `proofConfig` is the proof object without `proofValue`, carrying the document's `@context`. Hashing the proof configuration into the signature is what binds `verificationMethod`, `proofPurpose`, `created`, `domain` and `challenge` to the document, because a construction that signed only the document body would let a valid signature be lifted onto a proof block claiming a different key or purpose.

Members passed through `additionalProperties` are bound into the signature as well, but they cannot override `type`, `cryptosuite`, `verificationMethod` or `proofPurpose`. The `Data Integrity proof - hash construction` tests recompute the signing input independently to pin both the construction and its byte order.

---

## Multiple proofs

did:webvh log entries and multi-signed credentials carry a `proof` array. `createProof` appends rather than replacing, and `verifyProof` selects by `verificationMethod`. With several proofs present and no selector, verification fails rather than silently picking one.
