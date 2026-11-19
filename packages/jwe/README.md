# `@otl/jwe`

Message encryption for the OTL Identity layer, using JWE Compact Serialization with ECDH-ES key agreement and A256GCM content encryption, which works with both X25519 and P-256 recipient keys.

The package depends only on `@otl/keys` and on `node:crypto`, so it can be used without pulling in any of the DID or credential machinery in `@otl/core`.

```ts
import { decryptToString, encrypt } from '@otl/jwe';

// The sender needs only the recipient's published keyAgreement key.
const jwe = encrypt({ plaintext: 'settlement instruction', recipientPublicKey });

// The recipient decrypts with a KeyProvider that supports key agreement, so the private key never has to leave it.
const message = await decryptToString({ jwe, provider, keyLabel: 'agreement' });
```

Failures raise `EncryptionError`, which derives from the package's own `OtlJweError` base class.

## Read this before relying on it

**The construction is confidential but not sender-authenticated.** The sender uses a fresh ephemeral key, so only the holder of the recipient's private key can read the message, but anyone who knows the recipient's published key can produce a ciphertext that decrypts successfully. A recipient therefore learns nothing about who sent a message from the fact that it decrypted, and a caller who needs to know the sender must add a separate signature over the plaintext, for example with `signRaw` from `@otl/core`.

**The envelope is provisional.** §3.1.1 of the OTL specification defines the key-agreement key types but no key-derivation function, no content-encryption algorithm and no wire format, so this package implements a proposal built from existing standards (RFC 7516, RFC 7518 and RFC 8037) and the format may change if the specification defines the envelope. Two conformant implementations should not be expected to exchange encrypted messages unless it does, and this is the reason the package is separate from `@otl/core`, so that changes to it can be released and consumed on their own.
