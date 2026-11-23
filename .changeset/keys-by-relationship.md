---
"@otl/core": minor
"@otl/credentials": minor
"@otl/resolver": minor
"@otl/cli": minor
---

Keys are chosen by verification relationship, never by fragment, as OTL Identity Layer Specification v0.7 §3.3 requires.

**Breaking (`@otl/resolver`):** `verifyWhois` verifies a presentation against the key its proof names, and accepts it only if the holder's current `authentication` references that key. `PROVISIONAL_VP_KEY_FRAGMENT` and the `vpKeyFragment` option are removed, because a holder may sign with any of its `authentication` keys. The new `resolveRelationshipKeys` returns every key a relationship lists, after validating the log once.

**Breaking (`@otl/core`):** `createDid` and `addKey` refuse a new key listed under `assertionMethod` and also under another relationship, because a credential signing key is used exclusively for credentials (§3.2.1). A document published before this check can still be updated.

`@otl/credentials` rejects a credential whose `type` also contains `BitstringStatusListCredential`, and a status list whose `type` is not exactly `["VerifiableCredential", "BitstringStatusListCredential"]` (§5.2). Credentials and status lists are signed with the same `assertionMethod` keys, so the type is what keeps a signature for one from being accepted as the other (threat T-REV-05).

**Breaking (`@otl/cli`):**

- `did create` creates `#authentication-key` under `authentication` only. Before, it created `#assertion-key` under both `assertionMethod` and `authentication`. `--no-assertion-key` is renamed `--no-authentication-key`.
- `did add-key` lists a signing key under `authentication` by default, not under `assertionMethod`.
- `credential issue`, `issue-hosting`, `revoke` and `refresh-status` sign with a key the current document lists under `assertionMethod`. That is the most recently added issuance key, or the one chosen with the new `--key <fragment>`. So after a new key is added during a rotation, issuance moves to it.
- `whois publish` signs with a key listed under `authentication`, the most recent by default or the one chosen with `--vp-key`, and refuses a key listed anywhere else. It no longer prints a provisional-key warning.
- `encrypt --key` is optional. Without it, the first recipient `keyAgreement` key of a supported type (X25519 or P-256) is used.
