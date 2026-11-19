---
"@otl/core": minor
"@otl/credentials": minor
"@otl/resolver": minor
"@otl/keys-dev": minor
"@otl/cli": minor
---

**Security:** DID log validation no longer lets an entry with an empty `updateKeys` list sidestep pre-rotation. Such an entry used to be authorized by the keys before it and was exempt from the commitment check, so whoever held only the current update key could empty the list and then append an entry naming keys of their own choosing. While pre-rotation is active an empty `updateKeys` list is now refused, no entry may follow one with an empty list, and an entry that omits `nextKeyHashes` keeps the earlier commitment in force rather than switching the check off. A later entry that changes `method` is refused as unsupported.

**Breaking:** whois presentations are now signed and verified with `proofPurpose: "authentication"`, as spec 6.3 requires, so a presentation signed with `assertionMethod` is rejected. Re-run `otl whois publish` to re-sign an existing presentation.

`verifyProof` now rejects a proof whose `expires` has passed or is not a date-time, and it accepts a `now` option. JCS canonicalization refuses sparse arrays and strings with lone surrogates instead of emitting output that is not valid I-JSON. Credential verification refuses a revocation status entry whose `statusSize` is not 1. The resolver refuses a DID whose path segments decode to `/`, `?`, `#`, a backslash or a control character.

`FileKeyProvider.getKey` and `listKeys` now check that the public key recorded in a key file belongs to its private key and that the file's label matches its name, so they need the correct passphrase.

The CLI adds `otl credential refresh-status`, which re-signs a status list before its 1-hour validity runs out, and `otl credential status-list` now shows when the list expires. `otl credential fetch` exits with code 2 when the presentation or any recognised credential fails validation. `otl verify` accepts only a key listed under `assertionMethod`, or under `authentication` when `--relationship authentication` is given.
