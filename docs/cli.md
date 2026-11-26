# Command line reference

The `otl` command is a non-production tool for the OTL Identity layer. It keeps
private keys in files on the local machine, so it is for development and for
learning the protocol and must never hold a key that protects anything real.
Run it with `npx @open-transaction-layer/cli <command>` or, once installed, as
`otl <command>`. `otl help` prints the command summary.

## Conventions

### Global options

| Option | Meaning |
| --- | --- |
| `--json` | Print the result as JSON on standard output and suppress the human-readable text. |
| `--did <did>` | Select the local DID a command acts on, by its full DID or its SCID. Without it the active DID is used, or the only DID when there is exactly one. For `verify`, `encrypt` and `trust add`, `--did` names the other party's DID instead. |
| `--allow-private-addresses` | Let commands that contact another participant reach loopback, link-local and private addresses, which are refused by default. |
| `--timeout <ms>` | Time limit in whole milliseconds for commands that contact another participant. |
| `--help` | Print the command summary. |

Options are written `--name value` or `--name=value`. The options `--json`,
`--help`, `--yes`, `--allow-empty`, `--allow-private-addresses` and
`--no-assertion-key` never take a value.

### Environment variables

| Variable | Meaning |
| --- | --- |
| `OTL_HOME` | Directory that holds all local state. The default is `~/.otl`. |
| `OTL_KEYSTORE_PASSPHRASE` | Passphrase that protects the live keys. The default is an empty passphrase. |
| `OTL_PREROTATION_PASSPHRASE` | Passphrase that protects the committed pre-rotation keys. It defaults to the live passphrase and the tool warns when it does, because the point of pre-rotation is that these keys are kept apart. |

### Output and exit codes

Results go to standard output and warnings go to standard error, so redirecting
standard output captures data without warnings mixed in. Commands that touch
the local keystore print a non-production notice on standard error that cannot
be turned off.

| Exit code | Meaning |
| --- | --- |
| 0 | The command succeeded. |
| 1 | The command failed or was invoked wrongly, for example an unknown command, a missing option, a missing key or an invalid DID. The message is printed after `error:` on standard error, with a hint where there is one. |
| 2 | A check ran and its result was negative: `did validate`, `validate`, `credential fetch` or `verify` found that a log, presentation, credential or signature is not valid. |

### Local state

```text
$OTL_HOME/
  config.json                 the active DID
  trust/perimeter.json        the trust perimeter
  dids/<scid>/
    meta.json                 labels, fragments and the next committed key
    log.jsonl                 the authoritative DID log
    keys/                     live keys
    prerotation/              committed keys, under their own passphrase
    export/                   exactly what is published, with no key material
```

## Local DID

### `did create`

```text
otl did create --domain <domain> [--curve ed25519|p256] [--no-assertion-key] [--time <iso>]
```

Creates a `did:webvh` identity for a domain, with its first log entry, a
management key, a committed pre-rotation key and, unless `--no-assertion-key`
is given, an assertion key. `--curve` picks the signing curve and defaults to
`ed25519`, and `--time` sets the entry time and defaults to now.

With `--json` it prints `{ "did", "scid", "exportDir" }`. Otherwise it prints the
DID, the SCID and where the published files go, which is
`https://<domain>/.well-known/`.

### `did list`

```text
otl did list
```

Lists the local DIDs and marks the active one with `*`. With `--json` it prints an
array of each DID's metadata with an `active` flag.

### `did show`

```text
otl did show [--version <n>]
```

Prints the DID document at the latest version, or at version `n`, as JSON. It fails
when that version does not exist.

### `did validate`

```text
otl did validate
```

Validates the local DID log from genesis. With `--json` it prints
`{ "valid", "issues", "versionCount" }`. It exits with 2 when the log is not valid.

### `did add-key`

```text
otl did add-key --label <fragment> [--curve <curve>] [--purpose <purposes>] [--time <iso>]
```

Adds a verification method with the given fragment to the DID document and
appends a new log entry. `--curve` accepts `ed25519`, `p256` and `x25519`, where
`x25519` is a key-agreement curve and cannot sign. `--purpose` lists the verification
relationships and has a default that depends on the curve. It fails when the DID already
has that fragment. Every state-changing command also rotates the management key.

### `did add-service`

```text
otl did add-service (--file <path> | --service <json>) [--time <iso>]
```

Adds a service entry, given as a JSON file or as inline JSON, and appends a log
entry. It fails when the input is not valid JSON.

### `did rotate`

```text
otl did rotate [--time <iso>]
```

Rotates the management key and changes nothing else. The committed key is promoted
and a fresh one is committed. With `--json` it prints `{ "rotated", "versionId", "updateKeys" }`.

### `did deactivate`

```text
otl did deactivate --yes [--time <iso>]
```

Permanently deactivates the DID. It refuses to run without `--yes`. With `--json` it
prints `{ "deactivated", "versionId" }`.

## Counterparties

These commands contact another participant over HTTPS and accept `--timeout` and
`--allow-private-addresses`.

### `resolve`

```text
otl resolve <did>
```

Fetches the DID document and prints it as JSON. It performs no validation, so the
result proves nothing, and a note saying so is printed on standard error before the
fetch.

### `validate`

```text
otl validate <did>
```

Fetches the DID log and validates it to genesis. With `--json` it prints
`{ "did", "valid", "versionCount", "deactivated", "issues" }`. It prints a note when the
DID has been deactivated and exits with 2 when the log is not valid.

### `credential fetch`

```text
otl credential fetch <did>
```

Fetches the participant's published presentation and validates it and each
credential in it against the local trust perimeter. It exits with 2 when the
presentation or any recognised credential fails, which is also the case when
the trust perimeter is empty and the issuer is therefore not trusted, and a warning
about an empty perimeter is printed. With `--json` it prints the full verification result.

## Credentials issued by this DID

### `credential add-issuance-key`

```text
otl credential add-issuance-key [--label <fragment>]
```

Adds a credential signing key under `assertionMethod`, with the fragment
`credential-issuance-key` unless `--label` gives another. It fails when that fragment
already exists. What makes the key authoritative is the `assertionMethod` reference and
not its name.

### `credential issue`

```text
otl credential issue --lei <code> --subject <did> [--list-id <id>] [--valid-until <iso>] [--gleif-file <path>]
```

Issues an `OtlLeiCredential` for the subject DID, allocates a revocation slot in a
status list, signs and publishes the list, and records the credential. `--lei` is the
20-character ISO 17442 code and `--list-id` defaults to `1`. With `--json` it prints
`{ "credential", "statusList" }`. Otherwise it prints `Issued <id> to <subject>` and the credential.
It fails when the DID has no credential signing key.

### `credential issue-hosting`

```text
otl credential issue-hosting --subject <did> --common-name <name> [--watchers <url,url>] [--list-id <id>] [--valid-until <iso>]
```

Issues an `OtlHostingCredential` stating that this DID operates the subject DID,
with the name the participant is known by and, optionally, its watchers. Its output and
failures are those of `credential issue`.

### `credential status-list`

```text
otl credential status-list [--list-id <id>]
```

Prints the current revocation list. With `--json` it prints the status list credential.
Otherwise it prints its URL, the number of entries, the revoked indices and when it is
valid until, and marks an expired list. It fails when the list does not exist yet,
because a list is created when the first credential is issued.

### `credential refresh-status`

```text
otl credential refresh-status [--list-id <id>]
```

Re-signs a status list with a fresh validity window and leaves every bit unchanged.
A status list is valid for 1 hour, and a verifier rejects every credential that points at an
expired list, so run this on a schedule shorter than that. Publish the export directory
again afterwards. With `--json` it prints the new status list.

### `credential revoke`

```text
otl credential revoke --credential <id>
```

Revokes a credential this DID issued by setting its bit and republishing the list. It
fails when this DID has no record of issuing that credential. With `--json` it prints
`{ "credentialId", "index", "alreadyRevoked", "statusList" }`.

## Credentials held by this DID

### `credential add`

```text
otl credential add --file <path>
```

Stores a credential that someone else issued to this DID so that it can be published.
It refuses a file that is not valid JSON, has no `id` or names a different subject. With
`--json` it prints `{ "stored", "type", "path" }`.

### `credential held`

```text
otl credential held
```

Lists the credentials held. With `--json` it prints them as an array.

### `whois publish`

```text
otl whois publish [--vp-key <label>] [--allow-empty]
```

Signs the held credentials into a presentation and writes it to the export tree as
`whois.vp`. The key that signs the presentation is provisional and can be chosen with
`--vp-key`. It refuses to publish an empty presentation unless `--allow-empty` is given.
With `--json` it prints `{ "holder", "credentials", "path", "vpKey" }`.

## Trust perimeter

Nothing is trusted by default, so credentials from an issuer are rejected until the
issuer is added here.

### `trust add`

```text
otl trust add --did <issuer-did> [--type <types>] [--note <text>]
```

Trusts an issuer for the listed credential types, comma separated, which default to
`OtlLeiCredential`. With `--json` it prints the perimeter.

### `trust remove`

```text
otl trust remove --did <issuer-did> [--type <types>]
```

Removes the issuer, or only the listed types. With `--json` it prints the perimeter.

### `trust list`

```text
otl trust list
```

Lists the trusted issuers with their types and notes. With `--json` it prints the perimeter.

## Cryptography

### `sign`

```text
otl sign --key <label> (--message <text> | --file <path>)
```

Signs a message with a local key and prints the detached signature. A note on standard
error says it is a raw signature and not a Data Integrity proof. With `--json` it prints
`{ "signature", "keyLabel", "did" }`.

### `verify`

```text
otl verify --did <did> --key <fragment> --signature <signature> (--message <text> | --file <path>) [--relationship assertionMethod|authentication]
```

Resolves and validates the other party's DID, takes the named key only when the DID lists
it under the chosen relationship, which defaults to `assertionMethod`, and checks the
signature. It prints `verified` or `NOT VERIFIED` and exits with 2 when the signature
does not verify. With `--json` it prints `{ "verified", "did", "keyLabel" }`.

### `encrypt`

```text
otl encrypt --did <recipient-did> --key <fragment> (--message <text> | --file <path>) [--sender <text>]
```

Encrypts a message to the recipient's key-agreement key as a JWE and prints it. The
envelope is provisional and does not authenticate the sender. With `--json` it prints
`{ "jwe" }`.

### `decrypt`

```text
otl decrypt --key <label> (--jwe <jwe> | --file <path>)
```

Decrypts a JWE with a local key and prints the text. With `--json` it prints
`{ "plaintext" }`.

## Publication

### `export`

```text
otl export
```

Reports the export tree, which is exactly what is uploaded to
`https://<domain>/.well-known/`. It refuses to report a tree that contains key material.
With `--json` it prints `{ "did", "exportDir", "files" }`.

### `serve`

```text
otl serve --cert <path> --key <path> [--port <n>]
```

Serves the export tree over HTTPS for local testing, on port 8443 unless `--port` is
given. The resolver offers no way around certificate verification, so a certificate and
key must be supplied, and the command prints how to make a throwaway one. It runs until
interrupted with Ctrl+C.
