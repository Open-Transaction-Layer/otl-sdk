# Interoperability testing

Our `did:webvh` method layer is written from the specification rather than
wrapped around an existing library. That means **nothing outside our own code
checks our output** unless we arrange it.

This is not a hypothetical gap. We emitted log-entry proofs as a bare object
where the spec shows an array; it survived four milestones and 400+ passing
tests, and made every DID we produced unresolvable by `didwebvh-dart`. The
symptom would only have appeared when a counterparty tried to resolve us.

## Automated: `didwebvh-ts` (runs in CI)

`packages/core/test/interop.test.ts` feeds logs from our real `createDid` /
`addService` / `addKey` / `deactivate` paths to
[`didwebvh-ts`](https://github.com/decentralized-identity/didwebvh-ts), a DIF
reference implementation written independently of us.

Half the suite is negative controls — deliberately broken logs the oracle must
reject. Without those, a future version that silently stopped validating would
leave the suite green and useless.

### Known limitation

**`didwebvh-ts` is a lenient oracle.** It tolerates things other
implementations reject. Verified: reintroducing the bare-object proof defect,
`didwebvh-ts` still accepts the log. Only our own explicit shape assertion
catches it.

It is also permissive about undefined `parameters` members, which it neither
rejects nor surfaces — the behaviour that made `genesisBoundKeys` appear to
work while silently doing nothing.

So passing this suite means "not obviously wrong", not "conformant".

## Manual: `didwebvh-dart` (run before releases and after method-layer changes)

[`didwebvh-dart`](https://github.com/decentralized-identity/didwebvh-dart) is a
separate lineage — a port of `didwebvh-java` — and is materially stricter. It is
what caught the proof-shape defect, and what proved `genesisBoundKeys` in
`parameters` breaks resolution.

Not automated because it needs a Dart SDK and a repository clone. Run it when
touching anything under `packages/core/src/didwebvh/`.

```bash
# 1. Emit fixtures from our implementation
cd ~/repos/otl-sdk
node --input-type=module -e "
  import { writeFileSync } from 'node:fs';
  import { createDid, addService, keyFromKeyInfo } from './packages/core/src/index.ts';
  import { InMemoryKeyProvider } from './packages/keys/src/index.ts';
  const p = new InMemoryKeyProvider();
  for (let i = 0; i < 3; i++) await p.generateKey('k' + i, 'Ed25519');
  const a = await p.generateKey('addr', 'Ed25519');
  const c = await createDid({ domain: 'vasp.example.com', provider: p,
    managementKeyLabel: 'k0', preRotationKeyLabel: 'k1', versionTime: '2026-01-01T00:00:00Z',
    keys: [keyFromKeyInfo('address-verification-key', a, ['assertionMethod'])],
    genesisBoundKeys: ['address-verification-key'] });
  const v2 = await addService({ did: c.did, previousEntry: c.entry, provider: p,
    signingKeyLabel: 'k1', nextKeyLabel: 'k2', versionTime: '2026-02-01T00:00:00Z',
    service: { id: '#whois', type: 'OtlWhois', serviceEndpoint: 'https://vasp.example.com/.well-known/whois.vp' } });
  writeFileSync('/tmp/otl.jsonl', [c.entry, v2].map(e => JSON.stringify(e)).join('\n') + '\n');
  writeFileSync('/tmp/otl.did', c.did);
  console.log(c.did);
"

# 2. Clone and resolve
git clone --depth 1 https://github.com/decentralized-identity/didwebvh-dart /tmp/didwebvh-dart
cd /tmp/didwebvh-dart && dart pub get
mkdir -p packages/didwebvh/bin && cat > packages/didwebvh/bin/otl.dart <<'DART'
import 'dart:io';
import 'package:didwebvh/didwebvh.dart';
Future<void> main() async {
  final jsonl = File('/tmp/otl.jsonl').readAsStringSync();
  final did = File('/tmp/otl.did').readAsStringSync().trim();
  for (final v in [('latest ', null), ('version1', 1)]) {
    final r = await DidResolver().resolveFromLog(
      jsonl, did, v.$2 == null ? null : ResolveOptions(versionNumber: v.$2));
    print(r.error != null
      ? '${v.$1} REJECTED  ${r.error}'
      : '${v.$1} ACCEPTED  genesisBoundKeys: ${r.didDocument?.asJsonObject()['genesisBoundKeys']}');
  }
}
DART
dart run packages/didwebvh/bin/otl.dart
```

Expected:

```
latest   ACCEPTED  genesisBoundKeys: null
version1 ACCEPTED  genesisBoundKeys: [did:webvh:...#address-verification-key]
```

`null` at the latest version is correct — the designation is deliberately not
carried forward, because spec 3.2.1 requires reading it from version 1 and
repeating it later would only offer somewhere misleading to read it from.

## Implementations not covered

- `didwebvh-rs` (Rust, Affinidi) — needs a Rust toolchain.
- `didwebvh-java` — needs Maven; and note `didwebvh-dart` is a port of it, so
  the two share a lineage and are not independent oracles of each other.
- The official [`didwebvh-test-suite`](https://github.com/decentralized-identity/didwebvh-test-suite)
  — not evaluated here, and the natural source of fuller coverage.
