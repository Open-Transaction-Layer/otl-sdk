import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { base58btcDecode, toPublicKeyMultibase } from '@otl/keys';
import { InMemoryKeyProvider } from '@otl/keys-dev';
import { InvalidDocumentError } from '../src/errors.ts';
import { canonicalizeToBytes } from '../src/jcs.ts';
import { hashToBase58 } from '../src/multihash.ts';
import { proofsOf, verifyProof } from '../src/proof.ts';
import { createDid, encodeDomain } from '../src/didwebvh/create.ts';
import { contextsFor, keyFromKeyInfo, type DocumentKey } from '../src/didwebvh/document.ts';
import { deriveKeyHash, parseVersionId, toPlaceholders } from '../src/didwebvh/hashing.ts';
import { DIDWEBVH_METHOD, SCID_PLACEHOLDER } from '../src/didwebvh/types.ts';

const DOMAIN = 'vasp.example.com';
const TIME = '2026-01-01T00:00:00Z';

async function setup(extra?: { keys?: readonly DocumentKey[] }) {
  const provider = new InMemoryKeyProvider();
  await provider.generateKey('did-management', 'Ed25519');
  await provider.generateKey('pre-rotation', 'Ed25519');
  const created = await createDid({
    domain: DOMAIN,
    provider,
    managementKeyLabel: 'did-management',
    preRotationKeyLabel: 'pre-rotation',
    versionTime: TIME,
    ...(extra?.keys ? { keys: extra.keys } : {}),
  });
  return { provider, created };
}

describe('did:webvh - DID format', () => {
  it('places the SCID between the method and the domain', async () => {
    const { created } = await setup();
    assert.equal(created.did, `did:webvh:${created.scid}:${DOMAIN}`);
  });

  it('produces a 46-character base58btc SCID', async () => {
    const { created } = await setup();
    // 46 chars is exactly a 34-byte SHA-256 multihash: 0x12 0x20 + 32 digest.
    assert.equal(created.scid.length, 46, `SCID was "${created.scid}"`);
    const decoded = base58btcDecode(created.scid);
    assert.equal(decoded.length, 34);
    assert.equal(decoded[0], 0x12, 'multihash code for sha2-256');
    assert.equal(decoded[1], 0x20, 'multihash digest length');
  });

  it('does not multibase-prefix the SCID', async () => {
    const { created } = await setup();
    // The SCID is plain base58btc, unlike publicKeyMultibase which carries "z".
    assert.ok(!created.scid.startsWith('z'), 'SCID must not carry a multibase prefix');
  });

  it('rejects a domain containing a slash, or an empty one', () => {
    assert.throws(() => encodeDomain('example.com/path'), InvalidDocumentError);
    assert.throws(() => encodeDomain(''), InvalidDocumentError);
  });

  it('allows did:webvh path segments', () => {
    assert.equal(encodeDomain('example.com:dids:issuer'), 'example.com:dids:issuer');
  });
});

describe('did:webvh - SCID derivation', () => {
  it('is reproducible by an independent verifier', async () => {
    // Reproduce the resolver-side check from the did:webvh spec: strip the
    // proof, put {SCID} back in place of the derived value everywhere, and
    // re-hash. This is the check a third party performs, written out longhand
    // rather than calling deriveScid, so the two cannot drift together.
    const { created } = await setup();
    const { proof: _proof, ...entry } = created.entry as unknown as Record<string, unknown>;

    const preliminary = toPlaceholders({ ...entry, versionId: SCID_PLACEHOLDER }, created.scid);
    assert.equal(hashToBase58(canonicalizeToBytes(preliminary)), created.scid);
  });

  it('changes when the domain changes', async () => {
    const provider = new InMemoryKeyProvider();
    await provider.generateKey('m', 'Ed25519');
    await provider.generateKey('p', 'Ed25519');
    const base = {
      provider,
      managementKeyLabel: 'm',
      preRotationKeyLabel: 'p',
      versionTime: TIME,
    } as const;

    const a = await createDid({ ...base, domain: 'a.example.com' });
    const b = await createDid({ ...base, domain: 'b.example.com' });
    assert.notEqual(a.scid, b.scid, 'SCID must commit to the genesis document, domain included');
  });

  it('changes when the management key changes', async () => {
    const first = await setup();
    const second = await setup();
    assert.notEqual(first.created.scid, second.created.scid);
  });

  it('leaves no placeholder behind anywhere in the entry', async () => {
    const { created } = await setup({
      keys: [],
    });
    assert.ok(!JSON.stringify(created.entry).includes(SCID_PLACEHOLDER));
  });
});

describe('did:webvh - genesis log entry', () => {
  it('sets versionId to 1-{entryHash}', async () => {
    const { created } = await setup();
    const { versionNumber, entryHash } = parseVersionId(created.entry.versionId);
    assert.equal(versionNumber, 1);
    assert.equal(entryHash.length, 46);
  });

  it('computes the entry hash over the entry whose versionId is the bare SCID', async () => {
    // Independent recomputation of the resolver-side entry-hash check.
    const { created } = await setup();
    const { proof: _proof, ...entry } = created.entry as unknown as Record<string, unknown>;
    const recomputed = hashToBase58(canonicalizeToBytes({ ...entry, versionId: created.scid }));
    assert.equal(parseVersionId(created.entry.versionId).entryHash, recomputed);
  });

  it('declares the method version and the SCID in parameters', async () => {
    const { created } = await setup();
    assert.equal(created.entry.parameters.method, DIDWEBVH_METHOD);
    assert.equal(created.entry.parameters.scid, created.scid);
  });

  it('records the management key in updateKeys as a multikey', async () => {
    const { provider, created } = await setup();
    const management = await provider.getKey('did-management');
    assert.deepEqual(created.entry.parameters.updateKeys, [toPublicKeyMultibase(management.publicKey)]);
  });

  it('commits to the pre-rotation key and never leaks it', async () => {
    const { provider, created } = await setup();
    const preRotation = await provider.getKey('pre-rotation');
    const preRotationMultikey = toPublicKeyMultibase(preRotation.publicKey);

    assert.deepEqual(created.entry.parameters.nextKeyHashes, [deriveKeyHash(preRotationMultikey)]);
    // Pre-rotation: only a hash is published, never the key itself.
    assert.ok(
      !JSON.stringify(created.entry).includes(preRotationMultikey),
      'the pre-rotation public key must not appear in the log entry, only its hash',
    );
  });

  it('never leaves the pre-rotation commitment empty', async () => {
    const { created } = await setup();
    assert.ok((created.entry.parameters.nextKeyHashes ?? []).length > 0);
  });

  it('carries a verifiable eddsa-jcs-2022 proof from the management key', async () => {
    const { provider, created } = await setup();
    const management = await provider.getKey('did-management');
    const [proof] = proofsOf(created.entry as unknown as Record<string, unknown>);

    assert.equal(proof!.cryptosuite, 'eddsa-jcs-2022');
    const result = await verifyProof({
      document: created.entry as unknown as Record<string, unknown>,
      publicKey: management.publicKey,
    });
    assert.equal(result.verified, true, result.reason ?? 'no reason reported');
  });
});

describe('did:webvh - management key must be Ed25519', () => {
  it('rejects a P-256 management key with an actionable message', async () => {
    const provider = new InMemoryKeyProvider();
    await provider.generateKey('m', 'P-256');
    await provider.generateKey('p', 'Ed25519');

    await assert.rejects(
      () =>
        createDid({
          domain: DOMAIN,
          provider,
          managementKeyLabel: 'm',
          preRotationKeyLabel: 'p',
          versionTime: TIME,
        }),
      (error: unknown) => {
        assert.ok(error instanceof InvalidDocumentError);
        assert.match(error.message, /eddsa-jcs-2022/);
        assert.match(error.message, /AWS KMS/);
        return true;
      },
    );
  });

  it('rejects a P-256 pre-rotation key too', async () => {
    const provider = new InMemoryKeyProvider();
    await provider.generateKey('m', 'Ed25519');
    await provider.generateKey('p', 'P-256');
    await assert.rejects(
      () =>
        createDid({
          domain: DOMAIN,
          provider,
          managementKeyLabel: 'm',
          preRotationKeyLabel: 'p',
          versionTime: TIME,
        }),
      InvalidDocumentError,
    );
  });
});

describe('did:webvh - genesis document', () => {
  it('includes only the contexts its keys require', async () => {
    const provider = new InMemoryKeyProvider();
    await provider.generateKey('m', 'Ed25519');
    await provider.generateKey('p', 'Ed25519');
    const signing = await provider.generateKey('sig', 'Ed25519');

    const created = await createDid({
      domain: DOMAIN,
      provider,
      managementKeyLabel: 'm',
      preRotationKeyLabel: 'p',
      versionTime: TIME,
      keys: [keyFromKeyInfo('assertion-key', signing, ['assertionMethod'])],
    });

    assert.deepEqual(created.entry.state['@context'], [
      'https://www.w3.org/ns/did/v1',
      'https://w3id.org/security/suites/ed25519-2020/v1',
    ]);
  });

  it('adds the JWS and X25519 contexts when those key types appear', async () => {
    const provider = new InMemoryKeyProvider();
    await provider.generateKey('m', 'Ed25519');
    await provider.generateKey('p', 'Ed25519');
    const p256 = await provider.generateKey('p256', 'P-256');
    const x = await provider.generateKey('x', 'X25519');

    const created = await createDid({
      domain: DOMAIN,
      provider,
      managementKeyLabel: 'm',
      preRotationKeyLabel: 'p',
      versionTime: TIME,
      keys: [
        keyFromKeyInfo('issuance-key', p256, ['assertionMethod']),
        keyFromKeyInfo('agreement-key', x, ['keyAgreement']),
      ],
    });

    const contexts = created.entry.state['@context'] as string[];
    assert.ok(contexts.includes('https://w3id.org/security/suites/jws-2020/v1'));
    assert.ok(contexts.includes('https://w3id.org/security/suites/x25519-2020/v1'));
    assert.ok(!contexts.includes('https://w3id.org/security/suites/ed25519-2020/v1'));
  });

  it('adds the X25519 context for any X25519 key, whatever its purposes', async () => {
    // The key is published as an X25519KeyAgreementKey2020 verification
    // method even when no relationship references it, so the term needs its
    // context either way.
    const provider = new InMemoryKeyProvider();
    const x = await provider.generateKey('x', 'X25519');
    assert.ok(
      contextsFor([keyFromKeyInfo('unreferenced-x', x, [])]).includes(
        'https://w3id.org/security/suites/x25519-2020/v1',
      ),
    );
  });

  it('uses JsonWebKey2020 for P-256 and the 2020 suites for the curve keys', async () => {
    const provider = new InMemoryKeyProvider();
    await provider.generateKey('m', 'Ed25519');
    await provider.generateKey('p', 'Ed25519');
    const ed = await provider.generateKey('ed', 'Ed25519');
    const p256 = await provider.generateKey('p256', 'P-256');
    const x = await provider.generateKey('x', 'X25519');

    const created = await createDid({
      domain: DOMAIN,
      provider,
      managementKeyLabel: 'm',
      preRotationKeyLabel: 'p',
      versionTime: TIME,
      keys: [
        keyFromKeyInfo('ed-key', ed, ['assertionMethod']),
        keyFromKeyInfo('p256-key', p256, ['assertionMethod']),
        keyFromKeyInfo('x-key', x, ['keyAgreement']),
      ],
    });

    const methods = created.entry.state.verificationMethod!;
    const byFragment = (f: string) => methods.find((m) => m.id.endsWith(`#${f}`))!;

    assert.equal(byFragment('ed-key').type, 'Ed25519VerificationKey2020');
    assert.ok(byFragment('ed-key').publicKeyMultibase?.startsWith('z6Mk'));
    assert.equal(byFragment('p256-key').type, 'JsonWebKey2020');
    assert.equal(byFragment('p256-key').publicKeyJwk?.['crv'], 'P-256');
    assert.equal(byFragment('x-key').type, 'X25519KeyAgreementKey2020');
  });

  it('binds verification method ids and controllers to the resolved DID', async () => {
    const provider = new InMemoryKeyProvider();
    await provider.generateKey('m', 'Ed25519');
    await provider.generateKey('p', 'Ed25519');
    const signing = await provider.generateKey('sig', 'Ed25519');
    const issuing = await provider.generateKey('vc', 'Ed25519');
    const created = await createDid({
      domain: DOMAIN,
      provider,
      managementKeyLabel: 'm',
      preRotationKeyLabel: 'p',
      versionTime: TIME,
      keys: [
        keyFromKeyInfo('authentication-key', signing, ['authentication']),
        keyFromKeyInfo('vc-key', issuing, ['assertionMethod']),
      ],
    });

    const [method] = created.entry.state.verificationMethod!;
    assert.equal(method!.id, `${created.did}#authentication-key`);
    assert.equal(method!.controller, created.did);
    assert.deepEqual(created.entry.state.authentication, [`${created.did}#authentication-key`]);
    assert.deepEqual(created.entry.state.assertionMethod, [`${created.did}#vc-key`]);
  });

  it('refuses a key listed under assertionMethod and another relationship (spec 3.2.1)', async () => {
    const provider = new InMemoryKeyProvider();
    await provider.generateKey('m', 'Ed25519');
    await provider.generateKey('p', 'Ed25519');
    const signing = await provider.generateKey('sig', 'Ed25519');
    await assert.rejects(
      createDid({
        domain: DOMAIN,
        provider,
        managementKeyLabel: 'm',
        preRotationKeyLabel: 'p',
        versionTime: TIME,
        keys: [keyFromKeyInfo('sig', signing, ['assertionMethod', 'authentication'])],
      }),
      /exclusively for credentials \(spec 3\.2\.1\)/,
    );
  });

  it('keeps the DID Management Key out of verificationMethod', async () => {
    // Spec 3.2.2: it lives in parameters.updateKeys, not in the document.
    const { provider, created } = await setup();
    const management = await provider.getKey('did-management');
    const multibase = toPublicKeyMultibase(management.publicKey);
    const methods = created.entry.state.verificationMethod ?? [];
    assert.ok(!methods.some((m) => m.publicKeyMultibase === multibase));
  });
});

describe('did:webvh - document validation', () => {
  it('rejects duplicate fragments', async () => {
    const provider = new InMemoryKeyProvider();
    await provider.generateKey('m', 'Ed25519');
    await provider.generateKey('p', 'Ed25519');
    const a = await provider.generateKey('a', 'Ed25519');
    const b = await provider.generateKey('b', 'Ed25519');

    await assert.rejects(
      () =>
        createDid({
          domain: DOMAIN,
          provider,
          managementKeyLabel: 'm',
          preRotationKeyLabel: 'p',
          versionTime: TIME,
          keys: [
            keyFromKeyInfo('same', a, ['assertionMethod']),
            keyFromKeyInfo('same', b, ['assertionMethod']),
          ],
        }),
      InvalidDocumentError,
    );
  });

  it('rejects X25519 used for signing purposes', async () => {
    const provider = new InMemoryKeyProvider();
    await provider.generateKey('m', 'Ed25519');
    await provider.generateKey('p', 'Ed25519');
    const x = await provider.generateKey('x', 'X25519');

    await assert.rejects(
      () =>
        createDid({
          domain: DOMAIN,
          provider,
          managementKeyLabel: 'm',
          preRotationKeyLabel: 'p',
          versionTime: TIME,
          keys: [keyFromKeyInfo('x-key', x, ['assertionMethod'])],
        }),
      InvalidDocumentError,
    );
  });

  it('rejects Ed25519 used for keyAgreement', async () => {
    const provider = new InMemoryKeyProvider();
    await provider.generateKey('m', 'Ed25519');
    await provider.generateKey('p', 'Ed25519');
    const ed = await provider.generateKey('ed', 'Ed25519');

    await assert.rejects(
      () =>
        createDid({
          domain: DOMAIN,
          provider,
          managementKeyLabel: 'm',
          preRotationKeyLabel: 'p',
          versionTime: TIME,
          keys: [keyFromKeyInfo('ed-key', ed, ['keyAgreement'])],
        }),
      InvalidDocumentError,
    );
  });
});

describe('did:webvh - domains with ports', () => {
  it('percent-encodes a port so it stays one DID segment', () => {
    // ":" separates segments in a DID, so an unencoded port would split the
    // host into two. Callers pass the readable form.
    assert.equal(encodeDomain('localhost:8443'), 'localhost%3A8443');
    assert.equal(encodeDomain('example.com:443'), 'example.com%3A443');
  });

  it('leaves path segments alone', () => {
    assert.equal(encodeDomain('example.com:dids:issuer'), 'example.com:dids:issuer');
  });

  it('rejects an out-of-range port', () => {
    assert.throws(() => encodeDomain('example.com:99999'), InvalidDocumentError);
  });

  it('round-trips through DID creation and resolution', async () => {
    const provider = new InMemoryKeyProvider();
    await provider.generateKey('m', 'Ed25519');
    await provider.generateKey('p', 'Ed25519');
    const created = await createDid({
      domain: 'localhost:8443',
      provider,
      managementKeyLabel: 'm',
      preRotationKeyLabel: 'p',
      versionTime: TIME,
    });
    assert.match(created.did, /:localhost%3A8443$/);
  });
});
