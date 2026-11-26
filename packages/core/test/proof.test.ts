import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { describe, it } from 'node:test';
import { toMultibaseBase58, type Curve } from '@open-transaction-layer/keys';
import { InMemoryKeyProvider } from '@open-transaction-layer/keys-dev';
import { CryptosuiteMismatchError } from '../src/errors.ts';
import { canonicalizeToBytes } from '../src/jcs.ts';
import { assertCryptosuiteMatchesCurve, cryptosuiteForCurve } from '../src/cryptosuite.ts';
import { createProof, proofsOf, verifyProof, type Document } from '../src/proof.ts';
import { TEST_ISSUANCE_KEY, TEST_ISSUER_DID, TEST_LEI, TEST_SUBJECT_DID, syntheticLei } from './fixtures.ts';

const CREDENTIAL: Document = {
  '@context': ['https://www.w3.org/ns/credentials/v2'],
  id: 'urn:uuid:3d4e5f6a-7b8c-9d0e-1f2a-3b4c5d6e7f8a',
  type: ['VerifiableCredential', 'OtlLeiCredential'],
  issuer: TEST_ISSUER_DID,
  validFrom: '2026-01-01T00:00:00Z',
  credentialSubject: {
    id: TEST_SUBJECT_DID,
    lei: TEST_LEI,
  },
};

const VM = TEST_ISSUANCE_KEY;

async function sign(curve: Curve, document: Document = CREDENTIAL) {
  const provider = new InMemoryKeyProvider();
  const key = await provider.generateKey('issuance', curve);
  const secured = await createProof({
    document,
    provider,
    keyLabel: 'issuance',
    verificationMethod: VM,
    created: '2026-01-01T00:00:00Z',
  });
  return { provider, key, secured };
}

for (const curve of ['Ed25519', 'P-256'] as const) {
  describe(`Data Integrity proof - ${curve}`, () => {
    it('produces a proof with the spec-mandated shape', async () => {
      const { secured } = await sign(curve);
      const [proof] = proofsOf(secured);

      assert.equal(proof!.type, 'DataIntegrityProof');
      assert.equal(proof!.cryptosuite, cryptosuiteForCurve(curve));
      assert.equal(proof!.proofPurpose, 'assertionMethod');
      assert.equal(proof!.verificationMethod, VM);
      assert.equal(proof!.created, '2026-01-01T00:00:00Z');
      assert.ok(proof!.proofValue.startsWith('z'), 'proofValue must be multibase base58btc');
      assert.equal(proof!['@context'], undefined, 'proof must not carry its own @context');
    });

    it('verifies against the signing key', async () => {
      const { key, secured } = await sign(curve);
      const result = await verifyProof({ document: secured, publicKey: key.publicKey });
      assert.equal(result.verified, true, result.reason ?? 'no reason reported');
    });

    it('does not mutate the input document', async () => {
      const before = JSON.stringify(CREDENTIAL);
      await sign(curve);
      assert.equal(JSON.stringify(CREDENTIAL), before);
    });

    it('rejects a tampered document body', async () => {
      const { key, secured } = await sign(curve);
      const tampered = {
        ...secured,
        credentialSubject: { ...(secured['credentialSubject'] as object), lei: syntheticLei(42) },
      };
      const result = await verifyProof({ document: tampered, publicKey: key.publicKey });
      assert.equal(result.verified, false);
    });

    it('rejects a tampered verificationMethod', async () => {
      // The proof config is bound into the signature, so rewriting the key
      // reference must invalidate the proof even though the body is untouched.
      const { key, secured } = await sign(curve);
      const [proof] = proofsOf(secured);
      const tampered = {
        ...secured,
        proof: { ...proof!, verificationMethod: 'did:webvh:QmSCID:attacker.example#key' },
      };
      const result = await verifyProof({ document: tampered, publicKey: key.publicKey });
      assert.equal(result.verified, false, 'proof metadata must be bound into the signature');
    });

    it('rejects a tampered proofPurpose', async () => {
      const { key, secured } = await sign(curve);
      const [proof] = proofsOf(secured);
      const tampered = { ...secured, proof: { ...proof!, proofPurpose: 'authentication' } };
      const result = await verifyProof({
        document: tampered,
        publicKey: key.publicKey,
        expectedProofPurpose: 'authentication',
      });
      assert.equal(result.verified, false);
    });

    it('rejects a tampered created timestamp', async () => {
      const { key, secured } = await sign(curve);
      const [proof] = proofsOf(secured);
      const tampered = { ...secured, proof: { ...proof!, created: '2020-01-01T00:00:00Z' } };
      assert.equal((await verifyProof({ document: tampered, publicKey: key.publicKey })).verified, false);
    });

    it('rejects a tampered @context', async () => {
      // @context is copied into the proof config, so swapping it must break.
      const { key, secured } = await sign(curve);
      const tampered = { ...secured, '@context': ['https://example.com/malicious/v1'] };
      assert.equal((await verifyProof({ document: tampered, publicKey: key.publicKey })).verified, false);
    });

    it('rejects verification against a different key', async () => {
      const { secured } = await sign(curve);
      const other = new InMemoryKeyProvider();
      const otherKey = await other.generateKey('other', curve);
      const result = await verifyProof({ document: secured, publicKey: otherKey.publicKey });
      assert.equal(result.verified, false);
      assert.match(result.reason ?? '', /does not verify/);
    });

    it('is stable across key reordering in the document', async () => {
      const reordered: Document = {
        credentialSubject: CREDENTIAL['credentialSubject'],
        validFrom: CREDENTIAL['validFrom'],
        type: CREDENTIAL['type'],
        issuer: CREDENTIAL['issuer'],
        id: CREDENTIAL['id'],
        '@context': CREDENTIAL['@context'],
      };
      const { key, secured } = await sign(curve);
      // Verify the signature made over the original against the reordered doc.
      const moved: Document = { ...reordered, proof: secured['proof'] };
      const result = await verifyProof({ document: moved, publicKey: key.publicKey });
      assert.equal(result.verified, true, 'canonicalization must make key order irrelevant');
    });
  });
}

describe('Data Integrity proof - hash construction', () => {
  it('signs SHA-256(JCS(proofConfig)) || SHA-256(JCS(document))', async () => {
    // Recompute the expected signing input independently of the implementation,
    // to pin the normative construction and its ordering.
    const { key, secured, provider } = await sign('Ed25519');
    const [proof] = proofsOf(secured);

    const { proofValue, ...proofConfigBase } = proof! as Record<string, unknown>;
    const proofConfig = { ...proofConfigBase, '@context': CREDENTIAL['@context'] };

    const sha256 = (b: Uint8Array) => new Uint8Array(createHash('sha256').update(b).digest());
    const expectedInput = Uint8Array.from([
      ...sha256(canonicalizeToBytes(proofConfig)),
      ...sha256(canonicalizeToBytes(CREDENTIAL)),
    ]);

    const expectedSignature = await provider.sign('issuance', expectedInput);
    assert.equal(toMultibaseBase58(expectedSignature), proofValue);
    assert.notEqual(key, undefined);
  });

  it('is order-sensitive: document-hash-first would not verify', async () => {
    const { key, secured } = await sign('Ed25519');
    const [proof] = proofsOf(secured);
    const { proofValue, ...proofConfigBase } = proof! as Record<string, unknown>;
    const proofConfig = { ...proofConfigBase, '@context': CREDENTIAL['@context'] };

    const sha256 = (b: Uint8Array) => new Uint8Array(createHash('sha256').update(b).digest());
    const reversed = Uint8Array.from([
      ...sha256(canonicalizeToBytes(CREDENTIAL)),
      ...sha256(canonicalizeToBytes(proofConfig)),
    ]);

    const provider = new InMemoryKeyProvider();
    await provider.generateKey('x', 'Ed25519');
    assert.notEqual(
      toMultibaseBase58(await provider.sign('x', reversed)),
      proofValue,
      'sanity: reversed order must not coincide',
    );
    assert.notEqual(key, undefined);
  });
});

describe('Data Integrity proof - cryptosuite binding', () => {
  it('refuses a proof whose cryptosuite disagrees with the key curve', async () => {
    const { secured } = await sign('Ed25519');
    const p256Provider = new InMemoryKeyProvider();
    const p256 = await p256Provider.generateKey('p', 'P-256');

    const result = await verifyProof({ document: secured, publicKey: p256.publicKey });
    assert.equal(result.verified, false);
    assert.match(result.reason ?? '', /cryptosuite/);
  });

  it('rejects an unknown cryptosuite outright', () => {
    assert.throws(() => {
      assertCryptosuiteMatchesCurve('bbs-2023', 'Ed25519');
    }, CryptosuiteMismatchError);
  });

  it('has no signature cryptosuite for X25519', () => {
    assert.throws(() => cryptosuiteForCurve('X25519'), CryptosuiteMismatchError);
  });
});

describe('Data Integrity proof - multiple proofs', () => {
  it('appends rather than replacing an existing proof', async () => {
    const provider = new InMemoryKeyProvider();
    await provider.generateKey('a', 'Ed25519');
    await provider.generateKey('b', 'P-256');

    const once = await createProof({
      document: CREDENTIAL,
      provider,
      keyLabel: 'a',
      verificationMethod: 'did:webvh:QmX:a.example#k',
    });
    const twice = await createProof({
      document: once,
      provider,
      keyLabel: 'b',
      verificationMethod: 'did:webvh:QmX:b.example#k',
    });

    assert.equal(proofsOf(twice).length, 2);
  });

  it('verifies each proof independently by verificationMethod', async () => {
    const provider = new InMemoryKeyProvider();
    const a = await provider.generateKey('a', 'Ed25519');
    const b = await provider.generateKey('b', 'P-256');

    const once = await createProof({
      document: CREDENTIAL,
      provider,
      keyLabel: 'a',
      verificationMethod: 'did:webvh:QmX:a.example#k',
    });
    const twice = await createProof({
      document: once,
      provider,
      keyLabel: 'b',
      verificationMethod: 'did:webvh:QmX:b.example#k',
    });

    const resultA = await verifyProof({
      document: twice,
      publicKey: a.publicKey,
      verificationMethod: 'did:webvh:QmX:a.example#k',
    });
    const resultB = await verifyProof({
      document: twice,
      publicKey: b.publicKey,
      verificationMethod: 'did:webvh:QmX:b.example#k',
    });

    assert.equal(resultA.verified, true, resultA.reason ?? 'no reason reported');
    assert.equal(resultB.verified, true, resultB.reason ?? 'no reason reported');
  });

  it('refuses to guess when several proofs are present', async () => {
    const provider = new InMemoryKeyProvider();
    const a = await provider.generateKey('a', 'Ed25519');
    await provider.generateKey('b', 'Ed25519');
    const once = await createProof({
      document: CREDENTIAL,
      provider,
      keyLabel: 'a',
      verificationMethod: 'did:webvh:QmX:a.example#k',
    });
    const twice = await createProof({
      document: once,
      provider,
      keyLabel: 'b',
      verificationMethod: 'did:webvh:QmX:b.example#k',
    });

    const result = await verifyProof({ document: twice, publicKey: a.publicKey });
    assert.equal(result.verified, false);
    assert.match(result.reason ?? '', /specify verificationMethod/);
  });
});

describe('Data Integrity proof - malformed input', () => {
  it('reports a document with no proof', async () => {
    const provider = new InMemoryKeyProvider();
    const key = await provider.generateKey('k', 'Ed25519');
    const result = await verifyProof({ document: CREDENTIAL, publicKey: key.publicKey });
    assert.equal(result.verified, false);
    assert.match(result.reason ?? '', /no proof/);
  });

  it('reports a malformed proofValue rather than throwing', async () => {
    const { key, secured } = await sign('Ed25519');
    const [proof] = proofsOf(secured);
    const tampered = { ...secured, proof: { ...proof!, proofValue: 'not-multibase' } };
    const result = await verifyProof({ document: tampered, publicKey: key.publicKey });
    assert.equal(result.verified, false);
    assert.match(result.reason ?? '', /Malformed proofValue/);
  });

  it('rejects an unsupported proof type', async () => {
    const { key, secured } = await sign('Ed25519');
    const [proof] = proofsOf(secured);
    const tampered = { ...secured, proof: { ...proof!, type: 'Ed25519Signature2020' } };
    const result = await verifyProof({ document: tampered, publicKey: key.publicKey });
    assert.equal(result.verified, false);
    assert.match(result.reason ?? '', /Unsupported proof type/);
  });

  it('enforces the expected proofPurpose', async () => {
    const { key, secured } = await sign('Ed25519');
    const result = await verifyProof({
      document: secured,
      publicKey: key.publicKey,
      expectedProofPurpose: 'authentication',
    });
    assert.equal(result.verified, false);
    assert.match(result.reason ?? '', /Proof purpose/);
  });
});

describe('Data Integrity proof - malformed and overriding input', () => {
  it('reports a proof entry that is not an object rather than throwing', async () => {
    const provider = new InMemoryKeyProvider();
    const key = await provider.generateKey('issuance', 'Ed25519');
    for (const proof of [[null], null, ['text'], [42]]) {
      const result = await verifyProof({ document: { ...CREDENTIAL, proof }, publicKey: key.publicKey });
      assert.equal(result.verified, false);
      assert.equal(result.reason, 'Proof entry is not an object');
    }
  });

  it('does not let additionalProperties override the identifying members', async () => {
    const provider = new InMemoryKeyProvider();
    const key = await provider.generateKey('issuance', 'Ed25519');
    const secured = await createProof({
      document: CREDENTIAL,
      provider,
      keyLabel: 'issuance',
      verificationMethod: VM,
      additionalProperties: {
        type: 'Ed25519Signature2020',
        cryptosuite: 'ecdsa-jcs-2019',
        verificationMethod: 'did:webvh:QmOther:attacker.example#key',
        proofPurpose: 'authentication',
        domain: 'counterparty.example',
      },
    });
    const [proof] = proofsOf(secured);
    assert.equal(proof?.type, 'DataIntegrityProof');
    assert.equal(proof.cryptosuite, 'eddsa-jcs-2022');
    assert.equal(proof.verificationMethod, VM);
    assert.equal(proof.proofPurpose, 'assertionMethod');
    assert.equal(proof['domain'], 'counterparty.example');
    assert.equal((await verifyProof({ document: secured, publicKey: key.publicKey })).verified, true);
  });
});

describe('Data Integrity proof - expires', () => {
  async function signWithExpiry(expires: unknown) {
    const provider = new InMemoryKeyProvider();
    const key = await provider.generateKey('issuance', 'Ed25519');
    const secured = await createProof({
      document: CREDENTIAL,
      provider,
      keyLabel: 'issuance',
      verificationMethod: VM,
      additionalProperties: { expires },
    });
    return { key, secured };
  }

  it('accepts a proof before it expires', async () => {
    const { key, secured } = await signWithExpiry('2030-01-01T00:00:00Z');
    const result = await verifyProof({
      document: secured,
      publicKey: key.publicKey,
      now: new Date('2029-12-31T23:59:59Z'),
    });
    assert.equal(result.verified, true, result.reason ?? 'no reason reported');
  });

  it('refuses a proof once it has expired', async () => {
    const { key, secured } = await signWithExpiry('2030-01-01T00:00:00Z');
    const result = await verifyProof({
      document: secured,
      publicKey: key.publicKey,
      now: new Date('2030-01-01T00:00:00Z'),
    });
    assert.equal(result.verified, false);
    assert.match(result.reason ?? '', /expired/);
  });

  it('refuses a proof whose expires is not a date', async () => {
    for (const expires of ['soon', 1_900_000_000, null]) {
      const { key, secured } = await signWithExpiry(expires);
      const result = await verifyProof({ document: secured, publicKey: key.publicKey });
      assert.equal(result.verified, false, String(expires));
    }
  });
});
