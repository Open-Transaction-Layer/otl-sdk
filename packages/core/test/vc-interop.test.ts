/**
 * Conformance of our Data Integrity proofs against an independent
 * implementation of the same W3C cryptosuite.
 *
 * ## Why this exists
 *
 * OTL spec Appendix A subordinates itself to the standards it cites: "Where
 * this document's field tables conflict with a cited standard's own text, the
 * standard is authoritative; this document only describes how OTL profiles or
 * constrains it." §6.3 requires the W3C DataIntegrityProof format, so
 * conformance is normative rather than aspirational.
 *
 * A credential test that signs and verifies with this package's own code only
 * checks self-consistency. A subtle error in canonicalization, in which fields
 * enter `proofConfig`, or in the order the two hashes are concatenated would
 * verify perfectly against itself and fail against every other
 * implementation, so this suite compares against an independent one.
 *
 * ## Why byte comparison rather than round-tripping
 *
 * Ed25519 is deterministic: the same key over the same input always yields the
 * same signature. So an identical `proofValue` proves both implementations
 * constructed a byte-identical signing input. That is a stronger and far more
 * legible result than "their verifier accepted it", which can pass for
 * uninteresting reasons.
 *
 * The counterpart, `@digitalbazaar/eddsa-jcs-2022-cryptosuite`, is written by
 * different people from the same specification.
 */

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { DataIntegrityProof } from '@digitalbazaar/data-integrity';
import { createSignCryptosuite } from '@digitalbazaar/eddsa-jcs-2022-cryptosuite';
import * as Ed25519Multikey from '@digitalbazaar/ed25519-multikey';
import jsigs from 'jsonld-signatures';
import { fromMultibaseBase58, toPublicKeyMultibase, type PublicKey } from '@otl/keys';
import { InMemoryKeyProvider } from '@otl/keys-dev';
// Reaching into @otl/keys internals: importing a raw private key is
// deliberately unsupported by the public API, and this harness needs both
// implementations holding the same key. A test may do this; a caller may not.
import { importPkcs8, publicKeyFrom, signWith } from '../../keys/src/nodecrypto.ts';
import { createProof, verifyProof, type Document } from '../src/index.ts';

const CONTROLLER = 'did:example:issuer';
const KEY_ID = `${CONTROLLER}#key`;
const CREATED = '2026-01-01T00:00:00Z';

/** PKCS#8 prefix for an Ed25519 private key, so both sides share key material. */
const ED25519_PKCS8_PREFIX = '302e020100300506032b657004220420';

interface Harnessed {
  readonly publicKey: PublicKey;
  readonly provider: InMemoryKeyProvider;
  readonly theirKey: Awaited<ReturnType<typeof Ed25519Multikey.generate>>;
}

/**
 * One keypair, usable by both implementations.
 *
 * Their key is generated first and imported into ours, because our providers
 * deliberately expose no import path — a test harness may reach past that, a
 * caller may not.
 */
async function shareOneKey(): Promise<Harnessed> {
  const theirKey = await Ed25519Multikey.generate({ controller: CONTROLLER, id: KEY_ID });
  const exported = await theirKey.export({ publicKey: true, secretKey: true });

  // Strip the multicodec prefix to get the raw 32-byte seed.
  const secretRaw = fromMultibaseBase58(exported.secretKeyMultibase as string).slice(2, 34);
  const keyObject = importPkcs8(
    new Uint8Array(Buffer.concat([Buffer.from(ED25519_PKCS8_PREFIX, 'hex'), Buffer.from(secretRaw)])),
  );
  const publicKey = publicKeyFrom(keyObject, 'Ed25519');

  assert.equal(
    toPublicKeyMultibase(publicKey),
    exported.publicKeyMultibase,
    'both implementations must hold identical key material, or nothing below means anything',
  );

  class Harness extends InMemoryKeyProvider {
    override capabilities() {
      return {
        signing: ['Ed25519'] as const,
        keyAgreement: [],
        canGenerate: false,
        canExportPrivateKey: false,
      };
    }
    override async getKey() {
      return { handle: { label: 'k' }, curve: 'Ed25519' as const, publicKey };
    }
    override async sign(_label: string, message: Uint8Array) {
      return signWith(keyObject, 'Ed25519', message);
    }
  }

  return { publicKey, provider: new Harness(), theirKey };
}

const CREDENTIAL: Document = {
  '@context': ['https://www.w3.org/ns/credentials/v2'],
  id: 'urn:uuid:11111111-2222-3333-4444-555555555555',
  type: ['VerifiableCredential'],
  issuer: CONTROLLER,
  validFrom: CREATED,
  credentialSubject: { id: 'did:example:subject' },
};

/** `eddsa-jcs-2022` canonicalizes with JCS, so no context is dereferenced. */
const documentLoader = async (url: string) => {
  if (url === 'https://www.w3.org/ns/credentials/v2') {
    return { contextUrl: null, documentUrl: url, document: { '@context': {} } };
  }
  throw new Error(`unexpected context fetch: ${url}`);
};

async function signWithOurs(document: Document, harness: Harnessed): Promise<Document> {
  return createProof({
    document,
    provider: harness.provider,
    keyLabel: 'k',
    verificationMethod: KEY_ID,
    proofPurpose: 'assertionMethod',
    created: CREATED,
  });
}

async function signWithTheirs(document: Document, harness: Harnessed): Promise<Document> {
  return jsigs.sign(
    { ...document },
    {
      suite: new DataIntegrityProof({
        signer: harness.theirKey.signer(),
        date: CREATED,
        cryptosuite: createSignCryptosuite(),
      }),
      purpose: new jsigs.purposes.AssertionProofPurpose(),
      documentLoader,
    },
  ) as Promise<Document>;
}

const proofOf = (document: Document) => document['proof'] as Record<string, unknown>;

describe('VC interop - our proofs are byte-identical to an independent implementation', () => {
  it('produces the same proofValue for the same credential and key', async () => {
    const harness = await shareOneKey();
    const ours = await signWithOurs(CREDENTIAL, harness);
    const theirs = await signWithTheirs(CREDENTIAL, harness);

    assert.equal(
      proofOf(ours)['proofValue'],
      proofOf(theirs)['proofValue'],
      'a differing signature means our signing input differs — canonicalization, ' +
        'proofConfig membership, or hash order',
    );
  });

  it('agrees on the proof metadata the spec fixes', async () => {
    const harness = await shareOneKey();
    const ours = proofOf(await signWithOurs(CREDENTIAL, harness));
    const theirs = proofOf(await signWithTheirs(CREDENTIAL, harness));

    for (const field of ['type', 'cryptosuite', 'created', 'verificationMethod', 'proofPurpose']) {
      assert.equal(ours[field], theirs[field], `proof.${field} differs`);
    }
  });

  it('stays identical as the credential varies', async () => {
    // One matching signature could be coincidence of a trivial document.
    const harness = await shareOneKey();
    const variants: Document[] = [
      { ...CREDENTIAL, credentialSubject: { id: 'did:example:other', name: 'Ünicode ✓' } },
      { ...CREDENTIAL, credentialSubject: { id: 'did:example:s', nested: { b: 2, a: [1, { z: 0 }] } } },
      // Numeric-looking keys: the case where naive canonicalization diverges.
      { ...CREDENTIAL, credentialSubject: { id: 'did:example:s', '10': 'ten', '9': 'nine' } },
    ];

    for (const [index, credential] of variants.entries()) {
      const ours = await signWithOurs(credential, harness);
      const theirs = await signWithTheirs(credential, harness);
      assert.equal(proofOf(ours)['proofValue'], proofOf(theirs)['proofValue'], `variant ${index} diverged`);
    }
  });
});

describe('VC interop - we accept their credentials', () => {
  it('verifies a credential they produced', async () => {
    // Their emitted proof carries an `@context` member ours omits, so this is
    // a genuinely different document shape rather than a round trip.
    const harness = await shareOneKey();
    const theirs = await signWithTheirs(CREDENTIAL, harness);
    assert.ok('@context' in proofOf(theirs), 'expected their proof to carry @context');

    const result = await verifyProof({ document: theirs, publicKey: harness.publicKey });
    assert.equal(result.verified, true, result.reason ?? 'no reason reported');
  });

  it('rejects a tampered credential in either shape', async () => {
    const harness = await shareOneKey();
    for (const signer of [signWithOurs, signWithTheirs]) {
      const secured = await signer(CREDENTIAL, harness);
      const tampered = { ...secured, credentialSubject: { id: 'did:example:attacker' } };
      const result = await verifyProof({ document: tampered, publicKey: harness.publicKey });
      assert.equal(result.verified, false, 'a tampered credential must not verify');
    }
  });
});
