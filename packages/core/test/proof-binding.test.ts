/**
 * Why the proof configuration is part of the signature input (spec 6.3).
 *
 * A signature over the JCS-canonicalized document body alone covers nothing in
 * the proof block, which states who signed, with which key, for what purpose,
 * when, and for which audience.
 *
 * The W3C cryptosuites that spec 6.3 names, and that this package implements,
 * sign a different input:
 *
 *     hashData = SHA-256(JCS(proofConfig)) || SHA-256(JCS(unsecuredDocument))
 *
 * These tests implement both constructions and run the same forgery against
 * each, so the reason for hashing the proof configuration is recorded as
 * evidence rather than as an assertion in a comment.
 */

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  fromMultibaseBase58,
  toMultibaseBase58,
  verifySignature,
  type KeyProvider,
  type PublicKey,
} from '@open-transaction-layer/keys';
import { InMemoryKeyProvider } from '@open-transaction-layer/keys-dev';
import { canonicalizeToBytes } from '../src/jcs.ts';
import { createProof, verifyProof, type Document } from '../src/proof.ts';

type Proof = Record<string, unknown> & { proofValue?: string };

function withoutProof(document: Document): Record<string, unknown> {
  const { proof: _proof, ...rest } = document;
  return rest;
}

// --- Construction A: the document body alone --------------------------------

const signBodyOnly = async (document: Document, provider: KeyProvider, keyLabel: string) =>
  toMultibaseBase58(await provider.sign(keyLabel, canonicalizeToBytes(withoutProof(document))));

const verifyBodyOnly = (document: Document, publicKey: PublicKey) =>
  verifySignature(
    publicKey,
    canonicalizeToBytes(withoutProof(document)),
    fromMultibaseBase58((document['proof'] as Proof).proofValue!),
  );

// ---------------------------------------------------------------------------

const PRESENTATION: Document = {
  '@context': ['https://www.w3.org/ns/credentials/v2'],
  type: ['VerifiablePresentation'],
  holder: 'did:webvh:QmTestScid:vasp.example.com',
  verifiableCredential: [],
};

/** A presentation bound to one counterparty, asserting a claim. */
const LEGITIMATE_PROOF = {
  type: 'DataIntegrityProof',
  cryptosuite: 'eddsa-jcs-2022',
  created: '2026-01-01T00:00:00Z',
  verificationMethod: 'did:webvh:QmTestScid:vasp.example.com#assertion-key',
  proofPurpose: 'assertionMethod',
  domain: 'counterparty-a.example',
  challenge: 'nonce-issued-by-a',
} as const;

/** The same proof block after an observer rewrites every unsigned field. */
const FORGED_PROOF = {
  ...LEGITIMATE_PROOF,
  proofPurpose: 'authentication',
  domain: 'counterparty-b.example',
  challenge: 'nonce-issued-by-b',
  created: '2026-08-27T00:00:00Z',
};

describe('signing the body alone is forgeable', () => {
  it('accepts a signature lifted onto a contradictory proof block', async () => {
    const provider = new InMemoryKeyProvider();
    const key = await provider.generateKey('holder', 'Ed25519');

    const signature = await signBodyOnly(PRESENTATION, provider, 'holder');
    const legitimate = { ...PRESENTATION, proof: { ...LEGITIMATE_PROOF, proofValue: signature } };
    const forged = { ...PRESENTATION, proof: { ...FORGED_PROOF, proofValue: signature } };

    assert.equal(verifyBodyOnly(legitimate, key.publicKey), true);
    assert.equal(
      verifyBodyOnly(forged, key.publicKey),
      true,
      'the signature bytes are untouched, so a body-only signature verifies on the forged block',
    );
  });
});

describe('the W3C construction rejects the same forgery', () => {
  async function sign(proofOptions: Record<string, unknown>) {
    const provider = new InMemoryKeyProvider();
    const key = await provider.generateKey('holder', 'Ed25519');
    const secured = await createProof({
      document: PRESENTATION,
      provider,
      keyLabel: 'holder',
      verificationMethod: LEGITIMATE_PROOF.verificationMethod,
      proofPurpose: LEGITIMATE_PROOF.proofPurpose,
      created: LEGITIMATE_PROOF.created,
      additionalProperties: proofOptions,
    });
    return { secured, publicKey: key.publicKey };
  }

  it('accepts the legitimate presentation', async () => {
    const { secured, publicKey } = await sign({
      domain: LEGITIMATE_PROOF.domain,
      challenge: LEGITIMATE_PROOF.challenge,
    });
    const result = await verifyProof({ document: secured, publicKey });
    assert.equal(result.verified, true, result.reason ?? 'no reason reported');
  });

  for (const [field, value, defeats] of [
    [
      'domain',
      'counterparty-b.example',
      'audience binding — replaying a presentation at another counterparty',
    ],
    ['challenge', 'nonce-issued-by-b', 'replay protection — answering a nonce the holder never saw'],
    ['proofPurpose', 'authentication', 'purpose separation — spec 3.3 treats these as distinct'],
    ['created', '2026-08-27T00:00:00Z', 'freshness — bypassing any maximum proof-age policy'],
  ] as const) {
    it(`rejects a rewritten "${field}" (defeats ${defeats})`, async () => {
      const { secured, publicKey } = await sign({
        domain: LEGITIMATE_PROOF.domain,
        challenge: LEGITIMATE_PROOF.challenge,
      });
      const proof = secured['proof'] as Proof;
      const forged = { ...secured, proof: { ...proof, [field]: value } };

      const result = await verifyProof({
        document: forged,
        publicKey,
        // proofPurpose is checked separately; this isolates the signature.
        expectedProofPurpose: null,
      });
      assert.equal(result.verified, false, `rewriting ${field} must invalidate the proof`);
    });
  }

  it('binds the verification method, though this one needs no protection in practice', async () => {
    // Weakest of the set, and worth stating accurately: swapping in an
    // attacker's OWN key fails anyway, because the signature will not verify
    // against it. This field only becomes exploitable when one DID publishes
    // the same key material under two fragments, which is operator error.
    const { secured, publicKey } = await sign({});
    const proof = secured['proof'] as Proof;
    const forged = {
      ...secured,
      proof: {
        ...proof,
        verificationMethod: 'did:webvh:QmTestScid:vasp.example.com#credential-issuance-key',
      },
    };

    const result = await verifyProof({ document: forged, publicKey });
    assert.equal(result.verified, false);
  });
});
