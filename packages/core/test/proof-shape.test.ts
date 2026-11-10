/**
 * Proof shape: array for log entries, bare object for credentials.
 *
 * The spec uses both forms: §3.2.2 shows `"proof": [{…}]` for a log entry, and
 * §4.10 and §5.2.1 show a bare object for credentials.
 *
 * The difference matters to resolvers. Among the DIF reference
 * implementations, `didwebvh-ts` accepts either shape for a log entry, but
 * `didwebvh-dart` rejects a bare object outright with "missing proof at entry
 * 1", so a log emitted with bare objects is unresolvable by one of them.
 *
 * These tests pin the shapes because a regression would otherwise surface only
 * when a third party tried to resolve the DID.
 */

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { InMemoryKeyProvider } from '@otl/keys-dev';
import { Bitstring, buildStatusListCredential, createDid, createProof, addService } from '../src/index.ts';

const DOMAIN = 'vasp.example.com';
const T1 = '2026-01-01T00:00:00Z';
const T2 = '2026-02-01T00:00:00Z';

async function log() {
  const provider = new InMemoryKeyProvider();
  for (let i = 0; i < 3; i++) await provider.generateKey(`k${i}`, 'Ed25519');
  const created = await createDid({
    domain: DOMAIN,
    provider,
    managementKeyLabel: 'k0',
    preRotationKeyLabel: 'k1',
    versionTime: T1,
  });
  const second = await addService({
    did: created.did,
    previousEntry: created.entry,
    provider,
    signingKeyLabel: 'k1',
    nextKeyLabel: 'k2',
    versionTime: T2,
    service: { id: '#whois', type: 'OtlWhois', serviceEndpoint: `https://${DOMAIN}/w.json` },
  });
  return { provider, created, second };
}

describe('proof shape - DID log entries carry an array', () => {
  it('on the genesis entry', async () => {
    const { created } = await log();
    const proof = (created.entry as unknown as { proof: unknown }).proof;
    assert.ok(Array.isArray(proof), 'spec 3.2.2 shows a log entry proof as an array');
    assert.equal((proof as unknown[]).length, 1);
  });

  it('on later entries', async () => {
    const { second } = await log();
    const proof = (second as unknown as { proof: unknown }).proof;
    assert.ok(Array.isArray(proof));
  });

  it('with the proof itself unchanged by the wrapping', async () => {
    // The proof is excluded from its own signing input, so the array wrapper
    // is purely a serialization choice and must not alter the signature.
    const { created } = await log();
    const [proof] = (created.entry as unknown as { proof: Record<string, unknown>[] }).proof;
    assert.equal(proof!['type'], 'DataIntegrityProof');
    assert.equal(proof!['cryptosuite'], 'eddsa-jcs-2022');
    assert.equal(typeof proof!['proofValue'], 'string');
  });
});

describe('proof shape - credentials carry a bare object', () => {
  it('on a status list credential', async () => {
    const provider = new InMemoryKeyProvider();
    await provider.generateKey('issuance', 'Ed25519');
    const issuer = 'did:webvh:QmTestScidIssuer:lou.example.org';

    const credential = await buildStatusListCredential({
      issuer,
      statusListCredentialUrl: 'https://lou.example.org/.well-known/status-lists/1',
      bitstring: Bitstring.create(),
      provider,
      keyLabel: 'issuance',
      verificationMethod: `${issuer}#credential-issuance-key`,
    });

    assert.ok(!Array.isArray(credential['proof']), 'spec 5.2.1 shows a bare object');
  });

  it('by default, for any document', async () => {
    const provider = new InMemoryKeyProvider();
    await provider.generateKey('k', 'Ed25519');
    const secured = await createProof({
      document: { '@context': [], id: 'urn:uuid:x' },
      provider,
      keyLabel: 'k',
      verificationMethod: 'did:webvh:QmX:a.example#k',
    });
    assert.ok(!Array.isArray(secured['proof']));
  });

  it('but produces an array when explicitly asked', async () => {
    const provider = new InMemoryKeyProvider();
    await provider.generateKey('k', 'Ed25519');
    const secured = await createProof({
      document: { '@context': [], id: 'urn:uuid:x' },
      provider,
      keyLabel: 'k',
      verificationMethod: 'did:webvh:QmX:a.example#k',
      proofFormat: 'array',
    });
    assert.ok(Array.isArray(secured['proof']));
  });

  it('always produces an array when appending to an existing proof', async () => {
    const provider = new InMemoryKeyProvider();
    await provider.generateKey('a', 'Ed25519');
    await provider.generateKey('b', 'Ed25519');
    const once = await createProof({
      document: { '@context': [], id: 'urn:uuid:x' },
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
    assert.ok(Array.isArray(twice['proof']));
    assert.equal((twice['proof'] as unknown[]).length, 2);
  });
});
