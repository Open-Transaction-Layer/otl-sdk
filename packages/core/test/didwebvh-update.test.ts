import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { toPublicKeyMultibase } from '@otl/keys';
import { InMemoryKeyProvider } from '@otl/keys-dev';
import { InvalidDocumentError } from '../src/errors.ts';
import { verifyProof } from '../src/proof.ts';
import { createDid } from '../src/didwebvh/create.ts';
import { keyFromKeyInfo } from '../src/didwebvh/document.ts';
import { deriveEntryHash, deriveKeyHash, parseVersionId } from '../src/didwebvh/hashing.ts';
import {
  addKey,
  addService,
  appendEntry,
  deactivate,
  documentKeysOf,
  validateServiceEntry,
} from '../src/didwebvh/update.ts';
import { canonicalizeToBytes } from '../src/jcs.ts';
import { hashToBase58 } from '../src/multihash.ts';

const DOMAIN = 'vasp.example.com';
const T1 = '2026-01-01T00:00:00Z';
const T2 = '2026-02-01T00:00:00Z';

/**
 * Genesis plus a pool of pre-generated Ed25519 keys named k0, k1, k2 ...
 * k0 signs entry 1 and entry 1 commits to k1, so k1 signs entry 2, and so on.
 */
async function genesis() {
  const provider = new InMemoryKeyProvider();
  for (let i = 0; i < 5; i++) await provider.generateKey(`k${i}`, 'Ed25519');

  const created = await createDid({
    domain: DOMAIN,
    provider,
    managementKeyLabel: 'k0',
    preRotationKeyLabel: 'k1',
    versionTime: T1,
  });
  return { provider, created };
}

describe('log evolution - chaining', () => {
  it('increments the version number', async () => {
    const { provider, created } = await genesis();
    const entry2 = await addService({
      did: created.did,
      previousEntry: created.entry,
      provider,
      signingKeyLabel: 'k1',
      nextKeyLabel: 'k2',
      versionTime: T2,
      service: {
        id: '#whois',
        type: 'OtlWhois',
        serviceEndpoint: `https://${DOMAIN}/.well-known/whois.vp`,
      },
    });

    assert.equal(parseVersionId(entry2.versionId).versionNumber, 2);
  });

  it('chains the entry hash to the previous versionId', async () => {
    // Recomputed longhand, as a resolver would, rather than via deriveEntryHash.
    const { provider, created } = await genesis();
    const entry2 = await addService({
      did: created.did,
      previousEntry: created.entry,
      provider,
      signingKeyLabel: 'k1',
      nextKeyLabel: 'k2',
      versionTime: T2,
      service: { id: '#whois', type: 'OtlWhois', serviceEndpoint: `https://${DOMAIN}/x.json` },
    });

    const { proof: _p, ...unsigned } = entry2 as unknown as Record<string, unknown>;
    const recomputed = hashToBase58(canonicalizeToBytes({ ...unsigned, versionId: created.entry.versionId }));
    assert.equal(parseVersionId(entry2.versionId).entryHash, recomputed);
  });

  it('produces a different entry hash if the predecessor differs', async () => {
    const { provider, created } = await genesis();
    const entry2 = await deactivate({
      did: created.did,
      previousEntry: created.entry,
      provider,
      signingKeyLabel: 'k1',
      nextKeyLabel: 'k2',
      versionTime: T2,
    });
    const forged = deriveEntryHash(entry2, 'some-other-version-id');
    assert.notEqual(parseVersionId(entry2.versionId).entryHash, forged);
  });

  it('carries a proof verifiable with the signing key', async () => {
    const { provider, created } = await genesis();
    const entry2 = await deactivate({
      did: created.did,
      previousEntry: created.entry,
      provider,
      signingKeyLabel: 'k1',
      nextKeyLabel: 'k2',
      versionTime: T2,
    });
    const k1 = await provider.getKey('k1');
    const result = await verifyProof({
      document: entry2 as unknown as Record<string, unknown>,
      publicKey: k1.publicKey,
    });
    assert.equal(result.verified, true, result.reason ?? 'no reason reported');
  });
});

describe('log evolution - pre-rotation enforcement', () => {
  it('accepts the key the previous entry committed to', async () => {
    const { provider, created } = await genesis();
    const entry2 = await deactivate({
      did: created.did,
      previousEntry: created.entry,
      provider,
      signingKeyLabel: 'k1',
      nextKeyLabel: 'k2',
      versionTime: T2,
    });
    const k1 = await provider.getKey('k1');
    assert.deepEqual(entry2.parameters.updateKeys, [toPublicKeyMultibase(k1.publicKey)]);
  });

  it('rejects a key that was never committed', async () => {
    // The core pre-rotation guarantee: an attacker holding some other key
    // cannot extend the log, even a key already in the provider.
    const { provider, created } = await genesis();
    await assert.rejects(
      () =>
        deactivate({
          did: created.did,
          previousEntry: created.entry,
          provider,
          signingKeyLabel: 'k3',
          nextKeyLabel: 'k4',
          versionTime: T2,
        }),
      (error: unknown) => {
        assert.ok(error instanceof InvalidDocumentError);
        assert.match(error.message, /not committed/);
        return true;
      },
    );
  });

  it('rejects reusing the genesis key to sign entry 2', async () => {
    // Under rotate-every-entry, k0 signed entry 1 and committed to k1, so k0
    // itself is not authorised to sign entry 2.
    const { provider, created } = await genesis();
    await assert.rejects(
      () =>
        deactivate({
          did: created.did,
          previousEntry: created.entry,
          provider,
          signingKeyLabel: 'k0',
          nextKeyLabel: 'k2',
          versionTime: T2,
        }),
      InvalidDocumentError,
    );
  });

  it('never leaves the commitment empty', async () => {
    const { provider, created } = await genesis();
    const entry2 = await deactivate({
      did: created.did,
      previousEntry: created.entry,
      provider,
      signingKeyLabel: 'k1',
      nextKeyLabel: 'k2',
      versionTime: T2,
    });
    assert.equal((entry2.parameters.nextKeyHashes ?? []).length, 1);
  });

  it('does not publish the committed key, only its hash', async () => {
    const { provider, created } = await genesis();
    const entry2 = await deactivate({
      did: created.did,
      previousEntry: created.entry,
      provider,
      signingKeyLabel: 'k1',
      nextKeyLabel: 'k2',
      versionTime: T2,
    });
    const k2 = await provider.getKey('k2');
    const multikey = toPublicKeyMultibase(k2.publicKey);
    assert.ok(!JSON.stringify(entry2).includes(multikey));
    assert.deepEqual(entry2.parameters.nextKeyHashes, [deriveKeyHash(multikey)]);
  });

  it('refuses to extend a log whose previous entry has no commitment', async () => {
    const { provider, created } = await genesis();
    const stripped = {
      ...created.entry,
      parameters: { ...created.entry.parameters, nextKeyHashes: [] },
    };
    await assert.rejects(
      () =>
        deactivate({
          did: created.did,
          previousEntry: stripped,
          provider,
          signingKeyLabel: 'k1',
          nextKeyLabel: 'k2',
          versionTime: T2,
        }),
      InvalidDocumentError,
    );
  });

  it('supports a retain-until-rotation policy when the caller commits to the live key', async () => {
    // Policy is expressed by what the caller commits to, not baked in: an entry
    // that re-commits to its own signing key lets the next entry retain it.
    const provider = new InMemoryKeyProvider();
    await provider.generateKey('m', 'Ed25519');
    const created = await createDid({
      domain: DOMAIN,
      provider,
      managementKeyLabel: 'm',
      preRotationKeyLabel: 'm',
      versionTime: T1,
    });
    const entry2 = await deactivate({
      did: created.did,
      previousEntry: created.entry,
      provider,
      signingKeyLabel: 'm',
      nextKeyLabel: 'm',
      versionTime: T2,
    });
    assert.equal(parseVersionId(entry2.versionId).versionNumber, 2);
  });
});

describe('log evolution - entry-1-only parameters', () => {
  it('omits scid from later entries', async () => {
    const { provider, created } = await genesis();
    const entry2 = await deactivate({
      did: created.did,
      previousEntry: created.entry,
      provider,
      signingKeyLabel: 'k1',
      nextKeyLabel: 'k2',
      versionTime: T2,
    });
    assert.equal(entry2.parameters.scid, undefined);
  });
});

describe('log evolution - addKey', () => {
  it('preserves existing keys and adds the new one', async () => {
    const provider = new InMemoryKeyProvider();
    for (let i = 0; i < 3; i++) await provider.generateKey(`k${i}`, 'Ed25519');
    const first = await provider.generateKey('first', 'Ed25519');
    const second = await provider.generateKey('second', 'P-256');

    const created = await createDid({
      domain: DOMAIN,
      provider,
      managementKeyLabel: 'k0',
      preRotationKeyLabel: 'k1',
      versionTime: T1,
      keys: [keyFromKeyInfo('assertion-key', first, ['assertionMethod'])],
    });

    const entry2 = await addKey({
      did: created.did,
      previousEntry: created.entry,
      provider,
      signingKeyLabel: 'k1',
      nextKeyLabel: 'k2',
      versionTime: T2,
      keys: [keyFromKeyInfo('credential-issuance-key', second, ['assertionMethod'])],
    });

    const fragments = (entry2.state.verificationMethod ?? []).map((m) =>
      m.id.slice(m.id.lastIndexOf('#') + 1),
    );
    assert.deepEqual(fragments, ['assertion-key', 'credential-issuance-key']);
    assert.ok(
      (entry2.state['@context'] as string[]).includes('https://w3id.org/security/suites/jws-2020/v1'),
    );
  });

  it('round-trips document keys through publish and rebuild', async () => {
    // documentKeysOf must recover both multibase and JWK encoded keys, or an
    // update would silently drop them from the next version.
    const provider = new InMemoryKeyProvider();
    for (let i = 0; i < 3; i++) await provider.generateKey(`k${i}`, 'Ed25519');
    const ed = await provider.generateKey('ed', 'Ed25519');
    const p256 = await provider.generateKey('p256', 'P-256');
    const x = await provider.generateKey('x', 'X25519');

    const created = await createDid({
      domain: DOMAIN,
      provider,
      managementKeyLabel: 'k0',
      preRotationKeyLabel: 'k1',
      versionTime: T1,
      keys: [
        keyFromKeyInfo('ed-key', ed, ['assertionMethod', 'authentication']),
        keyFromKeyInfo('p256-key', p256, ['assertionMethod']),
        keyFromKeyInfo('x-key', x, ['keyAgreement']),
      ],
    });

    const recovered = documentKeysOf(created.entry.state);
    assert.deepEqual(
      recovered.map((k) => [k.fragment, k.publicKey.curve, [...k.purposes].sort()]),
      [
        ['ed-key', 'Ed25519', ['assertionMethod', 'authentication']],
        ['p256-key', 'P-256', ['assertionMethod']],
        ['x-key', 'X25519', ['keyAgreement']],
      ],
    );
  });

  it('rejects a duplicate fragment', async () => {
    const provider = new InMemoryKeyProvider();
    for (let i = 0; i < 3; i++) await provider.generateKey(`k${i}`, 'Ed25519');
    const a = await provider.generateKey('a', 'Ed25519');
    const b = await provider.generateKey('b', 'Ed25519');

    const created = await createDid({
      domain: DOMAIN,
      provider,
      managementKeyLabel: 'k0',
      preRotationKeyLabel: 'k1',
      versionTime: T1,
      keys: [keyFromKeyInfo('same', a, ['assertionMethod'])],
    });

    await assert.rejects(
      () =>
        addKey({
          did: created.did,
          previousEntry: created.entry,
          provider,
          signingKeyLabel: 'k1',
          nextKeyLabel: 'k2',
          versionTime: T2,
          keys: [keyFromKeyInfo('same', b, ['assertionMethod'])],
        }),
      InvalidDocumentError,
    );
  });
});

describe('log evolution - addService', () => {
  it('adds the entry and preserves prior services', async () => {
    const { provider, created } = await genesis();
    const entry2 = await addService({
      did: created.did,
      previousEntry: created.entry,
      provider,
      signingKeyLabel: 'k1',
      nextKeyLabel: 'k2',
      versionTime: T2,
      service: {
        id: '#whois',
        type: 'OtlWhois',
        serviceEndpoint: `https://${DOMAIN}/.well-known/whois.vp`,
      },
    });
    const entry3 = await addService({
      did: created.did,
      previousEntry: entry2,
      provider,
      signingKeyLabel: 'k2',
      nextKeyLabel: 'k3',
      versionTime: T2,
      service: {
        id: '#status',
        type: 'OtlStatusList',
        serviceEndpoint: `https://${DOMAIN}/.well-known/status-lists/1`,
      },
    });

    assert.deepEqual(
      (entry3.state.service ?? []).map((s) => s.id),
      ['#whois', '#status'],
    );
  });

  it('rejects a duplicate service id', async () => {
    const { provider, created } = await genesis();
    const service = { id: '#whois', type: 'OtlWhois', serviceEndpoint: `https://${DOMAIN}/w.json` };
    const entry2 = await addService({
      did: created.did,
      previousEntry: created.entry,
      provider,
      signingKeyLabel: 'k1',
      nextKeyLabel: 'k2',
      versionTime: T2,
      service,
    });
    await assert.rejects(
      () =>
        addService({
          did: created.did,
          previousEntry: entry2,
          provider,
          signingKeyLabel: 'k2',
          nextKeyLabel: 'k3',
          versionTime: T2,
          service,
        }),
      InvalidDocumentError,
    );
  });
});

describe('service entry validation', () => {
  const did = 'did:webvh:QmScid:vasp.example.com';
  const valid = { id: '#whois', type: 'OtlWhois', serviceEndpoint: 'https://vasp.example.com/w.json' };

  it('accepts a well-formed entry', () => {
    assert.doesNotThrow(() => {
      validateServiceEntry(valid, did);
    });
  });

  it('accepts an absolute id within the DID', () => {
    assert.doesNotThrow(() => {
      validateServiceEntry({ ...valid, id: `${did}#whois` }, did);
    });
  });

  it('accepts array and object endpoints', () => {
    assert.doesNotThrow(() => {
      validateServiceEntry(
        { ...valid, serviceEndpoint: ['https://a.example/x', 'https://b.example/y'] },
        did,
      );
    });
    assert.doesNotThrow(() => {
      validateServiceEntry({ ...valid, serviceEndpoint: { origins: ['https://a.example/x'] } }, did);
    });
  });

  it('rejects a non-HTTPS endpoint', () => {
    // Every endpoint the Identity layer defines is fetched over HTTPS.
    for (const endpoint of ['http://vasp.example.com/w.json', 'ftp://x/y', 'file:///etc/passwd']) {
      assert.throws(
        () => {
          validateServiceEntry({ ...valid, serviceEndpoint: endpoint }, did);
        },
        InvalidDocumentError,
        endpoint,
      );
    }
  });

  it('rejects a malformed endpoint', () => {
    for (const endpoint of ['not a url', '', 42, null, {}, []]) {
      assert.throws(() => {
        validateServiceEntry({ ...valid, serviceEndpoint: endpoint }, did);
      }, InvalidDocumentError);
    }
  });

  it('rejects a missing or foreign id', () => {
    assert.throws(() => {
      validateServiceEntry({ ...valid, id: '' }, did);
    }, InvalidDocumentError);
    assert.throws(() => {
      validateServiceEntry({ ...valid, id: 'did:webvh:QmOther:attacker.example#whois' }, did);
    }, InvalidDocumentError);
  });

  it('rejects a missing or empty type', () => {
    assert.throws(() => {
      validateServiceEntry({ ...valid, type: '' }, did);
    }, InvalidDocumentError);
    assert.throws(() => {
      validateServiceEntry({ ...valid, type: [] }, did);
    }, InvalidDocumentError);
  });
});

describe('log evolution - deactivation', () => {
  it('marks the DID deactivated', async () => {
    const { provider, created } = await genesis();
    const entry2 = await deactivate({
      did: created.did,
      previousEntry: created.entry,
      provider,
      signingKeyLabel: 'k1',
      nextKeyLabel: 'k2',
      versionTime: T2,
    });
    assert.equal(entry2.parameters.deactivated, true);
  });

  it('leaves deactivated unset on ordinary updates', async () => {
    const { provider, created } = await genesis();
    const entry2 = await addService({
      did: created.did,
      previousEntry: created.entry,
      provider,
      signingKeyLabel: 'k1',
      nextKeyLabel: 'k2',
      versionTime: T2,
      service: { id: '#whois', type: 'OtlWhois', serviceEndpoint: `https://${DOMAIN}/w.json` },
    });
    assert.equal(entry2.parameters.deactivated, undefined);
  });
});

describe('log evolution - curve enforcement', () => {
  it('refuses a non-Ed25519 signing key', async () => {
    const provider = new InMemoryKeyProvider();
    for (let i = 0; i < 3; i++) await provider.generateKey(`k${i}`, 'Ed25519');
    await provider.generateKey('p', 'P-256');
    const created = await createDid({
      domain: DOMAIN,
      provider,
      managementKeyLabel: 'k0',
      preRotationKeyLabel: 'k1',
      versionTime: T1,
    });

    await assert.rejects(
      () =>
        appendEntry({
          previousEntry: created.entry,
          state: created.entry.state,
          provider,
          signingKeyLabel: 'p',
          nextKeyLabel: 'k2',
          versionTime: T2,
        }),
      (error: unknown) => {
        assert.match((error as Error).message, /eddsa-jcs-2022/);
        return true;
      },
    );
  });
});

describe('log evolution - guards on the caller', () => {
  const service = {
    id: '#whois',
    type: 'OtlWhois',
    serviceEndpoint: `https://${DOMAIN}/.well-known/whois.vp`,
  };

  it('rejects an absolute service id under a DID that merely shares a prefix', () => {
    const did = 'did:webvh:QmScid:vasp.example.com';
    assert.doesNotThrow(() => {
      validateServiceEntry({ ...service, id: `${did}#whois` }, did);
    });
    assert.throws(() => {
      validateServiceEntry({ ...service, id: `${did}.attacker.example#whois` }, did);
    }, InvalidDocumentError);
  });

  it('refuses addKey, addService and deactivate for a different DID', async () => {
    const { provider, created } = await genesis();
    const other = 'did:webvh:QmOther:attacker.example';
    const common = {
      did: other,
      previousEntry: created.entry,
      provider,
      signingKeyLabel: 'k1',
      nextKeyLabel: 'k2',
      versionTime: T2,
    };
    await assert.rejects(() => addService({ ...common, service }), /does not match the previous entry's DID/);
    await assert.rejects(() => addKey({ ...common, keys: [] }), /does not match the previous entry's DID/);
    await assert.rejects(() => deactivate(common), /does not match the previous entry's DID/);
  });

  it('refuses to extend a deactivated log', async () => {
    const { provider, created } = await genesis();
    const closed = await deactivate({
      did: created.did,
      previousEntry: created.entry,
      provider,
      signingKeyLabel: 'k1',
      nextKeyLabel: 'k2',
      versionTime: T2,
    });
    await assert.rejects(
      () =>
        addService({
          did: created.did,
          previousEntry: closed,
          provider,
          signingKeyLabel: 'k2',
          nextKeyLabel: 'k3',
          versionTime: '2026-03-01T00:00:00Z',
          service,
        }),
      /deactivated log cannot be extended/,
    );
  });
});
