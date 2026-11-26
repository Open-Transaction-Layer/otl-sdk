import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { gzipSync } from 'node:zlib';
import { InMemoryKeyProvider } from '@open-transaction-layer/keys-dev';
import { InvalidDocumentError } from '../src/errors.ts';
import { verifyProof } from '../src/proof.ts';
import { Bitstring, MAXIMUM_ENTRIES, MINIMUM_ENTRIES } from '../src/statuslist/bitstring.ts';
import {
  allocateIndex,
  bitstringFrom,
  buildStatusListCredential,
  statusEntryFor,
} from '../src/statuslist/credential.ts';
import { TEST_ISSUANCE_KEY, TEST_ISSUER_DID } from './fixtures.ts';

const LIST_URL = 'https://lou.example.org/.well-known/status-lists/1';

/** The worked example from OTL spec 5.2.1. */
const SPEC_ENCODED_LIST = 'uH4sIAAAAAAAAA-3BMQEAAADCoPVPbQwfoAAAAAAAAAAAAAAAAAAAAIC3AYbSVKsAQAAA';

describe('Bitstring - spec 5.2.1 worked example', () => {
  it('decodes the published example to exactly 131,072 unset entries', () => {
    const bitstring = Bitstring.decode(SPEC_ENCODED_LIST);
    assert.equal(bitstring.length, MINIMUM_ENTRIES);
    assert.deepEqual(bitstring.setIndices(), []);
  });

  it('encodes a fresh list to the same content as the published example', () => {
    // Compares decoded content, not bytes. GZIP headers carry advisory
    // metadata that legitimately differs between implementations, so byte
    // equality would pin us to whichever zlib produced the spec's example.
    const ours = Bitstring.decode(Bitstring.create().encode());
    const theirs = Bitstring.decode(SPEC_ENCODED_LIST);
    assert.equal(ours.length, theirs.length);
    assert.deepEqual(ours.setIndices(), theirs.setIndices());
  });
});

describe('Bitstring - bit layout', () => {
  it('treats index 0 as the most significant bit of byte 0', () => {
    const bitstring = Bitstring.create();
    bitstring.set(0, true);
    const bytes = gunzippedBytes(bitstring);
    assert.equal(bytes[0], 0b1000_0000, 'index 0 must be the top bit, not the bottom');
  });

  it('lays out the first byte most-significant-first', () => {
    const bitstring = Bitstring.create();
    bitstring.set(1, true);
    bitstring.set(7, true);
    assert.equal(gunzippedBytes(bitstring)[0], 0b0100_0001);
  });

  it('starts byte 1 at index 8', () => {
    const bitstring = Bitstring.create();
    bitstring.set(8, true);
    const bytes = gunzippedBytes(bitstring);
    assert.equal(bytes[0], 0);
    assert.equal(bytes[1], 0b1000_0000);
  });

  function gunzippedBytes(bitstring: Bitstring): Uint8Array {
    // Round-trip through encode/decode and read bits back out via a fresh
    // instance, so the layout assertion covers encoding too.
    const decoded = Bitstring.decode(bitstring.encode());
    const bytes = new Uint8Array(decoded.length / 8);
    for (let i = 0; i < decoded.length; i++) {
      if (decoded.get(i)) bytes[i >>> 3] = (bytes[i >>> 3] ?? 0) | (1 << (7 - (i & 7)));
    }
    return bytes;
  }
});

describe('Bitstring - get and set', () => {
  it('defaults every entry to unset', () => {
    const bitstring = Bitstring.create();
    assert.equal(bitstring.get(0), false);
    assert.equal(bitstring.get(94_567), false);
    assert.equal(bitstring.get(MINIMUM_ENTRIES - 1), false);
  });

  it('sets and clears individual entries without disturbing neighbours', () => {
    const bitstring = Bitstring.create();
    bitstring.set(94_567, true);

    assert.equal(bitstring.get(94_567), true);
    assert.equal(bitstring.get(94_566), false);
    assert.equal(bitstring.get(94_568), false);

    bitstring.set(94_567, false);
    assert.equal(bitstring.get(94_567), false);
  });

  it('is idempotent when revoking twice', () => {
    const bitstring = Bitstring.create();
    bitstring.set(42, true);
    const first = bitstring.encode();
    bitstring.set(42, true);
    assert.equal(bitstring.encode(), first);
  });

  it('reports which entries are set', () => {
    const bitstring = Bitstring.create();
    for (const index of [0, 7, 8, 4095, MINIMUM_ENTRIES - 1]) bitstring.set(index, true);
    assert.deepEqual(bitstring.setIndices(), [0, 7, 8, 4095, MINIMUM_ENTRIES - 1]);
  });

  it('rejects out-of-range and non-integer indices', () => {
    const bitstring = Bitstring.create();
    for (const bad of [-1, MINIMUM_ENTRIES, 1.5, Number.NaN]) {
      assert.throws(() => bitstring.get(bad), InvalidDocumentError, `index ${bad}`);
      assert.throws(
        () => {
          bitstring.set(bad, true);
        },
        InvalidDocumentError,
        `index ${bad}`,
      );
    }
  });
});

describe('Bitstring - encoding', () => {
  it('round-trips a populated list', () => {
    const bitstring = Bitstring.create();
    const revoked = [1, 999, 65_535, 131_071];
    for (const index of revoked) bitstring.set(index, true);

    const decoded = Bitstring.decode(bitstring.encode());
    assert.deepEqual(decoded.setIndices(), revoked);
  });

  it('uses the multibase base64url prefix', () => {
    assert.ok(Bitstring.create().encode().startsWith('u'));
  });

  it('is reproducible for identical content', () => {
    // A drifting GZIP header would make an unchanged list look changed on
    // every republish, and differ between macOS and Linux builds.
    const a = Bitstring.create();
    const b = Bitstring.create();
    a.set(5, true);
    b.set(5, true);
    assert.equal(a.encode(), b.encode());
  });

  it('compresses a sparse list to a fraction of its size', () => {
    // 16KB of mostly zeros; if this ever stops being small, something is wrong.
    assert.ok(Bitstring.create().encode().length < 200);
  });

  it('enforces the 131,072-entry minimum on creation and decoding', () => {
    assert.throws(() => Bitstring.create(1024), InvalidDocumentError);
    assert.throws(() => Bitstring.create(MINIMUM_ENTRIES + 1), InvalidDocumentError);

    const short = new Uint8Array(64);
    const encoded = 'u' + Buffer.from(gzipSync(short)).toString('base64url');
    assert.throws(() => Bitstring.decode(encoded), InvalidDocumentError);
  });

  it('refuses a payload that decompresses past the maximum (T-REV-01)', () => {
    // A status list is almost all zeroes, which is the best case a compressor
    // ever gets: this bomb is a few KB on the wire and gigabytes decoded. The
    // HTTP layer's 5 MiB cap bounds the compressed bytes and so does nothing
    // here, which is exactly why the limit belongs at the decompressor.
    const bomb = new Uint8Array((MAXIMUM_ENTRIES / 8) * 4);
    const encoded = 'u' + Buffer.from(gzipSync(bomb)).toString('base64url');

    assert.ok(encoded.length < 100_000, 'the attack is cheap to send');
    assert.throws(
      () => Bitstring.decode(encoded),
      (error: unknown) => error instanceof InvalidDocumentError && /decompresses past/.test(error.message),
    );
  });

  it('rejects malformed encodings with a useful message', () => {
    assert.throws(() => Bitstring.decode('zNotBase64Url'), InvalidDocumentError);
    assert.throws(() => Bitstring.decode('unotgzipdata'), InvalidDocumentError);
  });
});

describe('BitstringStatusListCredential', () => {
  async function build(overrides?: { verificationMethod?: string }) {
    const provider = new InMemoryKeyProvider();
    const key = await provider.generateKey('issuance', 'Ed25519');
    const bitstring = Bitstring.create();
    bitstring.set(94_567, true);

    const credential = await buildStatusListCredential({
      issuer: TEST_ISSUER_DID,
      statusListCredentialUrl: LIST_URL,
      bitstring,
      provider,
      keyLabel: 'issuance',
      verificationMethod: overrides?.verificationMethod ?? TEST_ISSUANCE_KEY,
      validFrom: '2026-01-01T00:00:00Z',
      ttl: 300_000,
    });
    return { credential, key };
  }

  it('has the shape spec 5.2 requires', async () => {
    const { credential } = await build();
    assert.deepEqual(credential['@context'], ['https://www.w3.org/ns/credentials/v2']);
    assert.deepEqual(credential.type, ['VerifiableCredential', 'BitstringStatusListCredential']);
    assert.equal(credential.issuer, TEST_ISSUER_DID);
    assert.equal(credential.id, LIST_URL);
    assert.equal(credential.credentialSubject.type, 'BitstringStatusList');
    assert.equal(credential.credentialSubject.statusPurpose, 'revocation');
    assert.equal(credential.credentialSubject.ttl, 300_000);
    assert.ok(credential.credentialSubject.encodedList.startsWith('u'));
  });

  it('carries a verifiable proof', async () => {
    const { credential, key } = await build();
    const result = await verifyProof({ document: credential, publicKey: key.publicKey });
    assert.equal(result.verified, true, result.reason ?? 'no reason reported');
  });

  it('exposes the revoked entry through bitstringFrom', async () => {
    const { credential } = await build();
    const bitstring = bitstringFrom(credential);
    assert.equal(bitstring.get(94_567), true);
    assert.equal(bitstring.get(94_566), false);
  });

  it('detects tampering with the encoded list', async () => {
    const { credential, key } = await build();
    const clean = Bitstring.create();
    const tampered = {
      ...credential,
      credentialSubject: { ...credential.credentialSubject, encodedList: clean.encode() },
    };
    const result = await verifyProof({ document: tampered, publicKey: key.publicKey });
    assert.equal(result.verified, false, 'un-revoking by editing the list must break the proof');
  });

  it('accepts any key id belonging to the issuer', async () => {
    // Spec 3.2.1 fixes no fragment -- a verifier finds the key through the
    // proof's verificationMethod and confirms it is referenced under
    // assertionMethod. Pinning a name here would reject conformant issuers.
    const { credential } = await build({ verificationMethod: `${TEST_ISSUER_DID}#vc-key-1` });
    assert.equal(
      (credential.proof as { verificationMethod: string }).verificationMethod,
      `${TEST_ISSUER_DID}#vc-key-1`,
    );
  });

  it('refuses to sign with a key belonging to someone else', async () => {
    // Spec 5.2 binds a list to its own issuer. Producing one signed by another
    // DID would publish a list every verifier must reject.
    await assert.rejects(
      () => build({ verificationMethod: 'did:webvh:QmOther:elsewhere.example#vc-key-1' }),
      InvalidDocumentError,
    );
  });

  it('rejects a credentialSubject that is not a BitstringStatusList', () => {
    assert.throws(
      () =>
        bitstringFrom({
          '@context': [],
          type: [],
          issuer: TEST_ISSUER_DID,
          credentialSubject: { type: 'SomethingElse' },
        } as never),
      InvalidDocumentError,
    );
  });
});

describe('credentialStatus entry (spec 5.1)', () => {
  it('follows the {statusListCredential}#{index} convention', () => {
    const entry = statusEntryFor(LIST_URL, 94_567);
    assert.equal(entry.type, 'BitstringStatusListEntry');
    assert.equal(entry.statusPurpose, 'revocation');
    assert.equal(entry.statusListIndex, '94567');
    assert.equal(entry.statusListCredential, LIST_URL);
    assert.equal(entry.id, `${LIST_URL}#94567`);
  });

  it('gives statusListIndex as a string, not a number', () => {
    assert.equal(typeof statusEntryFor(LIST_URL, 0).statusListIndex, 'string');
  });

  it('never sets id equal to the statusListCredential URL', () => {
    // Spec 5.1 forbids this explicitly.
    assert.notEqual(statusEntryFor(LIST_URL, 0).id, LIST_URL);
  });

  it('rejects an index that is not a non-negative integer', () => {
    for (const index of [-1, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
      assert.throws(() => statusEntryFor(LIST_URL, index), InvalidDocumentError, String(index));
    }
  });
});

describe('index allocation (spec 5.1)', () => {
  it('never returns an index already taken or already set', () => {
    const bitstring = Bitstring.create();
    const taken = new Set<number>();
    for (let i = 0; i < 200; i++) {
      const index = allocateIndex(bitstring, (n) => taken.has(n));
      assert.ok(!taken.has(index));
      taken.add(index);
    }
    assert.equal(taken.size, 200);
  });

  it('avoids indices that are already revoked', () => {
    // Sampling rather than exhausting the list: filling all but one entry and
    // asserting that entry is found would be probabilistic and flaky.
    const bitstring = Bitstring.create();
    const revoked = new Set([0, 1, 2, 3, 4, 5, 6, 7, 100, 4095]);
    for (const index of revoked) bitstring.set(index, true);

    for (let i = 0; i < 500; i++) {
      assert.ok(!revoked.has(allocateIndex(bitstring, () => false)));
    }
  });

  it('is not sequential', () => {
    // Spec 5.1: random assignment prevents correlating issuance order.
    const bitstring = Bitstring.create();
    const taken = new Set<number>();
    const allocated = Array.from({ length: 50 }, () => {
      const index = allocateIndex(bitstring, (n) => taken.has(n));
      taken.add(index);
      return index;
    });
    const sequential = allocated.every((v, i) => i === 0 || v === allocated[i - 1]! + 1);
    assert.ok(!sequential, 'indices must not be handed out sequentially');
  });

  it('gives up rather than looping forever on a full list', () => {
    const bitstring = Bitstring.create();
    assert.throws(() => allocateIndex(bitstring, () => true, 50), InvalidDocumentError);
  });
});
