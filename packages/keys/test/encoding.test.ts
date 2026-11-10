import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { describe, it } from 'node:test';
import {
  base58btcDecode,
  base58btcEncode,
  bytesEqual,
  compressP256,
  decompressP256,
  fromMultibaseBase64url,
  fromPublicKeyMultibase,
  toMultibaseBase64url,
  toPublicKeyMultibase,
} from '../src/encoding.ts';
import { InvalidKeyError } from '../src/errors.ts';
import { generateKeyObject, publicKeyFrom } from '../src/nodecrypto.ts';
import type { Curve, PublicKey } from '../src/types.ts';

/**
 * A freshly generated public key for `curve`. These cases only need real
 * key bytes to encode, so they go straight to the Node primitives rather
 * than through a KeyProvider, which keeps the encoding layer under test on
 * its own.
 */
const publicKeyOf = (curve: Curve): PublicKey => publicKeyFrom(generateKeyObject(curve).publicKey, curve);

describe('base58btc', () => {
  // Vectors from the base58 specification / BIP-0173 test corpus.
  const vectors: [string, string][] = [
    ['', ''],
    ['61', '2g'],
    ['626262', 'a3gV'],
    ['636363', 'aPEr'],
    ['00000000000000000000', '1111111111'],
    ['516b6fcd0f', 'ABnLTmg'],
    ['bf4f89001e670274dd', '3SEo3LWLoPntC'],
  ];

  for (const [hex, expected] of vectors) {
    it(`encodes ${hex === '' ? '(empty)' : hex}`, () => {
      assert.equal(base58btcEncode(Uint8Array.from(Buffer.from(hex, 'hex'))), expected);
    });
    it(`round-trips ${hex === '' ? '(empty)' : hex}`, () => {
      assert.equal(Buffer.from(base58btcDecode(expected)).toString('hex'), hex);
    });
  }

  it('round-trips arbitrary byte strings', () => {
    // Broader than the fixed vectors above: exercises every length boundary
    // and carry path rather than the handful of published known answers.
    for (let length = 0; length <= 68; length++) {
      for (let trial = 0; trial < 8; trial++) {
        const bytes = randomBytes(length);
        assert.ok(
          bytesEqual(base58btcDecode(base58btcEncode(bytes)), bytes),
          `failed to round-trip ${length} bytes`,
        );
      }
    }
  });

  it('preserves leading zero bytes as leading "1"s', () => {
    const bytes = Uint8Array.from([0, 0, 0, 1, 2, 3]);
    assert.ok(base58btcEncode(bytes).startsWith('111'));
    assert.ok(bytesEqual(base58btcDecode(base58btcEncode(bytes)), bytes));
  });

  it('rejects characters outside the alphabet', () => {
    assert.throws(() => base58btcDecode('abc0def'), InvalidKeyError);
    assert.throws(() => base58btcDecode('abcOdef'), InvalidKeyError);
    assert.throws(() => base58btcDecode('abcIdef'), InvalidKeyError);
    assert.throws(() => base58btcDecode('abcldef'), InvalidKeyError);
  });
});

describe('multibase base64url', () => {
  it('round-trips with the "u" prefix', () => {
    const bytes = Uint8Array.from([0xde, 0xad, 0xbe, 0xef, 0x00, 0x7f]);
    const encoded = toMultibaseBase64url(bytes);
    assert.ok(encoded.startsWith('u'));
    assert.ok(bytesEqual(fromMultibaseBase64url(encoded), bytes));
  });

  it('rejects a missing or wrong prefix', () => {
    assert.throws(() => fromMultibaseBase64url('zabc'), InvalidKeyError);
  });
});

describe('P-256 point compression', () => {
  it('round-trips uncompressed -> compressed -> uncompressed', () => {
    const publicKey = publicKeyOf('P-256');
    const compressed = compressP256(publicKey.bytes);

    assert.equal(compressed.length, 33);
    assert.ok(compressed[0] === 0x02 || compressed[0] === 0x03);
    assert.ok(bytesEqual(decompressP256(compressed), publicKey.bytes));
  });

  it('rejects malformed input', () => {
    assert.throws(() => compressP256(Uint8Array.from([0x04, 0x01])), InvalidKeyError);
    assert.throws(() => decompressP256(new Uint8Array(33).fill(0x09)), InvalidKeyError);
  });
});

describe('publicKeyMultibase', () => {
  it('uses the documented multicodec prefix per curve', () => {
    // Ed25519 -> 0xed01 -> "z6Mk…"; X25519 -> 0xec01 -> "z6LS…"; P-256 -> 0x8024 -> "zDn…"
    const expectedPrefix: Record<string, string> = {
      Ed25519: 'z6Mk',
      X25519: 'z6LS',
      'P-256': 'zDn',
    };
    for (const curve of ['Ed25519', 'X25519', 'P-256'] as const) {
      const multibase = toPublicKeyMultibase(publicKeyOf(curve));
      assert.ok(
        multibase.startsWith(expectedPrefix[curve]!),
        `${curve} multikey should start with ${expectedPrefix[curve]}, got ${multibase.slice(0, 6)}`,
      );
    }
  });

  it('round-trips every curve back to canonical raw bytes', () => {
    for (const curve of ['Ed25519', 'X25519', 'P-256'] as const) {
      const publicKey = publicKeyOf(curve);
      const decoded = fromPublicKeyMultibase(toPublicKeyMultibase(publicKey));
      assert.equal(decoded.curve, curve);
      assert.ok(bytesEqual(decoded.bytes, publicKey.bytes));
    }
  });

  it('rejects an unrecognized multicodec prefix', () => {
    assert.throws(() => fromPublicKeyMultibase('z2DEADBEEF'), InvalidKeyError);
  });
});
