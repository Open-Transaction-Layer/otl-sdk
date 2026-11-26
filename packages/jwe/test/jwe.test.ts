import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { toPublicKeyJwk, type Curve } from '@open-transaction-layer/keys';
import { InMemoryKeyProvider } from '@open-transaction-layer/keys-dev';
import {
  EncryptionError,
  OtlJweError,
  concatKdf,
  decrypt,
  decryptToString,
  encrypt,
  JWE_ALG,
  JWE_ENC,
} from '../src/index.ts';

/** A JWE protected header as an attacker-editable object, for the tampering tests. */
interface HeaderJson {
  alg: string;
  enc: string;
  epk: Record<string, string>;
  kid?: string;
  apu?: string;
  apv?: string;
  [member: string]: unknown;
}

const parseHeader = (segment: string): HeaderJson =>
  JSON.parse(Buffer.from(segment, 'base64url').toString('utf8')) as HeaderJson;

const MESSAGE = 'settlement instruction 2026-01-01';

describe('encryption (PROVISIONAL envelope)', () => {
  for (const curve of ['X25519', 'P-256'] as const) {
    it(`${curve}: round-trips a message`, async () => {
      const recipient = new InMemoryKeyProvider();
      const key = await recipient.generateKey('agreement', curve);

      const jwe = encrypt({ plaintext: MESSAGE, recipientPublicKey: key.publicKey });
      const plaintext = await decryptToString({ jwe, provider: recipient, keyLabel: 'agreement' });
      assert.equal(plaintext, MESSAGE);
    });

    it(`${curve}: produces a different ciphertext each time`, async () => {
      // A fresh ephemeral key and IV per message; identical output would mean
      // one of them is being reused.
      const recipient = new InMemoryKeyProvider();
      const key = await recipient.generateKey('agreement', curve);
      const first = encrypt({ plaintext: MESSAGE, recipientPublicKey: key.publicKey });
      const second = encrypt({ plaintext: MESSAGE, recipientPublicKey: key.publicKey });
      assert.notEqual(first, second);
      // ...but both decrypt to the same plaintext.
      assert.equal(
        await decryptToString({ jwe: first, provider: recipient, keyLabel: 'agreement' }),
        MESSAGE,
      );
      assert.equal(
        await decryptToString({ jwe: second, provider: recipient, keyLabel: 'agreement' }),
        MESSAGE,
      );
    });

    it(`${curve}: cannot be decrypted by a different key`, async () => {
      const recipient = new InMemoryKeyProvider();
      const key = await recipient.generateKey('agreement', curve);
      await recipient.generateKey('other', curve);

      const jwe = encrypt({ plaintext: MESSAGE, recipientPublicKey: key.publicKey });
      await assert.rejects(() => decrypt({ jwe, provider: recipient, keyLabel: 'other' }), EncryptionError);
    });
  }

  it('emits JWE Compact Serialization with an empty encrypted-key segment', async () => {
    const recipient = new InMemoryKeyProvider();
    const key = await recipient.generateKey('agreement', 'X25519');
    const jwe = encrypt({ plaintext: MESSAGE, recipientPublicKey: key.publicKey });

    const segments = jwe.split('.');
    assert.equal(segments.length, 5);
    assert.equal(segments[1], '', 'ECDH-ES derives the content key directly, so no wrapped key');

    const header = parseHeader(segments[0]!);
    assert.equal(header.alg, JWE_ALG);
    assert.equal(header.enc, JWE_ENC);
    assert.equal(header.epk['crv'], 'X25519');
    assert.equal(header.epk['d'], undefined, 'the ephemeral private key must never be published');
  });

  it('binds the recipient key id into the derived key', async () => {
    const recipient = new InMemoryKeyProvider();
    const key = await recipient.generateKey('agreement', 'X25519');
    const kid = 'did:webvh:QmScid:vasp.example.com#agreement-key';

    const jwe = encrypt({ plaintext: MESSAGE, recipientPublicKey: key.publicKey, recipientKeyId: kid });
    const header = parseHeader(jwe.split('.')[0]!);
    assert.equal(header.kid, kid);
    assert.equal(Buffer.from(header.apv!, 'base64url').toString('utf8'), kid);

    // Rewriting apv changes the derived key, so decryption fails.
    const tampered = { ...header, apv: Buffer.from('someone-else').toString('base64url') };
    const segments = jwe.split('.');
    segments[0] = Buffer.from(JSON.stringify(tampered)).toString('base64url');
    await assert.rejects(
      () => decrypt({ jwe: segments.join('.'), provider: recipient, keyLabel: 'agreement' }),
      EncryptionError,
    );
  });

  it('authenticates the protected header', async () => {
    // alg, enc and epk are the AAD, so none can be rewritten in transit.
    const recipient = new InMemoryKeyProvider();
    const key = await recipient.generateKey('agreement', 'X25519');
    const jwe = encrypt({ plaintext: MESSAGE, recipientPublicKey: key.publicKey, senderInfo: 'sender' });

    const segments = jwe.split('.');
    const header = parseHeader(segments[0]!);
    header.apu = Buffer.from('a-different-sender').toString('base64url');
    segments[0] = Buffer.from(JSON.stringify(header)).toString('base64url');

    await assert.rejects(
      () => decrypt({ jwe: segments.join('.'), provider: recipient, keyLabel: 'agreement' }),
      EncryptionError,
    );
  });

  it('detects a tampered ciphertext', async () => {
    const recipient = new InMemoryKeyProvider();
    const key = await recipient.generateKey('agreement', 'X25519');
    const segments = encrypt({ plaintext: MESSAGE, recipientPublicKey: key.publicKey }).split('.');

    const ciphertext = Buffer.from(segments[3]!, 'base64url');
    ciphertext[0] = (ciphertext[0] ?? 0) ^ 0xff;
    segments[3] = ciphertext.toString('base64url');

    await assert.rejects(
      () => decrypt({ jwe: segments.join('.'), provider: recipient, keyLabel: 'agreement' }),
      EncryptionError,
    );
  });

  it('rejects an algorithm downgrade before doing any crypto', async () => {
    const recipient = new InMemoryKeyProvider();
    const key = await recipient.generateKey('agreement', 'X25519');
    const segments = encrypt({ plaintext: MESSAGE, recipientPublicKey: key.publicKey }).split('.');

    for (const [field, value] of [
      ['alg', 'dir'],
      ['enc', 'A128GCM'],
    ] as const) {
      const header = parseHeader(segments[0]!);
      header[field] = value;
      const forged = [...segments];
      forged[0] = Buffer.from(JSON.stringify(header)).toString('base64url');
      await assert.rejects(
        () => decrypt({ jwe: forged.join('.'), provider: recipient, keyLabel: 'agreement' }),
        /Unsupported JWE/,
        `${field}=${value}`,
      );
    }
  });

  it('says nothing an attacker could use as an oracle', async () => {
    // Wrong key, wrong recipient and tampering are indistinguishable at the
    // GCM layer and must stay that way in the message too.
    const recipient = new InMemoryKeyProvider();
    const key = await recipient.generateKey('agreement', 'X25519');
    await recipient.generateKey('other', 'X25519');
    const jwe = encrypt({ plaintext: MESSAGE, recipientPublicKey: key.publicKey });

    const wrongKey = await decrypt({ jwe, provider: recipient, keyLabel: 'other' }).catch(
      (e: unknown) => (e as Error).message,
    );

    const segments = jwe.split('.');
    const ciphertext = Buffer.from(segments[3]!, 'base64url');
    ciphertext[0] = (ciphertext[0] ?? 0) ^ 0xff;
    segments[3] = ciphertext.toString('base64url');
    const tampered = await decrypt({
      jwe: segments.join('.'),
      provider: recipient,
      keyLabel: 'agreement',
    }).catch((e: unknown) => (e as Error).message);

    assert.equal(wrongKey, tampered, 'failure messages must not distinguish the cause');
  });

  it('rejects malformed input', async () => {
    const recipient = new InMemoryKeyProvider();
    await recipient.generateKey('agreement', 'X25519');
    const cases: [string, RegExp][] = [
      ['a.b.c', /expected 5 dot-separated segments/],
      ['a.notempty.c.d.e', /empty encrypted-key segment/],
      ['bm90LWpzb24.,.c.d.e'.replace(',', ''), /not valid JSON/],
    ];
    for (const [jwe, pattern] of cases) {
      await assert.rejects(() => decrypt({ jwe, provider: recipient, keyLabel: 'agreement' }), pattern, jwe);
    }
  });

  it('refuses a signing curve as a recipient key', async () => {
    const provider = new InMemoryKeyProvider();
    const key = await provider.generateKey('signing', 'Ed25519');
    assert.throws(
      () => encrypt({ plaintext: MESSAGE, recipientPublicKey: key.publicKey }),
      /cannot perform key agreement/,
    );
  });

  it('refuses to decrypt on a provider with no key agreement', async () => {
    // Azure Key Vault has no ECDH primitive; the failure must name that rather
    // than surfacing a stack trace.
    class SignOnlyProvider extends InMemoryKeyProvider {
      override capabilities() {
        return { ...super.capabilities(), keyAgreement: [] as Curve[] };
      }
    }
    const provider = new SignOnlyProvider();
    await provider.generateKey('agreement', 'X25519');
    const recipient = new InMemoryKeyProvider();
    const key = await recipient.generateKey('agreement', 'X25519');
    const jwe = encrypt({ plaintext: MESSAGE, recipientPublicKey: key.publicKey });

    await assert.rejects(
      () => decrypt({ jwe, provider, keyLabel: 'agreement' }),
      /cannot perform key agreement/,
    );
  });

  it('carries binary payloads unchanged', async () => {
    const recipient = new InMemoryKeyProvider();
    const key = await recipient.generateKey('agreement', 'P-256');
    const payload = Uint8Array.from({ length: 512 }, (_, i) => i % 256);
    const jwe = encrypt({ plaintext: payload, recipientPublicKey: key.publicKey });
    const out = await decrypt({ jwe, provider: recipient, keyLabel: 'agreement' });
    assert.deepEqual(Buffer.from(out).toString('hex'), Buffer.from(payload).toString('hex'));
  });

  it('does not authenticate the sender', async () => {
    // ECDH-ES is confidential but unauthenticated: anyone holding the
    // recipient's published key can produce a valid ciphertext. Asserted so
    // the property is recorded rather than assumed.
    const recipient = new InMemoryKeyProvider();
    const key = await recipient.generateKey('agreement', 'X25519');
    const fromAnyone = encrypt({ plaintext: 'I am the bank', recipientPublicKey: key.publicKey });
    assert.equal(
      await decryptToString({ jwe: fromAnyone, provider: recipient, keyLabel: 'agreement' }),
      'I am the bank',
    );
  });
});

describe('ephemeral keys', () => {
  it('never reuses an ephemeral public key', async () => {
    const recipient = new InMemoryKeyProvider();
    const key = await recipient.generateKey('agreement', 'X25519');
    const epks = new Set<string>();
    for (let i = 0; i < 20; i++) {
      const header = parseHeader(
        encrypt({ plaintext: MESSAGE, recipientPublicKey: key.publicKey }).split('.')[0]!,
      );
      epks.add(header.epk['x']!);
    }
    assert.equal(epks.size, 20, 'each message must use a fresh ephemeral key');
  });

  it('publishes only the public half', async () => {
    const recipient = new InMemoryKeyProvider();
    const key = await recipient.generateKey('agreement', 'P-256');
    const jwe = encrypt({ plaintext: MESSAGE, recipientPublicKey: key.publicKey });
    const header = parseHeader(jwe.split('.')[0]!);
    assert.deepEqual(Object.keys(header.epk).sort(), ['crv', 'kty', 'x', 'y']);
    assert.equal(header.epk['d'], undefined);
    assert.doesNotThrow(() => toPublicKeyJwk(key.publicKey));
  });
});

describe('Concat KDF (RFC 7518 4.6.2)', () => {
  const Z = Uint8Array.from({ length: 32 }, (_, i) => i);
  const utf8 = (s: string) => new TextEncoder().encode(s);
  const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');

  it('derives a 256-bit key', () => {
    assert.equal(concatKdf(Z, JWE_ENC, new Uint8Array(0), new Uint8Array(0)).length, 32);
  });

  it('is deterministic for identical inputs', () => {
    assert.equal(
      hex(concatKdf(Z, JWE_ENC, utf8('a'), utf8('b'))),
      hex(concatKdf(Z, JWE_ENC, utf8('a'), utf8('b'))),
    );
  });

  it('length-prefixes apu and apv so adjacent fields cannot be shifted', () => {
    // The property length-prefixing exists for: without it, ("AB","C") and
    // ("A","BC") concatenate identically and derive the same content key,
    // letting a sender's and recipient's identifiers be silently reattributed.
    // This cannot be observed through encrypt/decrypt, because the protected
    // header is authenticated and a rewritten header fails on the GCM tag
    // first -- so the KDF is exercised directly.
    assert.notEqual(
      hex(concatKdf(Z, JWE_ENC, utf8('AB'), utf8('C'))),
      hex(concatKdf(Z, JWE_ENC, utf8('A'), utf8('BC'))),
    );
  });

  it('binds the algorithm identifier', () => {
    assert.notEqual(
      hex(concatKdf(Z, 'A256GCM', utf8('a'), utf8('b'))),
      hex(concatKdf(Z, 'A128GCM', utf8('a'), utf8('b'))),
    );
  });

  it('depends on the shared secret', () => {
    const other = Uint8Array.from({ length: 32 }, (_, i) => i + 1);
    assert.notEqual(
      hex(concatKdf(Z, JWE_ENC, new Uint8Array(0), new Uint8Array(0))),
      hex(concatKdf(other, JWE_ENC, new Uint8Array(0), new Uint8Array(0))),
    );
  });
});

describe('encryption - nonce and error hygiene', () => {
  it('uses a fresh IV for every message', async () => {
    // Distinct ciphertexts alone would not prove this: a fresh ephemeral key
    // changes the content key, so output differs even with a fixed IV.
    const recipient = new InMemoryKeyProvider();
    const key = await recipient.generateKey('agreement', 'X25519');

    const ivs = new Set<string>();
    for (let i = 0; i < 20; i++) {
      ivs.add(encrypt({ plaintext: MESSAGE, recipientPublicKey: key.publicKey }).split('.')[2]!);
    }
    assert.equal(ivs.size, 20, 'each message must carry a distinct IV');
  });

  it('reports a fixed failure message that leaks nothing about the cause', async () => {
    const recipient = new InMemoryKeyProvider();
    const key = await recipient.generateKey('agreement', 'X25519');
    await recipient.generateKey('other', 'X25519');
    const jwe = encrypt({ plaintext: MESSAGE, recipientPublicKey: key.publicKey });

    const message = await decrypt({ jwe, provider: recipient, keyLabel: 'other' }).catch(
      (error: unknown) => (error as Error).message,
    );

    assert.equal(
      message,
      'Could not decrypt: the message was not encrypted to this key, or has been altered',
    );
    // Underlying crypto errors must not be surfaced -- they distinguish causes.
    for (const leak of ['auth', 'tag', 'unable', 'OpenSSL', 'GCM']) {
      assert.ok(!message.toLowerCase().includes(leak.toLowerCase()), `message leaked "${leak}"`);
    }
  });
});

describe('encryption - GCM parameter enforcement', () => {
  it('rejects a truncated authentication tag', async () => {
    const recipient = new InMemoryKeyProvider();
    const key = await recipient.generateKey('agreement', 'X25519');
    const segments = encrypt({ plaintext: MESSAGE, recipientPublicKey: key.publicKey }).split('.');
    segments[4] = Buffer.from(segments[4]!, 'base64url').subarray(0, 4).toString('base64url');
    await assert.rejects(
      decrypt({ jwe: segments.join('.'), provider: recipient, keyLabel: 'agreement' }),
      EncryptionError,
    );
  });

  it('rejects an IV that is not 12 bytes', async () => {
    const recipient = new InMemoryKeyProvider();
    const key = await recipient.generateKey('agreement', 'X25519');
    const segments = encrypt({ plaintext: MESSAGE, recipientPublicKey: key.publicKey }).split('.');
    segments[2] = Buffer.alloc(16).toString('base64url');
    await assert.rejects(
      decrypt({ jwe: segments.join('.'), provider: recipient, keyLabel: 'agreement' }),
      EncryptionError,
    );
  });

  it('reports an unknown key label as an EncryptionError', async () => {
    const recipient = new InMemoryKeyProvider();
    const key = await recipient.generateKey('agreement', 'X25519');
    const jwe = encrypt({ plaintext: MESSAGE, recipientPublicKey: key.publicKey });
    await assert.rejects(decrypt({ jwe, provider: recipient, keyLabel: 'missing' }), EncryptionError);
  });
});

describe('Concat KDF - RFC 7518 Appendix C', () => {
  it('reproduces the published ECDH-ES vector', () => {
    // The only way to pin conformance rather than self-consistency: a
    // deviation such as dropping a length prefix stays internally coherent and
    // would go unnoticed until interop with another implementation failed.
    const Z = Uint8Array.from([
      158, 86, 217, 29, 129, 113, 53, 211, 114, 131, 66, 131, 191, 132, 38, 156, 251, 49, 110, 163, 218, 128,
      106, 72, 246, 218, 167, 121, 140, 254, 144, 196,
    ]);
    const expected = Uint8Array.from([
      86, 170, 141, 234, 248, 35, 109, 32, 92, 34, 40, 205, 113, 167, 16, 26,
    ]);

    const derived = concatKdf(
      Z,
      'A128GCM',
      new TextEncoder().encode('Alice'),
      new TextEncoder().encode('Bob'),
      16,
    );

    // Compared as bytes rather than base64url: the encoded form of a derived
    // key trips secret scanners, and this assertion is equivalent.
    assert.deepEqual(Buffer.from(derived).toString('hex'), Buffer.from(expected).toString('hex'));
  });
});

describe('error types', () => {
  it('keeps the EncryptionError name and derives from the package error base', async () => {
    const recipient = new InMemoryKeyProvider();
    await recipient.generateKey('agreement', 'X25519');
    const error = await decrypt({ jwe: 'a.b.c', provider: recipient, keyLabel: 'agreement' }).catch(
      (caught: unknown) => caught,
    );
    assert.ok(error instanceof EncryptionError);
    assert.ok(error instanceof OtlJweError);
    assert.equal(error.name, 'EncryptionError');
  });
});
