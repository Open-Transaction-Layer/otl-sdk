import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { InMemoryKeyProvider } from '@open-transaction-layer/keys-dev';
import { SigningError, signRaw, verifyRaw } from '../src/signing.ts';

const MESSAGE = 'settlement instruction 2026-01-01';

describe('raw signing', () => {
  for (const curve of ['Ed25519', 'P-256'] as const) {
    it(`${curve}: round-trips a signature`, async () => {
      const provider = new InMemoryKeyProvider();
      const key = await provider.generateKey('signing', curve);

      const signature = await signRaw({ message: MESSAGE, provider, keyLabel: 'signing' });
      assert.ok(signature.startsWith('z'), 'signature must be multibase base58btc');
      assert.equal(verifyRaw({ message: MESSAGE, signature, publicKey: key.publicKey }), true);
    });

    it(`${curve}: rejects a different message`, async () => {
      const provider = new InMemoryKeyProvider();
      const key = await provider.generateKey('signing', curve);
      const signature = await signRaw({ message: MESSAGE, provider, keyLabel: 'signing' });
      assert.equal(verifyRaw({ message: 'something else', signature, publicKey: key.publicKey }), false);
    });

    it(`${curve}: rejects a different key`, async () => {
      const provider = new InMemoryKeyProvider();
      await provider.generateKey('signing', curve);
      const other = await provider.generateKey('other', curve);
      const signature = await signRaw({ message: MESSAGE, provider, keyLabel: 'signing' });
      assert.equal(verifyRaw({ message: MESSAGE, signature, publicKey: other.publicKey }), false);
    });
  }

  it('signs raw bytes as well as strings', async () => {
    const provider = new InMemoryKeyProvider();
    const key = await provider.generateKey('signing', 'Ed25519');
    const bytes = Uint8Array.from([0, 1, 2, 250, 255]);
    const signature = await signRaw({ message: bytes, provider, keyLabel: 'signing' });
    assert.equal(verifyRaw({ message: bytes, signature, publicKey: key.publicKey }), true);
  });

  it('distinguishes a malformed signature from a wrong one', async () => {
    // "not a signature" and "does not match" are different operator problems.
    const provider = new InMemoryKeyProvider();
    const key = await provider.generateKey('signing', 'Ed25519');
    assert.throws(
      () => verifyRaw({ message: MESSAGE, signature: 'not-multibase', publicKey: key.publicKey }),
      SigningError,
    );
  });

  it('refuses to sign with a key-agreement key', async () => {
    const provider = new InMemoryKeyProvider();
    await provider.generateKey('agreement', 'X25519');
    await assert.rejects(() => signRaw({ message: MESSAGE, provider, keyLabel: 'agreement' }), /cannot sign/);
  });
});
