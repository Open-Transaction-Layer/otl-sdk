/**
 * Behaviour specific to the file provider: at-rest encryption, permissions,
 * and the guarantee that nothing sensitive leaks into the stored file.
 */

import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { InvalidKeyError } from '@open-transaction-layer/keys';
import { verifyWith } from '@open-transaction-layer/keys/node';
import { FileKeyProvider } from '../src/file.ts';

const PASSPHRASE = 'correct horse battery staple';
const freshDir = () => mkdtempSync(join(tmpdir(), 'otl-keys-file-'));
const freshProvider = (directory = freshDir()) => new FileKeyProvider({ directory, passphrase: PASSPHRASE });

describe('FileKeyProvider', () => {
  it('refuses to construct without a passphrase', () => {
    assert.throws(() => new FileKeyProvider({ directory: freshDir(), passphrase: '' }), InvalidKeyError);
  });

  it('persists keys across provider instances', async () => {
    const directory = freshDir();
    const first = freshProvider(directory);
    const generated = await first.generateKey('persisted', 'Ed25519');

    const second = freshProvider(directory);
    const loaded = await second.getKey('persisted');

    assert.equal(loaded.curve, generated.curve);
    assert.deepEqual(
      Buffer.from(loaded.publicKey.bytes).toString('hex'),
      Buffer.from(generated.publicKey.bytes).toString('hex'),
    );

    // And the reloaded key still signs correctly.
    const signature = await second.sign('persisted', new TextEncoder().encode('hello'));
    assert.ok(verifyWith(loaded.publicKey, new TextEncoder().encode('hello'), signature));
  });

  it('writes key files 0600 and the directory 0700', async () => {
    const directory = freshDir();
    const provider = freshProvider(directory);
    await provider.generateKey('perms', 'Ed25519');

    assert.equal(statSync(join(directory, 'perms.json')).mode & 0o777, 0o600);
    assert.equal(statSync(directory).mode & 0o777, 0o700);
  });

  it('stores no private key material in the clear', async () => {
    const directory = freshDir();
    const provider = freshProvider(directory);
    await provider.generateKey('secret', 'Ed25519');
    const exported = await provider.exportPrivateKey('secret');

    const raw = readFileSync(join(directory, 'secret.json'), 'utf8');
    const parsed = JSON.parse(raw) as Record<string, unknown>;

    assert.ok(!raw.includes(Buffer.from(exported).toString('base64')));
    assert.ok(!raw.includes(Buffer.from(exported).toString('hex')));
    assert.ok(parsed['privateKey'] !== null && typeof parsed['privateKey'] === 'object');
    const wrapped = parsed['privateKey'] as Record<string, unknown>;
    assert.equal(wrapped['kdf'], 'pbkdf2-sha256');
    assert.equal(wrapped['cipher'], 'aes-256-gcm');
    assert.ok((wrapped['iterations'] as number) >= 600_000);
  });

  it('uses a fresh salt and nonce for every key', async () => {
    const directory = freshDir();
    const provider = freshProvider(directory);
    await provider.generateKey('one', 'Ed25519');
    await provider.generateKey('two', 'Ed25519');

    const read = (label: string) =>
      (
        JSON.parse(readFileSync(join(directory, `${label}.json`), 'utf8')) as {
          privateKey: { salt: string; nonce: string };
        }
      ).privateKey;

    assert.notEqual(read('one').salt, read('two').salt);
    assert.notEqual(read('one').nonce, read('two').nonce);
  });

  it('rejects the wrong passphrase rather than returning garbage', async () => {
    const directory = freshDir();
    await freshProvider(directory).generateKey('locked', 'Ed25519');

    const wrong = new FileKeyProvider({ directory, passphrase: 'not the passphrase' });
    // getKey checks the public key against the private key, so it needs the
    // passphrase too.
    await assert.rejects(() => wrong.getKey('locked'), InvalidKeyError);
    await assert.rejects(() => wrong.sign('locked', new TextEncoder().encode('x')), InvalidKeyError);
  });

  it('refuses a key file whose recorded public key was swapped', async () => {
    // Someone who can write to the directory must not be able to make getKey
    // report a key of their choosing, which would then be published or
    // committed to while signing still used the real key.
    const directory = freshDir();
    const provider = freshProvider(directory);
    await provider.generateKey('victim', 'Ed25519');
    await provider.generateKey('other', 'Ed25519');
    const otherFile = JSON.parse(readFileSync(join(directory, 'other.json'), 'utf8')) as {
      publicKeyMultibase: string;
    };

    const path = join(directory, 'victim.json');
    const file = JSON.parse(readFileSync(path, 'utf8')) as { publicKeyMultibase: string };
    file.publicKeyMultibase = otherFile.publicKeyMultibase;
    writeFileSync(path, JSON.stringify(file));

    await assert.rejects(() => freshProvider(directory).getKey('victim'), /does not match its private key/);
    await assert.rejects(() => freshProvider(directory).listKeys(), InvalidKeyError);
  });

  it('refuses a key file copied under another label', async () => {
    const directory = freshDir();
    await freshProvider(directory).generateKey('original', 'Ed25519');
    writeFileSync(join(directory, 'copy.json'), readFileSync(join(directory, 'original.json')));
    await assert.rejects(() => freshProvider(directory).getKey('copy'), /is labelled "original"/);
  });

  it('detects tampering with the stored ciphertext', async () => {
    const directory = freshDir();
    const provider = freshProvider(directory);
    await provider.generateKey('tampered', 'Ed25519');

    const path = join(directory, 'tampered.json');
    const file = JSON.parse(readFileSync(path, 'utf8')) as { privateKey: { ciphertext: string } };
    const bytes = Buffer.from(file.privateKey.ciphertext, 'base64');
    bytes[0] = (bytes[0] ?? 0) ^ 0xff;
    file.privateKey.ciphertext = bytes.toString('base64');
    writeFileSync(path, JSON.stringify(file));

    await assert.rejects(
      () => freshProvider(directory).sign('tampered', new TextEncoder().encode('x')),
      InvalidKeyError,
      'AES-GCM authentication must reject a modified key file',
    );
  });

  it('rejects labels that would escape the key directory', async () => {
    const provider = freshProvider();
    for (const label of ['../escape', 'a/b', '..', '', '.hidden', 'x'.repeat(65)]) {
      await assert.rejects(() => provider.generateKey(label, 'Ed25519'), InvalidKeyError, `label: ${label}`);
    }
  });
});
