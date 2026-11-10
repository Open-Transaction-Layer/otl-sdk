/**
 * Behaviour specific to the file provider: at-rest encryption, permissions,
 * and the guarantee that nothing sensitive leaks into the stored file.
 */

import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { InvalidKeyError } from '@otl/keys';
import { verifyWith } from '@otl/keys/node';
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
    // Public metadata is readable — only the private key is protected.
    await wrong.getKey('locked');
    await assert.rejects(() => wrong.sign('locked', new TextEncoder().encode('x')), InvalidKeyError);
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
