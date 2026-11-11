/**
 * NON-PRODUCTION. Filesystem-backed key storage for local development.
 *
 * Private keys are held as PKCS#8 DER, encrypted with AES-256-GCM under a key
 * derived from an operator passphrase (PBKDF2-SHA256, 600,000 iterations, a
 * fresh 16-byte salt and a fresh 12-byte nonce per key). Files are written
 * 0600 and the containing directory 0700.
 *
 * This is still a private key on a disk. It is appropriate for development and
 * for exercising the protocol end to end; it is not a custody solution.
 * Production deployments MUST bridge {@link KeyProvider} to a KMS or HSM.
 */

import type { KeyObject } from 'node:crypto';
import { createCipheriv, createDecipheriv, pbkdf2Sync, randomBytes } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  InvalidKeyError,
  KeyAlreadyExistsError,
  KeyNotFoundError,
  UnsupportedOperationError,
} from '@otl/keys';
import { fromPublicKeyMultibase, toPublicKeyMultibase } from '@otl/keys';
import {
  deriveSharedSecretWith,
  exportPkcs8,
  generateKeyObject,
  importPkcs8,
  publicKeyFrom,
  signWith,
} from '@otl/keys/node';
import {
  KeyProvider,
  type DerivesSharedSecrets,
  type ExportsPrivateKeys,
  type GeneratesKeys,
} from '@otl/keys';
import {
  isKeyAgreementCurve,
  isSigningCurve,
  KEY_AGREEMENT_CURVES,
  SIGNING_CURVES,
  type Curve,
  type KeyInfo,
  type ProviderCapabilities,
  type PublicKey,
} from '@otl/keys';

const KDF_ITERATIONS = 600_000; // OWASP guidance for PBKDF2-SHA256
// Bounds accepted when reading a key file, so a tampered file cannot weaken
// the KDF or make it run for an unbounded time.
const MIN_KDF_ITERATIONS = 100_000;
const MAX_KDF_ITERATIONS = 10_000_000;
const KDF_DIGEST = 'sha256';
const SALT_BYTES = 16;
const NONCE_BYTES = 12;
const KEY_BYTES = 32;
const FILE_VERSION = 1;

interface KeyFile {
  readonly version: number;
  readonly label: string;
  readonly curve: Curve;
  readonly publicKeyMultibase: string;
  readonly createdAt: string;
  readonly privateKey: {
    readonly kdf: 'pbkdf2-sha256';
    readonly iterations: number;
    readonly salt: string; // base64
    readonly cipher: 'aes-256-gcm';
    readonly nonce: string; // base64
    readonly ciphertext: string; // base64
    readonly tag: string; // base64
  };
}

export interface FileKeyProviderOptions {
  /** Directory holding one JSON file per key. Created 0700 if absent. */
  readonly directory: string;
  /**
   * Passphrase protecting every key in this directory. Required — this
   * provider will not write an unencrypted private key.
   */
  readonly passphrase: string;
}

export class FileKeyProvider
  extends KeyProvider
  implements GeneratesKeys, DerivesSharedSecrets, ExportsPrivateKeys
{
  override readonly id = 'file';
  readonly #directory: string;
  readonly #passphrase: string;

  constructor(options: FileKeyProviderOptions) {
    super();
    // Also rejects a non-string, which the types forbid but a JavaScript caller
    // could still pass; an unencrypted key must never be written.
    const passphrase = options.passphrase as string | undefined;
    if (passphrase === undefined || passphrase === '') {
      throw new InvalidKeyError(
        'FileKeyProvider requires a passphrase; refusing to store an unencrypted private key',
      );
    }
    this.#directory = options.directory;
    this.#passphrase = options.passphrase;
    mkdirSync(this.#directory, { recursive: true, mode: 0o700 });
    chmodSync(this.#directory, 0o700);
  }

  override capabilities(): ProviderCapabilities {
    return {
      signing: SIGNING_CURVES,
      keyAgreement: KEY_AGREEMENT_CURVES,
      canGenerate: true,
      canExportPrivateKey: true,
    };
  }

  override async getKey(label: string): Promise<KeyInfo> {
    return toKeyInfo(this.#readFile(label), this.id);
  }

  override async listKeys(): Promise<readonly KeyInfo[]> {
    if (!existsSync(this.#directory)) return [];
    return readdirSync(this.#directory)
      .filter((f) => f.endsWith('.json'))
      .map((f) => toKeyInfo(this.#readFile(f.slice(0, -'.json'.length)), this.id));
  }

  override async sign(label: string, message: Uint8Array): Promise<Uint8Array> {
    const file = this.#readFile(label);
    if (!isSigningCurve(file.curve)) {
      throw new UnsupportedOperationError(`Key "${label}" uses ${file.curve}, which cannot sign`);
    }
    return signWith(this.#decryptPrivateKey(file), file.curve, message);
  }

  async generateKey(label: string, curve: Curve): Promise<KeyInfo> {
    assertSafeLabel(label);
    if (existsSync(this.#pathFor(label))) throw new KeyAlreadyExistsError(label);

    const { privateKey, publicKey } = generateKeyObject(curve);
    const file: KeyFile = {
      version: FILE_VERSION,
      label,
      curve,
      publicKeyMultibase: toPublicKeyMultibase(publicKeyFrom(publicKey, curve)),
      createdAt: new Date().toISOString(),
      privateKey: this.#encryptPrivateKey(exportPkcs8(privateKey)),
    };

    const path = this.#pathFor(label);
    try {
      // 'wx' fails if the file appeared since the check above, so a concurrent
      // generateKey for the same label can never overwrite a key.
      writeFileSync(path, JSON.stringify(file, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'EEXIST') throw new KeyAlreadyExistsError(label);
      throw error;
    }
    chmodSync(path, 0o600);
    return toKeyInfo(file, this.id);
  }

  async deriveSharedSecret(label: string, peerPublicKey: PublicKey): Promise<Uint8Array> {
    const file = this.#readFile(label);
    if (!isKeyAgreementCurve(file.curve)) {
      throw new UnsupportedOperationError(
        `Key "${label}" uses ${file.curve}, which cannot perform key agreement`,
      );
    }
    return deriveSharedSecretWith(this.#decryptPrivateKey(file), file.curve, peerPublicKey);
  }

  async exportPrivateKey(label: string): Promise<Uint8Array> {
    return exportPkcs8(this.#decryptPrivateKey(this.#readFile(label)));
  }

  #pathFor(label: string): string {
    assertSafeLabel(label);
    return join(this.#directory, `${label}.json`);
  }

  #readFile(label: string): KeyFile {
    const path = this.#pathFor(label);
    if (!existsSync(path)) throw new KeyNotFoundError(label);

    let parsed: KeyFile;
    try {
      parsed = JSON.parse(readFileSync(path, 'utf8')) as KeyFile;
    } catch (cause) {
      throw new InvalidKeyError(`Key file for "${label}" is not valid JSON`, { cause });
    }
    if (parsed.version !== FILE_VERSION) {
      throw new InvalidKeyError(`Key file for "${label}" has unsupported version ${parsed.version}`);
    }
    return parsed;
  }

  #encryptPrivateKey(pkcs8: Uint8Array): KeyFile['privateKey'] {
    const salt = randomBytes(SALT_BYTES);
    const nonce = randomBytes(NONCE_BYTES);
    const cipher = createCipheriv('aes-256-gcm', this.#deriveWrappingKey(salt), nonce);
    const ciphertext = Buffer.concat([cipher.update(pkcs8), cipher.final()]);
    return {
      kdf: 'pbkdf2-sha256',
      iterations: KDF_ITERATIONS,
      salt: salt.toString('base64'),
      cipher: 'aes-256-gcm',
      nonce: nonce.toString('base64'),
      ciphertext: ciphertext.toString('base64'),
      tag: cipher.getAuthTag().toString('base64'),
    };
  }

  #decryptPrivateKey(file: KeyFile): KeyObject {
    const { salt, nonce, ciphertext, tag, iterations } = file.privateKey;
    // Widened to string: the type says one literal but the file is untrusted.
    const kdf: string = file.privateKey.kdf;
    const cipher: string = file.privateKey.cipher;
    // The key file is untrusted input: an unexpected scheme or an unbounded
    // iteration count must be rejected before any work is done with it.
    if (
      kdf !== 'pbkdf2-sha256' ||
      cipher !== 'aes-256-gcm' ||
      !Number.isInteger(iterations) ||
      iterations < MIN_KDF_ITERATIONS ||
      iterations > MAX_KDF_ITERATIONS
    ) {
      throw new InvalidKeyError(
        `Key file for "${file.label}" uses an unsupported or out-of-range encryption scheme`,
      );
    }
    try {
      const decipher = createDecipheriv(
        'aes-256-gcm',
        this.#deriveWrappingKey(Buffer.from(salt, 'base64'), iterations),
        Buffer.from(nonce, 'base64'),
        { authTagLength: 16 },
      );
      decipher.setAuthTag(Buffer.from(tag, 'base64'));
      const pkcs8 = Buffer.concat([decipher.update(Buffer.from(ciphertext, 'base64')), decipher.final()]);
      return importPkcs8(new Uint8Array(pkcs8));
    } catch (cause) {
      // GCM tag mismatch. Overwhelmingly the wrong passphrase; possibly tampering.
      throw new InvalidKeyError(
        `Could not decrypt key "${file.label}" — wrong passphrase, or the key file has been modified`,
        { cause },
      );
    }
  }

  #deriveWrappingKey(salt: Buffer, iterations: number = KDF_ITERATIONS): Buffer {
    return pbkdf2Sync(this.#passphrase, salt, iterations, KEY_BYTES, KDF_DIGEST);
  }
}

function toKeyInfo(file: KeyFile, providerId: string): KeyInfo {
  return {
    handle: { label: file.label, providerRef: `${providerId}:${file.label}` },
    curve: file.curve,
    publicKey: fromPublicKeyMultibase(file.publicKeyMultibase),
    createdAt: file.createdAt,
  };
}

/** Labels become filenames, so they must not escape the key directory. */
function assertSafeLabel(label: string): void {
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(label) || label.includes('..')) {
    throw new InvalidKeyError(
      `Invalid key label "${label}" — use 1-64 characters of [A-Za-z0-9._-], starting alphanumeric`,
    );
  }
}
