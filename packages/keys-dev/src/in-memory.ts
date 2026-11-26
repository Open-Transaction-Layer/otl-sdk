/**
 * NON-PRODUCTION. Ephemeral, process-local key storage.
 *
 * Intended for tests and throwaway runs. Key material lives in plain process
 * memory and is lost on exit. Production deployments MUST bridge
 * `KeyProvider` to a KMS or HSM instead.
 */

import type { KeyObject } from 'node:crypto';
import {
  KeyAlreadyExistsError,
  KeyNotFoundError,
  UnsupportedOperationError,
} from '@open-transaction-layer/keys';
import {
  deriveSharedSecretWith,
  exportPkcs8,
  generateKeyObject,
  publicKeyFrom,
  signWith,
} from '@open-transaction-layer/keys/node';
import {
  KeyProvider,
  type DerivesSharedSecrets,
  type ExportsPrivateKeys,
  type GeneratesKeys,
} from '@open-transaction-layer/keys';
import {
  isKeyAgreementCurve,
  isSigningCurve,
  KEY_AGREEMENT_CURVES,
  SIGNING_CURVES,
  type Curve,
  type KeyInfo,
  type ProviderCapabilities,
  type PublicKey,
} from '@open-transaction-layer/keys';

interface StoredKey {
  readonly info: KeyInfo;
  readonly privateKey: KeyObject;
}

export class InMemoryKeyProvider
  extends KeyProvider
  implements GeneratesKeys, DerivesSharedSecrets, ExportsPrivateKeys
{
  override readonly id = 'in-memory';
  readonly #keys = new Map<string, StoredKey>();

  override capabilities(): ProviderCapabilities {
    return {
      signing: SIGNING_CURVES,
      keyAgreement: KEY_AGREEMENT_CURVES,
      canGenerate: true,
      canExportPrivateKey: true,
    };
  }

  override async getKey(label: string): Promise<KeyInfo> {
    return this.#require(label).info;
  }

  override async listKeys(): Promise<readonly KeyInfo[]> {
    return [...this.#keys.values()].map((k) => k.info);
  }

  override async sign(label: string, message: Uint8Array): Promise<Uint8Array> {
    const { info, privateKey } = this.#require(label);
    if (!isSigningCurve(info.curve)) {
      throw new UnsupportedOperationError(`Key "${label}" uses ${info.curve}, which cannot sign`);
    }
    return signWith(privateKey, info.curve, message);
  }

  async generateKey(label: string, curve: Curve): Promise<KeyInfo> {
    if (this.#keys.has(label)) throw new KeyAlreadyExistsError(label);

    const { privateKey, publicKey } = generateKeyObject(curve);
    const info: KeyInfo = {
      handle: { label, providerRef: `${this.id}:${label}` },
      curve,
      publicKey: publicKeyFrom(publicKey, curve),
      createdAt: new Date().toISOString(),
    };
    this.#keys.set(label, { info, privateKey });
    return info;
  }

  async deriveSharedSecret(label: string, peerPublicKey: PublicKey): Promise<Uint8Array> {
    const { info, privateKey } = this.#require(label);
    if (!isKeyAgreementCurve(info.curve)) {
      throw new UnsupportedOperationError(
        `Key "${label}" uses ${info.curve}, which cannot perform key agreement`,
      );
    }
    return deriveSharedSecretWith(privateKey, info.curve, peerPublicKey);
  }

  async exportPrivateKey(label: string): Promise<Uint8Array> {
    return exportPkcs8(this.#require(label).privateKey);
  }

  #require(label: string): StoredKey {
    const stored = this.#keys.get(label);
    if (!stored) throw new KeyNotFoundError(label);
    return stored;
  }
}
