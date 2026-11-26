/**
 * Negative control for the conformance kit itself.
 *
 * A test kit that passes everything is worthless, so these providers make the
 * three mistakes a real bridge is most likely to make, and we assert the kit
 * rejects each one. This is what stops the kit silently rotting into a no-op.
 */

import assert from 'node:assert/strict';
import { generateKeyPairSync, sign as nodeSign, type KeyObject } from 'node:crypto';
import { describe, it } from 'node:test';
import { keyProviderConformanceCases } from '@open-transaction-layer/keys/conformance';
import type { KeyProvider } from '@open-transaction-layer/keys';
import { InMemoryKeyProvider } from '../src/in-memory.ts';
import type { Curve, KeyInfo } from '@open-transaction-layer/keys';

/** Mistake 1: returns DER-encoded ECDSA — what AWS KMS and Key Vault do by default. */
class DerSigningProvider extends InMemoryKeyProvider {
  readonly #shadow = new Map<string, KeyObject>();
  override async generateKey(label: string, curve: Curve): Promise<KeyInfo> {
    const info = await super.generateKey(label, curve);
    if (curve === 'P-256') {
      this.#shadow.set(label, generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey);
    }
    return info;
  }
  override async sign(label: string, message: Uint8Array): Promise<Uint8Array> {
    const info = await this.getKey(label);
    const shadow = this.#shadow.get(label);
    if (info.curve === 'P-256' && shadow) {
      return new Uint8Array(nodeSign('sha256', message, shadow)); // no dsaEncoding => DER
    }
    return super.sign(label, message);
  }
}

/** Mistake 2: capability declarations that do not match behaviour. */
class LyingCapabilitiesProvider extends InMemoryKeyProvider {
  override capabilities() {
    return { ...super.capabilities(), canExportPrivateKey: false };
  }
}

/** Mistake 3: leaks a backend-native error instead of translating it. */
class BackendNativeErrorProvider extends InMemoryKeyProvider {
  override async getKey(label: string): Promise<KeyInfo> {
    try {
      return await super.getKey(label);
    } catch {
      throw new Error(`AccessDeniedException: key ${label}`);
    }
  }
}

/** Runs every case and returns the names that failed. */
async function failingCases(factory: () => KeyProvider): Promise<string[]> {
  const failures: string[] = [];
  for (const testCase of keyProviderConformanceCases()) {
    try {
      await testCase.run(factory());
    } catch {
      failures.push(testCase.name);
    }
  }
  return failures;
}

describe('conformance kit rejects broken providers', () => {
  it('catches DER-encoded signatures', async () => {
    const failures = await failingCases(() => new DerSigningProvider());
    assert.ok(
      failures.includes('P-256: signature is raw fixed-width, never DER'),
      `expected the DER case to fail; failures were: ${failures.join(', ')}`,
    );
  });

  it('catches capability declarations that do not match behaviour', async () => {
    const failures = await failingCases(() => new LyingCapabilitiesProvider());
    assert.ok(failures.includes('declared canExportPrivateKey matches observed behaviour'));
  });

  it('catches untranslated backend-native errors', async () => {
    const failures = await failingCases(() => new BackendNativeErrorProvider());
    assert.ok(failures.includes('unknown label raises KeyNotFoundError, not a backend-native error'));
  });

  it('passes a correct provider cleanly', async () => {
    const failures = await failingCases(() => new InMemoryKeyProvider());
    assert.deepEqual(failures, [], 'the reference provider must pass every case');
  });
});
