/**
 * Conformance kit for {@link "keys/src"!KeyProvider} implementations.
 *
 * `@open-transaction-layer/keys` ships an abstraction and no production implementation. The
 * correctness of every real deployment therefore lives in a bridge we do not
 * write, so we ship the suite that defines correct.
 *
 * ```ts
 * import { runKeyProviderConformance } from '@open-transaction-layer/keys/conformance';
 *
 * runKeyProviderConformance('our KMS bridge', () => new OurKmsKeyProvider(config));
 * ```
 *
 * The suite exercises only what the provider declares in `capabilities()`, and
 * separately asserts that those declarations match observed behaviour. Cases
 * are exposed as plain data by {@link keyProviderConformanceCases} so that a
 * consumer on a different test runner can adapt them.
 */

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { KeyAlreadyExistsError, KeyNotFoundError, UnsupportedOperationError } from '../errors.ts';
import { verifyWith } from '../nodecrypto.ts';
import {
  supportsGeneration,
  supportsKeyAgreement,
  supportsPrivateKeyExport,
  type KeyProvider,
} from '../provider.ts';
import { PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH, isSigningCurve, type Curve } from '../types.ts';

export interface ConformanceCase {
  readonly name: string;
  readonly run: (provider: KeyProvider) => Promise<void>;
}

/** Provider factory. Each case receives a fresh provider. */
export type ProviderFactory = () => KeyProvider | Promise<KeyProvider>;

const MESSAGE = new TextEncoder().encode('OTL conformance — the quick brown fox');
const OTHER_MESSAGE = new TextEncoder().encode('OTL conformance — a different message');

/**
 * The first signing curve a provider declares. The coherence case asserts the
 * list is non-empty on its own; this asserts it again so that a provider that
 * fails that case reports a clear message here instead of a type error.
 */
function firstSigningCurve(provider: KeyProvider): Curve {
  const curve = provider.capabilities().signing[0];
  assert.ok(curve !== undefined, 'a provider that cannot sign cannot participate in the Identity layer');
  return curve;
}

/**
 * Heuristic: does this look like a DER-wrapped ECDSA signature?
 *
 * A DER signature is `0x30 <len> 0x02 <rlen> r 0x02 <slen> s`, typically 70-72
 * bytes for P-256. This is the single most likely bridge defect, so it gets its
 * own explicit assertion rather than only failing the length check.
 */
function looksLikeDer(signature: Uint8Array): boolean {
  return (
    signature.length >= 8 &&
    signature[0] === 0x30 &&
    signature[1] === signature.length - 2 &&
    signature[2] === 0x02
  );
}

async function ensureKey(provider: KeyProvider, label: string, curve: Curve) {
  if (supportsGeneration(provider)) return provider.generateKey(label, curve);
  // Sign-only provider: the key must have been provisioned out of band.
  return provider.getKey(label);
}

export function keyProviderConformanceCases(): readonly ConformanceCase[] {
  const cases: ConformanceCase[] = [];

  // ---- Capability declarations ------------------------------------------

  cases.push({
    name: 'capabilities() is internally coherent',
    async run(provider) {
      const caps = provider.capabilities();
      assert.ok(Array.isArray(caps.signing), 'capabilities().signing must be an array');
      assert.ok(Array.isArray(caps.keyAgreement), 'capabilities().keyAgreement must be an array');
      assert.equal(typeof caps.canGenerate, 'boolean');
      assert.equal(typeof caps.canExportPrivateKey, 'boolean');
      assert.ok(
        caps.signing.every(isSigningCurve),
        'capabilities().signing must not contain a key-agreement-only curve such as X25519',
      );
      assert.ok(
        !caps.keyAgreement.includes('Ed25519'),
        'Ed25519 cannot perform key agreement; declare X25519 instead',
      );
      assert.ok(
        caps.signing.length > 0,
        'a provider that cannot sign cannot participate in the Identity layer',
      );
    },
  });

  cases.push({
    name: 'declared canGenerate matches observed behaviour',
    async run(provider) {
      if (!supportsGeneration(provider)) {
        assert.equal(
          typeof (provider as { generateKey?: unknown }).generateKey,
          'undefined',
          'provider declares canGenerate: false but exposes generateKey()',
        );
        return;
      }
      const curve = firstSigningCurve(provider);
      const info = await provider.generateKey('caps-generate', curve);
      assert.equal(info.handle.label, 'caps-generate');
    },
  });

  cases.push({
    name: 'declared canExportPrivateKey matches observed behaviour',
    async run(provider) {
      const declared = provider.capabilities().canExportPrivateKey;
      const present = typeof (provider as { exportPrivateKey?: unknown }).exportPrivateKey === 'function';
      assert.equal(
        declared,
        present,
        declared
          ? 'provider declares canExportPrivateKey: true but exposes no exportPrivateKey()'
          : 'provider declares canExportPrivateKey: false but exposes exportPrivateKey()',
      );
    },
  });

  // ---- Key lookup --------------------------------------------------------

  cases.push({
    name: 'unknown label raises KeyNotFoundError, not a backend-native error',
    async run(provider) {
      await assert.rejects(
        () => provider.getKey('no-such-key-exists'),
        (error: unknown) => {
          assert.ok(
            error instanceof KeyNotFoundError,
            `expected KeyNotFoundError, got ${(error as { constructor?: { name?: string } } | null | undefined)?.constructor?.name}`,
          );
          return true;
        },
      );
    },
  });

  cases.push({
    name: 'signing with an unknown label raises KeyNotFoundError',
    async run(provider) {
      await assert.rejects(() => provider.sign('no-such-key-exists', MESSAGE), KeyNotFoundError);
    },
  });

  cases.push({
    name: 'generateKey refuses to overwrite an existing label',
    async run(provider) {
      if (!supportsGeneration(provider)) return;
      const curve = firstSigningCurve(provider);
      await provider.generateKey('duplicate', curve);
      await assert.rejects(() => provider.generateKey('duplicate', curve), KeyAlreadyExistsError);
    },
  });

  cases.push({
    name: 'listKeys includes every key the provider reports',
    async run(provider) {
      if (!supportsGeneration(provider)) return;
      const curve = firstSigningCurve(provider);
      await provider.generateKey('listed-a', curve);
      await provider.generateKey('listed-b', curve);
      const labels = (await provider.listKeys()).map((k) => k.handle.label);
      assert.ok(labels.includes('listed-a'));
      assert.ok(labels.includes('listed-b'));
    },
  });

  // ---- Public key encoding, per declared curve ---------------------------

  for (const curve of ['Ed25519', 'P-256', 'X25519'] as const) {
    cases.push({
      name: `public key encoding is canonical for ${curve}`,
      async run(provider) {
        const caps = provider.capabilities();
        const declared = caps.signing.includes(curve) || caps.keyAgreement.includes(curve);
        if (!declared || !supportsGeneration(provider)) return;

        const info = await provider.generateKey(`pubkey-${curve.toLowerCase()}`, curve);
        assert.equal(info.curve, curve);
        assert.equal(
          info.publicKey.bytes.length,
          PUBLIC_KEY_LENGTH[curve],
          `${curve} public key must be ${PUBLIC_KEY_LENGTH[curve]} raw bytes`,
        );
        if (curve === 'P-256') {
          assert.equal(
            info.publicKey.bytes[0],
            0x04,
            'P-256 public key must be SEC1 uncompressed (leading 0x04), not compressed or DER-wrapped',
          );
        }
        assert.equal(info.publicKey.curve, curve, 'PublicKey.curve must match KeyInfo.curve');
      },
    });
  }

  // ---- Signing -----------------------------------------------------------

  for (const curve of ['Ed25519', 'P-256'] as const) {
    cases.push({
      name: `${curve}: signature is raw fixed-width, never DER`,
      async run(provider) {
        if (!provider.capabilities().signing.includes(curve)) return;
        const label = `sign-${curve.toLowerCase()}`;
        await ensureKey(provider, label, curve);

        const signature = await provider.sign(label, MESSAGE);
        assert.ok(!looksLikeDer(signature), `${curve} signature appears DER-encoded; convert it to raw r‖s`);
        assert.equal(
          signature.length,
          SIGNATURE_LENGTH[curve],
          `${curve} signature must be exactly ${SIGNATURE_LENGTH[curve]} bytes (IEEE P1363 r‖s), got ${signature.length}`,
        );
      },
    });

    cases.push({
      name: `${curve}: signature verifies against the reported public key`,
      async run(provider) {
        if (!provider.capabilities().signing.includes(curve)) return;
        const label = `verify-${curve.toLowerCase()}`;
        const info = await ensureKey(provider, label, curve);

        const signature = await provider.sign(label, MESSAGE);
        assert.ok(
          verifyWith(info.publicKey, MESSAGE, signature),
          `${curve} signature did not verify against the public key the provider reported`,
        );
        assert.ok(
          !verifyWith(info.publicKey, OTHER_MESSAGE, signature),
          `${curve} signature verified against the wrong message`,
        );
      },
    });

    cases.push({
      name: `${curve}: signs the full message, not a truncated or pre-hashed one`,
      async run(provider) {
        if (!provider.capabilities().signing.includes(curve)) return;
        const label = `fullmsg-${curve.toLowerCase()}`;
        const info = await ensureKey(provider, label, curve);

        // Two messages sharing a long prefix: a provider that truncates or
        // signs only a prefix would produce cross-verifying signatures.
        const a = new Uint8Array(4096).fill(0x61);
        const b = Uint8Array.from(a);
        b[4095] = 0x62;

        const sigA = await provider.sign(label, a);
        assert.ok(verifyWith(info.publicKey, a, sigA));
        assert.ok(!verifyWith(info.publicKey, b, sigA), 'signature ignored the tail of the message');

        const empty = await provider.sign(label, new Uint8Array(0));
        assert.ok(verifyWith(info.publicKey, new Uint8Array(0), empty), 'failed to sign an empty message');
      },
    });
  }

  cases.push({
    name: 'signing with a key-agreement-only key raises UnsupportedOperationError',
    async run(provider) {
      const caps = provider.capabilities();
      if (!caps.keyAgreement.includes('X25519') || !supportsGeneration(provider)) return;
      await provider.generateKey('x25519-nosign', 'X25519');
      await assert.rejects(
        () => provider.sign('x25519-nosign', MESSAGE),
        UnsupportedOperationError,
        'X25519 keys must refuse to sign rather than producing an unusable signature',
      );
    },
  });

  // ---- Key agreement -----------------------------------------------------

  for (const curve of ['X25519', 'P-256'] as const) {
    cases.push({
      name: `${curve}: ECDH is symmetric between two parties`,
      async run(provider) {
        if (!supportsKeyAgreement(provider)) return;
        if (!provider.capabilities().keyAgreement.includes(curve)) return;
        if (!supportsGeneration(provider)) return;

        const alice = await provider.generateKey(`ecdh-a-${curve.toLowerCase()}`, curve);
        const bob = await provider.generateKey(`ecdh-b-${curve.toLowerCase()}`, curve);

        const zAlice = await provider.deriveSharedSecret(alice.handle.label, bob.publicKey);
        const zBob = await provider.deriveSharedSecret(bob.handle.label, alice.publicKey);

        assert.ok(zAlice.length > 0, 'shared secret must not be empty');
        assert.deepEqual(
          Buffer.from(zAlice).toString('hex'),
          Buffer.from(zBob).toString('hex'),
          'both parties must derive an identical shared secret',
        );
      },
    });
  }

  cases.push({
    name: 'ECDH across mismatched curves is rejected',
    async run(provider) {
      const caps = provider.capabilities();
      if (!supportsKeyAgreement(provider) || !supportsGeneration(provider)) return;
      if (!caps.keyAgreement.includes('X25519') || !caps.keyAgreement.includes('P-256')) return;

      const x = await provider.generateKey('ecdh-mismatch-x', 'X25519');
      const p = await provider.generateKey('ecdh-mismatch-p', 'P-256');
      await assert.rejects(
        () => provider.deriveSharedSecret(x.handle.label, p.publicKey),
        UnsupportedOperationError,
      );
    },
  });

  // ---- Export ------------------------------------------------------------

  cases.push({
    name: 'exportPrivateKey returns material only when declared (non-production only)',
    async run(provider) {
      if (!supportsPrivateKeyExport(provider)) return;
      if (!supportsGeneration(provider)) return;
      const curve = firstSigningCurve(provider);
      await provider.generateKey('exportable', curve);
      const exported = await provider.exportPrivateKey('exportable');
      assert.ok(exported.length > 0, 'exportPrivateKey returned no bytes');
    },
  });

  return cases;
}

/**
 * node:test adapter. Runs every conformance case against a fresh provider.
 *
 * @param name  Label for the suite, e.g. `'our KMS bridge'`.
 * @param factory Produces a fresh, empty provider per case.
 */
export function runKeyProviderConformance(name: string, factory: ProviderFactory): void {
  describe(`KeyProvider conformance: ${name}`, () => {
    for (const testCase of keyProviderConformanceCases()) {
      it(testCase.name, async () => {
        await testCase.run(await factory());
      });
    }
  });
}
