/**
 * Seeded fuzz tests for JWE decryption, which takes a message from the network.
 *
 * Every generator is driven by a fixed seed, so a failure names the seed and
 * iteration and reproduces exactly. Set OTL_FUZZ_ITERATIONS to run more
 * iterations than the default.
 */

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { InMemoryKeyProvider } from '@open-transaction-layer/keys-dev';
import { OtlJweError, decryptToString, encrypt } from '../src/index.ts';

const configured = Number(process.env['OTL_FUZZ_ITERATIONS']);
const ITERATIONS = Number.isInteger(configured) && configured > 0 ? configured : 1000;
const MESSAGE = 'settlement instruction 2026-01-01';

/** Small deterministic generator (mulberry32), so every failure reproduces. */
function makeRandom(seed: number) {
  let state = seed >>> 0;
  const next = (): number => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  const int = (below: number): number => Math.floor(next() * below);
  const pick = <T>(items: readonly T[]): T => items[int(items.length)] as T;
  return { next, int, pick };
}

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

describe('fuzz - JWE decryption', () => {
  it('rejects arbitrary five-segment strings with a JWE error and never crashes', async () => {
    const recipient = new InMemoryKeyProvider();
    await recipient.generateKey('agreement', 'X25519');
    const random = makeRandom(0x5eed11);
    for (let i = 0; i < ITERATIONS; i++) {
      const segments = Array.from({ length: random.pick([1, 3, 4, 5, 5, 5, 6]) }, () => {
        let text = '';
        for (let n = random.int(60); n > 0; n--) text += ALPHABET.charAt(random.int(ALPHABET.length));
        return random.next() < 0.1 ? '' : text;
      });
      await assert.rejects(
        decryptToString({ jwe: segments.join('.'), provider: recipient, keyLabel: 'agreement' }),
        (error: unknown) => error instanceof OtlJweError,
        `seed 0x5eed11 iteration ${i}`,
      );
    }
  });

  for (const curve of ['X25519', 'P-256'] as const) {
    it(`${curve}: a damaged message either fails with a JWE error or still yields the original text`, async () => {
      const recipient = new InMemoryKeyProvider();
      const key = await recipient.generateKey('agreement', curve);
      const original = encrypt({ plaintext: MESSAGE, recipientPublicKey: key.publicKey });
      const random = makeRandom(curve === 'X25519' ? 0x5eed12 : 0x5eed13);
      for (let i = 0; i < ITERATIONS; i++) {
        const chars = [...original];
        for (let n = 1 + random.int(3); n > 0; n--) {
          const at = random.int(chars.length);
          chars[at] = chars[at] === '.' ? random.pick(['x', '.']) : random.pick([...ALPHABET, '.']);
        }
        const damaged = chars.join('');
        try {
          const text = await decryptToString({ jwe: damaged, provider: recipient, keyLabel: 'agreement' });
          assert.equal(
            text,
            MESSAGE,
            `${curve} iteration ${i}: a damaged message decrypted to different text`,
          );
        } catch (error) {
          assert.ok(
            error instanceof OtlJweError,
            `${curve} iteration ${i}: expected an OtlJweError, got ${String(error)}`,
          );
        }
      }
    });
  }
});
