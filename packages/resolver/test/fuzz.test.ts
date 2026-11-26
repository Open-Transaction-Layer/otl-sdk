/**
 * Seeded fuzz tests for the resolver's input checks: the address guard that
 * keeps it away from internal hosts, and the DID parser that turns an
 * identifier into a URL.
 *
 * Every generator is driven by a fixed seed, so a failure names the seed and
 * iteration and reproduces exactly. Set OTL_FUZZ_ITERATIONS to run more
 * iterations than the default.
 */

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { isPrivateAddress } from '../src/address.ts';
import { InvalidDidError, parseDid } from '../src/url.ts';

const configured = Number(process.env['OTL_FUZZ_ITERATIONS']);
const ITERATIONS = Number.isInteger(configured) && configured > 0 ? configured : 1000;

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
type Random = ReturnType<typeof makeRandom>;

/** An IPv4 address in a range that must never be reached from a resolver. */
function randomInternalV4(random: Random): [number, number, number, number] {
  const byte = () => random.int(256);
  return random.pick<() => [number, number, number, number]>([
    () => [10, byte(), byte(), byte()],
    () => [127, byte(), byte(), byte()],
    () => [169, 254, byte(), byte()],
    () => [172, 16 + random.int(16), byte(), byte()],
    () => [192, 168, byte(), byte()],
    () => [0, byte(), byte(), byte()],
    () => [100, 64 + random.int(64), byte(), byte()],
  ])();
}

const hex = (value: number): string => value.toString(16);

describe('fuzz - address guard', () => {
  it('blocks every internal IPv4 address however it is written', () => {
    const random = makeRandom(0x5eed21);
    for (let i = 0; i < ITERATIONS; i++) {
      const [a, b, c, d] = randomInternalV4(random);
      const dotted = `${a}.${b}.${c}.${d}`;
      const high = hex(a * 256 + b);
      const low = hex(c * 256 + d);
      const spellings = [
        dotted,
        `[${dotted}]`,
        `::ffff:${dotted}`,
        `::ffff:${high}:${low}`,
        `[::ffff:${high}:${low}]`,
        `0:0:0:0:0:ffff:${high}:${low}`,
        `64:ff9b::${dotted}`,
        `2002:${high}:${low}::`,
        `2002:${high}:${low}::1`,
      ];
      for (const address of spellings) {
        assert.equal(
          isPrivateAddress(address),
          true,
          `seed 0x5eed21 iteration ${i}: ${address} was not blocked`,
        );
      }
    }
  });

  it('classifies arbitrary text without throwing', () => {
    const random = makeRandom(0x5eed22);
    const pieces = [
      '0',
      '1',
      '9',
      'a',
      'f',
      'g',
      ':',
      '.',
      '[',
      ']',
      '%',
      'eth0',
      '::',
      'ffff',
      '255',
      '256',
      '-',
      ' ',
    ];
    for (let i = 0; i < ITERATIONS; i++) {
      let text = '';
      for (let n = random.int(14); n > 0; n--) text += random.pick(pieces);
      assert.equal(typeof isPrivateAddress(text), 'boolean', `seed 0x5eed22 iteration ${i}`);
    }
  });
});

describe('fuzz - DID parsing', () => {
  it('parses a DID or rejects it with InvalidDidError, whatever the text', () => {
    const random = makeRandom(0x5eed23);
    const scid = 'QmZ1111111111111111111111';
    const pieces = [
      'did:webvh:',
      scid,
      ':',
      'example.com',
      '%3A',
      '8443',
      '%2F',
      '%',
      '%zz',
      '..',
      '/',
      '?',
      '#',
      '\\',
      '\u0000',
      'é',
      '😀',
      ' ',
    ];
    for (let i = 0; i < ITERATIONS; i++) {
      let did = random.pick(['did:webvh:', 'did:webvh:' + scid + ':', 'did:web:', '']);
      for (let n = random.int(9); n > 0; n--) did += random.pick(pieces);
      try {
        const parsed = parseDid(did);
        assert.equal(
          parsed.origin.startsWith('https://'),
          true,
          `seed 0x5eed23 iteration ${i}: ${did} gave ${parsed.origin}`,
        );
      } catch (error) {
        assert.ok(
          error instanceof InvalidDidError,
          `seed 0x5eed23 iteration ${i}: ${did} threw ${String(error)}`,
        );
      }
    }
  });
});
