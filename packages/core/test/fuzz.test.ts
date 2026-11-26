/**
 * Seeded fuzz tests for the code that parses input an attacker controls.
 *
 * Each test feeds thousands of random or mutated inputs to one parser and
 * checks a single property: the parser either accepts the input or rejects it
 * with one of this package's own error types. Anything else, such as a
 * TypeError from reading a member that is not there, is a crash on hostile
 * input and fails the test. Every generator is driven by a fixed seed, so a
 * failure names the seed and iteration and reproduces exactly. Set
 * OTL_FUZZ_ITERATIONS to run more iterations than the default.
 */

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { gzipSync } from 'node:zlib';
import { InMemoryKeyProvider } from '@open-transaction-layer/keys-dev';
import { createDid } from '../src/didwebvh/create.ts';
import { addService } from '../src/didwebvh/update.ts';
import { parseDidLog, validateDidLog } from '../src/didwebvh/validate.ts';
import type { DidLogEntry } from '../src/didwebvh/types.ts';
import { OtlCoreError } from '../src/errors.ts';
import { canonicalize } from '../src/jcs.ts';
import { Bitstring, MAXIMUM_ENTRIES } from '../src/statuslist/bitstring.ts';
import { bitstringFrom, type StatusListCredential } from '../src/statuslist/credential.ts';

const configured = Number(process.env['OTL_FUZZ_ITERATIONS']);
const ITERATIONS = Number.isInteger(configured) && configured > 0 ? configured : 1000;
/** Validating a DID log verifies signatures, so it runs fewer iterations. */
const SLOW_ITERATIONS = Math.max(20, Math.floor(ITERATIONS / 5));

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

const WORDS = ['a', 'b', 'id', 'type', '', '9', '10', 'é', '€', '😀', 'constructor', 'toString'];

function randomString(random: Random): string {
  const length = random.int(6);
  let text = '';
  for (let i = 0; i < length; i++) text += random.pick(WORDS);
  return text;
}

function randomJson(random: Random, depth: number): unknown {
  const kind = random.int(depth <= 0 ? 4 : 6);
  switch (kind) {
    case 0:
      return null;
    case 1:
      return random.next() < 0.5;
    case 2:
      return random.pick([0, 1, -1, 1.5, 1e21, 1e-7, 123456789012, Number.MAX_SAFE_INTEGER, 0.1 + 0.2]);
    case 3:
      return randomString(random);
    case 4:
      return Array.from({ length: random.int(4) }, () => randomJson(random, depth - 1));
    default: {
      const object: Record<string, unknown> = {};
      for (let i = random.int(4); i > 0; i--) object[randomString(random)] = randomJson(random, depth - 1);
      return object;
    }
  }
}

/** A value of the wrong kind, which is what a hostile document puts where a parser expects another. */
function randomHostileValue(random: Random): unknown {
  return random.pick<unknown>([
    null,
    true,
    0,
    -1,
    1.5,
    1e308,
    '',
    'x',
    'u',
    'did:webvh:x',
    '\ud800',
    'a'.repeat(5000),
    [],
    {},
    [[]],
    { a: { b: { c: [] } } },
    randomJson(random, 3),
  ]);
}

/** Run `action` and require that it returns or throws one of this package's own errors. */
function onlyDomainErrors(label: string, action: () => unknown): void {
  try {
    action();
  } catch (error) {
    assert.ok(
      error instanceof OtlCoreError,
      `${label}: expected an OtlCoreError, got ${error instanceof Error ? `${error.name}: ${error.message}` : String(error)}`,
    );
  }
}

async function onlyDomainErrorsAsync(label: string, action: () => Promise<unknown>): Promise<void> {
  try {
    await action();
  } catch (error) {
    assert.ok(
      error instanceof OtlCoreError,
      `${label}: expected an OtlCoreError, got ${error instanceof Error ? `${error.name}: ${error.message}` : String(error)}`,
    );
  }
}

describe('fuzz - JCS canonicalization', () => {
  it('is idempotent and independent of key order for any JSON value', () => {
    const random = makeRandom(0x5eed01);
    for (let i = 0; i < ITERATIONS; i++) {
      const value = randomJson(random, 4);
      const label = `seed 0x5eed01 iteration ${i}`;
      const canonical = canonicalize(value);
      assert.equal(canonicalize(JSON.parse(canonical)), canonical, `${label}: not idempotent`);
      if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
        const reversed = Object.fromEntries(Object.entries(value).reverse());
        assert.equal(canonicalize(reversed), canonical, `${label}: depends on key order`);
      }
    }
  });

  it('rejects values JSON cannot represent with a domain error and never crashes', () => {
    const cyclic: Record<string, unknown> = {};
    cyclic['self'] = cyclic;
    const sparse: unknown[] = [];
    sparse[3] = 1;
    const unrepresentable: unknown[] = [
      Number.NaN,
      Number.POSITIVE_INFINITY,
      undefined,
      10n,
      () => 1,
      Symbol('s'),
      new Date(0),
      new Map(),
      new Uint8Array(2),
      cyclic,
      sparse,
      '\ud800',
      { key: undefined },
      { '\udc00': 1 },
      Object.create(null) as object,
      new (class Custom {})(),
    ];
    const random = makeRandom(0x5eed02);
    for (let i = 0; i < ITERATIONS; i++) {
      const hostile = random.pick(unrepresentable);
      const wrapped = random.pick([
        hostile,
        [hostile],
        { a: hostile },
        { a: [randomJson(random, 2), hostile] },
      ]);
      onlyDomainErrors(`seed 0x5eed02 iteration ${i}`, () => canonicalize(wrapped));
    }
  });
});

describe('fuzz - status list decoding', () => {
  const valid = Bitstring.create().encode();
  const base64urlBody = valid.slice(1);

  it('decodes only what it can bound, for arbitrary strings', () => {
    const random = makeRandom(0x5eed03);
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=+/ .';
    for (let i = 0; i < ITERATIONS; i++) {
      let text = random.pick(['u', 'u', 'z', '', 'U']);
      for (let n = random.int(80); n > 0; n--) text += alphabet.charAt(random.int(alphabet.length));
      onlyDomainErrors(`seed 0x5eed03 iteration ${i}`, () => {
        assert.ok(Bitstring.decode(text).length <= MAXIMUM_ENTRIES);
      });
    }
  });

  it('survives every kind of damage to a valid list', () => {
    const random = makeRandom(0x5eed04);
    const bytes = Buffer.from(base64urlBody, 'base64url');
    for (let i = 0; i < ITERATIONS; i++) {
      const damaged = Buffer.from(bytes);
      for (let n = 1 + random.int(4); n > 0; n--) damaged[random.int(damaged.length)] = random.int(256);
      const cut = random.next() < 0.3 ? damaged.subarray(0, random.int(damaged.length)) : damaged;
      onlyDomainErrors(`seed 0x5eed04 iteration ${i}`, () => {
        assert.ok(Bitstring.decode(`u${cut.toString('base64url')}`).length <= MAXIMUM_ENTRIES);
      });
    }
  });

  it('refuses a small payload that expands far past the ceiling without allocating it', () => {
    const bomb = gzipSync(Buffer.alloc(MAXIMUM_ENTRIES), { level: 9 }); // 8x the byte ceiling once decompressed
    assert.throws(() => Bitstring.decode(`u${bomb.toString('base64url')}`), OtlCoreError);
  });

  it('rejects a credential whose members are of the wrong kind with a domain error', () => {
    const random = makeRandom(0x5eed05);
    for (let i = 0; i < ITERATIONS; i++) {
      const subject = {
        type: random.pick<unknown>(['BitstringStatusList', 'x', 1, null]),
        statusPurpose: random.pick<unknown>(['revocation', 'suspension', 7, null]),
        encodedList: random.pick<unknown>([valid, randomHostileValue(random)]),
      };
      const credential = random.pick<unknown>([
        { credentialSubject: subject },
        { credentialSubject: randomHostileValue(random) },
        {},
      ]);
      onlyDomainErrors(`seed 0x5eed05 iteration ${i}`, () =>
        bitstringFrom(credential as StatusListCredential),
      );
    }
  });
});

describe('fuzz - DID log parsing and validation', () => {
  const DOMAIN = 'vasp.example.com';

  async function validLog() {
    const provider = new InMemoryKeyProvider();
    for (let i = 0; i < 4; i++) await provider.generateKey(`k${i}`, 'Ed25519');
    const created = await createDid({
      domain: DOMAIN,
      provider,
      managementKeyLabel: 'k0',
      preRotationKeyLabel: 'k1',
      versionTime: '2026-01-01T00:00:00Z',
    });
    const second = await addService({
      did: created.did,
      previousEntry: created.entry,
      provider,
      signingKeyLabel: 'k1',
      nextKeyLabel: 'k2',
      versionTime: '2026-02-01T00:00:00Z',
      service: { id: '#whois', type: 'OtlWhois', serviceEndpoint: `https://${DOMAIN}/.well-known/whois.vp` },
    });
    return [created.entry, second] as DidLogEntry[];
  }

  /** Replace, delete or duplicate one member found by walking a random path into the value. */
  function mutate(random: Random, root: unknown): unknown {
    const copy = JSON.parse(JSON.stringify(root)) as unknown;
    let parent: unknown = undefined;
    let key: string | number = '';
    let current: unknown = copy;
    for (let depth = 1 + random.int(5); depth > 0; depth--) {
      if (Array.isArray(current) && current.length > 0) {
        parent = current;
        key = random.int(current.length);
        current = current[key];
      } else if (typeof current === 'object' && current !== null && Object.keys(current).length > 0) {
        parent = current;
        key = random.pick(Object.keys(current));
        current = (current as Record<string, unknown>)[key];
      } else {
        break;
      }
    }
    if (parent === undefined) return copy;
    const container = parent as Record<string | number, unknown>;
    if (random.next() < 0.25) {
      if (Array.isArray(parent)) parent.splice(Number(key), 1);
      else delete container[key];
    } else {
      container[key] = randomHostileValue(random);
    }
    return copy;
  }

  it('parses arbitrary text into entries or a SyntaxError', async () => {
    const entries = await validLog();
    const text = entries.map((entry) => JSON.stringify(entry)).join('\n');
    const random = makeRandom(0x5eed06);
    for (let i = 0; i < ITERATIONS; i++) {
      const chars = [...text];
      for (let n = 1 + random.int(5); n > 0; n--)
        chars[random.int(chars.length)] = random.pick(['"', '{', '}', '\n', '\\', '\u0000', 'x']);
      try {
        parseDidLog(chars.join(''));
      } catch (error) {
        assert.ok(error instanceof SyntaxError, `seed 0x5eed06 iteration ${i}: ${String(error)}`);
      }
    }
  });

  it('never crashes while validating a log with a hostile member', async () => {
    const entries = await validLog();
    const random = makeRandom(0x5eed07);
    for (let i = 0; i < SLOW_ITERATIONS; i++) {
      const hostile = mutate(random, entries) as DidLogEntry[];
      await onlyDomainErrorsAsync(`seed 0x5eed07 iteration ${i}`, async () => {
        const result = await validateDidLog(hostile);
        assert.equal(typeof result.valid, 'boolean');
      });
    }
  });
});
