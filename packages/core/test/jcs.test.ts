import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { OtlCoreError } from '../src/errors.ts';
import { CanonicalizationError, canonicalize, canonicalizeToBytes } from '../src/jcs.ts';

const EURO = '€';

describe('JCS - key ordering', () => {
  it('sorts by UTF-16 code unit, not numerically', () => {
    // The trap: ECMAScript enumerates integer-like keys numerically and first,
    // so a sort-then-stringify implementation emits {"9":...,"10":...} here.
    const input: Record<string, number> = {};
    input['9'] = 1;
    input['10'] = 2;
    input['b'] = 3;
    input['a'] = 4;
    assert.equal(canonicalize(input), '{"10":2,"9":1,"a":4,"b":3}');
  });

  it('is independent of insertion order', () => {
    const a = { z: 1, m: 2, a: 3 };
    const b = { a: 3, z: 1, m: 2 };
    assert.equal(canonicalize(a), canonicalize(b));
    assert.equal(canonicalize(a), '{"a":3,"m":2,"z":1}');
  });

  it('sorts uppercase before lowercase (code-unit order, not locale)', () => {
    assert.equal(canonicalize({ a: 1, B: 2 }), '{"B":2,"a":1}');
  });

  it('sorts nested objects too', () => {
    assert.equal(canonicalize({ outer: { z: 1, a: 2 }, another: 3 }), '{"another":3,"outer":{"a":2,"z":1}}');
  });

  it('orders non-ASCII keys after ASCII, by code unit', () => {
    const input = { [EURO]: 'Euro', '\r': 'Carriage Return', '1': 'One' };
    assert.equal(canonicalize(input), String.raw`{"\r":"Carriage Return","1":"One","` + EURO + '":"Euro"}');
  });
});

describe('JCS - numbers', () => {
  const vectors: [number, string][] = [
    [0, '0'],
    [-0, '0'], // RFC 8785: negative zero serializes as "0"
    [1, '1'],
    [4.5, '4.5'],
    [0.002, '0.002'],
    [1e30, '1e+30'],
    [1e-27, '1e-27'],
    // The literal is written exactly as RFC 8785 Appendix B prints it, which has more digits than a double holds.
    // eslint-disable-next-line no-loss-of-precision -- the excess digits are the point of this vector
    [333333333.33333329, '333333333.3333333'],
    [-1.5, '-1.5'],
    [Number.MAX_SAFE_INTEGER, '9007199254740991'],
  ];

  for (const [value, expected] of vectors) {
    it(`serializes ${expected}`, () => {
      assert.equal(canonicalize(value), expected);
    });
  }

  it('rejects non-finite numbers rather than emitting null', () => {
    for (const bad of [Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY]) {
      assert.throws(() => canonicalize(bad), CanonicalizationError);
      assert.throws(() => canonicalize({ v: bad }), CanonicalizationError);
    }
  });
});

describe('JCS - strings', () => {
  it('uses short escapes for the control characters that have them', () => {
    assert.equal(canonicalize('\b\t\n\f\r"\\'), String.raw`"\b\t\n\f\r\"\\"`);
  });

  it('uses \\uXXXX for other C0 controls', () => {
    assert.equal(canonicalize('\u0000\u000f\u001f'), String.raw`"\u0000\u000f\u001f"`);
  });

  it('emits non-ASCII literally rather than escaping it', () => {
    const value = EURO + ' — 日本語';
    assert.equal(canonicalize(value), '"' + value + '"');
  });

  it('escapes lone surrogates', () => {
    assert.equal(canonicalize('\ud800'), String.raw`"\ud800"`);
  });

  it('does not escape the forward slash', () => {
    assert.equal(canonicalize('a/b'), '"a/b"');
  });
});

describe('JCS - structure', () => {
  it('emits no insignificant whitespace', () => {
    assert.equal(canonicalize({ a: [1, 2, { b: 3 }] }), '{"a":[1,2,{"b":3}]}');
  });

  it('preserves array order', () => {
    assert.equal(canonicalize([3, 1, 2]), '[3,1,2]');
  });

  it('handles literals and empty containers', () => {
    assert.equal(
      canonicalize({ n: null, t: true, f: false, a: [], o: {} }),
      '{"a":[],"f":false,"n":null,"o":{},"t":true}',
    );
  });

  it('omits undefined and function members, as JSON.stringify does', () => {
    const input = { a: 1, b: undefined, c: () => 1, d: 2 };
    assert.equal(canonicalize(input), '{"a":1,"d":2}');
  });

  it('rejects undefined and bigint at the top level', () => {
    assert.throws(() => canonicalize(undefined), CanonicalizationError);
    assert.throws(() => canonicalize(1n), CanonicalizationError);
    assert.throws(() => canonicalize([undefined]), CanonicalizationError);
  });

  it('rejects cyclic structures instead of overflowing the stack', () => {
    const cyclic: Record<string, unknown> = { a: 1 };
    cyclic['self'] = cyclic;
    assert.throws(() => canonicalize(cyclic), CanonicalizationError);
  });

  it('allows the same object to appear twice without being cyclic', () => {
    const shared = { v: 1 };
    assert.equal(canonicalize({ a: shared, b: shared }), '{"a":{"v":1},"b":{"v":1}}');
  });
});

describe('JCS - RFC 8785 Appendix B', () => {
  it('matches the published canonical output', () => {
    // The RFC's own input document, parsed from its literal JSON text.
    const input: unknown = JSON.parse(
      String.raw`{
        "numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],
        "string": "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"/",
        "literals": [null, true, false]
      }`,
    );

    const expected =
      '{"literals":[null,true,false],' +
      '"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],' +
      '"string":"' +
      EURO +
      String.raw`$\u000f\nA'B\"\\\\\"/` +
      '"}';

    assert.equal(canonicalize(input), expected);
  });
});

describe('canonicalizeToBytes', () => {
  it('encodes as UTF-8', () => {
    const bytes = canonicalizeToBytes({ k: EURO });
    assert.equal(
      Buffer.from(bytes).toString('hex'),
      Buffer.from('{"k":"' + EURO + '"}', 'utf8').toString('hex'),
    );
    // Three bytes in UTF-8 (E2 82 AC), not the two of UTF-16.
    assert.ok(Buffer.from(bytes).includes(Buffer.from([0xe2, 0x82, 0xac])));
  });
});

describe('JCS - non-plain objects', () => {
  it('rejects objects whose JSON form depends on their prototype', () => {
    class Point {
      readonly x: number;
      constructor(x: number) {
        this.x = x;
      }
    }
    for (const bad of [new Date(0), new Map([['a', 1]]), new Set([1]), new Point(1), new Uint8Array(2)]) {
      assert.throws(() => canonicalize(bad), CanonicalizationError);
      assert.throws(() => canonicalize({ v: bad }), CanonicalizationError);
    }
  });

  it('accepts null-prototype objects', () => {
    const bare = Object.create(null) as Record<string, number>;
    bare['b'] = 2;
    bare['a'] = 1;
    assert.equal(canonicalize(bare), '{"a":1,"b":2}');
  });

  it('raises CanonicalizationError as an OtlCoreError', () => {
    assert.throws(() => canonicalize(undefined), OtlCoreError);
  });
});
