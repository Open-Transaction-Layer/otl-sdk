/**
 * JSON Canonicalization Scheme (RFC 8785).
 *
 * Signatures are computed over bytes, so two implementations that serialize the
 * same data differently produce signatures that will not verify against each
 * other. JCS fixes one serialization: keys sorted, no insignificant whitespace,
 * one number format, one string escaping.
 *
 * ## Why this is written out by hand
 *
 * The obvious implementation — rebuild the object with sorted keys, then call
 * `JSON.stringify` — is wrong. ECMAScript orders integer-like own properties
 * numerically and ahead of all string keys, regardless of insertion order:
 *
 * ```js
 * const o = {}; o['9'] = 1; o['10'] = 2;
 * JSON.stringify(o);          // {"9":1,"10":2}
 * ```
 *
 * RFC 8785 sorts by UTF-16 code unit, which puts `"10"` before `"9"`. Any
 * document with numeric-looking keys would therefore canonicalize differently
 * from every conforming implementation, and the only symptom would be an
 * unhelpful "invalid signature". So the serializer emits the string itself and
 * never relies on property enumeration order.
 *
 * Scalars are delegated to `JSON.stringify`, which is correct by construction:
 * RFC 8785 defines its number format as ECMAScript `Number::toString` and its
 * string escaping as ES2019 well-formed `JSON.stringify`.
 */

import { OtlCoreError } from './errors.ts';

/** Any value representable in JSON. */
export type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue };

/** A value could not be canonicalized because JSON cannot represent it. */
export class CanonicalizationError extends OtlCoreError {}

/**
 * Serialize `value` to its RFC 8785 canonical form.
 *
 * @throws {CanonicalizationError} for input JSON cannot represent: non-finite
 * numbers, `undefined`, functions, symbols, bigints, cyclic structures, or
 * objects that are neither arrays nor plain objects (such as `Date`, `Map` or
 * a class instance), whose JSON form would otherwise depend on their prototype.
 */
export function canonicalize(value: unknown): string {
  return serialize(value, new Set(), '');
}

/** Canonical form as UTF-8 bytes — what actually gets hashed and signed. */
export const canonicalizeToBytes = (value: unknown): Uint8Array =>
  new TextEncoder().encode(canonicalize(value));

/** Locate a value inside an error message; the root has no path. */
const at = (path: string): string => (path === '' ? '' : ` at ${path}`);

function serialize(value: unknown, seen: Set<object>, path: string): string {
  if (value === null) return 'null';

  switch (typeof value) {
    case 'boolean':
      return value ? 'true' : 'false';

    case 'number':
      if (!Number.isFinite(value)) {
        throw new CanonicalizationError(`JSON cannot represent ${String(value)}${at(path)}`);
      }
      // RFC 8785 numbers are ECMAScript Number::toString, which is exactly
      // what JSON.stringify emits. Note -0 serializes as "0", per the RFC.
      return JSON.stringify(value);

    case 'string':
      // ES2019 well-formed JSON.stringify matches RFC 8785 escaping: the short
      // escapes for \b \t \n \f \r \" \\, \uXXXX for other C0 controls, and
      // everything else emitted as literal UTF-8.
      return serializeString(value, path);

    case 'undefined':
      throw new CanonicalizationError(`JSON cannot represent undefined${at(path)}`);
    case 'function':
    case 'symbol':
      throw new CanonicalizationError(`JSON cannot represent a ${typeof value}${at(path)}`);
    case 'bigint':
      throw new CanonicalizationError(
        `JSON cannot represent a bigint${at(path)}; convert it to a string or number first`,
      );
    case 'object':
      // Arrays and plain objects are handled below.
      break;
  }

  const object = value;
  if (!Array.isArray(object)) {
    const prototype: unknown = Object.getPrototypeOf(object);
    if (prototype !== Object.prototype && prototype !== null) {
      const name = (object as { constructor?: { name?: unknown } }).constructor?.name;
      throw new CanonicalizationError(
        `JSON cannot represent a ${typeof name === 'string' && name !== '' ? name : 'non-plain object'}${at(path)}; ` +
          `convert it to a plain object, array or string first`,
      );
    }
  }
  if (seen.has(object)) {
    throw new CanonicalizationError(`Cyclic structure detected${at(path)}`);
  }
  seen.add(object);
  try {
    return Array.isArray(object)
      ? serializeArray(object, seen, path)
      : serializeObject(object as Record<string, unknown>, seen, path);
  } finally {
    seen.delete(object);
  }
}

/**
 * RFC 8785 requires I-JSON input, which excludes lone surrogates. They have no
 * UTF-8 encoding, so two implementations would hash them differently; refusing
 * them is the only answer that cannot disagree with another implementation.
 */
function serializeString(value: string, path: string): string {
  // In a `u` regular expression a valid pair is one code point, so only an
  // unpaired surrogate matches.
  if (/\p{Surrogate}/u.test(value)) {
    throw new CanonicalizationError(`String contains a lone surrogate${at(path)}`);
  }
  return JSON.stringify(value);
}

function serializeArray(array: unknown[], seen: Set<object>, path: string): string {
  // An index loop, not map: map skips the holes of a sparse array, which would
  // leave an empty slot and emit something that is not JSON at all.
  const items: string[] = [];
  for (let index = 0; index < array.length; index++) {
    if (!Object.hasOwn(array, index)) {
      throw new CanonicalizationError(`JSON cannot represent an array hole at ${path}[${index}]`);
    }
    items.push(serialize(array[index], seen, `${path}[${index}]`));
  }
  return `[${items.join(',')}]`;
}

function serializeObject(object: Record<string, unknown>, seen: Set<object>, path: string): string {
  const members: string[] = [];

  // Own enumerable string keys only — inherited and symbol keys are not JSON.
  // Sorting here, and emitting the string ourselves, is what sidesteps
  // ECMAScript's integer-key reordering. See the module comment.
  for (const key of Object.keys(object).sort(compareByUtf16CodeUnits)) {
    const child = object[key];
    // Matching JSON.stringify: a property whose value is undefined or a
    // function is omitted rather than being an error.
    if (child === undefined || typeof child === 'function' || typeof child === 'symbol') continue;
    const childPath = path !== '' ? `${path}.${key}` : key;
    members.push(`${serializeString(key, childPath)}:${serialize(child, seen, childPath)}`);
  }

  return `{${members.join(',')}}`;
}

/**
 * Compare by UTF-16 code unit, as RFC 8785 requires.
 *
 * `Array.prototype.sort`'s default comparator already does this, but it is
 * spelled out rather than relying on the default, because a future reader
 * reaching for `localeCompare` here would silently break canonicalization for
 * any document with non-ASCII keys.
 */
function compareByUtf16CodeUnits(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}
