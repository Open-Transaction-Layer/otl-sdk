/**
 * Binary <-> text encodings used by the OTL Identity layer.
 *
 * Kept in one place, and out of providers entirely, so that two bridges can
 * never disagree about how a key or signature is represented.
 */

import { ECDH } from 'node:crypto';
import { InvalidKeyError } from './errors.ts';
import { PUBLIC_KEY_LENGTH, type Curve, type PublicKey } from './types.ts';

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

/**
 * Read an element the caller has already bounds-checked.
 *
 * With `noUncheckedIndexedAccess` an index read is `T | undefined`. Every call
 * site here is inside a loop bounded by the array's own length, so the
 * `undefined` branch cannot happen; throwing, rather than defaulting to 0, is
 * the safe outcome if that ever stops being true, because a defaulted byte
 * would silently corrupt a key or make two different values compare equal.
 */
function at<T>(items: ArrayLike<T>, index: number): T {
  const item = items[index];
  if (item === undefined) throw new InvalidKeyError(`Index ${index} is out of range`);
  return item;
}

/** base58btc — the alphabet omits 0, O, I and l to avoid transcription errors. */
export function base58btcEncode(bytes: Uint8Array): string {
  if (bytes.length === 0) return '';

  // Count leading zero bytes; each becomes a literal '1'.
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++;

  // Repeated division of the whole byte array by 58.
  const digits: number[] = [];
  const buf = Uint8Array.from(bytes);
  let start = zeros;
  while (start < buf.length) {
    let remainder = 0;
    for (let i = start; i < buf.length; i++) {
      const acc = (remainder << 8) | at(buf, i);
      buf[i] = Math.floor(acc / 58);
      remainder = acc % 58;
    }
    digits.push(remainder);
    while (start < buf.length && buf[start] === 0) start++;
  }

  return (
    '1'.repeat(zeros) +
    digits
      .reverse()
      .map((d) => at(BASE58_ALPHABET, d))
      .join('')
  );
}

export function base58btcDecode(text: string): Uint8Array {
  if (text.length === 0) return new Uint8Array(0);

  let zeros = 0;
  while (zeros < text.length && text[zeros] === '1') zeros++;

  const bytes: number[] = [];
  for (let i = zeros; i < text.length; i++) {
    const value = BASE58_ALPHABET.indexOf(at(text, i));
    if (value === -1) {
      throw new InvalidKeyError(`Invalid base58btc character "${text[i]}" at index ${i}`);
    }
    let carry = value;
    for (let j = 0; j < bytes.length; j++) {
      const acc = at(bytes, j) * 58 + carry;
      bytes[j] = acc & 0xff;
      carry = acc >> 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }

  return Uint8Array.from([...new Array<number>(zeros).fill(0), ...bytes.reverse()]);
}

/**
 * Multibase prefixes (https://github.com/multiformats/multibase).
 * Only the two the Identity layer uses are defined here.
 */
export const MULTIBASE_BASE58BTC = 'z';
export const MULTIBASE_BASE64URL = 'u';

/** Encode as multibase base58btc — the `z...` form used for keys and proofValue. */
export const toMultibaseBase58 = (bytes: Uint8Array): string => MULTIBASE_BASE58BTC + base58btcEncode(bytes);

export function fromMultibaseBase58(text: string): Uint8Array {
  if (!text.startsWith(MULTIBASE_BASE58BTC)) {
    throw new InvalidKeyError(
      `Expected a multibase base58btc string starting with "${MULTIBASE_BASE58BTC}", got "${text.slice(0, 8)}…"`,
    );
  }
  return base58btcDecode(text.slice(1));
}

/** Encode as multibase base64url — the `u...` form used for status-list bitstrings. */
export const toMultibaseBase64url = (bytes: Uint8Array): string =>
  MULTIBASE_BASE64URL + Buffer.from(bytes).toString('base64url');

export function fromMultibaseBase64url(text: string): Uint8Array {
  if (!text.startsWith(MULTIBASE_BASE64URL)) {
    throw new InvalidKeyError(
      `Expected a multibase base64url string starting with "${MULTIBASE_BASE64URL}", got "${text.slice(0, 8)}…"`,
    );
  }
  return new Uint8Array(Buffer.from(text.slice(1), 'base64url'));
}

/**
 * Multicodec prefixes for public keys, as varints.
 *
 * Per the Multikey specification, P-256 keys are encoded in their *compressed*
 * 33-byte form, while Ed25519 and X25519 use their natural 32-byte form.
 */
const MULTICODEC_PREFIX: Readonly<Record<Curve, Uint8Array>> = {
  Ed25519: Uint8Array.from([0xed, 0x01]),
  X25519: Uint8Array.from([0xec, 0x01]),
  'P-256': Uint8Array.from([0x80, 0x24]),
};

/** Compress a SEC1 uncompressed P-256 point (65 bytes) to its 33-byte form. */
export function compressP256(uncompressed: Uint8Array): Uint8Array {
  if (uncompressed.length !== 65 || uncompressed[0] !== 0x04) {
    throw new InvalidKeyError('Expected a 65-byte SEC1 uncompressed P-256 point beginning with 0x04');
  }
  // Omitting the encodings makes node return a Buffer rather than a string.
  try {
    return new Uint8Array(
      ECDH.convertKey(Buffer.from(uncompressed), 'prime256v1', undefined, undefined, 'compressed') as Buffer,
    );
  } catch (cause) {
    throw new InvalidKeyError('Not a valid point on the P-256 curve', { cause });
  }
}

/** Expand a compressed P-256 point (33 bytes) back to SEC1 uncompressed (65 bytes). */
export function decompressP256(compressed: Uint8Array): Uint8Array {
  if (compressed.length !== 33 || (compressed[0] !== 0x02 && compressed[0] !== 0x03)) {
    throw new InvalidKeyError('Expected a 33-byte compressed P-256 point beginning with 0x02 or 0x03');
  }
  try {
    return new Uint8Array(
      ECDH.convertKey(Buffer.from(compressed), 'prime256v1', undefined, undefined, 'uncompressed') as Buffer,
    );
  } catch (cause) {
    throw new InvalidKeyError('Not a valid point on the P-256 curve', { cause });
  }
}

/**
 * Render a public key as `publicKeyMultibase` — the multicodec-prefixed,
 * multibase-base58btc form that appears in DID documents and in the
 * did:webvh `updateKeys` parameter.
 */
export function toPublicKeyMultibase(key: PublicKey): string {
  const prefix = MULTICODEC_PREFIX[key.curve];
  const payload = key.curve === 'P-256' ? compressP256(key.bytes) : key.bytes;
  return toMultibaseBase58(Uint8Array.from([...prefix, ...payload]));
}

/** Inverse of {@link toPublicKeyMultibase}. */
export function fromPublicKeyMultibase(multibase: string): PublicKey {
  const decoded = fromMultibaseBase58(multibase);

  for (const [curve, prefix] of Object.entries(MULTICODEC_PREFIX) as [Curve, Uint8Array][]) {
    if (decoded.length < prefix.length) continue;
    if (!prefix.every((b, i) => decoded[i] === b)) continue;

    const payload = decoded.slice(prefix.length);
    const bytes = curve === 'P-256' ? decompressP256(payload) : payload;
    if (bytes.length !== PUBLIC_KEY_LENGTH[curve]) {
      throw new InvalidKeyError(
        `Multikey declares ${curve} but carries ${bytes.length} bytes; expected ${PUBLIC_KEY_LENGTH[curve]}`,
      );
    }
    return { curve, bytes };
  }

  throw new InvalidKeyError('Unrecognized multicodec prefix; not an Ed25519, X25519 or P-256 Multikey');
}

/**
 * Render a public key as a JWK — the form `JsonWebKey2020` verification method
 * entries carry (OTL spec 3.1).
 */
export function toPublicKeyJwk(key: PublicKey): Record<string, string> {
  const b64u = (b: Uint8Array): string => Buffer.from(b).toString('base64url');
  switch (key.curve) {
    case 'P-256':
      if (key.bytes.length !== 65 || key.bytes[0] !== 0x04) {
        throw new InvalidKeyError('P-256 public key must be SEC1 uncompressed (leading 0x04)');
      }
      return { kty: 'EC', crv: 'P-256', x: b64u(key.bytes.slice(1, 33)), y: b64u(key.bytes.slice(33, 65)) };
    case 'Ed25519':
    case 'X25519':
      return { kty: 'OKP', crv: key.curve, x: b64u(key.bytes) };
  }
}

/** Inverse of {@link toPublicKeyJwk}. */
export function fromPublicKeyJwk(jwk: Record<string, unknown>): PublicKey {
  const unb64u = (v: unknown): Uint8Array => {
    if (typeof v !== 'string') throw new InvalidKeyError('JWK coordinate must be a string');
    return new Uint8Array(Buffer.from(v, 'base64url'));
  };

  switch (jwk['crv']) {
    case 'P-256': {
      const x = unb64u(jwk['x']);
      const y = unb64u(jwk['y']);
      if (x.length !== 32 || y.length !== 32) {
        throw new InvalidKeyError('P-256 JWK coordinates must each be 32 bytes');
      }
      return { curve: 'P-256', bytes: Uint8Array.from([0x04, ...x, ...y]) };
    }
    case 'Ed25519':
    case 'X25519': {
      const bytes = unb64u(jwk['x']);
      if (bytes.length !== 32) {
        throw new InvalidKeyError(`${jwk['crv']} JWK coordinate must be 32 bytes`);
      }
      return { curve: jwk['crv'], bytes };
    }
    default:
      throw new InvalidKeyError(`Unsupported JWK curve "${String(jwk['crv'])}"`);
  }
}

/** Constant-time-ish byte comparison, for comparing key material and hashes. */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= at(a, i) ^ at(b, i);
  return diff === 0;
}
