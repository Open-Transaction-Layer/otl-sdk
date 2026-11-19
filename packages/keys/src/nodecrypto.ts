/**
 * Thin binding between the OTL curve model and `node:crypto`.
 *
 * Exposed to provider authors through `@otl/keys/node`, so that every
 * Node-based provider shares exactly one implementation of each primitive and
 * none of them contains raw algorithm names.
 *
 * Node's `dsaEncoding: 'ieee-p1363'` gives us raw r‖s P-256 signatures
 * directly, so this package never performs a DER conversion. A bridge to a
 * backend that returns DER (KMS, Key Vault, most PKCS#11 modules) must do that
 * conversion itself — see `KeyProvider.sign`.
 */

import {
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  sign as nodeSign,
  verify as nodeVerify,
  type KeyObject,
} from 'node:crypto';
import { InvalidKeyError, UnsupportedOperationError } from './errors.ts';
import { PUBLIC_KEY_LENGTH, type Curve, type PublicKey } from './types.ts';

const b64u = (b: Uint8Array): string => Buffer.from(b).toString('base64url');
const unb64u = (s: string): Uint8Array => new Uint8Array(Buffer.from(s, 'base64url'));

export function generateKeyObject(curve: Curve): { privateKey: KeyObject; publicKey: KeyObject } {
  switch (curve) {
    case 'Ed25519':
      return generateKeyPairSync('ed25519');
    case 'X25519':
      return generateKeyPairSync('x25519');
    case 'P-256':
      return generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  }
}

/** Extract the canonical raw public key (see {@link PublicKey}) from a key object. */
export function publicKeyFrom(key: KeyObject, curve: Curve): PublicKey {
  // `createPublicKey` derives the public half from a private key, but rejects
  // a key object that is already public — so only convert when we need to.
  const pub = key.type === 'public' ? key : createPublicKey(key);
  const jwk = pub.export({ format: 'jwk' }) as { x?: string; y?: string };
  if (jwk.x === undefined || jwk.x === '')
    throw new InvalidKeyError(`Key object for ${curve} has no public coordinate`);

  if (curve === 'P-256') {
    if (jwk.y === undefined || jwk.y === '')
      throw new InvalidKeyError('P-256 key object has no y coordinate');
    // SEC1 uncompressed: 0x04 || X || Y, each coordinate left-padded to 32 bytes.
    const x = pad32(unb64u(jwk.x));
    const y = pad32(unb64u(jwk.y));
    return { curve, bytes: Uint8Array.from([0x04, ...x, ...y]) };
  }

  const bytes = unb64u(jwk.x);
  if (bytes.length !== PUBLIC_KEY_LENGTH[curve]) {
    throw new InvalidKeyError(`Expected ${PUBLIC_KEY_LENGTH[curve]} bytes for ${curve}, got ${bytes.length}`);
  }
  return { curve, bytes };
}

function pad32(b: Uint8Array): Uint8Array {
  if (b.length === 32) return b;
  if (b.length > 32) throw new InvalidKeyError(`Coordinate longer than 32 bytes (${b.length})`);
  const out = new Uint8Array(32);
  out.set(b, 32 - b.length);
  return out;
}

/** Rebuild a node public key object from canonical raw bytes. */
export function importPublicKey(key: PublicKey): KeyObject {
  const expected = PUBLIC_KEY_LENGTH[key.curve];
  if (key.bytes.length !== expected) {
    throw new InvalidKeyError(
      `Expected ${expected} bytes for a ${key.curve} public key, got ${key.bytes.length}`,
    );
  }

  if (key.curve === 'P-256') {
    if (key.bytes[0] !== 0x04) {
      throw new InvalidKeyError('P-256 public key must be SEC1 uncompressed (leading 0x04)');
    }
    return createPublicKey({
      format: 'jwk',
      key: {
        kty: 'EC',
        crv: 'P-256',
        x: b64u(key.bytes.slice(1, 33)),
        y: b64u(key.bytes.slice(33, 65)),
      },
    });
  }

  return createPublicKey({
    format: 'jwk',
    key: { kty: 'OKP', crv: key.curve, x: b64u(key.bytes) },
  });
}

/**
 * Sign the full message with a raw, fixed-width signature.
 * X25519 deliberately has no case here — it is a key-agreement curve only.
 */
export function signWith(privateKey: KeyObject, curve: Curve, message: Uint8Array): Uint8Array {
  switch (curve) {
    case 'Ed25519':
      return new Uint8Array(nodeSign(null, message, privateKey));
    case 'P-256':
      return new Uint8Array(nodeSign('sha256', message, { key: privateKey, dsaEncoding: 'ieee-p1363' }));
    case 'X25519':
      throw new UnsupportedOperationError('X25519 is a key-agreement curve and cannot sign');
  }
}

/** Verify a raw fixed-width signature. Used by the conformance kit and `otl verify`. */
export function verifyWith(publicKey: PublicKey, message: Uint8Array, signature: Uint8Array): boolean {
  const keyObject = importPublicKey(publicKey);
  switch (publicKey.curve) {
    case 'Ed25519':
      return nodeVerify(null, message, keyObject, signature);
    case 'P-256':
      return nodeVerify('sha256', message, { key: keyObject, dsaEncoding: 'ieee-p1363' }, signature);
    case 'X25519':
      throw new UnsupportedOperationError('X25519 is a key-agreement curve and cannot verify signatures');
  }
}

/** Raw ECDH shared secret Z. Key derivation and the envelope happen in `@otl/jwe`. */
export function deriveSharedSecretWith(
  privateKey: KeyObject,
  curve: Curve,
  peerPublicKey: PublicKey,
): Uint8Array {
  if (peerPublicKey.curve !== curve) {
    throw new UnsupportedOperationError(
      `Key agreement requires matching curves; local key is ${curve} but peer key is ${peerPublicKey.curve}`,
    );
  }
  if (curve === 'Ed25519') {
    throw new UnsupportedOperationError(
      'Ed25519 is a signing curve and cannot perform key agreement; use X25519',
    );
  }
  return new Uint8Array(diffieHellman({ privateKey, publicKey: importPublicKey(peerPublicKey) }));
}

/** PKCS#8 DER, for at-rest storage by non-production providers only. */
export const exportPkcs8 = (privateKey: KeyObject): Uint8Array =>
  new Uint8Array(privateKey.export({ format: 'der', type: 'pkcs8' }) as Buffer);

export const importPkcs8 = (der: Uint8Array): KeyObject =>
  createPrivateKey({ key: Buffer.from(der), format: 'der', type: 'pkcs8' });
