/**
 * Data Integrity cryptosuites permitted by the OTL Identity layer (spec 6.3).
 *
 * A cryptosuite name pins the signature algorithm *and* the canonicalization
 * together, so a verifier never has to negotiate or guess — and cannot be
 * talked into a weaker combination.
 */

import type { Curve } from '@otl/keys';
import { CryptosuiteMismatchError } from './errors.ts';

export type CryptosuiteName = 'eddsa-jcs-2022' | 'ecdsa-jcs-2019';

export const CRYPTOSUITES: readonly CryptosuiteName[] = ['eddsa-jcs-2022', 'ecdsa-jcs-2019'];

/** The one cryptosuite a given signing curve may use. */
export function cryptosuiteForCurve(curve: Curve): CryptosuiteName {
  switch (curve) {
    case 'Ed25519':
      return 'eddsa-jcs-2022';
    case 'P-256':
      return 'ecdsa-jcs-2019';
    case 'X25519':
      throw new CryptosuiteMismatchError('X25519 is a key-agreement curve and has no signature cryptosuite');
  }
}

/** The one curve a given cryptosuite may be used with. */
export function curveForCryptosuite(cryptosuite: string): Curve {
  switch (cryptosuite) {
    case 'eddsa-jcs-2022':
      return 'Ed25519';
    case 'ecdsa-jcs-2019':
      return 'P-256';
    default:
      throw new CryptosuiteMismatchError(
        `Unsupported cryptosuite "${cryptosuite}"; the Identity layer permits ${CRYPTOSUITES.join(' or ')}`,
      );
  }
}

/**
 * Reject a proof whose declared cryptosuite does not match the key being used
 * to verify it.
 *
 * Without this check a document could declare `eddsa-jcs-2022` while being
 * verified against a P-256 key, letting an attacker steer a verifier onto an
 * algorithm/key pairing neither party intended.
 */
export function assertCryptosuiteMatchesCurve(cryptosuite: string, curve: Curve): void {
  const expected = curveForCryptosuite(cryptosuite);
  if (expected !== curve) {
    throw new CryptosuiteMismatchError(
      `Proof declares cryptosuite "${cryptosuite}" (${expected}) but the verification key is ${curve}`,
    );
  }
}
