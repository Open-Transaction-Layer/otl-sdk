/**
 * Ephemeral key agreement.
 *
 * ECDH-ES derives a content key from a fresh sender keypair and the
 * recipient's static public key, so the sender needs no stored key at all —
 * which is why this lives outside {@link KeyProvider}. An ephemeral key exists
 * for one message and is discarded; putting it through a KMS or HSM would add
 * custody machinery to something with nothing to custody, and would make
 * encryption impossible for a sign-only provider.
 *
 * The recipient's side is different: decryption uses their long-lived private
 * key and therefore does go through the provider's `deriveSharedSecret`.
 */

import { generateKeyObject, publicKeyFrom, deriveSharedSecretWith } from './nodecrypto.ts';
import { UnsupportedOperationError } from './errors.ts';
import { isKeyAgreementCurve, type Curve, type PublicKey } from './types.ts';

export interface EphemeralAgreement {
  /** Public half, to be published in the message header so the recipient can derive. */
  readonly ephemeralPublicKey: PublicKey;
  /** Raw shared secret Z. Key derivation happens in `@open-transaction-layer/jwe`. */
  readonly sharedSecret: Uint8Array;
}

/**
 * Generate a one-time keypair on the recipient key's curve and derive a shared secret with
 * `recipientPublicKey`. The private half never leaves this function.
 */
export function agreeEphemeral(recipientPublicKey: PublicKey): EphemeralAgreement {
  const curve: Curve = recipientPublicKey.curve;
  if (!isKeyAgreementCurve(curve)) {
    throw new UnsupportedOperationError(
      `${curve} is a signing curve and cannot perform key agreement; the recipient must publish an X25519 or P-256 keyAgreement key`,
    );
  }

  const { privateKey, publicKey } = generateKeyObject(curve);
  return {
    ephemeralPublicKey: publicKeyFrom(publicKey, curve),
    sharedSecret: deriveSharedSecretWith(privateKey, curve, recipientPublicKey),
  };
}
