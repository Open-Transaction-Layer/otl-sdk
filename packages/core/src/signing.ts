/**
 * Message signing and verification (the CLI's `sign` and `verify`).
 *
 * Two forms, kept deliberately separate:
 *
 *  - **Document signing** attaches a `DataIntegrityProof` and is what the spec
 *    defines (6.3). Use it for anything another OTL implementation will read.
 *  - **Raw signing** produces a detached signature over arbitrary bytes. The
 *    spec says nothing about this; it exists because operators need to sign
 *    things that are not JSON documents.
 *
 * They are not interchangeable, and the separation is the point: a raw
 * signature carries no `verificationMethod`, no `proofPurpose` and no binding
 * to a document, so it must never be presented as a spec-conformant proof.
 */

import {
  toMultibaseBase58,
  fromMultibaseBase58,
  verifySignature,
  type KeyProvider,
  type PublicKey,
} from '@otl/keys';
import { OtlCoreError } from './errors.ts';

export class SigningError extends OtlCoreError {}

export interface SignRawOptions {
  readonly message: Uint8Array | string;
  readonly provider: KeyProvider;
  readonly keyLabel: string;
}

/** Sign arbitrary bytes. Returns a detached multibase base58btc signature. */
export async function signRaw(options: SignRawOptions): Promise<string> {
  const { message, provider, keyLabel } = options;
  const bytes = typeof message === 'string' ? new TextEncoder().encode(message) : message;
  return toMultibaseBase58(await provider.sign(keyLabel, bytes));
}

export interface VerifyRawOptions {
  readonly message: Uint8Array | string;
  /** Multibase base58btc, as produced by {@link signRaw}. */
  readonly signature: string;
  readonly publicKey: PublicKey;
}

/**
 * Verify a detached signature.
 *
 * Returns a boolean rather than throwing: a bad signature is an expected
 * outcome of verification, not an exceptional condition. Malformed input is
 * distinguished, because "this is not a signature" and "this signature does not
 * match" are different problems for an operator.
 */
export function verifyRaw(options: VerifyRawOptions): boolean {
  const { message, signature, publicKey } = options;

  let decoded: Uint8Array;
  try {
    decoded = fromMultibaseBase58(signature);
  } catch (cause) {
    throw new SigningError(`Signature is not multibase base58btc: ${(cause as Error).message}`, { cause });
  }

  const bytes = typeof message === 'string' ? new TextEncoder().encode(message) : message;
  try {
    return verifySignature(publicKey, bytes, decoded);
  } catch (cause) {
    throw new SigningError(`Could not verify signature: ${(cause as Error).message}`, { cause });
  }
}
