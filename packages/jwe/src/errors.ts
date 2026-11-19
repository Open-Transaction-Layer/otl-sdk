/**
 * Errors raised by `@otl/jwe`.
 *
 * The package carries its own base class rather than extending `OtlCoreError`
 * from `@otl/core`, because depending on the protocol core for one small base
 * class would drag DID and credential machinery into a package that has
 * nothing to do with either.
 */

export class OtlJweError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = new.target.name;
  }
}

/** Encryption or decryption failed, or the input was not a valid message. */
export class EncryptionError extends OtlJweError {}
