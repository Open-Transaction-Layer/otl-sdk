/** Errors raised by the protocol core. */

export class OtlCoreError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = new.target.name;
  }
}

/** A document was structurally invalid for the operation requested. */
export class InvalidDocumentError extends OtlCoreError {}

/** A proof could not be constructed or was malformed. */
export class ProofError extends OtlCoreError {}

/** A cryptosuite was unknown, or inconsistent with the key it was used with. */
export class CryptosuiteMismatchError extends OtlCoreError {}
