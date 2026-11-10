/**
 * Typed errors every provider must raise.
 *
 * Bridges MUST translate backend-native failures into these, so that callers
 * can branch on the failure mode without knowing which backend is in play.
 * The conformance kit checks this.
 */

export class KeyProviderError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = new.target.name;
  }
}

/** No key exists under this label. */
export class KeyNotFoundError extends KeyProviderError {
  readonly label: string;
  constructor(label: string, options?: { cause?: unknown }) {
    super(`No key found with label "${label}"`, options);
    this.label = label;
  }
}

/** A key already exists under this label; providers MUST NOT silently overwrite. */
export class KeyAlreadyExistsError extends KeyProviderError {
  readonly label: string;
  constructor(label: string) {
    super(`A key with label "${label}" already exists`);
    this.label = label;
  }
}

/**
 * The requested operation is not supported by this provider or this curve —
 * e.g. signing with X25519, or ECDH on a provider that has no key-agreement
 * primitive. Raised *before* any cryptographic work is attempted, never after
 * producing an unusable result.
 */
export class UnsupportedOperationError extends KeyProviderError {
  // Deliberately narrows the parent's signature: this error never wraps a cause.
  // eslint-disable-next-line @typescript-eslint/no-useless-constructor -- narrows the inherited signature
  constructor(message: string) {
    super(message);
  }
}

/** Key material or an encoded value was structurally invalid. */
export class InvalidKeyError extends KeyProviderError {}
