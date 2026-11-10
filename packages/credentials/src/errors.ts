export class CredentialError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = new.target.name;
  }
}

/** A credential was structurally invalid for its declared type. */
export class InvalidCredentialError extends CredentialError {}

/** A credential type was requested that is not registered. */
export class UnknownCredentialTypeError extends CredentialError {
  readonly typeName: string;
  constructor(typeName: string) {
    super(`No credential type registered under "${typeName}"`);
    this.typeName = typeName;
  }
}

/** An upstream registry (e.g. GLEIF) could not be reached or returned junk. */
export class RegistryLookupError extends CredentialError {}
