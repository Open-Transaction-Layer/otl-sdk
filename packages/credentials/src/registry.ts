/**
 * Credential-type registry (OTL spec 4.1-4.5).
 *
 * The spec splits itself into a general framework (4.1-4.5) and LEI as its
 * first instance (4.6-4.11), explicitly as "a template for how a future
 * credential type would specify itself". This registry mirrors that split, so
 * adding a type is a registration rather than a change to the issuing
 * and verifying machinery.
 */

import { UnknownCredentialTypeError } from './errors.ts';

export interface SubjectValidation {
  readonly valid: boolean;
  readonly issues: readonly string[];
}

export const validSubject: SubjectValidation = { valid: true, issues: [] };
export const invalidSubject = (...issues: string[]): SubjectValidation => ({ valid: false, issues });

/**
 * One credential type. `TInput` is whatever the issuer supplies (for LEI, an
 * LEI code and a subject DID); `TSubject` is the `credentialSubject` payload.
 */
// `TSubject` documents the `credentialSubject` shape for implementers and
// callers; no member references it.
// eslint-disable-next-line @typescript-eslint/no-unused-vars -- documents the subject shape
export interface CredentialType<TInput = unknown, TSubject = unknown> {
  /** Second element of the `type` array, e.g. `OtlLeiCredential` (spec 4.3). */
  readonly typeName: string;
  /** Contexts beyond `credentials/v2` this type requires. */
  readonly additionalContexts: readonly string[];
  /** Spec 4.3: `MAY` in general; a type may strengthen it to `MUST` (LEI does). */
  readonly requiresCredentialStatus: boolean;
  /** Spec 4.3: `validUntil` is `MAY` in general; a type may require it (LEI does, 4.8). */
  readonly requiresValidUntil: boolean;
  /** Spec 4.3: self-issued credentials are invalid unless a type allows it. */
  readonly allowsSelfIssuance: boolean;

  buildSubject(input: TInput): Promise<Record<string, unknown>>;
  validateSubject(subject: unknown): SubjectValidation;

  /**
   * Optional checks spanning the whole credential rather than its subject.
   *
   * `validateSubject` only ever sees `credentialSubject`, so a rule relating an
   * outer field to a subject field — LEI's `validUntil <= nextRenewalDate`
   * (spec 4.8) — has nowhere else to live. Applied at issuance and at
   * verification, so the two cannot drift.
   */
  validateCredential?(credential: Record<string, unknown>): SubjectValidation;

  /**
   * The `validUntil` to use when the issuer supplies none.
   *
   * A type that requires expiry usually knows when the thing it attests stops
   * being true — for LEI, the registration's own renewal date — so the issuer
   * should not have to restate it and risk contradicting the subject.
   */
  defaultValidUntil?(subject: Record<string, unknown>): string | undefined;
}

export class CredentialTypeRegistry {
  readonly #types = new Map<string, CredentialType<never, never>>();

  register<TInput, TSubject>(type: CredentialType<TInput, TSubject>): this {
    this.#types.set(type.typeName, type);
    return this;
  }

  /** @throws {UnknownCredentialTypeError} */
  get(typeName: string): CredentialType {
    const type = this.#types.get(typeName);
    if (!type) throw new UnknownCredentialTypeError(typeName);
    return type;
  }

  has(typeName: string): boolean {
    return this.#types.has(typeName);
  }

  typeNames(): string[] {
    return [...this.#types.keys()];
  }

  /**
   * Identify a credential by inspecting its own `type` array (spec 4.4).
   *
   * Returns `undefined` for an unrecognized type rather than throwing:
   * "Unrecognized types MUST be skipped gracefully, not treated as an error."
   * This is what lets a verifier keep working as new types are introduced.
   */
  identify(credential: unknown): CredentialType | undefined {
    const types = (credential as { type?: unknown } | null | undefined)?.type;
    if (!Array.isArray(types)) return undefined;
    for (const name of types) {
      if (typeof name === 'string' && this.#types.has(name)) {
        return this.#types.get(name);
      }
    }
    return undefined;
  }
}
