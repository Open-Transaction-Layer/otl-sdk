/**
 * `@otl/credentials` — verifiable credentials for the OTL Identity layer.
 *
 * LEI and hosting credentials are registered like any other credential type,
 * so adding a type means writing a `CredentialType` rather than touching the issuing or
 * verifying machinery.
 */

export * from './context-url.ts';
export * from './errors.ts';
export * from './registry.ts';
export * from './credential.ts';
export * from './trust.ts';
export * from './verify.ts';
export * from './lei/lei-code.ts';
export * from './lei/gleif.ts';
export * from './lei/type.ts';
export * from './hosting/type.ts';

import { CredentialTypeRegistry } from './registry.ts';
import { OtlLeiCredentialType } from './lei/type.ts';
import { OtlHostingCredentialType } from './hosting/type.ts';

/** A registry with the credential types this spec version defines (spec 4.7). */
export function defaultRegistry(): CredentialTypeRegistry {
  return new CredentialTypeRegistry()
    .register(new OtlLeiCredentialType())
    .register(new OtlHostingCredentialType());
}
