/**
 * Generic verifiable credential assembly (OTL spec 4.3).
 *
 * Every OTL credential shares this outer shape; a type's own specification
 * fixes some fields and defines its own `credentialSubject`.
 */

import { randomUUID } from 'node:crypto';
import { createProof, type BitstringStatusListEntry, type Document } from '@otl/core';
import type { KeyProvider } from '@otl/keys';
import { InvalidCredentialError } from './errors.ts';
import type { CredentialType } from './registry.ts';

export const CREDENTIALS_V2_CONTEXT = 'https://www.w3.org/ns/credentials/v2';

export interface VerifiableCredential extends Document {
  readonly '@context': readonly string[];
  readonly id: string;
  readonly type: readonly string[];
  readonly issuer: string;
  readonly validFrom: string;
  /** Spec 4.3. `MAY` in general; a type may strengthen it to `MUST` (LEI does). */
  readonly validUntil?: string;
  readonly credentialSubject: Record<string, unknown> & { readonly id: string };
  readonly credentialStatus?: readonly BitstringStatusListEntry[];
}

export interface IssueCredentialOptions<TInput> {
  readonly type: CredentialType<TInput>;
  readonly input: TInput;
  /** did:webvh of the issuing party (spec 4.2). */
  readonly issuer: string;
  /** did:webvh of the subject. */
  readonly subject: string;
  readonly provider: KeyProvider;
  /** Label of the credential signing key in the provider. */
  readonly keyLabel: string;
  /**
   * Full reference to the signing key, e.g. `did:webvh:lou.example#vc-key-1`.
   *
   * Spec 3.2.1 fixes no id — "a verifier finds it through the
   * `verificationMethod` of the credential's proof" — so the issuer chooses it,
   * and MUST reference it from its own `assertionMethod`.
   */
  readonly verificationMethod: string;
  /** Revocation pointer. Required when the type demands one (spec 4.8 for LEI). */
  readonly credentialStatus?: readonly BitstringStatusListEntry[];
  /** ISO 8601. Defaults to now. */
  readonly validFrom?: string;
  /** ISO 8601. Required when the type demands it (spec 4.8 for LEI). */
  readonly validUntil?: string;
  /** Credential id. Defaults to a fresh `urn:uuid:`. */
  readonly id?: string;
}

/** Build and sign a credential of the given type. */
export async function issueCredential<TInput>(
  options: IssueCredentialOptions<TInput>,
): Promise<VerifiableCredential> {
  const {
    type,
    input,
    issuer,
    subject,
    provider,
    keyLabel,
    verificationMethod,
    credentialStatus,
    validFrom = new Date().toISOString(),
    validUntil,
    id = `urn:uuid:${randomUUID()}`,
  } = options;

  if (!verificationMethod.startsWith(`${issuer}#`)) {
    throw new InvalidCredentialError(
      `verificationMethod "${verificationMethod}" is not a key of the issuer "${issuer}" (spec 3.2.1)`,
    );
  }

  // Spec 4.3: "Self-issued credentials (issuer equal to credentialSubject.id)
  // are invalid unless a specific credential type's own rules explicitly allow
  // self-issuance." Refused at issuance so we never mint something every
  // verifier would reject.
  if (issuer === subject && !type.allowsSelfIssuance) {
    throw new InvalidCredentialError(
      `${type.typeName} may not be self-issued: issuer and credentialSubject.id are both "${issuer}"`,
    );
  }

  if (type.requiresCredentialStatus && (credentialStatus === undefined || credentialStatus.length === 0)) {
    throw new InvalidCredentialError(
      `${type.typeName} requires a credentialStatus entry; verifiers MUST check revocation before trusting it`,
    );
  }

  const subjectPayload = await type.buildSubject(input);
  const validation = type.validateSubject({ ...subjectPayload, id: subject });
  if (!validation.valid) {
    throw new InvalidCredentialError(
      `${type.typeName} credentialSubject is invalid: ${validation.issues.join('; ')}`,
    );
  }

  const expiry = validUntil ?? type.defaultValidUntil?.(subjectPayload);

  // Refused at issuance so we never mint something every verifier would reject
  // under spec 5.3's binding checks.
  if (type.requiresValidUntil && expiry === undefined) {
    throw new InvalidCredentialError(
      `${type.typeName} requires validUntil; verifiers MUST reject it as expired without one (spec 4.8)`,
    );
  }

  const unsigned: VerifiableCredential = {
    '@context': [CREDENTIALS_V2_CONTEXT, ...type.additionalContexts],
    id,
    type: ['VerifiableCredential', type.typeName],
    issuer,
    validFrom,
    ...(expiry !== undefined && expiry !== '' ? { validUntil: expiry } : {}),
    credentialSubject: { ...subjectPayload, id: subject },
    ...(credentialStatus ? { credentialStatus } : {}),
  };

  const credentialValidation = type.validateCredential?.(unsigned);
  if (credentialValidation && !credentialValidation.valid) {
    throw new InvalidCredentialError(
      `${type.typeName} is invalid: ${credentialValidation.issues.join('; ')}`,
    );
  }

  return (await createProof({
    document: unsigned,
    provider,
    keyLabel,
    verificationMethod,
    proofPurpose: 'assertionMethod',
  })) as VerifiableCredential;
}
