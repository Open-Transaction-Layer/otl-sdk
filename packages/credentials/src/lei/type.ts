/**
 * `OtlLeiCredential` — the first instance of the general framework
 * (OTL spec 4.6-4.11).
 *
 * It is a plugin like any other, so that adding a credential type is a
 * registration rather than a change to the issuing machinery.
 */

import { invalidSubject, validSubject, type CredentialType, type SubjectValidation } from '../registry.ts';
import {
  CORROBORATION_LEVELS,
  ENTITY_CATEGORIES,
  fetchLeiRecord,
  type GleifClientOptions,
  type LeiCredentialSubject,
} from './gleif.ts';
import { isValidLei } from './lei-code.ts';

export const OTL_LEI_CREDENTIAL = 'OtlLeiCredential';

export interface LeiCredentialInput {
  /** ISO 17442 20-character code. */
  readonly lei: string;
  readonly gleif?: GleifClientOptions;
}

export class OtlLeiCredentialType implements CredentialType<LeiCredentialInput, LeiCredentialSubject> {
  readonly typeName = OTL_LEI_CREDENTIAL;

  /** Spec 4.10's example carries `credentials/v2` only. */
  readonly additionalContexts: readonly string[] = [];

  /**
   * Spec 4.8 strengthens the general `MAY` of 4.3 to a `MUST`: an
   * OtlLeiCredential without a revocation pointer cannot be checked, and
   * "validators MUST check before trusting".
   */
  readonly requiresCredentialStatus = true;

  /**
   * Spec 4.8: `validUntil` "MUST be present (stricter than the general MAY in
   * 4.3) and MUST NOT be later than credentialSubject.registration.nextRenewalDate".
   */
  readonly requiresValidUntil = true;

  /** Spec 4.8: "Self-issued LEI credentials are not valid." */
  readonly allowsSelfIssuance = false;

  /**
   * Expire the credential when the LEI registration does (spec 4.8).
   *
   * The renewal date is already in the subject, so defaulting to it keeps the
   * two from contradicting each other and means an issuer cannot accidentally
   * mint a credential that outlives the registration it attests.
   */
  defaultValidUntil(subject: Record<string, unknown>): string | undefined {
    const registration = subject['registration'];
    if (registration === null || typeof registration !== 'object') return undefined;
    const renewal = (registration as Record<string, unknown>)['nextRenewalDate'];
    return typeof renewal === 'string' ? renewal : undefined;
  }

  /**
   * Spec 4.8: `validUntil` must not outlast the LEI registration itself.
   *
   * Without this the credential would keep asserting a registration that has
   * lapsed, and enforcement would rest entirely on the LOU remembering to
   * revoke — the dependency 4.8 exists to remove.
   */
  validateCredential(credential: Record<string, unknown>): SubjectValidation {
    // Absence is `requiresValidUntil`'s business, reported generically; saying
    // it again here would surface one fault as two issues.
    const validUntil = credential['validUntil'];
    if (typeof validUntil !== 'string') return validSubject;

    const subject = credential['credentialSubject'];
    const registration =
      subject !== null && typeof subject === 'object'
        ? (subject as Record<string, unknown>)['registration']
        : undefined;
    const renewal =
      registration !== null && typeof registration === 'object'
        ? (registration as Record<string, unknown>)['nextRenewalDate']
        : undefined;

    if (typeof renewal !== 'string') return validSubject;

    const until = Date.parse(validUntil);
    const next = Date.parse(renewal);
    if (Number.isNaN(until) || Number.isNaN(next)) {
      return invalidSubject('validUntil and registration.nextRenewalDate must be ISO 8601 timestamps');
    }
    if (until > next) {
      return invalidSubject(
        `validUntil (${validUntil}) must not be later than registration.nextRenewalDate (${renewal}) (spec 4.8)`,
      );
    }
    return validSubject;
  }

  async buildSubject(input: LeiCredentialInput): Promise<Record<string, unknown>> {
    const subject = await fetchLeiRecord(input.lei, input.gleif ?? {});
    return subject as unknown as Record<string, unknown>;
  }

  /**
   * Validate a credentialSubject against spec 4.9.
   *
   * Applied to credentials we issue *and* to credentials we receive, so a
   * counterparty cannot present something structurally malformed and have it
   * pass on the strength of a valid signature alone.
   */
  validateSubject(subject: unknown): SubjectValidation {
    if (subject === null || typeof subject !== 'object') {
      return invalidSubject('credentialSubject must be an object');
    }
    const value = subject as Record<string, unknown>;
    const issues: string[] = [];

    if (typeof value['id'] !== 'string' || !value['id'].startsWith('did:webvh:')) {
      issues.push('credentialSubject.id must be a did:webvh DID');
    }

    const lei = value['lei'];
    if (typeof lei !== 'string' || !isValidLei(lei)) {
      issues.push('lei must be a valid ISO 17442 20-character code');
    }

    const entity = value['entity'];
    if (entity === null || typeof entity !== 'object') {
      issues.push('entity is required');
    } else {
      const e = entity as Record<string, unknown>;
      if (typeof e['legalName'] !== 'string' || e['legalName'] === '') {
        issues.push('entity.legalName is required');
      }
      if (typeof e['jurisdiction'] !== 'string' || !/^[A-Z]{2}(-[A-Z0-9]{1,3})?$/.test(e['jurisdiction'])) {
        issues.push('entity.jurisdiction must be an ISO 3166-1 alpha-2 or ISO 3166-2 code');
      }
      issues.push(...addressIssues(e['legalAddress'], 'entity.legalAddress'));
      issues.push(...addressIssues(e['headquartersAddress'], 'entity.headquartersAddress'));

      const category = e['category'];
      if (category !== undefined && !ENTITY_CATEGORIES.includes(category as never)) {
        issues.push(
          `entity.category ${JSON.stringify(category)} is not one of ${ENTITY_CATEGORIES.join(', ')}`,
        );
      }
    }

    const registration = value['registration'];
    if (registration === null || typeof registration !== 'object') {
      issues.push('registration is required');
    } else {
      const r = registration as Record<string, unknown>;
      for (const field of ['initialRegistrationDate', 'nextRenewalDate', 'managingLou'] as const) {
        if (typeof r[field] !== 'string' || r[field] === '') issues.push(`registration.${field} is required`);
      }
      if (typeof r['managingLou'] === 'string' && !isValidLei(r['managingLou'])) {
        issues.push('registration.managingLou must be a valid LEI');
      }
      const level = r['corroborationLevel'];
      if (!CORROBORATION_LEVELS.includes(level as never)) {
        issues.push(
          `registration.corroborationLevel "${String(level)}" is not one of ${CORROBORATION_LEVELS.join(', ')}`,
        );
      }
    }

    return issues.length === 0 ? validSubject : invalidSubject(...issues);
  }
}

function addressIssues(value: unknown, path: string): string[] {
  if (value === null || typeof value !== 'object') return [`${path} is required`];
  const address = value as Record<string, unknown>;
  const issues: string[] = [];

  if (!Array.isArray(address['addressLines'])) issues.push(`${path}.addressLines must be an array`);
  if (typeof address['city'] !== 'string' || address['city'] === '') issues.push(`${path}.city is required`);
  if (typeof address['country'] !== 'string' || !/^[A-Z]{2}$/.test(address['country'])) {
    issues.push(`${path}.country must be an ISO 3166-1 alpha-2 code`);
  }
  const region = address['region'];
  if (region !== undefined && (typeof region !== 'string' || !/^[A-Z]{2}-[A-Z0-9]{1,3}$/.test(region))) {
    issues.push(`${path}.region must be an ISO 3166-2 code such as DE-HE`);
  }
  return issues;
}

/**
 * Spec 4.11: an OtlLeiCredential's trust chain is a single hop, LOU to VASP.
 * The LOU is the root; a verifier confirms it sits in the local trust perimeter
 * and stops there.
 */
export const LEI_TRUST_CHAIN_DEPTH = 1;
