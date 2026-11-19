/**
 * `OtlHostingCredential` — the second instance of the general framework
 * (OTL spec 4.12-4.17).
 *
 * A hosting provider issues this to say it operates a participant's DID:
 * it serves the document and log, controls the DID Management Key, and
 * controls or has vetted every other key in the document (spec 4.12). It
 * names the participant by the common name the provider knows it by, and
 * optionally carries the **watcher set** for that DID.
 *
 * The watchers are the point. The DID's own `watchers` parameter lives in the
 * version log, so whoever holds the DID Management Key can rewrite it — after
 * a hostile takeover the attacker simply lists watchers it operates. A list
 * issued by the provider is signed by a different party and withdrawn by
 * revoking the credential, which the attacker cannot do (spec 2.4, 4.17).
 */

import { invalidSubject, validSubject, type CredentialType, type SubjectValidation } from '../registry.ts';

export const OTL_HOSTING_CREDENTIAL = 'OtlHostingCredential';

export interface HostingCredentialInput {
  /**
   * The name the provider knows the hosted participant by (spec 4.14).
   *
   * Not a legal name: the authoritative one is `entity.legalName` in the
   * participant's own OtlLeiCredential. This is the recognisable one, and it
   * is checked against no registry.
   */
  readonly commonName: string;

  /**
   * did:webvh watcher endpoints for the subject DID (spec 4.14).
   *
   * Optional: a provider may attest that it hosts a DID without running
   * watchers for it.
   */
  readonly watchers?: readonly string[];
}

export interface HostingCredentialSubject {
  /** did:webvh of the hosted participant. */
  readonly id: string;
  /** Display label only — never an identifier (spec 4.14). */
  readonly commonName: string;
  readonly watchers?: readonly string[];
}

export class OtlHostingCredentialType implements CredentialType<
  HostingCredentialInput,
  HostingCredentialSubject
> {
  readonly typeName = OTL_HOSTING_CREDENTIAL;

  /** Spec 4.15's example carries `credentials/v2` only. */
  readonly additionalContexts: readonly string[] = [];

  /**
   * Spec 4.13 strengthens the general `MAY` of 4.3 to a `MUST`. Revocation is
   * the whole withdrawal mechanism here (4.17): it is how a provider says it
   * no longer vouches for the DID, including after a takeover.
   */
  readonly requiresCredentialStatus = true;

  /**
   * Spec 4.13 does NOT require `validUntil`, unlike the LEI credential (4.8).
   * An LEI credential expires because the registration behind it does; a
   * hosting relationship has no such date, so the provider revokes instead.
   * A provider MAY still set one, and verification enforces it when present.
   */
  readonly requiresValidUntil = false;

  /** Spec 4.13: "Self-issued hosting credentials are not valid." */
  readonly allowsSelfIssuance = false;

  buildSubject(input: HostingCredentialInput): Promise<Record<string, unknown>> {
    // `id` is not set here: issueCredential supplies it from its own `subject`.
    //
    // The name is trimmed on the way out so that what we publish is the
    // canonical form. Credentials we receive are not rewritten, only checked.
    return Promise.resolve({
      commonName: input.commonName.trim(),
      ...(input.watchers === undefined ? {} : { watchers: [...input.watchers] }),
    });
  }

  /**
   * Validate a credentialSubject against spec 4.14.
   *
   * Applied to credentials we issue *and* to credentials we receive, so a
   * provider cannot present something structurally malformed and have it pass
   * on the strength of a valid signature alone.
   */
  validateSubject(subject: unknown): SubjectValidation {
    if (subject === null || typeof subject !== 'object') {
      return invalidSubject('credentialSubject must be an object');
    }
    const value = subject as Record<string, unknown>;
    const issues: string[] = [];

    // Spec 4.14 also permits a did:web subject, but this implementation
    // resolves did:webvh only, so that branch — and with it 4.14's "watchers MUST be
    // omitted when id is a did:web" rule — is unreachable here rather than
    // silently dropped.
    if (typeof value['id'] !== 'string' || !value['id'].startsWith('did:webvh:')) {
      issues.push('credentialSubject.id must be a did:webvh DID');
    }

    const commonName = value['commonName'];
    if (typeof commonName !== 'string') {
      issues.push('credentialSubject.commonName is required (spec 4.14)');
    } else {
      const trimmed = commonName.trim();
      if (trimmed === '') {
        issues.push('credentialSubject.commonName must not be blank');
      } else if (trimmed.length > MAX_COMMON_NAME_LENGTH) {
        issues.push(`credentialSubject.commonName must be at most ${MAX_COMMON_NAME_LENGTH} characters`);
      }
      if (DISALLOWED_IN_COMMON_NAME.test(commonName)) {
        issues.push('credentialSubject.commonName must not contain control characters');
      }
    }

    const watchers = value['watchers'];
    if (watchers !== undefined) {
      if (!Array.isArray(watchers)) {
        issues.push('watchers must be an array of HTTPS URLs');
      } else {
        // An empty array is accepted as equivalent to omitting the field:
        // spec 4.14 makes watchers optional and does not forbid the empty
        // form, so refusing it would reject a conformant credential.
        const seen = new Set<string>();
        for (const entry of watchers) {
          if (typeof entry !== 'string') {
            issues.push('every watcher must be a string');
            continue;
          }
          if (!isHttpsUrl(entry)) {
            issues.push(`watcher "${entry}" must be an absolute https:// URL (spec 4.14)`);
            continue;
          }
          // Not tidiness: a repeated endpoint would inflate any count of
          // independent corroboration drawn from this list (spec 2.4).
          if (seen.has(entry)) issues.push(`watcher "${entry}" is listed more than once`);
          seen.add(entry);
        }
      }
    }

    return issues.length === 0 ? validSubject : invalidSubject(...issues);
  }
}

/** Spec 4.14. Long enough for a real entity name, short enough to render. */
const MAX_COMMON_NAME_LENGTH = 128;

/**
 * C0/C1 control characters, plus the Unicode directional marks and overrides.
 *
 * The issuer chooses this string and a verifier shows it to a person, so the
 * two display attacks are worth closing at the type: a newline lets the value
 * forge a second line of whatever renders it, and U+202E and its relatives
 * reverse the rendered order, so that `gro.elpmaxe` appears as `example.org`.
 *
 * The zero-width joiners elsewhere in `\p{Cf}` are deliberately left alone.
 * They are load-bearing in Persian and several Indic scripts, and a name that
 * needs one is not an attack.
 */
const DISALLOWED_IN_COMMON_NAME = /[\p{Cc}\u200E\u200F\u202A-\u202E\u2066-\u2069]/u;

function isHttpsUrl(value: string): boolean {
  try {
    return new URL(value).protocol === 'https:';
  } catch {
    return false;
  }
}
