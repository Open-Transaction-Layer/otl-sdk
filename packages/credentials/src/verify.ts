/**
 * The counterparty validation chain (OTL spec 5.3).
 *
 * "starting from a presented credential, recursively verify proof and
 * revocation status one link at a time, walking up the issuance chain, until a
 * root of trust is reached — a locally configured trusted issuer. If any link
 * fails — an untrusted issuer, a bad proof, a revoked credential, or an
 * unreachable status list — the whole chain is invalid."
 *
 * The failure that is easiest to get wrong is the last one: an unreachable
 * status list is a **failure**, never a pass. "I could not check" must not
 * quietly become "it is fine", so there is no code path here that treats a
 * fetch error as anything but invalid.
 */

import {
  Bitstring,
  bitstringFrom,
  verifyProof,
  type BitstringStatusListEntry,
  type Document,
  type StatusListCredential,
} from '@otl/core';
import type { PublicKey } from '@otl/keys';
import type { VerifiableCredential } from './credential.ts';
import type { CredentialTypeRegistry } from './registry.ts';
import type { TrustPerimeter } from './trust.ts';

export interface CredentialVerificationResult {
  readonly valid: boolean;
  readonly issues: readonly string[];
  /** Recognized type name, when the registry knew it. */
  readonly typeName?: string;
  /** True when the credential was skipped as an unrecognized type (spec 4.4). */
  readonly skipped?: boolean;
}

/**
 * Resolve the credential signing key a proof names (spec 3.2.1).
 *
 * Injected rather than performed here, because resolving it correctly means
 * fetching and fully validating the issuer's DID log — which belongs to the
 * DID layer, not the credential layer. The implementation MUST confirm the key
 * is referenced under the issuer's `assertionMethod`; presence in
 * `verificationMethod` is not authority to issue.
 */
export type ResolveAssertionKey = (issuerDid: string, verificationMethod: string) => Promise<PublicKey>;

/** Fetch and parse a status list credential. Injected for the same reason. */
export type FetchStatusList = (url: string) => Promise<StatusListCredential>;

/**
 * Which version of each status list we have already accepted (spec 5.2).
 *
 * A status list stays validly signed after it is superseded, so rejecting a
 * rollback needs memory across verifications. Injected for the same reason
 * `fetchStatusList` is: the credential layer should not own storage. The
 * default is per-process; a long-lived verifier should persist it.
 */
export interface StatusListMemory {
  /** Newest `validFrom` accepted for this list URL, if any. */
  lastAccepted(url: string): string | undefined;
  record(url: string, validFrom: string): void;
}

export class InMemoryStatusListMemory implements StatusListMemory {
  readonly #seen = new Map<string, string>();
  lastAccepted(url: string): string | undefined {
    return this.#seen.get(url);
  }
  record(url: string, validFrom: string): void {
    const previous = this.#seen.get(url);
    // Compared as instants, not strings: "…T00:00:00+01:00" sorts after
    // "…T00:00:00Z" lexically while being the earlier moment.
    if (previous === undefined || Date.parse(validFrom) > Date.parse(previous)) {
      this.#seen.set(url, validFrom);
    }
  }
}

/** Spec 5.2: a list older than this is stale. Overridable per risk tier. */
export const DEFAULT_MAX_STATUS_LIST_AGE_MS = 24 * 60 * 60 * 1000;

export interface VerifyCredentialOptions {
  readonly credential: unknown;
  readonly registry: CredentialTypeRegistry;
  readonly trustPerimeter: TrustPerimeter;
  readonly resolveAssertionKey: ResolveAssertionKey;
  readonly fetchStatusList: FetchStatusList;
  /**
   * Who we expect this credential to be about — the authenticated counterparty
   * or the `holder` of the presentation carrying it (spec 5.3, binding check 1).
   * Credentials are public, so without this a party can present someone else's.
   */
  readonly expectedSubject?: string;
  /**
   * Defaults to a fresh per-call memory, i.e. no cross-verification history.
   * Without one that outlives the call, a rolled-back status list (spec 5.2)
   * cannot be detected: pass a shared, ideally persistent, memory to get it.
   */
  readonly statusListMemory?: StatusListMemory;
  readonly maxStatusListAgeMs?: number;
  /** Defaults to now. Injectable so expiry is testable without faking clocks. */
  readonly now?: Date;
  /** Skip revocation checking. Only for inspecting a credential offline. */
  readonly skipRevocationCheck?: boolean;
}

export async function verifyCredential(
  options: VerifyCredentialOptions,
): Promise<CredentialVerificationResult> {
  const { credential, registry, trustPerimeter, resolveAssertionKey, fetchStatusList } = options;
  const now = options.now ?? new Date();
  const issues: string[] = [];

  // Spec 4.4: identify by the credential's own type array first, and skip an
  // unrecognized type gracefully rather than treating it as an error. This is
  // what lets a verifier keep working as new credential types appear.
  const type = registry.identify(credential);
  if (type === undefined) {
    return { valid: false, skipped: true, issues: ['Unrecognized credential type; skipped'] };
  }

  const vc = credential as VerifiableCredential;
  const issuer = vc.issuer;
  // The credential is untrusted input: `credentialSubject` is checked even
  // though the declared type says it is always present.
  const credentialSubject = vc.credentialSubject as VerifiableCredential['credentialSubject'] | undefined;
  const subject = credentialSubject?.id;

  if (typeof issuer !== 'string' || issuer.length === 0) {
    return { valid: false, typeName: type.typeName, issues: ['Credential has no issuer'] };
  }

  // ---- Step 1: trust perimeter, before any network I/O ------------------
  // Spec 5.3: "A validator MUST ... check the credential's issuer DID and type
  // against its trust perimeter before it makes any network request on the
  // credential's behalf." The issuer DID and every URL below it are chosen by
  // whoever presented this credential, so fetching first would let any stranger
  // steer us at hosts of their choosing (T-VC-02). Nothing above this line
  // touches the network, and the early return keeps it that way.
  if (!trustPerimeter.trusts(issuer, type.typeName)) {
    return {
      valid: false,
      typeName: type.typeName,
      issues: [
        ...issues,
        `Issuer "${issuer}" is not in the local trust perimeter for ${type.typeName} (spec 6.1). ` +
          `Trust is a local decision; add the issuer explicitly to accept its credentials.`,
      ],
    };
  }

  // ---- Step 2: structural and binding checks (spec 5.3) -----------------
  if (!Array.isArray(vc.type) || vc.type[0] !== 'VerifiableCredential') {
    issues.push('type array must begin with "VerifiableCredential" (spec 4.3)');
  }
  if (issuer === subject && !type.allowsSelfIssuance) {
    issues.push(`${type.typeName} may not be self-issued (spec 4.3)`);
  }
  if (typeof subject === 'string' && trustPerimeter.isDenied(subject)) {
    issues.push(`Subject "${subject}" is on the local deny list (spec 6.1)`);
  }
  // Binding check 1: credentials are public documents, so a valid proof proves
  // only who issued it — never who is entitled to present it.
  if (options.expectedSubject !== undefined && subject !== options.expectedSubject) {
    issues.push(
      `Credential is about "${String(subject)}", not "${options.expectedSubject}" (spec 5.3). ` +
        `A credential copied from another party's whois presentation fails here.`,
    );
  }
  issues.push(...validityWindow(vc, type, now));

  const subjectValidation = type.validateSubject(vc.credentialSubject);
  if (!subjectValidation.valid) issues.push(...subjectValidation.issues);

  const credentialValidation = type.validateCredential?.(vc);
  if (credentialValidation && !credentialValidation.valid) {
    issues.push(...credentialValidation.issues);
  }

  // ---- Step 3: verify the proof against the issuer's DID document -------
  // Spec 3.2.1 fixes no key id, so the reference comes from the proof itself;
  // the resolver is what confirms the issuer designated it under assertionMethod.
  const verificationMethod = proofVerificationMethod(vc);
  if (verificationMethod === undefined) {
    return {
      valid: false,
      typeName: type.typeName,
      issues: [...issues, 'Credential proof names no verificationMethod (spec 6.3)'],
    };
  }

  let issuanceKey: PublicKey;
  try {
    issuanceKey = await resolveAssertionKey(issuer, verificationMethod);
  } catch (error) {
    // Unresolvable issuer is a failure, not an unknown.
    return {
      valid: false,
      typeName: type.typeName,
      issues: [...issues, `Could not resolve issuer "${issuer}": ${(error as Error).message}`],
    };
  }

  const proofResult = await verifyProof({
    document: credential as Document,
    publicKey: issuanceKey,
    verificationMethod,
  });
  if (!proofResult.verified) {
    issues.push(`Credential proof did not verify: ${proofResult.reason}`);
  }

  // ---- Step 4: revocation ----------------------------------------------
  const status = vc.credentialStatus;
  if (type.requiresCredentialStatus && (!Array.isArray(status) || status.length === 0)) {
    issues.push(`${type.typeName} MUST carry a credentialStatus entry (spec 4.8)`);
  } else if (Array.isArray(status) && status.length > 0 && !options.skipRevocationCheck) {
    issues.push(
      ...(await checkRevocation(status, issuer, {
        fetchStatusList,
        resolveAssertionKey,
        memory: options.statusListMemory ?? new InMemoryStatusListMemory(),
        maxAgeMs: options.maxStatusListAgeMs ?? DEFAULT_MAX_STATUS_LIST_AGE_MS,
        now,
      })),
    );
  }

  return { valid: issues.length === 0, typeName: type.typeName, issues };
}

/** The `verificationMethod` of the credential's proof (spec 6.3). */
function proofVerificationMethod(vc: VerifiableCredential): string | undefined {
  const proof = (vc as { proof?: unknown }).proof;
  const first: unknown = Array.isArray(proof) ? (proof[0] as unknown) : proof;
  const reference = (first as { verificationMethod?: unknown } | undefined)?.verificationMethod;
  return typeof reference === 'string' && reference.length > 0 ? reference : undefined;
}

/**
 * Spec 5.3, binding check 4: `validFrom` not in the future, `validUntil` not
 * passed. Deliberately independent of revocation — an issuer that never gets
 * round to revoking an expired credential must not thereby keep it alive.
 */
function validityWindow(
  vc: VerifiableCredential,
  type: { readonly typeName: string; readonly requiresValidUntil?: boolean },
  now: Date,
): string[] {
  const issues: string[] = [];
  const at = now.getTime();

  if (typeof vc.validFrom === 'string') {
    const from = Date.parse(vc.validFrom);
    if (Number.isNaN(from)) issues.push(`validFrom "${vc.validFrom}" is not a valid timestamp`);
    else if (from > at) issues.push(`Credential is not yet valid (validFrom ${vc.validFrom})`);
  }

  if (vc.validUntil === undefined) {
    if (type.requiresValidUntil) {
      issues.push(`${type.typeName} MUST carry validUntil (spec 4.8)`);
    }
    return issues;
  }

  const until = Date.parse(vc.validUntil);
  if (Number.isNaN(until)) issues.push(`validUntil "${vc.validUntil}" is not a valid timestamp`);
  else if (until <= at) issues.push(`Credential expired at ${vc.validUntil} (spec 5.3)`);

  return issues;
}

interface RevocationContext {
  readonly fetchStatusList: FetchStatusList;
  readonly resolveAssertionKey: ResolveAssertionKey;
  readonly memory: StatusListMemory;
  readonly maxAgeMs: number;
  readonly now: Date;
}

async function checkRevocation(
  entries: readonly BitstringStatusListEntry[],
  credentialIssuer: string,
  context: RevocationContext,
): Promise<string[]> {
  const { fetchStatusList, resolveAssertionKey, memory, maxAgeMs, now } = context;
  const issues: string[] = [];

  for (const entry of entries) {
    // Status entries come from the credential being verified, so their
    // discriminators are compared as plain strings: anything unrecognized must
    // be reported rather than assumed to be the one value the type allows.
    const entryType: string = entry.type;
    if (entryType !== 'BitstringStatusListEntry') {
      issues.push(`Unsupported credentialStatus type "${entryType}"`);
      continue;
    }
    const statusPurpose: string = entry.statusPurpose;
    if (statusPurpose !== 'revocation') {
      issues.push(`Unsupported statusPurpose "${statusPurpose}"`);
      continue;
    }
    if (entry.id !== undefined && entry.id === entry.statusListCredential) {
      issues.push('credentialStatus.id MUST NOT equal the statusListCredential URL (spec 5.1)');
    }

    const index = Number(entry.statusListIndex);
    if (!Number.isInteger(index) || index < 0) {
      issues.push(`statusListIndex "${entry.statusListIndex}" is not a non-negative integer`);
      continue;
    }

    let list: StatusListCredential;
    try {
      list = await fetchStatusList(entry.statusListCredential);
    } catch (error) {
      // Spec 5.3: an unreachable status list invalidates the credential.
      issues.push(
        `Could not fetch status list ${entry.statusListCredential}: ${(error as Error).message}. ` +
          `An unreachable status list invalidates the credential (spec 5.3).`,
      );
      continue;
    }

    // Spec 5.2, issuer binding. Checked BEFORE resolving anything, because
    // verifying the list against its own self-declared issuer proves only that
    // whoever served it owns some valid DID. Whoever can serve this URL — a
    // lapsed domain, a compromised cache — would otherwise be free to sign a
    // list with the revocation bit cleared and have it accepted.
    if (list.issuer !== credentialIssuer) {
      issues.push(
        `Status list at ${entry.statusListCredential} is issued by "${list.issuer}", ` +
          `not by the credential's issuer "${credentialIssuer}" (spec 5.2).`,
      );
      continue;
    }
    if (list.id !== undefined && list.id !== entry.statusListCredential) {
      issues.push(
        `Status list declares id "${list.id}" but was fetched from ${entry.statusListCredential} (spec 5.2).`,
      );
      continue;
    }

    const freshness = checkFreshness(list, entry.statusListCredential, memory, maxAgeMs, now);
    if (freshness.length > 0) {
      issues.push(...freshness);
      continue;
    }

    // The status list is itself a signed VC and its own proof must be checked,
    // or an attacker could serve an all-zero list to un-revoke everything.
    const listReference = listVerificationMethod(list);
    if (listReference === undefined) {
      issues.push(`Status list at ${entry.statusListCredential} has no proof verificationMethod (spec 5.2).`);
      continue;
    }

    try {
      const listKey = await resolveAssertionKey(list.issuer, listReference);
      const listProof = await verifyProof({
        document: list,
        publicKey: listKey,
        verificationMethod: listReference,
      });
      if (!listProof.verified) {
        issues.push(`Status list proof did not verify: ${listProof.reason}`);
        continue;
      }
    } catch (error) {
      issues.push(`Could not verify the status list's issuer: ${(error as Error).message}`);
      continue;
    }

    // Only once the list is proven, bound and fresh does it become the version
    // future verifications must not be rolled back behind.
    if (typeof list.validFrom === 'string') memory.record(entry.statusListCredential, list.validFrom);

    let bitstring: Bitstring;
    try {
      bitstring = bitstringFrom(list);
    } catch (error) {
      issues.push(`Status list is malformed: ${(error as Error).message}`);
      continue;
    }

    try {
      if (bitstring.get(index)) issues.push(`Credential is revoked (status list index ${index})`);
    } catch (error) {
      issues.push(`Status list index ${index} is out of range: ${(error as Error).message}`);
    }
  }

  return issues;
}

/** The `verificationMethod` of a status list credential's proof. */
function listVerificationMethod(list: StatusListCredential): string | undefined {
  const proof = (list as { proof?: unknown }).proof;
  const first: unknown = Array.isArray(proof) ? (proof[0] as unknown) : proof;
  const reference = (first as { verificationMethod?: unknown } | undefined)?.verificationMethod;
  return typeof reference === 'string' && reference.length > 0 ? reference : undefined;
}

/**
 * Spec 5.2, freshness and rollback.
 *
 * A superseded status list stays validly signed forever, so a signature check
 * cannot tell "current" from "the copy taken before the revocation". These
 * three rules are what distinguish them: an explicit end of life, a bound on
 * how old a list may be at all, and a refusal to go backwards from the newest
 * version we have already honoured.
 */
function checkFreshness(
  list: StatusListCredential,
  url: string,
  memory: StatusListMemory,
  maxAgeMs: number,
  now: Date,
): string[] {
  const issues: string[] = [];
  const at = now.getTime();

  if (typeof list.validUntil !== 'string') {
    issues.push(`Status list at ${url} carries no validUntil (spec 5.2).`);
  } else {
    const until = Date.parse(list.validUntil);
    if (Number.isNaN(until))
      issues.push(`Status list validUntil "${list.validUntil}" is not a valid timestamp`);
    else if (until <= at) issues.push(`Status list at ${url} expired at ${list.validUntil} (spec 5.2).`);
  }

  if (typeof list.validFrom !== 'string') {
    issues.push(`Status list at ${url} carries no validFrom (spec 5.2).`);
    return issues;
  }

  const from = Date.parse(list.validFrom);
  if (Number.isNaN(from)) {
    issues.push(`Status list validFrom "${list.validFrom}" is not a valid timestamp`);
    return issues;
  }
  if (at - from > maxAgeMs) {
    issues.push(
      `Status list at ${url} is ${Math.round((at - from) / 1000)}s old, over the ` +
        `${Math.round(maxAgeMs / 1000)}s maximum this verifier accepts (spec 5.2).`,
    );
  }

  const lastAccepted = memory.lastAccepted(url);
  if (lastAccepted !== undefined && from < Date.parse(lastAccepted)) {
    issues.push(
      `Status list at ${url} is dated ${list.validFrom}, behind the ${lastAccepted} version ` +
        `already accepted — a rollback (spec 5.2).`,
    );
  }

  return issues;
}
