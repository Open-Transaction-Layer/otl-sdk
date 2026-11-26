/**
 * BitstringStatusListCredential — the signed revocation list (OTL spec 5.2),
 * and the `credentialStatus` entry that points into it (5.1).
 */

import { randomInt } from 'node:crypto';
import type { KeyProvider } from '@open-transaction-layer/keys';
import { InvalidDocumentError } from '../errors.ts';
import { createProof, type Document } from '../proof.ts';
import { Bitstring } from './bitstring.ts';

/** Spec 5.1: the only purpose OTL uses. */
export const STATUS_PURPOSE_REVOCATION = 'revocation';

/** Spec 5.2: the status list credential needs no context beyond credentials/v2. */
export const CREDENTIALS_V2_CONTEXT = 'https://www.w3.org/ns/credentials/v2';

export interface BitstringStatusListEntry {
  readonly id?: string;
  readonly type: 'BitstringStatusListEntry';
  readonly statusPurpose: 'revocation';
  /** Decimal integer, as a string (spec 5.1). */
  readonly statusListIndex: string;
  readonly statusListCredential: string;
  /** Bits per entry; 1 for revocation. Omitted when 1, since that is the default. */
  readonly statusSize?: number;
}

export interface StatusListCredential extends Document {
  readonly '@context': readonly string[];
  readonly id?: string;
  readonly type: readonly string[];
  readonly issuer: string;
  /** Spec 5.2: required; each new version carries a later one than it replaces. */
  readonly validFrom?: string;
  /** Spec 5.2: required; after this the list MUST NOT be relied on. */
  readonly validUntil?: string;
  readonly credentialSubject: {
    readonly id?: string;
    readonly type: 'BitstringStatusList';
    readonly statusPurpose: 'revocation';
    readonly encodedList: string;
    readonly ttl?: number;
  };
}

export interface BuildStatusListOptions {
  /** did:webvh of the issuer. */
  readonly issuer: string;
  /** URL the credential is served from, e.g. `https://lou.example.org/.well-known/status-lists/1`. */
  readonly statusListCredentialUrl: string;
  readonly bitstring: Bitstring;
  readonly provider: KeyProvider;
  /** Label of the credential signing key within the provider. */
  readonly keyLabel: string;
  /**
   * Verification method reference. Spec 5.2 requires a key referenced in the
   * issuer's `assertionMethod`; the id itself is the issuer's choice (3.2.1).
   */
  readonly verificationMethod: string;
  /** ISO 8601 timestamp of this update (spec 5.2). */
  readonly validFrom?: string;
  /** ISO 8601 expiry of this version (spec 5.2). */
  readonly validUntil?: string;
  /** Suggested cache TTL in milliseconds (spec 5.2). */
  readonly ttl?: number;
}

/** Build and sign a BitstringStatusListCredential. */
export async function buildStatusListCredential(
  options: BuildStatusListOptions,
): Promise<StatusListCredential> {
  const {
    issuer,
    statusListCredentialUrl,
    bitstring,
    provider,
    keyLabel,
    verificationMethod,
    validFrom,
    validUntil,
    ttl,
  } = options;

  assertIssuerKeyReference(verificationMethod, issuer);

  const unsigned: StatusListCredential = {
    '@context': [CREDENTIALS_V2_CONTEXT],
    id: statusListCredentialUrl,
    type: ['VerifiableCredential', 'BitstringStatusListCredential'],
    issuer,
    ...(validFrom !== undefined ? { validFrom } : {}),
    ...(validUntil !== undefined ? { validUntil } : {}),
    credentialSubject: {
      id: `${statusListCredentialUrl}#list`,
      type: 'BitstringStatusList',
      statusPurpose: STATUS_PURPOSE_REVOCATION,
      encodedList: bitstring.encode(),
      ...(ttl !== undefined ? { ttl } : {}),
    },
  };

  return (await createProof({
    document: unsigned,
    provider,
    keyLabel,
    verificationMethod,
    proofPurpose: 'assertionMethod',
  })) as StatusListCredential;
}

/**
 * Spec 5.2: a status list's proof must be by a key of its own issuer.
 *
 * The fragment is the issuer's choice (3.2.1), so only ownership can be checked
 * here; that the key is referenced under `assertionMethod` is confirmed at
 * verification, where the DID document is actually resolved. Enforcing
 * ownership at construction stops an issuer publishing a list nothing accepts.
 */
function assertIssuerKeyReference(verificationMethod: string, issuer: string): void {
  if (!verificationMethod.startsWith(`${issuer}#`)) {
    throw new InvalidDocumentError(
      `Status list credentials MUST be signed by a key of the issuer (spec 5.2). ` +
        `"${verificationMethod}" is not a key of "${issuer}".`,
    );
  }
}

/** Extract the bitstring from a status list credential. Does NOT verify its proof. */
export function bitstringFrom(credential: StatusListCredential): Bitstring {
  // A status list credential is fetched from the network, so its members are
  // checked rather than trusted even though the declared type says they are
  // always present and always carry these exact values.
  const subject = credential.credentialSubject as StatusListCredential['credentialSubject'] | undefined;
  const subjectType = subject?.type as string | undefined;
  if (subject === undefined || subjectType !== 'BitstringStatusList') {
    throw new InvalidDocumentError(
      `credentialSubject.type must be "BitstringStatusList", got "${String(subjectType)}"`,
    );
  }
  const statusPurpose: string = subject.statusPurpose;
  if (statusPurpose !== STATUS_PURPOSE_REVOCATION) {
    throw new InvalidDocumentError(`statusPurpose must be "revocation", got "${statusPurpose}"`);
  }
  return Bitstring.decode(subject.encodedList);
}

/**
 * Build the `credentialStatus` entry embedded in an issued credential (5.1).
 *
 * `id` follows the spec's convention `{statusListCredential}#{index}` and must
 * not equal the `statusListCredential` URL itself.
 *
 * @throws {InvalidDocumentError} when `index` is not a non-negative integer.
 */
export function statusEntryFor(statusListCredentialUrl: string, index: number): BitstringStatusListEntry {
  if (!Number.isSafeInteger(index) || index < 0) {
    throw new InvalidDocumentError(`Status list index must be a non-negative integer, got ${String(index)}`);
  }
  return {
    id: `${statusListCredentialUrl}#${index}`,
    type: 'BitstringStatusListEntry',
    statusPurpose: STATUS_PURPOSE_REVOCATION,
    statusListIndex: String(index),
    statusListCredential: statusListCredentialUrl,
  };
}

/**
 * Allocate an unused index.
 *
 * Spec 5.1: indices "SHOULD be assigned randomly to prevent correlation".
 * Sequential allocation would leak which credentials were issued adjacently,
 * reconstructing an issuance timeline from the list alone.
 *
 * Uses `crypto.randomInt` rather than `Math.random`, and rejects rather than
 * looping forever once the list is effectively full.
 */
export function allocateIndex(
  bitstring: Bitstring,
  isTaken: (index: number) => boolean,
  maxAttempts = 1000,
): number {
  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    const candidate = randomInt(0, bitstring.length);
    if (!isTaken(candidate) && !bitstring.get(candidate)) return candidate;
  }
  throw new InvalidDocumentError(
    `Could not find a free status list index after ${maxAttempts} attempts; ` +
      `the list of ${bitstring.length} entries is too full. Start a new list.`,
  );
}
