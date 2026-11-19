/**
 * The whois presentation (OTL spec 4.4) and status list retrieval (5.2).
 */

import { bitstringFrom, verifyProof, type Document, type StatusListCredential } from '@otl/core';
import {
  verifyCredential,
  type CredentialTypeRegistry,
  type CredentialVerificationResult,
  type StatusListMemory,
  type TrustPerimeter,
} from '@otl/credentials';
import type { PublicKey } from '@otl/keys';
import { fetchJson, type FetchOptions } from './http.ts';
import type { DidHeadMemory } from './memory.ts';
import {
  resolveVerificationKey,
  ResolutionError,
  serviceEndpointOf,
  validateDid,
  type DidValidationOptions,
} from './resolve.ts';
import { whoisUrl } from './url.ts';

export interface VerifiablePresentation extends Document {
  readonly '@context': readonly string[];
  readonly type: readonly string[];
  readonly holder: string;
  readonly verifiableCredential: readonly unknown[];
}

/**
 * Fragment of the key that signs the presentation's own proof.
 *
 * **Provisional.** Spec 6.3 requires the key on a VP to be under the holder's
 * DID and listed in the holder's `authentication`, so the verifier refuses any
 * key that is not referenced there. Which key a holder uses for presentations
 * is left to whichever other layer defines the holder's general-purpose signing
 * key, so this default fragment is a convention of this SDK and can be
 * overridden per call.
 */
export const PROVISIONAL_VP_KEY_FRAGMENT = '#assertion-key';

/** Fetch a participant's presentation, preferring their advertised `#whois`. */
export async function fetchWhois(
  did: string,
  options: DidValidationOptions = {},
): Promise<VerifiablePresentation> {
  const validated = await validateDid(did, options);
  if (!validated.valid) {
    throw new ResolutionError(
      `Cannot fetch whois for "${did}": its DID log failed validation:\n  - ` +
        validated.issues.map((i) => i.message).join('\n  - '),
    );
  }

  // Prefer the advertised endpoint, but only after the log that advertises it
  // has been validated; fall back to the well-known location.
  const advertised = validated.document ? serviceEndpointOf(validated.document, '#whois') : undefined;
  const url = advertised ?? whoisUrl(did);

  const presentation = await fetchJson<VerifiablePresentation | null>(url, options);
  if (presentation?.holder !== did) {
    throw new ResolutionError(
      `Presentation at ${url} declares holder "${String(presentation?.holder)}", not "${did}"`,
    );
  }
  return presentation;
}

export interface WhoisVerificationResult {
  readonly holder: string;
  /** Whether the presentation's own proof verified, when one was present. */
  readonly presentationVerified: boolean;
  readonly presentationIssue?: string;
  /** One result per contained credential, in order. */
  readonly credentials: readonly CredentialVerificationResult[];
  /** Credentials that passed every link of the chain (spec 5.3). */
  readonly valid: readonly CredentialVerificationResult[];
}

export interface VerifyWhoisOptions {
  readonly did: string;
  readonly registry: CredentialTypeRegistry;
  readonly trustPerimeter: TrustPerimeter;
  readonly resolveAssertionKey: (did: string, verificationMethod: string) => Promise<PublicKey>;
  readonly fetchStatusList: (url: string) => Promise<StatusListCredential>;
  readonly presentation?: VerifiablePresentation;
  /**
   * Which status list versions this verifier has already accepted (spec 5.2),
   * forwarded to every credential check. Omitting it means each credential is
   * checked against a fresh, empty memory, so a superseded but validly signed
   * status list cannot be recognised as a rollback. A long-lived verifier
   * should pass one that outlives the call, and persist it.
   */
  readonly statusListMemory?: StatusListMemory;
  /**
   * Applied to the DID logs this function resolves itself: the holder's own
   * log, for the presentation and its signing key. The `resolveAssertionKey`
   * you pass resolves issuers' logs on its own, so build it with the same
   * memory (`resolveAssertionKey({ didHeadMemory })`) to cover them too.
   */
  readonly didHeadMemory?: DidHeadMemory;
  /** Override the provisional VP key fragment. */
  readonly vpKeyFragment?: string;
  readonly fetchOptions?: FetchOptions;
}

/**
 * Fetch and validate every credential a participant publishes (spec 4.4, 5.3).
 *
 * Unrecognized credential types are skipped rather than failing the batch:
 * "Unrecognized types MUST be skipped gracefully, not treated as an error."
 * That is what lets a deployed verifier keep working as new types appear.
 */
export async function verifyWhois(options: VerifyWhoisOptions): Promise<WhoisVerificationResult> {
  const {
    did,
    registry,
    trustPerimeter,
    resolveAssertionKey,
    fetchStatusList,
    vpKeyFragment = PROVISIONAL_VP_KEY_FRAGMENT,
    fetchOptions = {},
  } = options;

  const resolveOptions: DidValidationOptions = {
    ...fetchOptions,
    ...(options.didHeadMemory !== undefined ? { didHeadMemory: options.didHeadMemory } : {}),
  };

  const presentation = options.presentation ?? (await fetchWhois(did, resolveOptions));

  // fetchWhois checks this for what it retrieves, but a caller-supplied
  // presentation has been through no such check. Spec 5.3 wants subject ==
  // holder == authenticated DID, so a presentation about someone else cannot
  // be allowed to answer a question asked about this DID.
  if (presentation.holder !== did) {
    throw new ResolutionError(`Presentation declares holder "${presentation.holder}", not "${did}"`);
  }

  let presentationVerified = false;
  let presentationIssue: string | undefined;

  if (presentation['proof'] === undefined) {
    presentationIssue = 'Presentation carries no proof';
  } else {
    try {
      const holderKey = await resolveVerificationKey(did, vpKeyFragment, {
        ...resolveOptions,
        relationship: 'authentication',
      });
      const result = await verifyProof({
        document: presentation,
        publicKey: holderKey,
        // Spec 6.3: a presentation proof is an authentication proof, and a
        // verifier MUST reject any other purpose.
        expectedProofPurpose: 'authentication',
      });
      presentationVerified = result.verified;
      if (!result.verified) presentationIssue = result.reason ?? 'Presentation proof did not verify';
    } catch (error) {
      presentationIssue = (error as Error).message;
    }
  }

  const credentials: CredentialVerificationResult[] = [];
  // Untrusted: the member may be absent whatever the declared type says.
  const held = presentation.verifiableCredential as
    VerifiablePresentation['verifiableCredential'] | undefined;
  for (const credential of held ?? []) {
    credentials.push(
      await verifyCredential({
        credential,
        registry,
        trustPerimeter,
        resolveAssertionKey,
        fetchStatusList,
        // Spec 5.3, binding check 1: the credential must be about the party
        // presenting it. Credentials are public, so without this anyone could
        // republish a counterparty's LEI credential as evidence about themselves.
        expectedSubject: did,
        ...(options.statusListMemory !== undefined ? { statusListMemory: options.statusListMemory } : {}),
      }),
    );
  }

  // Spec 5.3, binding check 2. A credential's own proof says who issued it, not
  // who was entitled to present it; that is what the presentation proof carries.
  // Treating an unverified presentation as merely a flag would let the contained
  // credentials be reported valid on the strength of the issuer's signature alone.
  const presentationIssues = presentationVerified
    ? []
    : [`Presentation proof did not verify: ${presentationIssue ?? 'unknown reason'} (spec 5.3)`];

  const credentialResults = presentationVerified
    ? credentials
    : credentials.map((c) => ({ ...c, valid: false, issues: [...c.issues, ...presentationIssues] }));

  return {
    holder: presentation.holder,
    presentationVerified,
    ...(presentationIssue !== undefined ? { presentationIssue } : {}),
    credentials: credentialResults,
    valid: credentialResults.filter((c) => c.valid),
  };
}

/** Fetch a status list credential. Supplied to the chain as `fetchStatusList`. */
export const fetchStatusList =
  (options: FetchOptions = {}) =>
  async (url: string): Promise<StatusListCredential> => {
    const list = await fetchJson<StatusListCredential>(url, options);
    // Decode eagerly so a malformed list fails here rather than deep in the chain.
    bitstringFrom(list);
    return list;
  };
