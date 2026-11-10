/**
 * Shared fixtures.
 *
 * LEIs here are synthetic, built from an all-zero prefix with correct ISO 17442
 * check digits: a realistic LEI is a 20-character high-entropy alphanumeric,
 * which secret scanners reliably flag. These pass validation and are
 * unmistakably not real registrations.
 */

import { Bitstring, buildStatusListCredential, statusEntryFor, type StatusListCredential } from '@otl/core';
import { type PublicKey } from '@otl/keys';
import { InMemoryKeyProvider } from '@otl/keys-dev';
import { leiCheckDigits } from '../src/lei/lei-code.ts';
import type { LeiCredentialSubject } from '../src/lei/gleif.ts';

export const syntheticLei = (n = 0): string => {
  const prefix = String(n).padStart(18, '0');
  return prefix + leiCheckDigits(prefix);
};

export const TEST_LEI = syntheticLei(0);
export const MANAGING_LOU_LEI = syntheticLei(1);

export const LOU_DID = 'did:webvh:QmTestScidLou:lou.example.org';
export const VASP_DID = 'did:webvh:QmTestScidVasp:vasp.example.com';
export const OTHER_LOU_DID = 'did:webvh:QmTestScidOther:other-lou.example.org';
export const STATUS_LIST_URL = 'https://lou.example.org/.well-known/status-lists/1';

/** A GLEIF JSON:API response body, in the shape the real API returns. */
export function gleifResponse(overrides: Record<string, unknown> = {}): unknown {
  return {
    data: {
      type: 'lei-records',
      id: TEST_LEI,
      attributes: {
        lei: TEST_LEI,
        entity: {
          legalName: { name: 'Example Participant GmbH', language: 'de' },
          otherNames: [{ name: 'Example Participant', language: 'en', type: 'TRADING_OR_OPERATING_NAME' }],
          legalAddress: {
            language: 'de',
            addressLines: ['Beispielstrasse 1'],
            addressNumber: null,
            city: 'Frankfurt am Main',
            region: 'DE-HE',
            country: 'DE',
            postalCode: '60311',
          },
          headquartersAddress: {
            language: 'de',
            addressLines: ['Beispielstrasse 1'],
            city: 'Frankfurt am Main',
            region: 'DE-HE',
            country: 'DE',
            postalCode: '60311',
          },
          registeredAt: { id: 'RA000563', other: null },
          registeredAs: 'HRB 12345',
          jurisdiction: 'DE',
          category: 'GENERAL',
          legalForm: { id: 'XTIQ', other: null },
          status: 'ACTIVE',
        },
        registration: {
          initialRegistrationDate: '2012-06-06T00:00:00Z',
          lastUpdateDate: '2026-01-01T00:00:00Z',
          status: 'ISSUED',
          nextRenewalDate: '2027-01-01T00:00:00Z',
          managingLou: MANAGING_LOU_LEI,
          corroborationLevel: 'FULLY_CORROBORATED',
        },
        ...overrides,
      },
    },
  };
}

/** A fetch stand-in that returns a fixed body. Never touches the network. */
export function stubFetch(body: unknown, status = 200) {
  return async () => ({ ok: status >= 200 && status < 300, status, json: async () => body });
}

export function failingFetch(message = 'network unreachable') {
  return async () => {
    throw new Error(message);
  };
}

/** A well-formed credentialSubject, for validation tests. */
export function leiSubject(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  const subject: LeiCredentialSubject & { id: string } = {
    id: VASP_DID,
    lei: TEST_LEI,
    entity: {
      legalName: 'Example Participant GmbH',
      legalAddress: {
        addressLines: ['Beispielstrasse 1'],
        city: 'Frankfurt am Main',
        region: 'DE-HE',
        country: 'DE',
        postalCode: '60311',
      },
      headquartersAddress: { addressLines: ['Beispielstrasse 1'], city: 'Frankfurt am Main', country: 'DE' },
      jurisdiction: 'DE',
      category: 'GENERAL',
    },
    registration: {
      initialRegistrationDate: '2012-06-06T00:00:00Z',
      nextRenewalDate: '2027-01-01T00:00:00Z',
      managingLou: MANAGING_LOU_LEI,
      corroborationLevel: 'FULLY_CORROBORATED',
    },
  };
  return { ...(subject as unknown as Record<string, unknown>), ...overrides };
}

/** The issuer's credential signing key reference (spec 3.2.1 fixes no id). */
export const LOU_VC_KEY = `${LOU_DID}#credential-issuance-key`;

/** An issuer with a credential signing key, plus a signed status list. */
export async function issuerSetup(
  revokedIndices: readonly number[] = [],
  listOverrides: { readonly validFrom?: string; readonly validUntil?: string } = {},
) {
  const provider = new InMemoryKeyProvider();
  const key = await provider.generateKey('issuance', 'Ed25519');

  const bitstring = Bitstring.create();
  for (const index of revokedIndices) bitstring.set(index, true);

  // Spec 5.2 gives every list a validity window, and a verifier rejects one
  // that is stale, so a fixture pinned to a fixed date would expire the suite.
  const now = Date.now();
  const statusList = await buildStatusListCredential({
    issuer: LOU_DID,
    statusListCredentialUrl: STATUS_LIST_URL,
    bitstring,
    provider,
    keyLabel: 'issuance',
    verificationMethod: LOU_VC_KEY,
    validFrom: listOverrides.validFrom ?? new Date(now - 60_000).toISOString(),
    validUntil: listOverrides.validUntil ?? new Date(now + 60 * 60_000).toISOString(),
  });

  const keys = new Map<string, PublicKey>([[LOU_DID, key.publicKey]]);

  return {
    provider,
    key,
    statusList,
    verificationMethod: LOU_VC_KEY,
    statusEntry: (index: number) => [statusEntryFor(STATUS_LIST_URL, index)],
    // Mirrors the real resolver's ownership check; assertionMethod membership
    // needs a real DID document and is covered in the resolver's own tests.
    resolveAssertionKey: async (did: string, verificationMethod: string): Promise<PublicKey> => {
      const found = keys.get(did);
      if (!found) throw new Error(`unknown issuer ${did}`);
      if (!verificationMethod.startsWith(`${did}#`)) {
        throw new Error(`"${verificationMethod}" is not a key of "${did}"`);
      }
      return found;
    },
    fetchStatusList: async (url: string): Promise<StatusListCredential> => {
      if (url !== STATUS_LIST_URL) throw new Error(`404 for ${url}`);
      return statusList;
    },
    registerIssuer: (did: string, publicKey: PublicKey) => keys.set(did, publicKey),
  };
}
