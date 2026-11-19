/**
 * GLEIF Level 1 lookup and mapping to the OTL credentialSubject (spec 4.9).
 *
 * The mapping is near-mechanical: spec 4.9's field names correspond directly to
 * the GLEIF API's own shape (`entity.legalName`, `entity.legalAddress`,
 * `registration.managingLou`, `registration.corroborationLevel`).
 *
 * GLEIF responses are untrusted input — they are about to be wrapped in
 * something we sign — so every field is validated on the way through rather
 * than spread into the credential.
 */

import { RegistryLookupError } from '../errors.ts';
import { explainInvalidLei } from './lei-code.ts';

export const GLEIF_API_BASE = 'https://api.gleif.org/api/v1';

/** Injectable so tests never reach the network. */
export type FetchLike = (
  url: string,
  init?: { headers?: Record<string, string> },
) => Promise<{
  ok: boolean;
  status: number;
  json: () => Promise<unknown>;
}>;

export interface OtlAddress {
  readonly addressLines: readonly string[];
  readonly city: string;
  readonly region?: string;
  readonly country: string;
  readonly postalCode?: string;
}

/** Spec 4.9. Optional members are omitted entirely rather than set to null. */
export interface LeiCredentialSubject {
  readonly lei: string;
  readonly entity: {
    readonly legalName: string;
    readonly otherNames?: readonly string[];
    readonly legalAddress: OtlAddress;
    readonly headquartersAddress: OtlAddress;
    readonly registeredAt?: { readonly id: string };
    readonly registeredAs?: string;
    readonly jurisdiction: string;
    readonly legalForm?: { readonly id: string };
    readonly category?: string;
  };
  readonly registration: {
    readonly initialRegistrationDate: string;
    readonly nextRenewalDate: string;
    readonly managingLou: string;
    readonly corroborationLevel: string;
  };
}

/** Spec 4.9 enumerates these. */
export const ENTITY_CATEGORIES = [
  'GENERAL',
  'SOLE_PROPRIETOR',
  'BRANCH',
  'FUND',
  'SUBFUND',
  'FUNDFAMILY',
  'INTERNATIONAL_ORGANIZATION',
] as const;

export const CORROBORATION_LEVELS = ['FULLY_CORROBORATED', 'PARTIALLY_CORROBORATED', 'PENDING'] as const;

export interface GleifClientOptions {
  readonly fetch?: FetchLike;
  readonly baseUrl?: string;
}

/** Fetch a Level 1 record and map it to spec 4.9. */
export async function fetchLeiRecord(
  lei: string,
  options: GleifClientOptions = {},
): Promise<LeiCredentialSubject> {
  const problem = explainInvalidLei(lei);
  if (problem !== undefined) throw new RegistryLookupError(`Refusing to look up an invalid LEI: ${problem}`);

  const doFetch = options.fetch ?? globalThis.fetch;
  const baseUrl = options.baseUrl ?? GLEIF_API_BASE;
  const url = `${baseUrl}/lei-records/${encodeURIComponent(lei)}`;

  let response: Awaited<ReturnType<FetchLike>>;
  try {
    response = await doFetch(url, { headers: { Accept: 'application/vnd.api+json' } });
  } catch (cause) {
    throw new RegistryLookupError(`Could not reach GLEIF at ${url}`, { cause });
  }

  if (response.status === 404) {
    throw new RegistryLookupError(`GLEIF has no record for LEI ${lei}`);
  }
  if (!response.ok) {
    throw new RegistryLookupError(`GLEIF returned HTTP ${response.status} for LEI ${lei}`);
  }

  let body: unknown;
  try {
    body = await response.json();
  } catch (cause) {
    throw new RegistryLookupError('GLEIF response was not valid JSON', { cause });
  }

  return mapGleifRecord(body, lei);
}

/** Map a GLEIF JSON:API record onto spec 4.9. Exported so it can be tested directly. */
export function mapGleifRecord(body: unknown, expectedLei: string): LeiCredentialSubject {
  const attributes = (body as { data?: { attributes?: unknown } } | null | undefined)?.data?.attributes;
  if (attributes === undefined || attributes === null || typeof attributes !== 'object') {
    throw new RegistryLookupError('GLEIF response has no data.attributes');
  }

  const record = attributes as Record<string, unknown>;
  const entity = requireObject(record['entity'], 'entity');
  const registration = requireObject(record['registration'], 'registration');

  const lei = requireString(record['lei'], 'lei');
  if (lei !== expectedLei) {
    // Guards against a redirect or cache serving a different entity's record.
    throw new RegistryLookupError(`GLEIF returned LEI "${lei}" but "${expectedLei}" was requested`);
  }

  const legalName = requireString(
    requireObject(entity['legalName'], 'entity.legalName')['name'],
    'entity.legalName.name',
  );
  const otherNames = mapOtherNames(entity['otherNames']);

  const subject: LeiCredentialSubject = {
    lei,
    entity: {
      legalName,
      ...(otherNames.length > 0 ? { otherNames } : {}),
      legalAddress: mapAddress(entity['legalAddress'], 'entity.legalAddress'),
      headquartersAddress: mapAddress(entity['headquartersAddress'], 'entity.headquartersAddress'),
      ...mapOptionalId(entity['registeredAt'], 'registeredAt'),
      ...optionalString(entity['registeredAs'], 'registeredAs'),
      jurisdiction: requireString(entity['jurisdiction'], 'entity.jurisdiction'),
      ...mapOptionalId(entity['legalForm'], 'legalForm'),
      ...optionalString(entity['category'], 'category'),
    },
    registration: {
      initialRegistrationDate: requireString(
        registration['initialRegistrationDate'],
        'registration.initialRegistrationDate',
      ),
      nextRenewalDate: requireString(registration['nextRenewalDate'], 'registration.nextRenewalDate'),
      managingLou: requireString(registration['managingLou'], 'registration.managingLou'),
      corroborationLevel: requireString(
        registration['corroborationLevel'],
        'registration.corroborationLevel',
      ),
    },
  };

  return subject;
}

function mapAddress(value: unknown, path: string): OtlAddress {
  const address = requireObject(value, path);
  const lines = address['addressLines'];
  const addressLines = Array.isArray(lines)
    ? lines.filter((line): line is string => typeof line === 'string' && line.length > 0)
    : [];

  return {
    addressLines,
    city: requireString(address['city'], `${path}.city`),
    ...optionalString(address['region'], 'region'),
    country: requireString(address['country'], `${path}.country`),
    ...optionalString(address['postalCode'], 'postalCode'),
  };
}

/** GLEIF gives objects with name/language/type; spec 4.9 wants names only. */
function mapOtherNames(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value
    .map((item) => (item as { name?: unknown } | null | undefined)?.name)
    .filter((name): name is string => typeof name === 'string' && name.length > 0);
}

function mapOptionalId(value: unknown, key: string): Record<string, { id: string }> {
  const id = (value as { id?: unknown } | null | undefined)?.id;
  return typeof id === 'string' && id.length > 0 ? { [key]: { id } } : {};
}

function optionalString(value: unknown, key: string): Record<string, string> {
  return typeof value === 'string' && value.length > 0 ? { [key]: value } : {};
}

function requireObject(value: unknown, path: string): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new RegistryLookupError(`GLEIF record is missing "${path}"`);
  }
  return value as Record<string, unknown>;
}

function requireString(value: unknown, path: string): string {
  if (typeof value !== 'string' || value.length === 0) {
    throw new RegistryLookupError(`GLEIF record is missing or has a non-string "${path}"`);
  }
  return value;
}
