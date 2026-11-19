import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { issueCredential } from '../src/credential.ts';
import { InvalidCredentialError, RegistryLookupError, UnknownCredentialTypeError } from '../src/errors.ts';
import { defaultRegistry } from '../src/index.ts';
import { fetchLeiRecord, mapGleifRecord } from '../src/lei/gleif.ts';
import { explainInvalidLei, isValidLei, leiCheckDigits } from '../src/lei/lei-code.ts';
import { OtlHostingCredentialType, OTL_HOSTING_CREDENTIAL } from '../src/hosting/type.ts';
import { OtlLeiCredentialType, OTL_LEI_CREDENTIAL } from '../src/lei/type.ts';
import { TrustPerimeter } from '../src/trust.ts';
import { InMemoryStatusListMemory, verifyCredential } from '../src/verify.ts';
import {
  failingFetch,
  gleifResponse,
  issuerSetup,
  leiSubject,
  LOU_DID,
  LOU_VC_KEY,
  MANAGING_LOU_LEI,
  OTHER_LOU_DID,
  STATUS_LIST_URL,
  stubFetch,
  syntheticLei,
  TEST_LEI,
  VASP_DID,
} from './fixtures.ts';

describe('LEI codes (ISO 17442)', () => {
  it('accepts a code with correct check digits', () => {
    assert.equal(isValidLei(TEST_LEI), true);
    assert.equal(isValidLei(syntheticLei(12345)), true);
  });

  it('rejects wrong check digits', () => {
    const prefix = TEST_LEI.slice(0, 18);
    const wrong = prefix + (TEST_LEI.slice(18) === '00' ? '01' : '00');
    assert.equal(isValidLei(wrong), false);
    assert.match(explainInvalidLei(wrong) ?? '', /check digits/);
  });

  it('rejects the wrong length or shape', () => {
    assert.match(explainInvalidLei('SHORT') ?? '', /exactly 20/);
    assert.match(explainInvalidLei('0'.repeat(19) + 'A') ?? '', /check digits|followed by/);
    assert.match(explainInvalidLei('abcdefghijklmnopqr00') ?? '', /uppercase/);
  });

  it('computes check digits that validate', () => {
    for (const n of [0, 1, 42, 999999]) {
      const prefix = String(n).padStart(18, '0');
      assert.equal(isValidLei(prefix + leiCheckDigits(prefix)), true);
    }
  });

  it('returns undefined for a valid code', () => {
    assert.equal(explainInvalidLei(TEST_LEI), undefined);
  });
});

describe('GLEIF mapping (spec 4.9)', () => {
  it('maps a Level 1 record onto the spec fields', async () => {
    const subject = await fetchLeiRecord(TEST_LEI, { fetch: stubFetch(gleifResponse()) });

    assert.equal(subject.lei, TEST_LEI);
    assert.equal(subject.entity.legalName, 'Example Participant GmbH');
    assert.deepEqual(subject.entity.otherNames, ['Example Participant']);
    assert.equal(subject.entity.jurisdiction, 'DE');
    assert.equal(subject.entity.category, 'GENERAL');
    assert.deepEqual(subject.entity.registeredAt, { id: 'RA000563' });
    assert.equal(subject.entity.registeredAs, 'HRB 12345');
    assert.deepEqual(subject.entity.legalForm, { id: 'XTIQ' });
    assert.equal(subject.registration.managingLou, MANAGING_LOU_LEI);
    assert.equal(subject.registration.corroborationLevel, 'FULLY_CORROBORATED');
  });

  it('reduces GLEIF address objects to the spec shape', async () => {
    const subject = await fetchLeiRecord(TEST_LEI, { fetch: stubFetch(gleifResponse()) });
    assert.deepEqual(subject.entity.legalAddress, {
      addressLines: ['Beispielstrasse 1'],
      city: 'Frankfurt am Main',
      region: 'DE-HE',
      country: 'DE',
      postalCode: '60311',
    });
    // GLEIF's language and addressNumber members are dropped, not carried over.
    assert.equal((subject.entity.legalAddress as Record<string, unknown>)['language'], undefined);
  });

  it('omits optional fields rather than emitting null', async () => {
    const body = gleifResponse({
      entity: {
        legalName: { name: 'Minimal Ltd' },
        otherNames: [],
        legalAddress: { addressLines: ['1 Road'], city: 'London', country: 'GB' },
        headquartersAddress: { addressLines: ['1 Road'], city: 'London', country: 'GB' },
        registeredAt: { id: null },
        registeredAs: null,
        jurisdiction: 'GB',
        legalForm: { id: null },
        category: null,
      },
    });
    const subject = await fetchLeiRecord(TEST_LEI, { fetch: stubFetch(body) });

    assert.ok(!('otherNames' in subject.entity));
    assert.ok(!('registeredAt' in subject.entity));
    assert.ok(!('registeredAs' in subject.entity));
    assert.ok(!('legalForm' in subject.entity));
    assert.ok(!('category' in subject.entity));
    assert.ok(!('region' in subject.entity.legalAddress));
  });

  it('refuses to look up a malformed LEI before making a request', async () => {
    let called = false;
    const spy = async () => {
      called = true;
      return { ok: true, status: 200, json: async () => gleifResponse() };
    };
    await assert.rejects(() => fetchLeiRecord('NOT-A-LEI', { fetch: spy }), RegistryLookupError);
    assert.equal(called, false, 'an obvious typo should never become a network call');
  });

  it('rejects a record for a different LEI than requested', () => {
    // Guards against a redirect or cache serving another entity's record.
    assert.throws(() => mapGleifRecord(gleifResponse(), syntheticLei(999)), RegistryLookupError);
  });

  it('reports missing required fields rather than producing a partial subject', () => {
    const body = gleifResponse({ registration: { initialRegistrationDate: '2012-06-06T00:00:00Z' } });
    assert.throws(() => mapGleifRecord(body, TEST_LEI), /registration.nextRenewalDate/);
  });

  it('surfaces HTTP and transport failures', async () => {
    await assert.rejects(() => fetchLeiRecord(TEST_LEI, { fetch: stubFetch({}, 404) }), /no record/);
    await assert.rejects(() => fetchLeiRecord(TEST_LEI, { fetch: stubFetch({}, 503) }), /HTTP 503/);
    await assert.rejects(() => fetchLeiRecord(TEST_LEI, { fetch: failingFetch() }), /Could not reach GLEIF/);
  });

  it('rejects a response with no data.attributes', () => {
    assert.throws(() => mapGleifRecord({ data: {} }, TEST_LEI), RegistryLookupError);
    assert.throws(() => mapGleifRecord(null, TEST_LEI), RegistryLookupError);
  });
});

describe('OtlLeiCredential subject validation (spec 4.9)', () => {
  const type = new OtlLeiCredentialType();

  it('accepts a well-formed subject', () => {
    assert.equal(type.validateSubject(leiSubject()).valid, true);
  });

  it('requires a did:webvh subject id', () => {
    const result = type.validateSubject(leiSubject({ id: 'https://vasp.example.com' }));
    assert.equal(result.valid, false);
    assert.match(result.issues.join(), /did:webvh/);
  });

  it('requires a valid LEI', () => {
    assert.equal(type.validateSubject(leiSubject({ lei: 'NOT-A-LEI' })).valid, false);
  });

  it('requires a valid managingLou', () => {
    const subject = leiSubject();
    const registration = { ...(subject['registration'] as object), managingLou: 'NOPE' };
    assert.equal(type.validateSubject({ ...subject, registration }).valid, false);
  });

  it('constrains corroborationLevel to the enumerated values', () => {
    const subject = leiSubject();
    const registration = { ...(subject['registration'] as object), corroborationLevel: 'PROBABLY' };
    const result = type.validateSubject({ ...subject, registration });
    assert.equal(result.valid, false);
    assert.match(result.issues.join(), /corroborationLevel/);
  });

  it('constrains entity.category to the enumerated values', () => {
    const subject = leiSubject();
    const entity = { ...(subject['entity'] as object), category: 'SOMETHING_ELSE' };
    assert.equal(type.validateSubject({ ...subject, entity }).valid, false);
  });

  it('requires ISO 3166 codes for jurisdiction and country', () => {
    const subject = leiSubject();
    const entity = subject['entity'] as Record<string, unknown>;

    assert.equal(
      type.validateSubject({ ...subject, entity: { ...entity, jurisdiction: 'Germany' } }).valid,
      false,
    );
    assert.equal(
      type.validateSubject({
        ...subject,
        entity: { ...entity, legalAddress: { addressLines: [], city: 'X', country: 'DEU' } },
      }).valid,
      false,
    );
    // ISO 3166-2 subdivisions are valid jurisdictions.
    assert.equal(
      type.validateSubject({ ...subject, entity: { ...entity, jurisdiction: 'DE-HE' } }).valid,
      true,
    );
  });

  it('rejects a region that is not an ISO 3166-2 code', () => {
    const subject = leiSubject();
    const entity = subject['entity'] as Record<string, unknown>;
    const legalAddress = { ...(entity['legalAddress'] as object), region: 'Hesse' };
    assert.equal(type.validateSubject({ ...subject, entity: { ...entity, legalAddress } }).valid, false);
  });

  it('reports every problem at once rather than only the first', () => {
    const result = type.validateSubject({ id: 'nope', lei: 'nope' });
    assert.ok(result.issues.length >= 3, `expected several issues, got ${result.issues.join('; ')}`);
  });

  it('rejects a non-object', () => {
    for (const bad of [null, 'string', 42, undefined]) {
      assert.equal(type.validateSubject(bad).valid, false);
    }
  });
});

describe('credential type registry (spec 4.4)', () => {
  it('identifies a credential from its own type array', () => {
    const registry = defaultRegistry();
    const type = registry.identify({ type: ['VerifiableCredential', OTL_LEI_CREDENTIAL] });
    assert.equal(type?.typeName, OTL_LEI_CREDENTIAL);
  });

  it('returns undefined for an unrecognized type rather than throwing', () => {
    // Spec 4.4: unrecognized types MUST be skipped gracefully.
    const registry = defaultRegistry();
    assert.equal(registry.identify({ type: ['VerifiableCredential', 'OtlKycCredential'] }), undefined);
    assert.equal(registry.identify({ type: 'not-an-array' }), undefined);
    assert.equal(registry.identify(null), undefined);
  });

  it('throws only on an explicit get of an unknown type', () => {
    assert.throws(() => defaultRegistry().get('OtlKycCredential'), UnknownCredentialTypeError);
  });

  it('carries a second real credential type without changes to the machinery', async () => {
    // The point of the registry: LEI is a plugin, not a special case. Asserted
    // with the real second type rather than a stub, so the claim is about
    // shipped code and cannot drift from it.
    const registry = defaultRegistry();
    assert.deepEqual(registry.typeNames().sort(), [OTL_HOSTING_CREDENTIAL, OTL_LEI_CREDENTIAL].sort());

    const setup = await issuerSetup();
    const credential = await issueCredential({
      type: new OtlHostingCredentialType(),
      input: { commonName: 'Example Participant', watchers: ['https://watcher-a.example.net'] },
      issuer: LOU_DID,
      subject: VASP_DID,
      provider: setup.provider,
      keyLabel: 'issuance',
      verificationMethod: LOU_VC_KEY,
      credentialStatus: setup.statusEntry(94_567),
    });

    assert.deepEqual(credential.type, ['VerifiableCredential', OTL_HOSTING_CREDENTIAL]);
    assert.equal(registry.identify(credential)?.typeName, OTL_HOSTING_CREDENTIAL);
  });
});

describe('issuing an OtlLeiCredential (spec 4.8, 4.10)', () => {
  async function issue(overrides: Record<string, unknown> = {}) {
    const setup = await issuerSetup();
    const credential = await issueCredential({
      type: new OtlLeiCredentialType(),
      input: { lei: TEST_LEI, gleif: { fetch: stubFetch(gleifResponse()) } },
      issuer: LOU_DID,
      subject: VASP_DID,
      provider: setup.provider,
      keyLabel: 'issuance',
      verificationMethod: LOU_VC_KEY,
      credentialStatus: setup.statusEntry(94_567),
      validFrom: '2026-01-01T00:00:00Z',
      ...overrides,
    });
    return { setup, credential };
  }

  it('has the shape spec 4.8 requires', async () => {
    const { credential } = await issue();
    assert.deepEqual(credential.type, ['VerifiableCredential', OTL_LEI_CREDENTIAL]);
    assert.deepEqual(credential['@context'], ['https://www.w3.org/ns/credentials/v2']);
    assert.equal(credential.issuer, LOU_DID);
    assert.equal(credential.credentialSubject.id, VASP_DID);
    assert.match(credential.id, /^urn:uuid:/);
    assert.equal(credential.credentialSubject['lei'], TEST_LEI);
  });

  it('is signed by #credential-issuance-key (spec 3.2.1)', async () => {
    const { credential } = await issue();
    const proof = credential['proof'] as { verificationMethod: string; cryptosuite: string };
    assert.equal(proof.verificationMethod, `${LOU_DID}#credential-issuance-key`);
    assert.equal(proof.cryptosuite, 'eddsa-jcs-2022');
  });

  it('refuses to issue without a credentialStatus (spec 4.8 strengthens 4.3)', async () => {
    await assert.rejects(
      () => issue({ credentialStatus: undefined }),
      (error: unknown) => {
        assert.ok(error instanceof InvalidCredentialError);
        assert.match(error.message, /credentialStatus/);
        return true;
      },
    );
  });

  it('refuses to self-issue (spec 4.8)', async () => {
    await assert.rejects(() => issue({ subject: LOU_DID }), InvalidCredentialError);
  });

  it('refuses to sign a subject that fails validation', async () => {
    // GLEIF output is untrusted input about to be wrapped in a signature.
    const body = gleifResponse({
      registration: {
        initialRegistrationDate: '2012-06-06T00:00:00Z',
        nextRenewalDate: '2027-01-01T00:00:00Z',
        managingLou: MANAGING_LOU_LEI,
        corroborationLevel: 'MADE_UP_LEVEL',
      },
    });
    await assert.rejects(
      () => issue({ input: { lei: TEST_LEI, gleif: { fetch: stubFetch(body) } } }),
      /corroborationLevel/,
    );
  });
});

describe('validation chain (spec 5.3)', () => {
  async function setupChain(options: { revoked?: readonly number[]; index?: number } = {}) {
    const setup = await issuerSetup(options.revoked ?? []);
    const index = options.index ?? 94_567;
    const credential = await issueCredential({
      type: new OtlLeiCredentialType(),
      input: { lei: TEST_LEI, gleif: { fetch: stubFetch(gleifResponse()) } },
      issuer: LOU_DID,
      subject: VASP_DID,
      provider: setup.provider,
      keyLabel: 'issuance',
      verificationMethod: LOU_VC_KEY,
      credentialStatus: setup.statusEntry(index),
      validFrom: '2026-01-01T00:00:00Z',
    });

    const trustPerimeter = new TrustPerimeter({
      issuers: [{ did: LOU_DID, credentialTypes: [OTL_LEI_CREDENTIAL] }],
    });

    const verify = (overrides: Record<string, unknown> = {}) =>
      verifyCredential({
        credential,
        registry: defaultRegistry(),
        trustPerimeter,
        resolveAssertionKey: setup.resolveAssertionKey,
        fetchStatusList: setup.fetchStatusList,
        ...overrides,
      });

    return { setup, credential, trustPerimeter, verify };
  }

  it('accepts a credential that passes every link', async () => {
    const { verify } = await setupChain();
    const result = await verify();
    assert.equal(result.valid, true, result.issues.join('; '));
    assert.equal(result.typeName, OTL_LEI_CREDENTIAL);
  });

  it('rejects a revoked credential', async () => {
    const { verify } = await setupChain({ revoked: [94_567] });
    const result = await verify();
    assert.equal(result.valid, false);
    assert.match(result.issues.join('; '), /revoked/);
  });

  it('treats an unreachable status list as a failure, never a pass', async () => {
    // Spec 5.3: "I could not check" must not become "it is fine".
    const { verify } = await setupChain();
    const result = await verify({ fetchStatusList: failingFetch('connection refused') });
    assert.equal(result.valid, false);
    assert.match(result.issues.join('; '), /unreachable status list invalidates/);
  });

  it('rejects an issuer outside the trust perimeter', async () => {
    const { credential, setup } = await setupChain();
    const result = await verifyCredential({
      credential,
      registry: defaultRegistry(),
      trustPerimeter: new TrustPerimeter({
        issuers: [{ did: OTHER_LOU_DID, credentialTypes: [OTL_LEI_CREDENTIAL] }],
      }),
      resolveAssertionKey: setup.resolveAssertionKey,
      fetchStatusList: setup.fetchStatusList,
    });
    assert.equal(result.valid, false);
    assert.match(result.issues.join('; '), /not in the local trust perimeter/);
  });

  it('makes no network request at all for an untrusted issuer (spec 5.3)', async () => {
    // The ordering IS the mitigation, so asserting the verdict is not enough:
    // a verifier that rejects the credential only after fetching has already
    // been steered at a host of the attacker's choosing (T-VC-02). These
    // injections fail the test by being called, not by returning anything.
    const { credential } = await setupChain();
    let calls = 0;
    const refuse = () => {
      calls += 1;
      throw new Error('network reached before the trust decision');
    };

    const result = await verifyCredential({
      credential,
      registry: defaultRegistry(),
      trustPerimeter: new TrustPerimeter({ issuers: [] }),
      resolveAssertionKey: refuse,
      fetchStatusList: refuse,
    });

    assert.equal(result.valid, false);
    assert.equal(calls, 0, 'an untrusted issuer must cost zero outbound requests');
    assert.match(result.issues.join('; '), /not in the local trust perimeter/);
  });

  it('rejects an issuer trusted only for a different credential type', async () => {
    const { credential, setup } = await setupChain();
    const result = await verifyCredential({
      credential,
      registry: defaultRegistry(),
      trustPerimeter: new TrustPerimeter({
        issuers: [{ did: LOU_DID, credentialTypes: ['OtlKycCredential'] }],
      }),
      resolveAssertionKey: setup.resolveAssertionKey,
      fetchStatusList: setup.fetchStatusList,
    });
    assert.equal(result.valid, false);
    assert.match(result.issues.join('; '), /trust perimeter/);
  });

  it('rejects a tampered credential body', async () => {
    const { credential, setup, trustPerimeter } = await setupChain();
    const tampered = {
      ...credential,
      credentialSubject: { ...credential.credentialSubject, lei: syntheticLei(7) },
    };
    const result = await verifyCredential({
      credential: tampered,
      registry: defaultRegistry(),
      trustPerimeter,
      resolveAssertionKey: setup.resolveAssertionKey,
      fetchStatusList: setup.fetchStatusList,
    });
    assert.equal(result.valid, false);
    assert.match(result.issues.join('; '), /did not verify/);
  });

  it('rejects a tampered status list', async () => {
    // An attacker serving an all-zero list to un-revoke everything must fail
    // the list's own proof check.
    const { credential, setup, trustPerimeter } = await setupChain({ revoked: [94_567] });
    const forged = {
      ...setup.statusList,
      credentialSubject: {
        ...setup.statusList.credentialSubject,
        encodedList: (await import('@otl/core')).Bitstring.create().encode(),
      },
    };
    const result = await verifyCredential({
      credential,
      registry: defaultRegistry(),
      trustPerimeter,
      resolveAssertionKey: setup.resolveAssertionKey,
      fetchStatusList: async () => forged,
    });
    assert.equal(result.valid, false);
    assert.match(result.issues.join('; '), /Status list proof did not verify/);
  });

  it('rejects a status list typed as anything more than a status list (spec 5.2)', async () => {
    // Checked before the list's proof: a list carrying an extra type could be
    // a credential signed as a status list, or the reverse (threat T-REV-05).
    const { credential, setup, trustPerimeter } = await setupChain();
    const result = await verifyCredential({
      credential,
      registry: defaultRegistry(),
      trustPerimeter,
      resolveAssertionKey: setup.resolveAssertionKey,
      fetchStatusList: async () =>
        ({
          ...setup.statusList,
          type: ['VerifiableCredential', 'BitstringStatusListCredential', OTL_LEI_CREDENTIAL],
        }) as unknown as typeof setup.statusList,
    });
    assert.equal(result.valid, false);
    assert.match(result.issues.join('; '), /must be typed exactly/);
  });

  it('rejects an unresolvable issuer', async () => {
    const { credential, trustPerimeter, setup } = await setupChain();
    const result = await verifyCredential({
      credential,
      registry: defaultRegistry(),
      trustPerimeter,
      resolveAssertionKey: async () => {
        throw new Error('DID log failed validation');
      },
      fetchStatusList: setup.fetchStatusList,
    });
    assert.equal(result.valid, false);
    assert.match(result.issues.join('; '), /Could not resolve issuer/);
  });

  it('skips an unrecognized credential type gracefully (spec 4.4)', async () => {
    const { setup, trustPerimeter } = await setupChain();
    const result = await verifyCredential({
      credential: { type: ['VerifiableCredential', 'OtlFutureCredential'], issuer: LOU_DID },
      registry: defaultRegistry(),
      trustPerimeter,
      resolveAssertionKey: setup.resolveAssertionKey,
      fetchStatusList: setup.fetchStatusList,
    });
    assert.equal(result.skipped, true);
    assert.equal(result.valid, false);
  });

  it('rejects a subject on the local deny list (spec 6.1)', async () => {
    const { credential, setup, trustPerimeter } = await setupChain();
    trustPerimeter.denyCounterparty(VASP_DID);
    const result = await verifyCredential({
      credential,
      registry: defaultRegistry(),
      trustPerimeter,
      resolveAssertionKey: setup.resolveAssertionKey,
      fetchStatusList: setup.fetchStatusList,
    });
    assert.equal(result.valid, false);
    assert.match(result.issues.join('; '), /deny list/);
  });

  it('rejects a credentialStatus id equal to the status list URL (spec 5.1)', async () => {
    const { setup, trustPerimeter } = await setupChain();
    const credential = await issueCredential({
      type: new OtlLeiCredentialType(),
      input: { lei: TEST_LEI, gleif: { fetch: stubFetch(gleifResponse()) } },
      issuer: LOU_DID,
      subject: VASP_DID,
      provider: setup.provider,
      keyLabel: 'issuance',
      verificationMethod: LOU_VC_KEY,
      credentialStatus: [
        {
          id: STATUS_LIST_URL,
          type: 'BitstringStatusListEntry',
          statusPurpose: 'revocation',
          statusListIndex: '5',
          statusListCredential: STATUS_LIST_URL,
        },
      ],
      validFrom: '2026-01-01T00:00:00Z',
    });
    const result = await verifyCredential({
      credential,
      registry: defaultRegistry(),
      trustPerimeter,
      resolveAssertionKey: setup.resolveAssertionKey,
      fetchStatusList: setup.fetchStatusList,
    });
    assert.equal(result.valid, false);
    assert.match(result.issues.join('; '), /MUST NOT equal/);
  });

  it('accepts a signing key whose fragment is not the conventional one (spec 3.2.1)', async () => {
    // The spec fixes no id. Hard-coding one would reject every conformant
    // issuer that names its key anything else.
    const setup = await issuerSetup();
    const credential = await issueCredential({
      type: new OtlLeiCredentialType(),
      input: { lei: TEST_LEI, gleif: { fetch: stubFetch(gleifResponse()) } },
      issuer: LOU_DID,
      subject: VASP_DID,
      provider: setup.provider,
      keyLabel: 'issuance',
      verificationMethod: `${LOU_DID}#vc-key-1`,
      credentialStatus: setup.statusEntry(94_567),
    });

    const result = await verifyCredential({
      credential,
      registry: defaultRegistry(),
      trustPerimeter: new TrustPerimeter({
        issuers: [{ did: LOU_DID, credentialTypes: [OTL_LEI_CREDENTIAL] }],
      }),
      resolveAssertionKey: setup.resolveAssertionKey,
      fetchStatusList: setup.fetchStatusList,
    });

    assert.equal(result.valid, true, result.issues.join('; '));
  });

  it('rejects a status list issued by anyone but the credential issuer (spec 5.2)', async () => {
    // Whoever can serve the status-list URL would otherwise choose who appears
    // to have signed it -- and a list signed by their own valid DID, with the
    // revocation bit clear, would verify.
    const { credential, setup, trustPerimeter } = await setupChain({ revoked: [94_567] });

    const impostor = await issuerSetup([]);
    impostor.registerIssuer(LOU_DID, setup.key.publicKey);
    const foreignList = {
      ...impostor.statusList,
      issuer: OTHER_LOU_DID,
    } as typeof impostor.statusList;

    const result = await verifyCredential({
      credential,
      registry: defaultRegistry(),
      trustPerimeter,
      resolveAssertionKey: setup.resolveAssertionKey,
      fetchStatusList: async () => foreignList,
    });

    assert.equal(result.valid, false);
    assert.match(result.issues.join('; '), /not by the credential's issuer/);
  });

  it('rejects an expired credential even when it is not revoked (spec 5.3)', async () => {
    const { setup, trustPerimeter } = await setupChain();
    const credential = await issueCredential({
      type: new OtlLeiCredentialType(),
      input: { lei: TEST_LEI, gleif: { fetch: stubFetch(gleifResponse()) } },
      issuer: LOU_DID,
      subject: VASP_DID,
      provider: setup.provider,
      keyLabel: 'issuance',
      verificationMethod: LOU_VC_KEY,
      credentialStatus: setup.statusEntry(94_567),
      validFrom: '2026-01-01T00:00:00Z',
      validUntil: '2026-02-01T00:00:00Z',
    });

    const result = await verifyCredential({
      credential,
      registry: defaultRegistry(),
      trustPerimeter,
      resolveAssertionKey: setup.resolveAssertionKey,
      fetchStatusList: setup.fetchStatusList,
      now: new Date('2026-06-01T00:00:00Z'),
    });

    assert.equal(result.valid, false);
    assert.match(result.issues.join('; '), /expired/);
  });

  it('defaults validUntil to the LEI renewal date (spec 4.8)', async () => {
    const setup = await issuerSetup();
    const credential = await issueCredential({
      type: new OtlLeiCredentialType(),
      input: { lei: TEST_LEI, gleif: { fetch: stubFetch(gleifResponse()) } },
      issuer: LOU_DID,
      subject: VASP_DID,
      provider: setup.provider,
      keyLabel: 'issuance',
      verificationMethod: LOU_VC_KEY,
      credentialStatus: setup.statusEntry(94_567),
    });

    assert.equal(
      credential.validUntil,
      (credential.credentialSubject['registration'] as { nextRenewalDate: string }).nextRenewalDate,
    );
  });

  it('refuses to issue a credential outliving the registration it attests (spec 4.8)', async () => {
    const setup = await issuerSetup();
    await assert.rejects(
      () =>
        issueCredential({
          type: new OtlLeiCredentialType(),
          input: { lei: TEST_LEI, gleif: { fetch: stubFetch(gleifResponse()) } },
          issuer: LOU_DID,
          subject: VASP_DID,
          provider: setup.provider,
          keyLabel: 'issuance',
          verificationMethod: LOU_VC_KEY,
          credentialStatus: setup.statusEntry(94_567),
          // leiSubject()'s nextRenewalDate is 2027-01-01.
          validUntil: '2030-01-01T00:00:00Z',
        }),
      /nextRenewalDate/,
    );
  });

  it('refuses a status list older than the newest one already accepted (spec 5.2)', async () => {
    // A superseded list stays validly signed forever, so only memory of what we
    // have already honoured distinguishes "current" from "the copy taken before
    // the revocation".
    const { credential, setup, trustPerimeter } = await setupChain();
    const memory = new InMemoryStatusListMemory();
    // The fixture's list is signed and current, so it is used as it stands: a
    // copy with different timestamps would no longer match its signature, and
    // would only appear to verify when the clock happened not to tick between
    // the fixture and the test. The older copy never reaches signature
    // verification because the rollback check runs first.
    const fresh = setup.statusList;
    const signedFrom = fresh.validFrom;
    assert.ok(signedFrom !== undefined, 'the fixture list must carry a validFrom');
    const stale = {
      ...fresh,
      validFrom: new Date(Date.parse(signedFrom) - 600_000).toISOString(),
    } as typeof setup.statusList;

    const accepted = await verifyCredential({
      credential,
      registry: defaultRegistry(),
      trustPerimeter,
      resolveAssertionKey: setup.resolveAssertionKey,
      fetchStatusList: async () => fresh,
      statusListMemory: memory,
    });
    assert.equal(accepted.valid, true, accepted.issues.join('; '));

    const rolledBack = await verifyCredential({
      credential,
      registry: defaultRegistry(),
      trustPerimeter,
      resolveAssertionKey: setup.resolveAssertionKey,
      fetchStatusList: async () => stale,
      statusListMemory: memory,
    });
    assert.equal(rolledBack.valid, false);
    assert.match(rolledBack.issues.join('; '), /rollback/);
  });

  it('refuses a status list past its validUntil (spec 5.2)', async () => {
    const { credential, setup, trustPerimeter } = await setupChain();
    const expired = {
      ...setup.statusList,
      validFrom: new Date(Date.now() - 7_200_000).toISOString(),
      validUntil: new Date(Date.now() - 3_600_000).toISOString(),
    } as typeof setup.statusList;

    const result = await verifyCredential({
      credential,
      registry: defaultRegistry(),
      trustPerimeter,
      resolveAssertionKey: setup.resolveAssertionKey,
      fetchStatusList: async () => expired,
    });

    assert.equal(result.valid, false);
    assert.match(result.issues.join('; '), /expired at/);
  });

  it('rejects a credential about someone other than the presenting party (spec 5.3)', async () => {
    // Credentials are public documents, so a valid issuer signature says
    // nothing about who is entitled to present it.
    const { credential, setup, trustPerimeter } = await setupChain();
    const result = await verifyCredential({
      credential,
      registry: defaultRegistry(),
      trustPerimeter,
      resolveAssertionKey: setup.resolveAssertionKey,
      fetchStatusList: setup.fetchStatusList,
      expectedSubject: OTHER_LOU_DID,
    });

    assert.equal(result.valid, false);
    assert.match(result.issues.join('; '), /is about/);
  });
});

describe('OtlHostingCredential (spec 4.12-4.17)', () => {
  const type = new OtlHostingCredentialType();

  async function issueHosting(
    input: { commonName?: string; watchers?: readonly string[] } = {},
    overrides = {},
  ) {
    const setup = await issuerSetup();
    const credential = await issueCredential({
      type: new OtlHostingCredentialType(),
      input: { commonName: 'Example Participant', ...input },
      issuer: LOU_DID,
      subject: VASP_DID,
      provider: setup.provider,
      keyLabel: 'issuance',
      verificationMethod: LOU_VC_KEY,
      credentialStatus: setup.statusEntry(94_567),
      ...overrides,
    });
    return { credential, setup };
  }

  const verify = (credential: unknown, setup: Awaited<ReturnType<typeof issuerSetup>>) =>
    verifyCredential({
      credential,
      registry: defaultRegistry(),
      trustPerimeter: new TrustPerimeter({
        issuers: [{ did: LOU_DID, credentialTypes: [OTL_HOSTING_CREDENTIAL] }],
      }),
      resolveAssertionKey: setup.resolveAssertionKey,
      fetchStatusList: setup.fetchStatusList,
    });

  it('issues and validates with no watchers at all', async () => {
    // A provider may host a DID without running watchers for it (spec 4.14).
    const { credential, setup } = await issueHosting();
    assert.equal(credential.credentialSubject['watchers'], undefined);

    const result = await verify(credential, setup);
    assert.equal(result.valid, true, result.issues.join('; '));
  });

  it('round-trips the watcher list', async () => {
    const watchers = ['https://watcher-a.example.net', 'https://watcher-b.example.com'];
    const { credential, setup } = await issueHosting({ watchers });

    assert.deepEqual(credential.credentialSubject['watchers'], watchers);
    const result = await verify(credential, setup);
    assert.equal(result.valid, true, result.issues.join('; '));
  });

  it('round-trips the common name, trimmed (spec 4.14)', async () => {
    const { credential, setup } = await issueHosting({ commonName: '  Example Participant  ' });
    assert.equal(credential.credentialSubject['commonName'], 'Example Participant');

    const result = await verify(credential, setup);
    assert.equal(result.valid, true, result.issues.join('; '));
  });

  it('needs no validUntil, unlike an LEI credential (spec 4.13 vs 4.8)', async () => {
    const { credential, setup } = await issueHosting();
    assert.equal(credential.validUntil, undefined);

    const result = await verify(credential, setup);
    assert.equal(result.valid, true, result.issues.join('; '));
  });

  it('honours a validUntil when the provider sets one', async () => {
    const { credential, setup } = await issueHosting({}, { validUntil: '2026-02-01T00:00:00Z' });
    const result = await verifyCredential({
      credential,
      registry: defaultRegistry(),
      trustPerimeter: new TrustPerimeter({
        issuers: [{ did: LOU_DID, credentialTypes: [OTL_HOSTING_CREDENTIAL] }],
      }),
      resolveAssertionKey: setup.resolveAssertionKey,
      fetchStatusList: setup.fetchStatusList,
      now: new Date('2026-06-01T00:00:00Z'),
    });
    assert.equal(result.valid, false);
    assert.match(result.issues.join('; '), /expired/);
  });

  it('requires a credentialStatus (spec 4.13)', async () => {
    const setup = await issuerSetup();
    await assert.rejects(
      () =>
        issueCredential({
          type: new OtlHostingCredentialType(),
          input: { commonName: 'Example Participant' },
          issuer: LOU_DID,
          subject: VASP_DID,
          provider: setup.provider,
          keyLabel: 'issuance',
          verificationMethod: LOU_VC_KEY,
        }),
      /requires a credentialStatus/,
    );
  });

  it('refuses self-issuance (spec 4.13)', async () => {
    const setup = await issuerSetup();
    await assert.rejects(
      () =>
        issueCredential({
          type: new OtlHostingCredentialType(),
          input: { commonName: 'Example Participant' },
          issuer: LOU_DID,
          subject: LOU_DID,
          provider: setup.provider,
          keyLabel: 'issuance',
          verificationMethod: LOU_VC_KEY,
          credentialStatus: setup.statusEntry(94_567),
        }),
      /may not be self-issued/,
    );
  });

  describe('validateSubject (spec 4.14)', () => {
    const subjectWith = (watchers: unknown) => ({
      id: VASP_DID,
      commonName: 'Example Participant',
      watchers,
    });

    it('accepts an absent watchers field', () => {
      assert.equal(type.validateSubject({ id: VASP_DID, commonName: 'Example Participant' }).valid, true);
    });

    it('accepts an empty array as equivalent to omission', () => {
      // 4.14 makes the field optional and does not forbid the empty form, so
      // rejecting it would refuse a conformant credential.
      assert.equal(type.validateSubject(subjectWith([])).valid, true);
    });

    it('rejects a non-HTTPS watcher', () => {
      const result = type.validateSubject(subjectWith(['http://watcher.example']));
      assert.equal(result.valid, false);
      assert.match(result.issues.join('; '), /absolute https:\/\/ URL/);
    });

    it('rejects a value that is not a URL at all', () => {
      const result = type.validateSubject(subjectWith(['watcher-a.example.net']));
      assert.equal(result.valid, false);
    });

    it('rejects a repeated watcher', () => {
      // A duplicate would inflate any count of independent corroboration
      // drawn from this list (spec 2.4).
      const url = 'https://watcher-a.example.net';
      const result = type.validateSubject(subjectWith([url, url]));
      assert.equal(result.valid, false);
      assert.match(result.issues.join('; '), /more than once/);
    });

    it('rejects watchers that are not an array', () => {
      assert.equal(type.validateSubject(subjectWith('https://watcher.example')).valid, false);
    });

    it('requires a common name', () => {
      const result = type.validateSubject({ id: VASP_DID });
      assert.equal(result.valid, false);
      assert.match(result.issues.join('; '), /commonName is required/);
    });

    it('rejects a blank common name', () => {
      const result = type.validateSubject({ id: VASP_DID, commonName: '   ' });
      assert.equal(result.valid, false);
      assert.match(result.issues.join('; '), /must not be blank/);
    });

    it('rejects a common name past 128 characters', () => {
      const result = type.validateSubject({ id: VASP_DID, commonName: 'a'.repeat(129) });
      assert.equal(result.valid, false);
      assert.match(result.issues.join('; '), /at most 128 characters/);
    });

    it('accepts a common name of exactly 128 characters', () => {
      assert.equal(type.validateSubject({ id: VASP_DID, commonName: 'a'.repeat(128) }).valid, true);
    });

    it('rejects a newline in the common name', () => {
      // It would forge a second line of whatever renders the value.
      const result = type.validateSubject({ id: VASP_DID, commonName: 'Acme\nVerified' });
      assert.equal(result.valid, false);
      assert.match(result.issues.join('; '), /control characters/);
    });

    it('rejects a bidirectional override in the common name', () => {
      // U+202E reverses the rendered order: this displays as "example.org".
      const result = type.validateSubject({ id: VASP_DID, commonName: 'Acme \u202Egro.elpmaxe' });
      assert.equal(result.valid, false);
      assert.match(result.issues.join('; '), /control characters/);
    });

    it('accepts a zero-width joiner, which real names need', () => {
      // \p{Cf} is not blocked wholesale: ZWNJ is load-bearing in Persian and
      // several Indic scripts.
      assert.equal(type.validateSubject({ id: VASP_DID, commonName: 'Acme\u200CCorp' }).valid, true);
    });

    it('rejects a subject id that is not a did:webvh', () => {
      assert.equal(
        type.validateSubject({ id: 'did:web:example.com', commonName: 'Example Participant' }).valid,
        false,
      );
    });
  });

  it('rejects a hostile credential whose watchers are malformed on receipt', async () => {
    // validateSubject must bite on credentials we receive, not only on ours:
    // an attacker signs their own, so issuance-time checks protect nobody.
    const setup = await issuerSetup();
    const { createProof } = await import('@otl/core');
    const credential = await createProof({
      document: {
        '@context': ['https://www.w3.org/ns/credentials/v2'],
        id: 'urn:uuid:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
        type: ['VerifiableCredential', OTL_HOSTING_CREDENTIAL],
        issuer: LOU_DID,
        validFrom: '2026-01-01T00:00:00Z',
        credentialSubject: {
          id: VASP_DID,
          commonName: 'Example Participant',
          watchers: ['http://attacker.example'],
        },
        credentialStatus: setup.statusEntry(94_567),
      },
      provider: setup.provider,
      keyLabel: 'issuance',
      verificationMethod: LOU_VC_KEY,
      proofPurpose: 'assertionMethod',
    });

    const result = await verify(credential, setup);
    assert.equal(result.valid, false);
    assert.match(result.issues.join('; '), /https/);
  });

  it('is not accepted from an issuer trusted only for LEI (spec 4.12)', async () => {
    // "Trust in a provider for OtlHostingCredential does not extend to any
    // other credential type it may issue" -- and the converse.
    const { credential, setup } = await issueHosting();
    const result = await verifyCredential({
      credential,
      registry: defaultRegistry(),
      trustPerimeter: new TrustPerimeter({
        issuers: [{ did: LOU_DID, credentialTypes: [OTL_LEI_CREDENTIAL] }],
      }),
      resolveAssertionKey: setup.resolveAssertionKey,
      fetchStatusList: setup.fetchStatusList,
    });
    assert.equal(result.valid, false);
    assert.match(result.issues.join('; '), /not in the local trust perimeter/);
  });

  it('is revoked through the provider status list (spec 4.17)', async () => {
    const setup = await issuerSetup([94_567]);
    const credential = await issueCredential({
      type: new OtlHostingCredentialType(),
      input: { commonName: 'Example Participant', watchers: ['https://watcher-a.example.net'] },
      issuer: LOU_DID,
      subject: VASP_DID,
      provider: setup.provider,
      keyLabel: 'issuance',
      verificationMethod: LOU_VC_KEY,
      credentialStatus: setup.statusEntry(94_567),
    });

    const result = await verify(credential, setup);
    assert.equal(result.valid, false);
    assert.match(result.issues.join('; '), /revoked/);
  });
});

describe('trust perimeter (spec 6.1)', () => {
  it('trusts an issuer only for the types it was added for', () => {
    const perimeter = new TrustPerimeter().addIssuer(LOU_DID, [OTL_LEI_CREDENTIAL]);
    assert.equal(perimeter.trusts(LOU_DID, OTL_LEI_CREDENTIAL), true);
    assert.equal(perimeter.trusts(LOU_DID, 'OtlKycCredential'), false);
    assert.equal(perimeter.trusts(OTHER_LOU_DID, OTL_LEI_CREDENTIAL), false);
  });

  it('extends rather than replaces on a second add', () => {
    const perimeter = new TrustPerimeter()
      .addIssuer(LOU_DID, [OTL_LEI_CREDENTIAL])
      .addIssuer(LOU_DID, ['OtlKycCredential']);
    assert.deepEqual(
      perimeter.issuers()[0]?.credentialTypes,
      ['OtlKycCredential', OTL_LEI_CREDENTIAL].sort(),
    );
  });

  it('removes a single type or the whole issuer', () => {
    const perimeter = new TrustPerimeter().addIssuer(LOU_DID, [OTL_LEI_CREDENTIAL, 'OtlKycCredential']);
    perimeter.removeIssuer(LOU_DID, ['OtlKycCredential']);
    assert.equal(perimeter.trusts(LOU_DID, OTL_LEI_CREDENTIAL), true);
    assert.equal(perimeter.trusts(LOU_DID, 'OtlKycCredential'), false);

    // Full removal is the documented recovery path for a compromised anchor
    // (spec 5.4), where revocation lists are useless.
    perimeter.removeIssuer(LOU_DID);
    assert.equal(perimeter.trusts(LOU_DID, OTL_LEI_CREDENTIAL), false);
    assert.deepEqual(perimeter.issuers(), []);
  });

  it('drops an issuer once its last type is removed', () => {
    const perimeter = new TrustPerimeter().addIssuer(LOU_DID, [OTL_LEI_CREDENTIAL]);
    perimeter.removeIssuer(LOU_DID, [OTL_LEI_CREDENTIAL]);
    assert.deepEqual(perimeter.issuers(), []);
  });

  it('keeps allow and deny mutually exclusive', () => {
    const perimeter = new TrustPerimeter();
    perimeter.denyCounterparty(VASP_DID);
    assert.equal(perimeter.isDenied(VASP_DID), true);
    perimeter.allowCounterparty(VASP_DID);
    assert.equal(perimeter.isDenied(VASP_DID), false);
    assert.equal(perimeter.isExplicitlyAllowed(VASP_DID), true);
  });

  it('round-trips through JSON', () => {
    const original = new TrustPerimeter()
      .addIssuer(LOU_DID, [OTL_LEI_CREDENTIAL], 'GLEIF-accredited LOU, added 2026-01-01')
      .denyCounterparty(VASP_DID);
    const restored = TrustPerimeter.fromJSON(
      JSON.parse(JSON.stringify(original.toJSON())) as ReturnType<TrustPerimeter['toJSON']>,
    );

    assert.equal(restored.trusts(LOU_DID, OTL_LEI_CREDENTIAL), true);
    assert.equal(restored.isDenied(VASP_DID), true);
    assert.equal(restored.issuers()[0]?.note, 'GLEIF-accredited LOU, added 2026-01-01');
  });

  it('starts empty — nothing is trusted by default', () => {
    // Spec 4.6: there is no protocol-defined universal root of trust.
    assert.deepEqual(new TrustPerimeter().issuers(), []);
    assert.equal(new TrustPerimeter().trusts(LOU_DID, OTL_LEI_CREDENTIAL), false);
  });
});

describe('validation chain - hostile credentials', () => {
  /**
   * Sign a credential body directly, bypassing issueCredential's guards.
   *
   * A counterparty's credential never passes through our issuer, so every rule
   * issueCredential enforces must be enforced again on the verifying side.
   * These fixtures are what an attacker would actually present.
   */
  async function signRaw(body: Record<string, unknown>) {
    const setup = await issuerSetup();
    const { createProof } = await import('@otl/core');
    const credential = await createProof({
      document: body,
      provider: setup.provider,
      keyLabel: 'issuance',
      verificationMethod: LOU_VC_KEY,
      proofPurpose: 'assertionMethod',
    });

    const trustPerimeter = new TrustPerimeter({
      issuers: [{ did: LOU_DID, credentialTypes: [OTL_LEI_CREDENTIAL] }],
    });

    return verifyCredential({
      credential,
      registry: defaultRegistry(),
      trustPerimeter,
      resolveAssertionKey: setup.resolveAssertionKey,
      fetchStatusList: setup.fetchStatusList,
    });
  }

  const base = (overrides: Record<string, unknown> = {}) => ({
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    id: 'urn:uuid:11111111-2222-3333-4444-555555555555',
    type: ['VerifiableCredential', OTL_LEI_CREDENTIAL],
    issuer: LOU_DID,
    validFrom: '2026-01-01T00:00:00Z',
    // Spec 4.8: required, and no later than registration.nextRenewalDate,
    // which leiSubject() puts at 2027-01-01.
    validUntil: '2027-01-01T00:00:00Z',
    credentialSubject: leiSubject(),
    credentialStatus: [
      {
        id: `${STATUS_LIST_URL}#12`,
        type: 'BitstringStatusListEntry',
        statusPurpose: 'revocation',
        statusListIndex: '12',
        statusListCredential: STATUS_LIST_URL,
      },
    ],
    ...overrides,
  });

  it('sanity: a well-formed hand-signed credential is accepted', async () => {
    const result = await signRaw(base());
    assert.equal(result.valid, true, result.issues.join('; '));
  });

  it('rejects a self-issued credential presented by a counterparty', async () => {
    // Spec 4.8: "Self-issued LEI credentials are not valid." Refusing this only
    // at issuance would protect nobody -- an attacker signs their own.
    const result = await signRaw(base({ credentialSubject: leiSubject({ id: LOU_DID }) }));
    assert.equal(result.valid, false);
    assert.match(result.issues.join('; '), /may not be self-issued/);
  });

  it('rejects a validly signed credential whose subject is malformed', async () => {
    // A valid signature says the issuer sent it, not that its contents conform.
    const result = await signRaw(base({ credentialSubject: leiSubject({ lei: 'NOT-A-VALID-LEI' }) }));
    assert.equal(result.valid, false);
    assert.match(result.issues.join('; '), /ISO 17442/);
  });

  it('rejects a subject claiming an unenumerated corroborationLevel', async () => {
    const subject = leiSubject();
    const registration = {
      ...(subject['registration'] as object),
      corroborationLevel: 'TOTALLY_CORROBORATED',
    };
    const result = await signRaw(base({ credentialSubject: { ...subject, registration } }));
    assert.equal(result.valid, false);
    assert.match(result.issues.join('; '), /corroborationLevel/);
  });

  it('rejects a type array not beginning with VerifiableCredential', async () => {
    // Spec 4.3 fixes the first element; a parser keying off position would
    // otherwise be steered by a reordered array.
    const result = await signRaw(base({ type: [OTL_LEI_CREDENTIAL, 'VerifiableCredential'] }));
    assert.equal(result.valid, false);
    assert.match(result.issues.join('; '), /must begin with/);
  });

  it('rejects a credential also typed BitstringStatusListCredential (threat T-REV-05)', async () => {
    // Credentials and status lists are signed by the same assertionMethod keys,
    // so a document claiming to be both could carry one's signature as the other.
    const result = await signRaw(
      base({ type: ['VerifiableCredential', OTL_LEI_CREDENTIAL, 'BitstringStatusListCredential'] }),
    );
    assert.equal(result.valid, false);
    assert.match(result.issues.join('; '), /must not also be typed BitstringStatusListCredential/);
  });

  it('rejects an OtlLeiCredential with no credentialStatus', async () => {
    const result = await signRaw(base({ credentialStatus: undefined }));
    assert.equal(result.valid, false);
    assert.match(result.issues.join('; '), /MUST carry a credentialStatus/);
  });

  it('rejects a non-integer statusListIndex', async () => {
    const result = await signRaw(
      base({
        credentialStatus: [
          {
            type: 'BitstringStatusListEntry',
            statusPurpose: 'revocation',
            statusListIndex: 'not-a-number',
            statusListCredential: STATUS_LIST_URL,
          },
        ],
      }),
    );
    assert.equal(result.valid, false);
    assert.match(result.issues.join('; '), /not a non-negative integer/);
  });

  it('rejects an out-of-range statusListIndex rather than reading past the list', async () => {
    const result = await signRaw(
      base({
        credentialStatus: [
          {
            type: 'BitstringStatusListEntry',
            statusPurpose: 'revocation',
            statusListIndex: '99999999',
            statusListCredential: STATUS_LIST_URL,
          },
        ],
      }),
    );
    assert.equal(result.valid, false);
    assert.match(result.issues.join('; '), /out of range/);
  });

  it('rejects any credentialStatus type other than BitstringStatusListEntry', async () => {
    const result = await signRaw(
      base({
        credentialStatus: [
          {
            type: 'some-other-status-mechanism',
            statusPurpose: 'revocation',
            statusListIndex: '12',
            statusListCredential: STATUS_LIST_URL,
          },
        ],
      }),
    );
    assert.equal(result.valid, false);
    assert.match(result.issues.join('; '), /Unsupported credentialStatus type/);
  });

  it('rejects a statusPurpose other than revocation', async () => {
    const result = await signRaw(
      base({
        credentialStatus: [
          {
            type: 'BitstringStatusListEntry',
            statusPurpose: 'suspension',
            statusListIndex: '12',
            statusListCredential: STATUS_LIST_URL,
          },
        ],
      }),
    );
    assert.equal(result.valid, false);
    assert.match(result.issues.join('; '), /Unsupported statusPurpose/);
  });

  it('rejects a revocation entry wider than one bit (spec 5.1)', async () => {
    const result = await signRaw(
      base({
        credentialStatus: [
          {
            type: 'BitstringStatusListEntry',
            statusPurpose: 'revocation',
            statusListIndex: '12',
            statusListCredential: STATUS_LIST_URL,
            statusSize: 2,
          },
        ],
      }),
    );
    assert.equal(result.valid, false);
    assert.match(result.issues.join('; '), /Unsupported statusSize/);
  });

  it('rejects a credential with no issuer', async () => {
    const result = await signRaw(base({ issuer: '' }));
    assert.equal(result.valid, false);
  });
});
