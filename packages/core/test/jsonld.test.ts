/**
 * JSON-LD expansion of our credentials.
 *
 * VC 2.0 is a JSON-LD data model, and its rule is that a conforming consumer
 * drops any term the `@context` does not define. Our other credential tests
 * treat credentials as plain JSON, so none of them can see this: a credential
 * whose entire payload is discarded still passes every structural check and
 * every signature check we have.
 *
 * These tests pin two things — the defect as it stands, and that the context
 * in `contexts/` fixes it. The first will start failing the day OTL publishes
 * a context and we begin emitting it, which is the point: it should not be
 * possible to fix this quietly or to regress it quietly.
 *
 * Contexts are loaded from disk. A test that fetches them would be slow,
 * flaky, and would leak which credentials we process to whoever hosts them.
 */

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import jsonld from 'jsonld';
import { InMemoryKeyProvider } from '@open-transaction-layer/keys-dev';
import {
  issueCredential,
  OtlHostingCredentialType,
  OtlLeiCredentialType,
  OTL_IDENTITY_CONTEXT,
} from '@open-transaction-layer/credentials';
import { Bitstring, buildStatusListCredential, statusEntryFor, verifyProof } from '../src/index.ts';

const HERE = import.meta.dirname;
const OTL_CONTEXT_URL = OTL_IDENTITY_CONTEXT;
const ISSUER = 'did:webvh:QmTestScidIssuer:lou.example.org';
const SUBJECT = 'did:webvh:QmTestScidSubject:vasp.example.com';

const read = (path: string) => JSON.parse(readFileSync(path, 'utf8')) as Record<string, unknown>;

const CONTEXTS: Record<string, Record<string, unknown>> = {
  'https://www.w3.org/ns/credentials/v2': read(join(HERE, 'contexts', 'credentials-v2.jsonld')),
  [OTL_CONTEXT_URL]: read(join(HERE, '..', '..', 'credentials', 'contexts', 'otl-identity-v1.jsonld')),
};

const documentLoader = async (url: string) => {
  const document = CONTEXTS[url];
  if (!document) throw new Error(`unexpected context fetch: ${url}`);
  return { contextUrl: null, documentUrl: url, document };
};

/** A GLEIF Level 1 record with every optional field populated. */
const GLEIF_RECORD = {
  data: {
    attributes: {
      lei: '00000000000000000098',
      entity: {
        legalName: { name: 'Example Participant GmbH' },
        otherNames: [{ name: 'Example Participant', type: 'TRADING_OR_OPERATING_NAME' }],
        legalAddress: {
          addressLines: ['Beispielstrasse 1'],
          city: 'Frankfurt',
          region: 'DE-HE',
          country: 'DE',
          postalCode: '60311',
        },
        headquartersAddress: {
          addressLines: ['Beispielstrasse 1'],
          city: 'Frankfurt',
          region: 'DE-HE',
          country: 'DE',
          postalCode: '60311',
        },
        registeredAt: { id: 'RA000563' },
        registeredAs: 'HRB 12345',
        jurisdiction: 'DE',
        legalForm: { id: 'XTIQ' },
        category: 'GENERAL',
      },
      registration: {
        initialRegistrationDate: '2012-06-06T00:00:00Z',
        nextRenewalDate: '2027-01-01T00:00:00Z',
        managingLou: '00000000000000000195',
        corroborationLevel: 'FULLY_CORROBORATED',
      },
    },
  },
};

/** Every §4.9 credentialSubject field, by the term the context must define. */
const SPEC_4_9_FIELDS = [
  'lei',
  'legalName',
  'otherName',
  'legalAddress',
  'headquartersAddress',
  'registeredAt',
  'registeredAs',
  'jurisdiction',
  'legalForm',
  'category',
  'initialRegistrationDate',
  'nextRenewalDate',
  'managingLou',
  'corroborationLevel',
] as const;

async function issueLeiCredential(additionalContexts: readonly string[] = []) {
  const provider = new InMemoryKeyProvider();
  const key = await provider.generateKey('issuance', 'Ed25519');

  const type = new OtlLeiCredentialType();
  if (additionalContexts.length > 0) {
    // `additionalContexts` is an instance field, so it is assigned rather than
    // subclassed — a getter on a subclass loses to the field.
    Object.defineProperty(type, 'additionalContexts', { value: additionalContexts });
  }

  const credential = await issueCredential({
    type,
    input: {
      lei: '00000000000000000098',
      gleif: { fetch: async () => ({ ok: true, status: 200, json: async () => GLEIF_RECORD }) },
    },
    issuer: ISSUER,
    subject: SUBJECT,
    provider,
    keyLabel: 'issuance',
    verificationMethod: `${ISSUER}#credential-issuance-key`,
    credentialStatus: [statusEntryFor('https://lou.example.org/.well-known/status-lists/1', 42)],
    validFrom: '2026-01-01T00:00:00Z',
  });
  return { credential, publicKey: key.publicKey };
}

const expandedText = async (document: unknown) =>
  JSON.stringify(await jsonld.expand(document, { documentLoader }));

describe('JSON-LD - the defect, as emitted', () => {
  it('discards every credentialSubject claim', async () => {
    // Exactly the shape spec §4.10 shows: credentials/v2 and nothing else.
    const { credential } = await issueLeiCredential();
    const flat = await expandedText(credential);

    for (const field of SPEC_4_9_FIELDS) {
      assert.ok(
        !flat.includes(`identity#${field}`),
        `${field} unexpectedly survived — has an OTL context been added to the credential? Update this test.`,
      );
    }

    const [expanded] = await jsonld.expand(credential, { documentLoader });
    const subject = expanded!['https://www.w3.org/2018/credentials#credentialSubject'] as unknown[];
    assert.deepEqual(subject, [{ '@id': SUBJECT }], 'the subject should retain nothing but its identifier');
  });

  it('still verifies, which is why this is invisible', async () => {
    // eddsa-jcs-2022 canonicalizes raw JSON, so expansion never reaches the
    // proof. Every signature check passes on a credential that says nothing.
    const { credential, publicKey } = await issueLeiCredential();
    assert.equal((await verifyProof({ document: credential, publicKey })).verified, true);
  });
});

describe('JSON-LD - the context in contexts/ fixes it', () => {
  it('preserves all fourteen §4.9 fields', async () => {
    const { credential } = await issueLeiCredential([OTL_CONTEXT_URL]);
    const flat = await expandedText(credential);

    const dropped = SPEC_4_9_FIELDS.filter((f) => !flat.includes(`identity#${f}`));
    assert.deepEqual(dropped, [], `dropped: ${dropped.join(', ')}`);
  });

  it('expands the credential type to an IRI', async () => {
    const { credential } = await issueLeiCredential([OTL_CONTEXT_URL]);
    assert.ok((await expandedText(credential)).includes('identity#OtlLeiCredential'));
  });

  it('does not disturb the signature', async () => {
    const { credential, publicKey } = await issueLeiCredential([OTL_CONTEXT_URL]);
    assert.equal((await verifyProof({ document: credential, publicKey })).verified, true);
  });

  it('cannot be retrofitted to an already-signed credential', async () => {
    // @context is hashed into proofConfig, so credentials must be ISSUED with
    // the context. Anything issued before it exists stays semantically empty.
    const { credential, publicKey } = await issueLeiCredential();
    const retrofitted = {
      ...credential,
      '@context': [...(credential['@context'] as string[]), OTL_CONTEXT_URL],
    };
    assert.equal((await verifyProof({ document: retrofitted, publicKey })).verified, false);
  });
});

describe('JSON-LD - the context covers OtlHostingCredential', () => {
  async function issueHostingCredential() {
    const provider = new InMemoryKeyProvider();
    const key = await provider.generateKey('issuance', 'Ed25519');
    const type = new OtlHostingCredentialType();
    Object.defineProperty(type, 'additionalContexts', { value: [OTL_CONTEXT_URL] });
    const credential = await issueCredential({
      type,
      input: { commonName: 'Example Participant', watchers: ['https://watcher-a.example.net'] },
      issuer: ISSUER,
      subject: SUBJECT,
      provider,
      keyLabel: 'issuance',
      verificationMethod: `${ISSUER}#credential-issuance-key`,
      credentialStatus: [statusEntryFor('https://lou.example.org/.well-known/status-lists/1', 7)],
      validFrom: '2026-01-01T00:00:00Z',
    });
    return { credential, publicKey: key.publicKey };
  }

  it('preserves both §4.14 fields and the type', async () => {
    const { credential } = await issueHostingCredential();
    const flat = await expandedText(credential);
    for (const term of ['commonName', 'watcher', 'OtlHostingCredential']) {
      assert.ok(flat.includes(`identity#${term}`), `dropped: ${term}`);
    }
  });

  it('expands each watcher as an IRI', async () => {
    const { credential } = await issueHostingCredential();
    const flat = await expandedText(credential);
    assert.ok(flat.includes('{"@id":"https://watcher-a.example.net"}'));
  });

  it('does not disturb the signature', async () => {
    const { credential, publicKey } = await issueHostingCredential();
    assert.equal((await verifyProof({ document: credential, publicKey })).verified, true);
  });
});

describe('JSON-LD - the status list needs no OTL context', () => {
  it('expands cleanly under credentials/v2 alone', async () => {
    // §5.2: "The @context is https://www.w3.org/ns/credentials/v2 only — no
    // separate status context URL is needed." Confirmed rather than assumed.
    const provider = new InMemoryKeyProvider();
    await provider.generateKey('issuance', 'Ed25519');
    const statusList = await buildStatusListCredential({
      issuer: ISSUER,
      statusListCredentialUrl: 'https://lou.example.org/.well-known/status-lists/1',
      bitstring: Bitstring.create(),
      provider,
      keyLabel: 'issuance',
      verificationMethod: `${ISSUER}#credential-issuance-key`,
      validFrom: '2026-01-01T00:00:00Z',
    });

    const flat = await expandedText(statusList);
    for (const term of ['encodedList', 'statusPurpose', 'BitstringStatusList']) {
      assert.ok(flat.includes(term), `${term} was dropped from the status list`);
    }
  });
});

/** N-Quads for a document, with `safe` so a dropped term or relative IRI throws. */
const toNQuads = async (document: unknown, base?: string): Promise<string> =>
  (await jsonld.toRDF(document, {
    documentLoader,
    format: 'application/n-quads',
    safe: true,
    ...(base === undefined ? {} : { base }),
  })) as string;

const NS = 'https://www.otl.network/ns/identity#';

describe('JSON-LD - the RDF layer, where two implementations agree or do not', () => {
  it('emits a statement carrying the value for all fourteen §4.9 fields, with no base IRI', async () => {
    const { credential } = await issueLeiCredential([OTL_CONTEXT_URL]);
    const nquads = await toNQuads(credential);

    const missing = SPEC_4_9_FIELDS.filter((f) => !nquads.includes(`<${NS}${f}>`));
    assert.deepEqual(missing, [], `no RDF statement for: ${missing.join(', ')}`);

    // The two fields whose values are `{ id: "…" }` objects: the code must
    // arrive as a literal, not as a relative IRI that vanishes without a base.
    assert.ok(nquads.includes(`<${NS}elfCode> "XTIQ"`), 'legalForm code must be a literal');
    assert.ok(
      nquads.includes(`<${NS}registrationAuthorityCode> "RA000563"`),
      'registeredAt code must be a literal',
    );
  });

  it('derives identical RDF whatever base IRI the verifier supplies', async () => {
    const { credential } = await issueLeiCredential([OTL_CONTEXT_URL]);
    const lines = (text: string) => text.split('\n').sort().join('\n');

    // Blank node labels are assigned in document order, so they match across runs.
    const unset = lines(await toNQuads(credential));
    const credentialBase = lines(await toNQuads(credential, 'https://lou.example.org/credentials/1'));
    const unrelated = lines(await toNQuads(credential, 'https://verifier.example/inbox/'));
    assert.equal(credentialBase, unset);
    assert.equal(unrelated, unset);
  });

  it('keeps the hosting credential terms', async () => {
    const hosting = {
      '@context': ['https://www.w3.org/ns/credentials/v2', OTL_CONTEXT_URL],
      type: ['VerifiableCredential', 'OtlHostingCredential'],
      issuer: ISSUER,
      validFrom: '2026-01-01T00:00:00Z',
      credentialSubject: {
        id: SUBJECT,
        commonName: 'Example Participant',
        watchers: ['https://watcher.example.org/'],
      },
    };
    const nquads = await toNQuads(hosting);
    for (const term of ['OtlHostingCredential', 'commonName', 'watcher']) {
      assert.ok(nquads.includes(`${NS}${term}`), `${term} was dropped`);
    }
    assert.ok(nquads.includes('<https://watcher.example.org/>'), 'watchers must be IRIs');
  });
});

describe('JSON-LD - nothing the SDK emits is left without a context term', () => {
  /** Every term name the bundled context defines, at any depth. */
  const definedTerms = (): Set<string> => {
    const terms = new Set<string>();
    const walk = (context: Record<string, unknown>) => {
      for (const [key, value] of Object.entries(context)) {
        if (key.startsWith('@')) continue;
        terms.add(key);
        if (typeof value === 'object' && value !== null) {
          const nested = (value as { '@context'?: Record<string, unknown> })['@context'];
          if (nested) walk(nested);
        }
      }
    };
    walk((CONTEXTS[OTL_CONTEXT_URL] as { '@context': Record<string, unknown> })['@context']);
    return terms;
  };

  /** Property names used in a subject; `id` and `type` are JSON-LD keywords here. */
  const usedKeys = (value: unknown, found = new Set<string>()): Set<string> => {
    if (Array.isArray(value)) value.forEach((v) => usedKeys(v, found));
    else if (typeof value === 'object' && value !== null) {
      for (const [key, inner] of Object.entries(value)) {
        if (key !== 'id' && key !== 'type') found.add(key);
        usedKeys(inner, found);
      }
    }
    return found;
  };

  const assertAllDefined = (subject: unknown) => {
    const used = usedKeys(subject);
    assert.ok(used.size > 0, 'the subject should carry at least one property');
    const terms = definedTerms();
    const undefinedKeys = [...used].filter((k) => !terms.has(k));
    assert.deepEqual(undefinedKeys, [], `no context term for: ${undefinedKeys.join(', ')}`);
  };

  it('defines a term for every property in an issued OtlLeiCredential', async () => {
    const { credential } = await issueLeiCredential([OTL_CONTEXT_URL]);
    assertAllDefined(credential['credentialSubject']);
    await toNQuads(credential); // safe mode throws if anything is still dropped
  });

  it('defines a term for every property in an issued OtlHostingCredential', async () => {
    const provider = new InMemoryKeyProvider();
    await provider.generateKey('issuance', 'Ed25519');
    const type = new OtlHostingCredentialType();
    Object.defineProperty(type, 'additionalContexts', { value: [OTL_CONTEXT_URL] });
    const credential = await issueCredential({
      type,
      input: { commonName: 'Example Participant', watchers: ['https://watcher-a.example.net'] },
      issuer: ISSUER,
      subject: SUBJECT,
      provider,
      keyLabel: 'issuance',
      verificationMethod: `${ISSUER}#credential-issuance-key`,
      credentialStatus: [statusEntryFor('https://lou.example.org/.well-known/status-lists/1', 8)],
      validFrom: '2026-01-01T00:00:00Z',
    });
    assertAllDefined(credential['credentialSubject']);
    await toNQuads(credential);
  });
});

describe('JSON-LD - issuing and verifying never touch the network', () => {
  it('performs no context fetch beyond the bundled loader', async () => {
    // The loader above throws on any URL it does not know, so success here is
    // the assertion: nothing in issue or verify reaches for a context.
    const { credential, publicKey } = await issueLeiCredential([OTL_CONTEXT_URL]);
    assert.equal((await verifyProof({ document: credential, publicKey })).verified, true);
  });
});
