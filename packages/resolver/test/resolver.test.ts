import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  Bitstring,
  buildStatusListCredential,
  createProof,
  statusEntryFor,
  type StatusListCredential,
} from '@otl/core';
import {
  defaultRegistry,
  InMemoryStatusListMemory,
  issueCredential,
  OtlHostingCredentialType,
  OtlLeiCredentialType,
  OTL_HOSTING_CREDENTIAL,
  OTL_LEI_CREDENTIAL,
  TrustPerimeter,
} from '@otl/credentials';
import { InMemoryKeyProvider } from '@otl/keys-dev';
import { createDid, keyFromKeyInfo, addService } from '@otl/core';
import {
  assertFetchableUrl,
  didDocumentUrl,
  didLogUrl,
  FetchError,
  fetchJson,
  fetchText,
  InMemoryDidHeadMemory,
  InvalidDidError,
  parseDid,
  ResolutionError,
  resolveDid,
  resolveAssertionKey,
  resolveVerificationKey,
  statusListUrl,
  validateDid,
  verifyWhois,
  whoisUrl,
  type DidHeadMemory,
  type VerifiablePresentation,
} from '../src/index.ts';

const SCID = 'QmTestScid1111111111111111111111111111111111111';
const DID = `did:webvh:${SCID}:vasp.example.com`;

// ---------------------------------------------------------------------------
// A tiny in-memory origin, so tests exercise the real fetch path without a network.
// ---------------------------------------------------------------------------

function serveMap(
  routes: Record<string, string>,
  overrides: Record<string, Partial<{ status: number; headers: Record<string, string>; body: string }>> = {},
) {
  return (async (input: URL | string) => {
    const url = String(input);
    const override = overrides[url];
    const body = override?.body ?? routes[url];
    const status = override?.status ?? (body === undefined ? 404 : 200);
    return new Response(status === 204 || body === undefined ? null : body, {
      status,
      headers: override?.headers ?? {},
    });
  }) as unknown as typeof globalThis.fetch;
}

describe('DID to URL (spec 2.3)', () => {
  it('strips the SCID and uses .well-known for a bare domain', () => {
    assert.equal(didLogUrl(DID), 'https://vasp.example.com/.well-known/did.jsonl');
    assert.equal(didDocumentUrl(DID), 'https://vasp.example.com/.well-known/did.json');
    assert.equal(whoisUrl(DID), 'https://vasp.example.com/.well-known/whois.vp');
    assert.equal(statusListUrl(DID), 'https://vasp.example.com/.well-known/status-lists/1');
  });

  it('drops .well-known when the DID carries path segments', () => {
    const withPath = `did:webvh:${SCID}:example.com:dids:issuer`;
    assert.equal(didLogUrl(withPath), 'https://example.com/dids/issuer/did.jsonl');
    assert.equal(whoisUrl(withPath), 'https://example.com/dids/issuer/whois.vp');
  });

  it('percent-decodes a port', () => {
    const parsed = parseDid(`did:webvh:${SCID}:example.com%3A8443`);
    assert.equal(parsed.host, 'example.com:8443');
    assert.equal(parsed.origin, 'https://example.com:8443');
  });

  it('rejects a DID with no SCID, naming the expected format', () => {
    // The specification's examples omit the SCID for brevity, but did:webvh requires it (§2.2).
    assert.throws(
      () => parseDid('did:webvh:vasp.example.com'),
      (error: unknown) => {
        assert.ok(error instanceof InvalidDidError);
        assert.match(error.message, /did:webvh:\{SCID\}:\{domain\}/);
        return true;
      },
    );
  });

  it('rejects a malformed percent-encoding as an invalid DID', () => {
    for (const bad of [`did:webvh:${SCID}:example.com%E0`, `did:webvh:${SCID}:example.com:a%ZZ`]) {
      assert.throws(() => parseDid(bad), InvalidDidError, bad);
    }
  });

  it('rejects malformed identifiers', () => {
    for (const bad of ['did:web:example.com', `did:webvh:${SCID}`, `did:webvh:${SCID}:`, 'nonsense']) {
      assert.throws(() => parseDid(bad), InvalidDidError, bad);
    }
  });

  it('rejects relative path segments', () => {
    assert.throws(() => parseDid(`did:webvh:${SCID}:example.com:..:etc`), InvalidDidError);
  });

  it('rejects a host that is not a hostname', () => {
    assert.throws(() => parseDid(`did:webvh:${SCID}:not%2Fa%2Fhost`), InvalidDidError);
  });
});

describe('guarded fetching', () => {
  it('refuses plaintext HTTP', () => {
    assert.throws(
      () => assertFetchableUrl('http://example.com/x'),
      (error: unknown) => {
        assert.match((error as Error).message, /requires HTTPS/);
        return true;
      },
    );
  });

  it('refuses private and link-local hosts when asked', () => {
    const blocked = [
      'https://localhost/x',
      'https://127.0.0.1/x',
      'https://10.0.0.5/x',
      'https://192.168.1.1/x',
      'https://172.16.0.1/x',
      'https://169.254.169.254/latest/meta-data/', // cloud metadata
      'https://[::1]/x',
    ];
    for (const url of blocked) {
      assert.throws(() => assertFetchableUrl(url, { blockPrivateAddresses: true }), FetchError, url);
      // Off by default, so local development keeps working.
      assert.doesNotThrow(() => assertFetchableUrl(url));
    }
  });

  it('refuses to follow a redirect', async () => {
    // A cross-origin redirect is how a counterparty aims a resolver at an
    // internal host.
    const fetchImpl = serveMap(
      {},
      {
        'https://vasp.example.com/.well-known/did.json': {
          status: 302,
          headers: { location: 'https://169.254.169.254/latest/meta-data/' },
        },
      },
    );
    await assert.rejects(
      () => fetchText('https://vasp.example.com/.well-known/did.json', { fetch: fetchImpl }),
      /Refusing to follow a redirect/,
    );
  });

  it('rejects a body larger than the cap', async () => {
    const fetchImpl = serveMap({ 'https://vasp.example.com/big': 'x'.repeat(5000) });
    await assert.rejects(
      () => fetchText('https://vasp.example.com/big', { fetch: fetchImpl, maxBytes: 1000 }),
      /exceeded the 1000-byte limit/,
    );
  });

  it('rejects a declared content-length above the cap without reading the body', async () => {
    const fetchImpl = serveMap(
      {},
      {
        'https://vasp.example.com/big': { body: 'small', headers: { 'content-length': '99999999' } },
      },
    );
    await assert.rejects(
      () => fetchText('https://vasp.example.com/big', { fetch: fetchImpl, maxBytes: 1000 }),
      /above the 1000-byte limit/,
    );
  });

  it('times out rather than waiting forever', async () => {
    // Honours the abort signal, as a real fetch does; a stub that ignored it
    // would hang the suite rather than exercise the timeout.
    const hang = ((_input: unknown, init?: { signal?: AbortSignal }) =>
      new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener('abort', () => {
          reject(Object.assign(new Error('aborted'), { name: 'AbortError' }));
        });
      })) as unknown as typeof globalThis.fetch;
    await assert.rejects(
      () => fetchText('https://vasp.example.com/slow', { fetch: hang, timeoutMs: 50 }),
      /Timed out after 50ms/,
    );
  });

  it('surfaces HTTP errors with the status', async () => {
    const fetchImpl = serveMap({});
    await assert.rejects(
      () => fetchText('https://vasp.example.com/missing', { fetch: fetchImpl }),
      /HTTP 404/,
    );
  });

  it('reports invalid JSON against the URL that served it', async () => {
    const fetchImpl = serveMap({ 'https://vasp.example.com/x': 'not json' });
    await assert.rejects(
      () => fetchJson('https://vasp.example.com/x', { fetch: fetchImpl }),
      /did not return valid JSON/,
    );
  });
});

// ---------------------------------------------------------------------------
// End-to-end: a real DID published to an in-memory origin, then resolved.
// ---------------------------------------------------------------------------

async function publishParticipant(domain = 'lou.example.org') {
  const provider = new InMemoryKeyProvider();
  for (let i = 0; i < 4; i++) await provider.generateKey(`k${i}`, 'Ed25519');
  const issuance = await provider.generateKey('issuance', 'Ed25519');
  const assertion = await provider.generateKey('assertion', 'Ed25519');
  // Present in verificationMethod, deliberately absent from assertionMethod.
  const authOnly = await provider.generateKey('auth-only', 'Ed25519');

  const created = await createDid({
    domain,
    provider,
    managementKeyLabel: 'k0',
    preRotationKeyLabel: 'k1',
    versionTime: '2026-01-01T00:00:00Z',
    keys: [
      keyFromKeyInfo('credential-issuance-key', issuance, ['assertionMethod']),
      keyFromKeyInfo('assertion-key', assertion, ['assertionMethod', 'authentication']),
      keyFromKeyInfo('auth-only-key', authOnly, ['authentication']),
    ],
  });

  const withWhois = await addService({
    did: created.did,
    previousEntry: created.entry,
    provider,
    signingKeyLabel: 'k1',
    nextKeyLabel: 'k2',
    versionTime: '2026-02-01T00:00:00Z',
    service: {
      id: '#whois',
      type: 'OtlWhois',
      serviceEndpoint: `https://${domain}/.well-known/whois.vp`,
    },
  });

  const entries = [created.entry, withWhois];
  const routes: Record<string, string> = {
    [`https://${domain}/.well-known/did.jsonl`]: entries.map((e) => JSON.stringify(e)).join('\n'),
    [`https://${domain}/.well-known/did.json`]: JSON.stringify(withWhois.state),
  };

  return { provider, created, entries, routes, issuance, assertion, document: withWhois.state };
}

describe('resolution', () => {
  it('resolves a DID document without validating it', async () => {
    const { created, routes } = await publishParticipant();
    const document = await resolveDid(created.did, { fetch: serveMap(routes) });
    assert.equal(document.id, created.did);
  });

  it('rejects a document whose id does not match the DID requested', async () => {
    const { created, routes } = await publishParticipant();
    const swapped = {
      ...routes,
      [didDocumentUrl(created.did)]: JSON.stringify({ id: 'did:webvh:QmX:attacker.example' }),
    };
    await assert.rejects(() => resolveDid(created.did, { fetch: serveMap(swapped) }), ResolutionError);
  });

  it('validates a published log to genesis', async () => {
    const { created, routes } = await publishParticipant();
    const result = await validateDid(created.did, { fetch: serveMap(routes) });
    assert.equal(result.valid, true, result.issues.map((i) => i.message).join('; '));
    assert.equal(result.versionCount, 2);
    assert.equal(result.did, created.did);
  });

  it('rejects a log served under the wrong DID', async () => {
    const { created, routes } = await publishParticipant();
    const other = `did:webvh:${SCID}:lou.example.org`;
    const result = await validateDid(other, {
      fetch: serveMap({ [didLogUrl(other)]: routes[didLogUrl(created.did)]! }),
    });
    assert.equal(result.valid, false);
  });

  it('resolves a verification key only after the log validates', async () => {
    const { created, routes, issuance } = await publishParticipant();
    const key = await resolveVerificationKey(created.did, '#credential-issuance-key', {
      fetch: serveMap(routes),
    });
    assert.deepEqual(
      Buffer.from(key.bytes).toString('hex'),
      Buffer.from(issuance.publicKey.bytes).toString('hex'),
    );
  });

  it('refuses to return a key from a log that fails validation', async () => {
    // An invalid log must never fall back to the served document.
    const { created, routes } = await publishParticipant();
    const lines = routes[didLogUrl(created.did)]!.split('\n');
    const entry = JSON.parse(lines[1]!) as Record<string, unknown>;
    entry['versionTime'] = '2030-01-01T00:00:00Z'; // breaks the entry hash
    const tampered = { ...routes, [didLogUrl(created.did)]: [lines[0], JSON.stringify(entry)].join('\n') };

    await assert.rejects(
      () => resolveVerificationKey(created.did, '#credential-issuance-key', { fetch: serveMap(tampered) }),
      /failed validation/,
    );
  });

  it('refuses to resolve a key for an unknown fragment', async () => {
    const { created, routes } = await publishParticipant();
    await assert.rejects(
      () => resolveVerificationKey(created.did, '#no-such-key', { fetch: serveMap(routes) }),
      /no verification method/,
    );
  });

  it('refuses a key the DID never designated for the purpose (spec 3.2.1)', async () => {
    // #auth-only-key IS in verificationMethod, so a lookup that only consults
    // that array would hand it back. The array is an inventory; authority to
    // sign credentials comes from the assertionMethod reference.
    const { created, routes } = await publishParticipant();

    const withoutRelationship = await resolveVerificationKey(created.did, '#auth-only-key', {
      fetch: serveMap(routes),
    });
    assert.ok(withoutRelationship.bytes.length > 0, 'the key is present in the document');

    await assert.rejects(
      () =>
        resolveVerificationKey(created.did, '#auth-only-key', {
          fetch: serveMap(routes),
          relationship: 'assertionMethod',
        }),
      /does not reference .* under assertionMethod/,
    );
  });

  it('refuses a verification method belonging to another DID (spec 3.2.1)', async () => {
    // Guards the suffix-match hole: a reference ending in the expected
    // fragment but rooted at a different DID must not be selectable.
    const { created, routes } = await publishParticipant();
    await assert.rejects(
      () =>
        resolveVerificationKey(created.did, `did:webvh:${SCID}:attacker.example#credential-issuance-key`, {
          fetch: serveMap(routes),
        }),
      /does not belong to/,
    );
  });

  it('resolves the credential signing key named by a proof', async () => {
    const { created, routes, issuance } = await publishParticipant();
    const key = await resolveAssertionKey({ fetch: serveMap(routes) })(
      created.did,
      `${created.did}#credential-issuance-key`,
    );
    assert.deepEqual(
      Buffer.from(key.bytes).toString('hex'),
      Buffer.from(issuance.publicKey.bytes).toString('hex'),
    );
  });
});

describe('DID head memory (threat T-RES-02)', () => {
  const T3 = '2026-03-01T00:00:00Z';

  /** The two-entry log from publishParticipant, plus a third entry. */
  async function threeVersions() {
    const published = await publishParticipant();
    const third = await addService({
      did: published.created.did,
      previousEntry: published.entries[1]!,
      provider: published.provider,
      signingKeyLabel: 'k2',
      nextKeyLabel: 'k3',
      versionTime: T3,
      service: {
        id: '#status',
        type: 'OtlStatusList',
        serviceEndpoint: 'https://lou.example.org/.well-known/status-lists/1',
      },
    });
    const url = didLogUrl(published.created.did);
    const serve = (entries: readonly unknown[]) =>
      serveMap({ ...published.routes, [url]: entries.map((e) => JSON.stringify(e)).join('\n') });
    return { ...published, third, serve };
  }

  it('records the head of a log that validates, and reports it unchanged next time', async () => {
    const { created, entries, serve } = await threeVersions();
    const memory = new InMemoryDidHeadMemory();

    const first = await validateDid(created.did, { fetch: serve(entries), didHeadMemory: memory });
    assert.equal(first.valid, true, first.issues.map((i) => i.message).join('; '));
    assert.equal(first.continuity, 'new');
    assert.equal((await memory.lastAccepted(created.scid))?.versionNumber, 2);

    const again = await validateDid(created.did, { fetch: serve(entries), didHeadMemory: memory });
    assert.equal(again.continuity, 'unchanged');
  });

  it('accepts a log that extends the remembered head, and advances it', async () => {
    const { created, entries, third, serve } = await threeVersions();
    const memory = new InMemoryDidHeadMemory();
    await validateDid(created.did, { fetch: serve(entries), didHeadMemory: memory });

    const later = await validateDid(created.did, {
      fetch: serve([...entries, third]),
      didHeadMemory: memory,
    });
    assert.equal(later.valid, true, later.issues.map((i) => i.message).join('; '));
    assert.equal(later.continuity, 'extended');
    assert.equal((await memory.lastAccepted(created.scid))?.versionNumber, 3);
  });

  it('refuses a truncated log, and leaves the remembered head alone', async () => {
    const { created, entries, third, serve } = await threeVersions();
    const memory = new InMemoryDidHeadMemory();
    await validateDid(created.did, { fetch: serve([...entries, third]), didHeadMemory: memory });

    const rolledBack = await validateDid(created.did, { fetch: serve(entries), didHeadMemory: memory });
    assert.equal(rolledBack.valid, false);
    assert.equal(rolledBack.issues[0]?.kind, 'rollback');
    assert.equal((await memory.lastAccepted(created.scid))?.versionNumber, 3);
  });

  it('refuses a fork of the remembered history', async () => {
    const { created, entries, provider, serve } = await threeVersions();
    const memory = new InMemoryDidHeadMemory();
    await validateDid(created.did, { fetch: serve(entries), didHeadMemory: memory });
    const remembered = await memory.lastAccepted(created.scid);

    // A different, fully valid second version signed by the same committed key.
    const alternative = await addService({
      did: created.did,
      previousEntry: created.entry,
      provider,
      signingKeyLabel: 'k1',
      nextKeyLabel: 'k2',
      versionTime: '2026-02-01T00:00:00Z',
      service: { id: '#other', type: 'OtlWhois', serviceEndpoint: 'https://lou.example.org/other.json' },
    });
    const forked = await validateDid(created.did, {
      fetch: serve([created.entry, alternative]),
      didHeadMemory: new InMemoryDidHeadMemory(),
    });
    assert.equal(forked.valid, true, 'the fork is valid with no history to contradict it');

    const refused = await validateDid(created.did, {
      fetch: serve([created.entry, alternative]),
      didHeadMemory: memory,
    });
    assert.equal(refused.valid, false);
    assert.equal(refused.issues[0]?.kind, 'fork');
    assert.deepEqual(await memory.lastAccepted(created.scid), remembered);
  });

  it('never records a log that fails validation', async () => {
    const { created, entries, serve } = await threeVersions();
    const memory = new InMemoryDidHeadMemory();
    const tampered = JSON.parse(JSON.stringify(entries)) as { versionTime: string }[];
    tampered[1]!.versionTime = '2030-01-01T00:00:00Z'; // breaks the entry hash

    const result = await validateDid(created.did, { fetch: serve(tampered), didHeadMemory: memory });
    assert.equal(result.valid, false);
    assert.equal(await memory.lastAccepted(created.scid), undefined);
  });

  it('makes key resolution fail on a rollback, never fall back to the served log', async () => {
    const { created, entries, third, serve } = await threeVersions();
    const memory = new InMemoryDidHeadMemory();
    await validateDid(created.did, { fetch: serve([...entries, third]), didHeadMemory: memory });

    await assert.rejects(
      () =>
        resolveVerificationKey(created.did, '#credential-issuance-key', {
          fetch: serve(entries),
          didHeadMemory: memory,
        }),
      /failed validation[\s\S]*rollback/,
    );
  });

  it('fails closed when the memory cannot be read or written', async () => {
    const { created, entries, serve } = await threeVersions();
    const broken = (failing: 'read' | 'write'): DidHeadMemory => ({
      lastAccepted: async () => {
        if (failing === 'read') throw new Error('storage unavailable');
        return undefined;
      },
      record: async () => {
        if (failing === 'write') throw new Error('storage unavailable');
      },
    });

    for (const failing of ['read', 'write'] as const) {
      await assert.rejects(
        () => validateDid(created.did, { fetch: serve(entries), didHeadMemory: broken(failing) }),
        /storage unavailable/,
        `a ${failing} failure must reject, not skip the check`,
      );
    }
  });

  it('keeps the highest head when recorded out of order', async () => {
    const { created, entries, third, serve } = await threeVersions();
    const memory = new InMemoryDidHeadMemory();
    const high = (await validateDid(created.did, { fetch: serve([...entries, third]) })).head!;
    const low = (await validateDid(created.did, { fetch: serve(entries) })).head!;

    await memory.record(high);
    await memory.record(low);
    assert.equal((await memory.lastAccepted(created.scid))?.versionNumber, 3);
  });
});

describe('whois and the full chain (spec 4.4, 5.3)', () => {
  async function publishEverything(
    options: { revoked?: boolean; holderKeyPurposes?: ('assertionMethod' | 'authentication')[] } = {},
  ) {
    const lou = await publishParticipant();
    // A hosting provider is a different entity from the LOU, with its own
    // DID, its own key and its own status list (spec 4.12).
    const hostingProvider = await publishParticipant('hosting.example.org');
    const statusListUrlValue = 'https://lou.example.org/.well-known/status-lists/1';
    const hostingStatusUrl = 'https://hosting.example.org/.well-known/status-lists/1';

    const bitstring = Bitstring.create();
    if (options.revoked) bitstring.set(42, true);

    const statusList = await buildStatusListCredential({
      issuer: lou.created.did,
      statusListCredentialUrl: statusListUrlValue,
      bitstring,
      provider: lou.provider,
      keyLabel: 'issuance',
      verificationMethod: `${lou.created.did}#credential-issuance-key`,
      validFrom: new Date(Date.now() - 60_000).toISOString(),
      validUntil: new Date(Date.now() + 3_600_000).toISOString(),
    });

    // The subject is a second participant with its own validated log.
    const vasp = new InMemoryKeyProvider();
    for (let i = 0; i < 3; i++) await vasp.generateKey(`k${i}`, 'Ed25519');
    const vaspAssertion = await vasp.generateKey('assertion', 'Ed25519');
    const vaspDid = await createDid({
      domain: 'vasp.example.com',
      provider: vasp,
      managementKeyLabel: 'k0',
      preRotationKeyLabel: 'k1',
      versionTime: '2026-01-01T00:00:00Z',
      // Spec 6.3: the key that signs the presentation must be listed under
      // the holder's authentication.
      keys: [
        keyFromKeyInfo(
          'assertion-key',
          vaspAssertion,
          options.holderKeyPurposes ?? ['assertionMethod', 'authentication'],
        ),
      ],
    });

    const credential = await issueCredential({
      type: new OtlLeiCredentialType(),
      input: {
        lei: '00000000000000000098',
        gleif: {
          fetch: async () => ({
            ok: true,
            status: 200,
            json: async () => ({
              data: {
                attributes: {
                  lei: '00000000000000000098',
                  entity: {
                    legalName: { name: 'Example VASP GmbH' },
                    legalAddress: { addressLines: ['1 Road'], city: 'Frankfurt', country: 'DE' },
                    headquartersAddress: { addressLines: ['1 Road'], city: 'Frankfurt', country: 'DE' },
                    jurisdiction: 'DE',
                  },
                  registration: {
                    initialRegistrationDate: '2012-06-06T00:00:00Z',
                    nextRenewalDate: '2027-01-01T00:00:00Z',
                    managingLou: '00000000000000000195',
                    corroborationLevel: 'FULLY_CORROBORATED',
                  },
                },
              },
            }),
          }),
        },
      },
      issuer: lou.created.did,
      subject: vaspDid.did,
      provider: lou.provider,
      keyLabel: 'issuance',
      verificationMethod: `${lou.created.did}#credential-issuance-key`,
      credentialStatus: [statusEntryFor(statusListUrlValue, 42)],
      validFrom: '2026-01-01T00:00:00Z',
    });

    const hostingStatusList = await buildStatusListCredential({
      issuer: hostingProvider.created.did,
      statusListCredentialUrl: hostingStatusUrl,
      bitstring: Bitstring.create(),
      provider: hostingProvider.provider,
      keyLabel: 'issuance',
      verificationMethod: `${hostingProvider.created.did}#credential-issuance-key`,
      validFrom: new Date(Date.now() - 60_000).toISOString(),
      validUntil: new Date(Date.now() + 3_600_000).toISOString(),
    });

    const hostingCredential = await issueCredential({
      type: new OtlHostingCredentialType(),
      input: { commonName: 'Example VASP', watchers: ['https://watcher-a.example.net'] },
      issuer: hostingProvider.created.did,
      subject: vaspDid.did,
      provider: hostingProvider.provider,
      keyLabel: 'issuance',
      verificationMethod: `${hostingProvider.created.did}#credential-issuance-key`,
      credentialStatus: [statusEntryFor(hostingStatusUrl, 7)],
      validFrom: '2026-01-01T00:00:00Z',
    });

    const presentation = (await createProof({
      document: {
        '@context': ['https://www.w3.org/ns/credentials/v2'],
        type: ['VerifiablePresentation'],
        holder: vaspDid.did,
        verifiableCredential: [
          credential,
          hostingCredential,
          { type: ['VerifiableCredential', 'OtlFutureCredential'] },
        ],
      },
      provider: vasp,
      keyLabel: 'assertion',
      verificationMethod: `${vaspDid.did}#assertion-key`,
    })) as unknown as VerifiablePresentation;

    const routes: Record<string, string> = {
      ...lou.routes,
      ...hostingProvider.routes,
      'https://vasp.example.com/.well-known/did.jsonl': JSON.stringify(vaspDid.entry),
      'https://vasp.example.com/.well-known/whois.vp': JSON.stringify(presentation),
      [statusListUrlValue]: JSON.stringify(statusList),
      [hostingStatusUrl]: JSON.stringify(hostingStatusList),
    };

    // Each issuer is trusted for its own type only (spec 4.12, 6.1).
    const trustPerimeter = new TrustPerimeter()
      .addIssuer(lou.created.did, [OTL_LEI_CREDENTIAL])
      .addIssuer(hostingProvider.created.did, [OTL_HOSTING_CREDENTIAL]);
    return { routes, vaspDid, lou, hostingProvider, trustPerimeter, presentation };
  }

  it('fetches and validates a participant credentials end to end', async () => {
    const { routes, vaspDid, trustPerimeter } = await publishEverything();
    const fetchImpl = serveMap(routes);

    const result = await verifyWhois({
      did: vaspDid.did,
      registry: defaultRegistry(),
      trustPerimeter,
      resolveAssertionKey: resolveAssertionKey({ fetch: fetchImpl }),
      fetchStatusList: (url) => Promise.resolve(JSON.parse(routes[url]!) as StatusListCredential),
      fetchOptions: { fetch: fetchImpl },
    });

    assert.equal(result.holder, vaspDid.did);
    assert.equal(result.presentationVerified, true, result.presentationIssue ?? 'no reason reported');
    // Two recognised types from two different issuers, each trusted only for
    // its own type, validated in one pass (spec 4.4, 4.12).
    assert.equal(result.valid.length, 2, result.credentials.map((c) => c.issues.join('; ')).join(' | '));
    assert.deepEqual(
      result.valid.map((c) => c.typeName).sort(),
      [OTL_HOSTING_CREDENTIAL, OTL_LEI_CREDENTIAL].sort(),
    );
  });

  it('refuses a presentation signed by a key not listed under authentication (spec 6.3)', async () => {
    const { routes, vaspDid, trustPerimeter } = await publishEverything({
      holderKeyPurposes: ['assertionMethod'],
    });
    const fetchImpl = serveMap(routes);

    const result = await verifyWhois({
      did: vaspDid.did,
      registry: defaultRegistry(),
      trustPerimeter,
      resolveAssertionKey: resolveAssertionKey({ fetch: fetchImpl }),
      fetchStatusList: (url) => Promise.resolve(JSON.parse(routes[url]!) as StatusListCredential),
      fetchOptions: { fetch: fetchImpl },
    });

    assert.equal(result.presentationVerified, false);
    assert.match(result.presentationIssue ?? '', /under authentication/);
    assert.equal(result.valid.length, 0);
  });

  it('skips an unrecognized credential type without failing the batch (spec 4.4)', async () => {
    const { routes, vaspDid, trustPerimeter } = await publishEverything();
    const fetchImpl = serveMap(routes);

    const result = await verifyWhois({
      did: vaspDid.did,
      registry: defaultRegistry(),
      trustPerimeter,
      resolveAssertionKey: resolveAssertionKey({ fetch: fetchImpl }),
      fetchStatusList: (url) => Promise.resolve(JSON.parse(routes[url]!) as StatusListCredential),
      fetchOptions: { fetch: fetchImpl },
    });

    assert.equal(result.credentials.length, 3);
    assert.equal(result.credentials[2]?.skipped, true, 'the unknown type is skipped, not failed');
    assert.equal(result.valid.length, 2, 'both recognized credentials must still validate');
  });

  it('reports a revoked credential as invalid', async () => {
    const { routes, vaspDid, trustPerimeter } = await publishEverything({ revoked: true });
    const fetchImpl = serveMap(routes);

    const result = await verifyWhois({
      did: vaspDid.did,
      registry: defaultRegistry(),
      trustPerimeter,
      resolveAssertionKey: resolveAssertionKey({ fetch: fetchImpl }),
      fetchStatusList: (url) => Promise.resolve(JSON.parse(routes[url]!) as StatusListCredential),
      fetchOptions: { fetch: fetchImpl },
    });

    // Only the LEI credential is revoked; the hosting one is untouched, which
    // is the point of each issuer keeping its own status list.
    assert.equal(result.valid.length, 1);
    assert.equal(result.valid[0]?.typeName, OTL_HOSTING_CREDENTIAL);
    assert.match(result.credentials[0]!.issues.join('; '), /revoked/);
  });

  describe('status list rollback memory (spec 5.2)', () => {
    const leiListUrl = 'https://lou.example.org/.well-known/status-lists/1';

    async function setupRollback() {
      const published = await publishEverything();
      const { routes, vaspDid, lou, trustPerimeter } = published;
      const fetchImpl = serveMap(routes);

      // Validly signed by the issuer, but dated before the list served on the
      // first call: the "copy taken before a revocation" that a signature check
      // alone cannot tell from the current one.
      const superseded = await buildStatusListCredential({
        issuer: lou.created.did,
        statusListCredentialUrl: leiListUrl,
        bitstring: Bitstring.create(),
        provider: lou.provider,
        keyLabel: 'issuance',
        verificationMethod: `${lou.created.did}#credential-issuance-key`,
        validFrom: new Date(Date.now() - 600_000).toISOString(),
        validUntil: new Date(Date.now() + 3_600_000).toISOString(),
      });

      const verify = (served: Record<string, unknown>, statusListMemory?: InMemoryStatusListMemory) =>
        verifyWhois({
          did: vaspDid.did,
          registry: defaultRegistry(),
          trustPerimeter,
          resolveAssertionKey: resolveAssertionKey({ fetch: fetchImpl }),
          fetchStatusList: async (url) => (served[url] ?? JSON.parse(routes[url]!)) as never,
          fetchOptions: { fetch: fetchImpl },
          ...(statusListMemory !== undefined ? { statusListMemory } : {}),
        });

      return { verify, superseded };
    }

    it('refuses a rolled-back status list when one memory is shared across calls', async () => {
      const { verify, superseded } = await setupRollback();
      const memory = new InMemoryStatusListMemory();

      const first = await verify({}, memory);
      assert.equal(first.valid.length, 2, first.credentials.map((c) => c.issues.join('; ')).join(' | '));

      const second = await verify({ [leiListUrl]: superseded }, memory);
      assert.equal(second.valid.length, 1, 'only the hosting credential survives');
      assert.equal(second.valid[0]?.typeName, OTL_HOSTING_CREDENTIAL);
      assert.match(second.credentials[0]!.issues.join('; '), /rollback/);
    });

    it('does not detect the same rollback when no memory is supplied (the default)', async () => {
      const { verify, superseded } = await setupRollback();

      await verify({});
      const second = await verify({ [leiListUrl]: superseded });

      assert.equal(
        second.valid.length,
        2,
        'each call starts from an empty memory, so nothing to roll back from',
      );
    });
  });

  it('applies one head memory to the holder and to every issuer it resolves', async () => {
    const { routes, vaspDid, lou, hostingProvider, trustPerimeter } = await publishEverything();
    const fetchImpl = serveMap(routes);
    const didHeadMemory = new InMemoryDidHeadMemory();

    const result = await verifyWhois({
      did: vaspDid.did,
      registry: defaultRegistry(),
      trustPerimeter,
      resolveAssertionKey: resolveAssertionKey({ fetch: fetchImpl, didHeadMemory }),
      fetchStatusList: (url) => Promise.resolve(JSON.parse(routes[url]!) as StatusListCredential),
      fetchOptions: { fetch: fetchImpl },
      didHeadMemory,
    });
    assert.equal(result.valid.length, 2, result.credentials.map((c) => c.issues.join('; ')).join(' | '));

    // The holder came through verifyWhois itself; the issuers through the
    // resolveAssertionKey built with the same memory.
    for (const did of [vaspDid, lou.created, hostingProvider.created]) {
      assert.ok(await didHeadMemory.lastAccepted(did.scid), `${did.did} should have a remembered head`);
    }
  });

  it('rejects a presentation whose holder does not match the DID', async () => {
    const { routes, vaspDid } = await publishEverything();
    const forged = {
      ...(JSON.parse(routes['https://vasp.example.com/.well-known/whois.vp']!) as Record<string, unknown>),
      holder: 'did:webvh:QmX:attacker.example',
    };
    const tampered = { ...routes, 'https://vasp.example.com/.well-known/whois.vp': JSON.stringify(forged) };

    await assert.rejects(
      () =>
        verifyWhois({
          did: vaspDid.did,
          registry: defaultRegistry(),
          trustPerimeter: new TrustPerimeter(),
          resolveAssertionKey: resolveAssertionKey({ fetch: serveMap(tampered) }),
          fetchStatusList: (url) => Promise.resolve(JSON.parse(routes[url]!) as StatusListCredential),
          fetchOptions: { fetch: serveMap(tampered) },
        }),
      /declares holder/,
    );
  });
});
