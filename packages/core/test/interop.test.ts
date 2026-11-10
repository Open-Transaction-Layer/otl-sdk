/**
 * Conformance against an independent did:webvh implementation.
 *
 * The method layer is written from the specification rather than wrapped
 * around an existing library, so nothing in this package's own tests checks
 * its output against anyone else's reading of the specification. A defect of
 * that kind, such as emitting a log-entry proof in a shape another resolver
 * rejects, would only appear when a counterparty tried to resolve the DID.
 *
 * So this suite treats `didwebvh-ts` as an oracle: it was written by other
 * people, from the same spec, without reference to this package.
 *
 * ## Why the negative controls matter
 *
 * An oracle that accepts everything proves nothing. Half of these tests feed
 * it deliberately broken logs and assert it rejects them. Without that, a
 * future version of the library that silently stopped validating would leave
 * this suite green and useless.
 *
 * ## Scope
 *
 * One implementation, not all of them. `didwebvh-dart` is an independent
 * lineage (it is a port of `didwebvh-java`) and rejects things `didwebvh-ts`
 * tolerates, such as a log-entry proof that is a bare object rather than an
 * array. Wiring it in needs a Dart
 * SDK, so it stays a periodic manual check; see `docs/interop.md`.
 */

import assert from 'node:assert/strict';
import { createPublicKey, verify as nodeVerify } from 'node:crypto';
import { describe, it } from 'node:test';
import { resolveDIDFromLog } from 'didwebvh-ts';
import { InMemoryKeyProvider } from '@otl/keys-dev';
import { addKey, addService, createDid, deactivate, keyFromKeyInfo } from '../src/index.ts';
import type { DidLogEntry } from '../src/didwebvh/types.ts';

const DOMAIN = 'vasp.example.com';
const T1 = '2026-01-01T00:00:00Z';
const T2 = '2026-02-01T00:00:00Z';
const T3 = '2026-03-01T00:00:00Z';

/**
 * `didwebvh-ts` is crypto-agnostic and requires a verifier. Deliberately
 * implemented with `node:crypto` directly rather than our own `verifySignature`
 * — an oracle that shares our verification code is not independent of us.
 */
const verifier = {
  async verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): Promise<boolean> {
    try {
      return nodeVerify(
        null,
        message,
        createPublicKey({
          format: 'jwk',
          key: { kty: 'OKP', crv: 'Ed25519', x: Buffer.from(publicKey).toString('base64url') },
        }),
        signature,
      );
    } catch {
      return false;
    }
  },
};

// didwebvh-ts' published declarations import types that do not resolve in this
// workspace, so its exports surface as `error`-typed. Pinning the one signature
// this suite relies on keeps that looseness out of every call site.
//
// From 3.0.0 the resolver returns the W3C `DIDResolutionResult` shape and
// reports failure in `didResolutionMetadata` instead of throwing, with the
// original message under `problemDetails.detail`.
const resolveOracle = resolveDIDFromLog as unknown as (
  log: readonly DidLogEntry[],
  options: Record<string, unknown>,
) => Promise<{
  didDocument: Record<string, unknown> | null;
  didResolutionMetadata: { error?: string; problemDetails?: { detail?: string } };
}>;

interface Verdict {
  readonly accepted: boolean;
  readonly did?: string | undefined;
  readonly document?: Record<string, unknown> | undefined;
  readonly reason?: string | undefined;
}

async function askOracle(
  entries: readonly DidLogEntry[],
  options: Record<string, unknown> = {},
): Promise<Verdict> {
  try {
    const result = await resolveOracle(entries, { verifier, ...options });
    const { error, problemDetails } = result.didResolutionMetadata;
    // With a version selector the resolver may return an earlier valid document
    // alongside an error for a later invalid entry, so any error is a rejection
    // however the document looks.
    if (error !== undefined) {
      return { accepted: false, reason: problemDetails?.detail ?? error };
    }
    const document = result.didDocument ?? undefined;
    return { accepted: true, did: document?.['id'] as string | undefined, document };
  } catch (error) {
    return { accepted: false, reason: (error as Error).message };
  }
}

/** A DID with a second version, a genesis-bound key, and an added key. */
async function buildLog() {
  const provider = new InMemoryKeyProvider();
  for (let i = 0; i < 4; i++) await provider.generateKey(`k${i}`, 'Ed25519');
  const address = await provider.generateKey('address', 'Ed25519');
  const agreement = await provider.generateKey('agreement', 'X25519');

  const created = await createDid({
    domain: DOMAIN,
    provider,
    managementKeyLabel: 'k0',
    preRotationKeyLabel: 'k1',
    versionTime: T1,
    keys: [keyFromKeyInfo('address-verification-key', address, ['assertionMethod'])],
    genesisBoundKeys: ['address-verification-key'],
  });

  const v2 = await addService({
    did: created.did,
    previousEntry: created.entry,
    provider,
    signingKeyLabel: 'k1',
    nextKeyLabel: 'k2',
    versionTime: T2,
    service: { id: '#whois', type: 'OtlWhois', serviceEndpoint: `https://${DOMAIN}/.well-known/whois.vp` },
  });

  const v3 = await addKey({
    did: created.did,
    previousEntry: v2,
    provider,
    signingKeyLabel: 'k2',
    nextKeyLabel: 'k3',
    versionTime: T3,
    keys: [keyFromKeyInfo('agreement-key', agreement, ['keyAgreement'])],
  });

  return { provider, created, entries: [created.entry, v2, v3] as DidLogEntry[] };
}

const clone = (entries: readonly DidLogEntry[]): Record<string, unknown>[] =>
  JSON.parse(JSON.stringify(entries)) as Record<string, unknown>[];

describe('interop - an independent implementation accepts what we produce', () => {
  it('accepts a genesis-only log', async () => {
    const { created } = await buildLog();
    const verdict = await askOracle([created.entry]);
    assert.equal(verdict.accepted, true, verdict.reason ?? 'no reason reported');
    assert.equal(verdict.did, created.did, 'and agrees on the resolved DID');
  });

  it('accepts a multi-version log with services and added keys', async () => {
    const { created, entries } = await buildLog();
    const verdict = await askOracle(entries);
    assert.equal(verdict.accepted, true, verdict.reason ?? 'no reason reported');
    assert.equal(verdict.did, created.did);
  });

  it('accepts a deactivated DID', async () => {
    const provider = new InMemoryKeyProvider();
    for (let i = 0; i < 3; i++) await provider.generateKey(`k${i}`, 'Ed25519');
    const created = await createDid({
      domain: DOMAIN,
      provider,
      managementKeyLabel: 'k0',
      preRotationKeyLabel: 'k1',
      versionTime: T1,
    });
    const closed = await deactivate({
      did: created.did,
      previousEntry: created.entry,
      provider,
      signingKeyLabel: 'k1',
      nextKeyLabel: 'k2',
      versionTime: T2,
    });
    const verdict = await askOracle([created.entry, closed]);
    assert.equal(verdict.accepted, true, verdict.reason ?? 'no reason reported');
  });

  it('emits log-entry proofs in the shape an independent implementation expects', async () => {
    // The spec shows an array, and didwebvh-dart rejects a bare object.
    // didwebvh-ts tolerates either, so this asserts the shape directly rather
    // than relying on the oracle to notice.
    const { entries } = await buildLog();
    for (const entry of entries) {
      assert.ok(Array.isArray((entry as unknown as { proof: unknown }).proof));
    }
  });

  it('carries genesisBoundKeys through to a third-party resolver', async () => {
    // Only at version 1, which is the version a verifier reads the
    // designation from. Later versions deliberately omit it.
    const { entries } = await buildLog();

    const atGenesis = await askOracle(entries, { versionNumber: 1 });
    assert.equal(atGenesis.accepted, true, atGenesis.reason ?? 'no reason reported');
    assert.ok(
      Array.isArray(atGenesis.document?.['genesisBoundKeys']),
      'the designation must survive third-party resolution of version 1',
    );

    const atLatest = await askOracle(entries);
    assert.equal(atLatest.document?.['genesisBoundKeys'], undefined);
  });
});

describe('interop - the oracle genuinely validates', () => {
  // Without these, "accepted" above would prove nothing: an implementation
  // that accepted anything would keep this suite green forever.

  it('rejects an altered genesis document', async () => {
    const { entries } = await buildLog();
    const tampered = clone(entries);
    (tampered[0]!['state'] as Record<string, unknown>)['alsoControlledBy'] = 'did:webvh:QmX:attacker.example';
    const verdict = await askOracle(tampered as never);
    assert.equal(verdict.accepted, false);
    assert.match(verdict.reason ?? '', /SCID/i);
  });

  it('rejects an altered later entry', async () => {
    const { entries } = await buildLog();
    const tampered = clone(entries);
    const service = (tampered[1]!['state'] as Record<string, unknown>)['service'] as Record<
      string,
      unknown
    >[];
    service[0]!['serviceEndpoint'] = 'https://attacker.example/whois.vp';
    const verdict = await askOracle(tampered as never);
    assert.equal(verdict.accepted, false);
    assert.match(verdict.reason ?? '', /hash chain|entry/i);
  });

  it('rejects a corrupted signature', async () => {
    const { entries } = await buildLog();
    const tampered = clone(entries);
    const proof = (tampered[0]!['proof'] as Record<string, string>[])[0]!;
    proof['proofValue'] = `${proof['proofValue']!.slice(0, -4)}AAAA`;
    const verdict = await askOracle(tampered as never);
    assert.equal(verdict.accepted, false);
    assert.match(verdict.reason ?? '', /proof|verification/i);
  });

  it('rejects reordered entries', async () => {
    const { entries } = await buildLog();
    const verdict = await askOracle([entries[1]!, entries[0]!, entries[2]!]);
    assert.equal(verdict.accepted, false);
  });
});
