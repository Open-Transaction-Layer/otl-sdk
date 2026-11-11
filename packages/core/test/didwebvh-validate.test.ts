import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { toPublicKeyMultibase } from '@otl/keys';
import { InMemoryKeyProvider } from '@otl/keys-dev';
import { createDid } from '../src/didwebvh/create.ts';
import { DIDWEBVH_1_0_PROFILE, OTL_EXTENDED_PROFILE } from '../src/didwebvh/profile.ts';
import { addService, deactivate } from '../src/didwebvh/update.ts';
import { deriveEntryHash, parseVersionId } from '../src/didwebvh/hashing.ts';
import { createProof } from '../src/proof.ts';
import { parseDidLog, validateDidLog } from '../src/didwebvh/validate.ts';
import type { DidLogEntry } from '../src/didwebvh/types.ts';
import { InvalidDocumentError } from '../src/errors.ts';

const DOMAIN = 'vasp.example.com';
const T1 = '2026-01-01T00:00:00Z';
const T2 = '2026-02-01T00:00:00Z';
const T3 = '2026-03-01T00:00:00Z';

/** A valid three-entry log: genesis, add-service, add-service. */
async function validLog() {
  const provider = new InMemoryKeyProvider();
  for (let i = 0; i < 5; i++) await provider.generateKey(`k${i}`, 'Ed25519');

  const created = await createDid({
    domain: DOMAIN,
    provider,
    managementKeyLabel: 'k0',
    preRotationKeyLabel: 'k1',
    versionTime: T1,
  });
  const entry2 = await addService({
    did: created.did,
    previousEntry: created.entry,
    provider,
    signingKeyLabel: 'k1',
    nextKeyLabel: 'k2',
    versionTime: T2,
    service: { id: '#whois', type: 'OtlWhois', serviceEndpoint: `https://${DOMAIN}/.well-known/whois.vp` },
  });
  const entry3 = await addService({
    did: created.did,
    previousEntry: entry2,
    provider,
    signingKeyLabel: 'k2',
    nextKeyLabel: 'k3',
    versionTime: T3,
    service: {
      id: '#status',
      type: 'OtlStatusList',
      serviceEndpoint: `https://${DOMAIN}/.well-known/status-lists/1`,
    },
  });

  return { provider, created, entries: [created.entry, entry2, entry3] as DidLogEntry[] };
}

/**
 * Deep clone, with readonly stripped.
 *
 * Tamper tests deliberately construct shapes the builders refuse to produce,
 * so they need to write to fields the domain types mark readonly.
 */
type DeepMutable<T> = T extends readonly (infer U)[]
  ? DeepMutable<U>[]
  : T extends object
    ? { -readonly [K in keyof T]: DeepMutable<T[K]> }
    : T;

const clone = <T>(value: T): DeepMutable<T> => JSON.parse(JSON.stringify(value)) as DeepMutable<T>;

const messages = (result: { issues: readonly { message: string }[] }) =>
  result.issues.map((i) => i.message).join(' | ');

/**
 * First proof on an entry.
 *
 * Log-entry proofs are an array (spec 3.2.2); credential proofs are a bare
 * object (spec 4.10). This accepts either, so a test reads the same whichever
 * shape it is handed.
 */
function firstProof(entry: unknown): Record<string, unknown> {
  const proof = (entry as { proof?: unknown }).proof;
  return (Array.isArray(proof) ? proof[0] : proof) as Record<string, unknown>;
}

describe('validation - a well-formed log', () => {
  it('accepts it', async () => {
    const { entries } = await validLog();
    const result = await validateDidLog(entries);
    assert.equal(result.valid, true, messages(result));
  });

  it('reports the resolved identity', async () => {
    const { created, entries } = await validLog();
    const result = await validateDidLog(entries);
    assert.equal(result.did, created.did);
    assert.equal(result.scid, created.scid);
    assert.equal(result.versionCount, 3);
    assert.equal(result.deactivated, false);
    assert.deepEqual(
      (result.document?.service ?? []).map((s) => s.id),
      ['#whois', '#status'],
    );
  });

  it('accepts a single-entry log', async () => {
    const { created } = await validLog();
    const result = await validateDidLog([created.entry]);
    assert.equal(result.valid, true, messages(result));
  });

  it('matches an expected DID and rejects a different one', async () => {
    const { created, entries } = await validLog();
    assert.equal((await validateDidLog(entries, { expectedDid: created.did })).valid, true);

    const wrong = await validateDidLog(entries, { expectedDid: 'did:webvh:QmOther:attacker.example' });
    assert.equal(wrong.valid, false);
    assert.match(messages(wrong), /was requested/);
  });
});

describe('validation - SCID', () => {
  it('rejects a genesis document altered after the fact', async () => {
    // The SCID commits to the genesis document, so any edit to it breaks.
    const { entries } = await validLog();
    const tampered = clone(entries);
    tampered[0]!.state = { ...tampered[0]!.state, alsoControlledBy: 'did:webvh:QmX:attacker.example' };

    const result = await validateDidLog(tampered);
    assert.equal(result.valid, false);
    assert.match(messages(result), /SCID mismatch/);
  });

  it('rejects a DID that does not embed its own SCID', async () => {
    const { entries } = await validLog();
    const tampered = clone(entries);
    tampered[0]!.parameters = { ...tampered[0]!.parameters, scid: 'z'.repeat(46) };

    const result = await validateDidLog(tampered);
    assert.equal(result.valid, false);
    assert.match(messages(result), /SCID mismatch|does not embed/);
  });

  it('rejects a genesis entry with no scid', async () => {
    const { entries } = await validLog();
    const tampered = clone(entries);
    delete (tampered[0]!.parameters as Record<string, unknown>)['scid'];
    const result = await validateDidLog(tampered);
    assert.equal(result.valid, false);
    assert.match(messages(result), /no parameters.scid/);
  });

  it('rejects an unknown method version', async () => {
    const { entries } = await validLog();
    const tampered = clone(entries);
    tampered[0]!.parameters = { ...tampered[0]!.parameters, method: 'did:webvh:0.5' };
    const result = await validateDidLog(tampered);
    assert.equal(result.valid, false);
    assert.match(messages(result), /method/);
  });
});

describe('validation - hash chain', () => {
  it('rejects a modified middle entry', async () => {
    const { entries } = await validLog();
    const tampered = clone(entries);
    tampered[1]!.versionTime = '2026-02-02T00:00:00Z';

    const result = await validateDidLog(tampered);
    assert.equal(result.valid, false);
    assert.match(messages(result), /Entry hash mismatch/);
  });

  it('rejects a removed entry', async () => {
    // Dropping entry 2 breaks both the version numbering and the chain.
    const { entries } = await validLog();
    const result = await validateDidLog([entries[0]!, entries[2]!]);
    assert.equal(result.valid, false);
    assert.match(messages(result), /version|hash mismatch/i);
  });

  it('rejects a reordered log', async () => {
    const { entries } = await validLog();
    const result = await validateDidLog([entries[0]!, entries[2]!, entries[1]!]);
    assert.equal(result.valid, false);
  });

  it('rejects a versionId whose entry hash was rewritten', async () => {
    const { entries } = await validLog();
    const tampered = clone(entries);
    tampered[1]!.versionId = `2-${'z'.repeat(46)}`;
    const result = await validateDidLog(tampered);
    assert.equal(result.valid, false);
    assert.match(messages(result), /Entry hash mismatch/);
  });

  it('rejects a malformed versionId', async () => {
    const { entries } = await validLog();
    const tampered = clone(entries);
    tampered[1]!.versionId = 'not-a-version-id';
    assert.equal((await validateDidLog(tampered)).valid, false);
  });

  it('rejects versionTime moving backwards', async () => {
    const { provider, created } = await validLog();
    const backwards = await addService({
      did: created.did,
      previousEntry: created.entry,
      provider,
      signingKeyLabel: 'k1',
      nextKeyLabel: 'k2',
      versionTime: '2020-01-01T00:00:00Z',
      service: { id: '#whois', type: 'OtlWhois', serviceEndpoint: `https://${DOMAIN}/w.json` },
    });
    const result = await validateDidLog([created.entry, backwards]);
    assert.equal(result.valid, false);
    assert.match(messages(result), /must strictly increase/);
  });
});

describe('validation - pre-rotation', () => {
  it('rejects an entry signed by a key that was never committed', async () => {
    // The core guarantee: an attacker who steals a live key still cannot
    // append, because the log committed to a different key in advance.
    const provider = new InMemoryKeyProvider();
    for (let i = 0; i < 4; i++) await provider.generateKey(`k${i}`, 'Ed25519');
    const rogue = await provider.generateKey('rogue', 'Ed25519');

    const created = await createDid({
      domain: DOMAIN,
      provider,
      managementKeyLabel: 'k0',
      preRotationKeyLabel: 'k1',
      versionTime: T1,
    });
    const legitimate = await deactivate({
      did: created.did,
      previousEntry: created.entry,
      provider,
      signingKeyLabel: 'k1',
      nextKeyLabel: 'k2',
      versionTime: T2,
    });

    // Swap in a rogue update key, leaving the (now wrong) proof in place.
    const forged = clone(legitimate);
    forged.parameters = {
      ...forged.parameters,
      updateKeys: [toPublicKeyMultibase(rogue.publicKey)],
    };

    const result = await validateDidLog([created.entry, forged]);
    assert.equal(result.valid, false);
    assert.match(messages(result), /not committed by the previous entry/);
  });

  it('rejects an empty commitment', async () => {
    const { entries } = await validLog();
    const tampered = clone(entries);
    tampered[1]!.parameters = { ...tampered[1]!.parameters, nextKeyHashes: [] };
    const result = await validateDidLog(tampered);
    assert.equal(result.valid, false);
    assert.match(messages(result), /commitment to the next update key must always be present/);
  });

  it('rejects a missing commitment', async () => {
    const { entries } = await validLog();
    const tampered = clone(entries);
    delete (tampered[1]!.parameters as Record<string, unknown>)['nextKeyHashes'];
    const result = await validateDidLog(tampered);
    assert.equal(result.valid, false);
    assert.match(messages(result), /commitment to the next update key must always be present/);
  });

  it('can be told to accept a plain did:webvh log without pre-rotation', async () => {
    // OTL requires pre-rotation; base did:webvh does not. A validator that
    // could not evaluate such a log would silently accept it instead.
    const { entries } = await validLog();
    const tampered = clone(entries);
    tampered[1]!.parameters = { ...tampered[1]!.parameters, nextKeyHashes: [] };

    const strict = await validateDidLog(tampered, { requirePreRotation: true });
    const lenient = await validateDidLog(tampered, { requirePreRotation: false });
    assert.equal(strict.valid, false);
    assert.ok(!messages(lenient).includes('commitment at all times'));
  });

  it('rejects updateKeys omitted while pre-rotation is active', async () => {
    const { entries } = await validLog();
    const tampered = clone(entries);
    delete (tampered[1]!.parameters as Record<string, unknown>)['updateKeys'];
    const result = await validateDidLog(tampered);
    assert.equal(result.valid, false);
    assert.match(messages(result), /explicit in every entry/);
  });
});

describe('validation - proofs', () => {
  it('rejects an entry with no proof', async () => {
    const { entries } = await validLog();
    const tampered = clone(entries);
    delete (tampered[1] as unknown as Record<string, unknown>)['proof'];
    const result = await validateDidLog(tampered);
    assert.equal(result.valid, false);
    assert.match(messages(result), /no proof/);
  });

  it('rejects a proof from a key outside the active updateKeys', async () => {
    const provider = new InMemoryKeyProvider();
    for (let i = 0; i < 4; i++) await provider.generateKey(`k${i}`, 'Ed25519');
    const outsider = await provider.generateKey('outsider', 'Ed25519');

    const created = await createDid({
      domain: DOMAIN,
      provider,
      managementKeyLabel: 'k0',
      preRotationKeyLabel: 'k1',
      versionTime: T1,
    });
    const entry2 = await deactivate({
      did: created.did,
      previousEntry: created.entry,
      provider,
      signingKeyLabel: 'k1',
      nextKeyLabel: 'k2',
      versionTime: T2,
    });

    const outsiderKey = toPublicKeyMultibase(outsider.publicKey);
    const forged = clone(entry2);
    (forged as unknown as Record<string, unknown>)['proof'] = [
      { ...firstProof(forged), verificationMethod: `did:key:${outsiderKey}#${outsiderKey}` },
    ];

    const result = await validateDidLog([created.entry, forged]);
    assert.equal(result.valid, false);
    assert.match(messages(result), /not in the active updateKeys/);
  });

  it('rejects a non-conformant cryptosuite', async () => {
    // did:webvh 1.0 permits only eddsa-jcs-2022 and requires rejection of
    // anything else rather than attempting verification.
    const { entries } = await validLog();
    const tampered = clone(entries);
    (tampered[1] as unknown as Record<string, unknown>)['proof'] = [
      { ...firstProof(tampered[1]!), cryptosuite: 'ecdsa-jcs-2019' },
    ];
    const result = await validateDidLog(tampered);
    assert.equal(result.valid, false);
    assert.match(messages(result), /permits only eddsa-jcs-2022/);
  });

  it('rejects a corrupted signature', async () => {
    const { entries } = await validLog();
    const tampered = clone(entries);
    const proof = firstProof(tampered[1]!);
    proof['proofValue'] = String(proof['proofValue']).slice(0, -4) + 'AAAA';
    const result = await validateDidLog(tampered);
    assert.equal(result.valid, false);
  });
});

describe('validation - entry-1-only parameters', () => {
  for (const [name, key, value] of [
    ['scid', 'scid', 'z'.repeat(46)],
    ['portable', 'portable', true],
  ] as const) {
    it(`rejects ${name} in a later entry`, async () => {
      const { entries } = await validLog();
      const tampered = clone(entries);
      tampered[1]!.parameters = { ...tampered[1]!.parameters, [key]: value };
      const result = await validateDidLog(tampered);
      assert.equal(result.valid, false);
      assert.match(messages(result), new RegExp(name));
    });
  }
});

describe('validation - deactivation', () => {
  it('reports a deactivated DID as valid but deactivated', async () => {
    const provider = new InMemoryKeyProvider();
    for (let i = 0; i < 4; i++) await provider.generateKey(`k${i}`, 'Ed25519');
    const created = await createDid({
      domain: DOMAIN,
      provider,
      managementKeyLabel: 'k0',
      preRotationKeyLabel: 'k1',
      versionTime: T1,
    });
    const entry2 = await deactivate({
      did: created.did,
      previousEntry: created.entry,
      provider,
      signingKeyLabel: 'k1',
      nextKeyLabel: 'k2',
      versionTime: T2,
    });

    const result = await validateDidLog([created.entry, entry2]);
    assert.equal(result.valid, true, messages(result));
    assert.equal(result.deactivated, true);
  });

  it('rejects an entry appended after deactivation', async () => {
    const provider = new InMemoryKeyProvider();
    for (let i = 0; i < 5; i++) await provider.generateKey(`k${i}`, 'Ed25519');
    const created = await createDid({
      domain: DOMAIN,
      provider,
      managementKeyLabel: 'k0',
      preRotationKeyLabel: 'k1',
      versionTime: T1,
    });
    const entry2 = await deactivate({
      did: created.did,
      previousEntry: created.entry,
      provider,
      signingKeyLabel: 'k1',
      nextKeyLabel: 'k2',
      versionTime: T2,
    });
    // appendEntry refuses to extend a deactivated log, so the extension is
    // built from a copy of entry 2 with the flag stripped. Entry 3 chains to
    // entry 2's versionId and is signed by the committed key either way.
    const entry3 = await addService({
      did: created.did,
      previousEntry: { ...entry2, parameters: { ...entry2.parameters, deactivated: false } },
      provider,
      signingKeyLabel: 'k2',
      nextKeyLabel: 'k3',
      versionTime: T3,
      service: { id: '#whois', type: 'OtlWhois', serviceEndpoint: `https://${DOMAIN}/w.json` },
    });

    const result = await validateDidLog([created.entry, entry2, entry3]);
    assert.equal(result.valid, false);
    assert.match(messages(result), /deactivated/);
  });
});

describe('validation - state binding', () => {
  it('rejects a document whose id does not match the DID', async () => {
    const { entries } = await validLog();
    const tampered = clone(entries);
    tampered[1]!.state = { ...tampered[1]!.state, id: 'did:webvh:QmOther:attacker.example' };
    const result = await validateDidLog(tampered);
    assert.equal(result.valid, false);
  });
});

describe('parseDidLog', () => {
  it('parses JSON Lines and ignores blank lines', async () => {
    const { entries } = await validLog();
    const jsonl = entries.map((e) => JSON.stringify(e)).join('\n') + '\n\n';
    const parsed = parseDidLog(jsonl);
    assert.equal(parsed.length, 3);
    assert.equal((await validateDidLog(parsed)).valid, true);
  });

  it('reports the offending line number', () => {
    assert.throws(() => parseDidLog('{"a":1}\nnot json\n'), /line 2/);
  });

  it('treats an empty log as invalid rather than vacuously valid', async () => {
    const result = await validateDidLog(parseDidLog(''));
    assert.equal(result.valid, false);
    assert.match(messages(result), /empty/);
  });
});

describe('validation - active updateKeys without pre-rotation', () => {
  /**
   * Builds a log entry by hand, so a test can construct shapes appendEntry
   * deliberately refuses to produce -- here, a log with pre-rotation turned off.
   */
  async function handBuiltEntry(options: {
    previousEntry: DidLogEntry;
    provider: InMemoryKeyProvider;
    signingKeyLabel: string;
    updateKeys: readonly string[];
    nextKeyHashes: readonly string[];
    versionTime: string;
  }): Promise<DidLogEntry> {
    const { previousEntry, provider, signingKeyLabel, updateKeys, nextKeyHashes, versionTime } = options;
    const previousVersion = parseVersionId(previousEntry.versionId).versionNumber;

    const unhashed = {
      versionId: previousEntry.versionId,
      versionTime,
      parameters: { updateKeys, nextKeyHashes },
      state: previousEntry.state,
    } as DidLogEntry;

    const entryHash = deriveEntryHash(unhashed, previousEntry.versionId);
    const unsigned = { ...unhashed, versionId: `${previousVersion + 1}-${entryHash}` };

    const signingKey = await provider.getKey(signingKeyLabel);
    const multikey = toPublicKeyMultibase(signingKey.publicKey);
    return (await createProof({
      document: unsigned,
      provider,
      keyLabel: signingKeyLabel,
      verificationMethod: `did:key:${multikey}#${multikey}`,
      proofPurpose: 'assertionMethod',
    })) as unknown as DidLogEntry;
  }

  /** Genesis, then an entry that switches pre-rotation off. */
  async function logWithPreRotationDisabled() {
    const provider = new InMemoryKeyProvider();
    for (let i = 0; i < 4; i++) await provider.generateKey(`k${i}`, 'Ed25519');
    const outsider = await provider.generateKey('outsider', 'Ed25519');

    const created = await createDid({
      domain: DOMAIN,
      provider,
      managementKeyLabel: 'k0',
      preRotationKeyLabel: 'k1',
      versionTime: T1,
    });

    const k1 = await provider.getKey('k1');
    const entry2 = await handBuiltEntry({
      previousEntry: created.entry,
      provider,
      signingKeyLabel: 'k1',
      updateKeys: [toPublicKeyMultibase(k1.publicKey)],
      nextKeyHashes: [], // deactivates pre-rotation
      versionTime: T2,
    });

    return { provider, created, entry2, outsider };
  }

  it('verifies against the previous entry updateKeys once pre-rotation is off', async () => {
    // With pre-rotation inactive, did:webvh says the active list is "the most
    // recent updateKeys BEFORE the entry to be verified". So entry 3 must be
    // signed by a key entry 2 authorized -- not merely one entry 3 names
    // itself, which an attacker controls completely.
    const { provider, created, entry2, outsider } = await logWithPreRotationDisabled();
    const outsiderKey = toPublicKeyMultibase(outsider.publicKey);

    const forged = await handBuiltEntry({
      previousEntry: entry2,
      provider,
      signingKeyLabel: 'outsider',
      updateKeys: [outsiderKey], // self-declared authority
      nextKeyHashes: [],
      versionTime: T3,
    });

    const result = await validateDidLog([created.entry, entry2, forged], {
      requirePreRotation: false,
    });
    assert.equal(result.valid, false, 'a self-authorized entry must not be accepted');
    assert.match(messages(result), /not in the active updateKeys/);
  });

  it('accepts an entry signed by a key the previous entry authorized', async () => {
    const { provider, created, entry2 } = await logWithPreRotationDisabled();

    const entry3 = await handBuiltEntry({
      previousEntry: entry2,
      provider,
      signingKeyLabel: 'k1', // still the key entry 2 declared
      updateKeys: [toPublicKeyMultibase((await provider.getKey('k1')).publicKey)],
      nextKeyHashes: [],
      versionTime: T3,
    });

    const result = await validateDidLog([created.entry, entry2, entry3], {
      requirePreRotation: false,
    });
    assert.equal(result.valid, true, messages(result));
  });
});

describe('validation - method profiles', () => {
  it('rejects a log declaring an unrecognized method', async () => {
    // Guessing which rules apply would mean verifying under rules the log
    // never claimed, so an unknown method is a rejection rather than a default.
    const { entries } = await validLog();
    const tampered = clone(entries);
    tampered[0]!.parameters = { ...tampered[0]!.parameters, method: 'did:webvh:99.0' };

    const result = await validateDidLog(tampered);
    assert.equal(result.valid, false);
    assert.match(messages(result), /not among the accepted profiles/);
  });

  it('rejects a widened profile unless the caller opts in', async () => {
    // A log announcing anything but did:webvh:1.0 is not resolvable by stock
    // tooling; accepting one silently would hide that from the operator.
    const { entries } = await validLog();
    const tampered = clone(entries);
    tampered[0]!.parameters = { ...tampered[0]!.parameters, method: OTL_EXTENDED_PROFILE.method };

    const strict = await validateDidLog(tampered);
    assert.equal(strict.valid, false);
    assert.match(messages(strict), /not among the accepted profiles/);

    // Opting in gets past the profile check; the SCID still fails, because the
    // genesis parameters are committed to by it.
    const opted = await validateDidLog(tampered, {
      allowedProfiles: [DIDWEBVH_1_0_PROFILE, OTL_EXTENDED_PROFILE],
    });
    assert.ok(!messages(opted).includes('not among the accepted profiles'));
  });

  it('validates a log built end to end under the widened profile', async () => {
    // P-256 log proofs, which stock did:webvh 1.0 forbids, announced through
    // parameters.method so a stock resolver rejects them loudly.
    const provider = new InMemoryKeyProvider();
    await provider.generateKey('m', 'P-256');
    await provider.generateKey('n', 'P-256');

    const created = await createDid({
      domain: DOMAIN,
      provider,
      managementKeyLabel: 'm',
      preRotationKeyLabel: 'n',
      versionTime: T1,
      profile: OTL_EXTENDED_PROFILE,
    });

    assert.equal(created.entry.parameters.method, OTL_EXTENDED_PROFILE.method);
    assert.equal(firstProof(created.entry)['cryptosuite'], 'ecdsa-jcs-2019');

    const result = await validateDidLog([created.entry], {
      allowedProfiles: [OTL_EXTENDED_PROFILE],
    });
    assert.equal(result.valid, true, messages(result));

    // And a stock resolver refuses it, which is the point of the label.
    const stock = await validateDidLog([created.entry]);
    assert.equal(stock.valid, false);
  });

  it('refuses a P-256 management key under stock did:webvh, naming the KMS consequence', async () => {
    const provider = new InMemoryKeyProvider();
    await provider.generateKey('m', 'P-256');
    await provider.generateKey('n', 'Ed25519');

    await assert.rejects(
      () =>
        createDid({
          domain: DOMAIN,
          provider,
          managementKeyLabel: 'm',
          preRotationKeyLabel: 'n',
          versionTime: T1,
        }),
      (error: unknown) => {
        assert.match((error as Error).message, /AWS KMS/);
        assert.match((error as Error).message, /parameters\.method/);
        return true;
      },
    );
  });
});

describe('continuity with a previously validated head (threat T-RES-02)', () => {
  const headOf = (entries: readonly DidLogEntry[], versionNumber: number, scid: string) => ({
    scid,
    did: `did:webvh:${scid}:${DOMAIN}`,
    versionNumber,
    versionId: entries[versionNumber - 1]!.versionId,
  });

  it('reports a first sighting as new and returns the head it establishes', async () => {
    const { entries } = await validLog();
    const result = await validateDidLog(entries);

    assert.equal(result.valid, true, messages(result));
    assert.equal(result.continuity, 'new');
    assert.deepEqual(result.head, headOf(entries, 3, result.scid!));
  });

  it('reports the same log again as unchanged', async () => {
    const { entries } = await validLog();
    const first = await validateDidLog(entries);
    const again = await validateDidLog(entries, { known: first.head! });

    assert.equal(again.valid, true, messages(again));
    assert.equal(again.continuity, 'unchanged');
  });

  it('accepts a log that extends the known head, and returns the newer one', async () => {
    const { entries } = await validLog();
    const earlier = await validateDidLog(entries.slice(0, 2));
    const later = await validateDidLog(entries, { known: earlier.head! });

    assert.equal(later.valid, true, messages(later));
    assert.equal(later.continuity, 'extended');
    assert.equal(later.head!.versionNumber, 3);
  });

  it('refuses a shorter log than the known head as a rollback', async () => {
    const { entries } = await validLog();
    const full = await validateDidLog(entries);
    const truncated = await validateDidLog(entries.slice(0, 2), { known: full.head! });

    // The truncated log is internally perfect; only memory can tell.
    assert.equal(truncated.valid, false);
    assert.equal(truncated.issues[0]!.kind, 'rollback');
    assert.match(messages(truncated), /rollback or truncation/);
    assert.equal(truncated.head, undefined, 'a refused log must not become a head');
  });

  it('refuses a log whose entry at the known position differs, as a fork', async () => {
    const { provider, created, entries } = await validLog();
    const known = await validateDidLog(entries);

    // A different but fully valid second version, signed by the same
    // committed key: a split view of the same DID.
    const alternative = await addService({
      did: created.did,
      previousEntry: created.entry,
      provider,
      signingKeyLabel: 'k1',
      nextKeyLabel: 'k2',
      versionTime: T2,
      service: { id: '#other', type: 'OtlWhois', serviceEndpoint: `https://${DOMAIN}/other.json` },
    });
    const forked = [created.entry, alternative];
    assert.equal((await validateDidLog(forked)).valid, true, 'the fork is valid on its own');

    const result = await validateDidLog(forked, { known: headOf(entries, 2, known.scid!) });
    assert.equal(result.valid, false);
    assert.equal(result.issues[0]!.kind, 'fork');
    assert.match(messages(result), /rewritten or forked/);
  });

  it('refuses a fork that is longer than the known head', async () => {
    const { provider, created, entries } = await validLog();
    const known = await validateDidLog(entries.slice(0, 2));

    // A different second version, extended by a third: longer than what we
    // know, and a valid log on its own, but not a continuation of it.
    const alternative = await addService({
      did: created.did,
      previousEntry: created.entry,
      provider,
      signingKeyLabel: 'k1',
      nextKeyLabel: 'k2',
      versionTime: T2,
      service: { id: '#other', type: 'OtlWhois', serviceEndpoint: `https://${DOMAIN}/other.json` },
    });
    const third = await addService({
      did: created.did,
      previousEntry: alternative,
      provider,
      signingKeyLabel: 'k2',
      nextKeyLabel: 'k3',
      versionTime: T3,
      service: { id: '#more', type: 'OtlWhois', serviceEndpoint: `https://${DOMAIN}/more.json` },
    });
    const longerFork = [created.entry, alternative, third];
    assert.equal((await validateDidLog(longerFork)).valid, true, 'the fork is valid on its own');

    const result = await validateDidLog(longerFork, { known: known.head! });
    assert.equal(result.valid, false);
    assert.equal(result.issues[0]!.kind, 'fork');
  });

  it('refuses to un-deactivate a DID by cutting the deactivation off', async () => {
    const { provider, created, entries } = await validLog();
    const deactivation = await deactivate({
      did: created.did,
      previousEntry: entries[2]!,
      provider,
      signingKeyLabel: 'k3',
      nextKeyLabel: 'k4',
      versionTime: '2026-04-01T00:00:00Z',
    });
    const withDeactivation = [...entries, deactivation];
    const seen = await validateDidLog(withDeactivation);
    assert.equal(seen.valid, true, messages(seen));
    assert.equal(seen.deactivated, true);

    const resurrected = await validateDidLog(entries, { known: seen.head! });
    assert.equal(resurrected.valid, false);
    assert.equal(resurrected.issues[0]!.kind, 'rollback');
  });

  it('never returns a head for an invalid log', async () => {
    const { entries } = await validLog();
    const tampered = clone(entries);
    tampered[2]!.versionTime = '2030-01-01T00:00:00Z';

    const result = await validateDidLog(tampered);
    assert.equal(result.valid, false);
    assert.equal(result.head, undefined);
    assert.equal(result.continuity, undefined);
  });

  it('fails closed on a malformed or foreign known head', async () => {
    const { entries } = await validLog();
    const good = (await validateDidLog(entries)).head!;

    const zero = await validateDidLog(entries, { known: { ...good, versionNumber: 0 } });
    assert.equal(zero.valid, false);
    assert.match(messages(zero), /malformed/);

    const foreign = await validateDidLog(entries, { known: { ...good, scid: 'QmSomeOtherScid' } });
    assert.equal(foreign.valid, false);
    assert.equal(foreign.issues[0]!.kind, 'fork');
  });

  it('does not mask ordinary failures', async () => {
    const { entries } = await validLog();
    const known = (await validateDidLog(entries)).head!;
    const reordered = await validateDidLog([entries[0]!, entries[2]!, entries[1]!], { known });

    assert.equal(reordered.valid, false);
    assert.ok(reordered.issues.length > 0);
  });
});

describe('validation - malformed input is reported, not thrown', () => {
  it('treats a null witness parameter as no witness requirement', async () => {
    const { entries } = await validLog();
    const tampered = clone(entries) as unknown as Record<string, Record<string, unknown>>[];
    tampered[1]!['parameters']!['witness'] = null;
    const result = await validateDidLog(tampered as unknown as DidLogEntry[]);
    // The edit breaks the entry hash, but it must not crash the validator or
    // be mistaken for a witness requirement.
    assert.equal(result.valid, false);
    assert.doesNotMatch(messages(result), /witness/);
  });

  it('reports a witness parameter that is not an object', async () => {
    const { entries } = await validLog();
    const tampered = clone(entries) as unknown as Record<string, Record<string, unknown>>[];
    tampered[1]!['parameters']!['witness'] = 'threshold-2';
    const result = await validateDidLog(tampered as unknown as DidLogEntry[]);
    assert.equal(result.valid, false);
    assert.match(messages(result), /parameters\.witness must be an object/);
  });

  it('reports an entry that is not an object', async () => {
    const { entries } = await validLog();
    const result = await validateDidLog([entries[0]!, null, entries[2]!] as unknown as DidLogEntry[]);
    assert.equal(result.valid, false);
    assert.ok(result.issues.some((i) => i.entry === 2 && /not an object/.test(i.message)));
  });

  it('reports an entry whose parameters is missing or not an object', async () => {
    const { entries } = await validLog();
    for (const parameters of [undefined, null, 'text', []]) {
      const tampered = clone(entries) as unknown as Record<string, unknown>[];
      tampered[2]!['parameters'] = parameters;
      const result = await validateDidLog(tampered as unknown as DidLogEntry[]);
      assert.equal(result.valid, false);
      assert.ok(
        result.issues.some((i) => i.entry === 3 && /parameters object/.test(i.message)),
        messages(result),
      );
    }
  });

  it('reports a malformed genesis entry', async () => {
    assert.equal((await validateDidLog([null] as unknown as DidLogEntry[])).valid, false);
    const { entries } = await validLog();
    const tampered = clone(entries) as unknown as Record<string, unknown>[];
    delete tampered[0]!['parameters'];
    const result = await validateDidLog(tampered as unknown as DidLogEntry[]);
    assert.equal(result.valid, false);
    assert.match(messages(result), /Genesis entry is not an object/);
  });

  it('reports a proof entry that is not an object', async () => {
    const { entries } = await validLog();
    for (const proof of [[null], null, ['text']]) {
      const tampered = clone(entries) as unknown as Record<string, unknown>[];
      tampered[1]!['proof'] = proof;
      const result = await validateDidLog(tampered as unknown as DidLogEntry[]);
      assert.equal(result.valid, false);
      assert.match(messages(result), /Proof entry is not an object/);
    }
  });

  it('reports updateKeys that is not an array of strings', async () => {
    const { entries } = await validLog();
    const tampered = clone(entries) as unknown as Record<string, Record<string, unknown>>[];
    tampered[1]!['parameters']!['updateKeys'] = 'z6Mk';
    const result = await validateDidLog(tampered as unknown as DidLogEntry[]);
    assert.equal(result.valid, false);
    assert.match(messages(result), /parameters\.updateKeys must be an array of strings/);
  });
});

describe('validation - versionTime', () => {
  it('rejects a versionTime that does not parse', async () => {
    for (const versionTime of ['not-a-date', '2026-13-45T00:00:00Z', 'Jan 1 2026', 1_767_225_600]) {
      const { entries } = await validLog();
      const tampered = clone(entries) as unknown as Record<string, unknown>[];
      tampered[1]!['versionTime'] = versionTime;
      const result = await validateDidLog(tampered as unknown as DidLogEntry[]);
      assert.equal(result.valid, false);
      assert.match(messages(result), /not a valid ISO 8601 date-time/);
    }
  });

  it('rejects a versionTime equal to the previous entry', async () => {
    const { provider, created } = await validLog();
    const same = await addService({
      did: created.did,
      previousEntry: created.entry,
      provider,
      signingKeyLabel: 'k1',
      nextKeyLabel: 'k2',
      versionTime: T1,
      service: { id: '#whois', type: 'OtlWhois', serviceEndpoint: `https://${DOMAIN}/w.json` },
    });
    const result = await validateDidLog([created.entry, same]);
    assert.equal(result.valid, false);
    assert.match(messages(result), /must strictly increase/);
  });

  it('rejects a versionTime in the future, relative to an injected clock', async () => {
    const { entries } = await validLog();
    // Entry 3 is dated T3; a clock set before it sees entry 3 as future.
    const result = await validateDidLog(entries, { now: new Date('2026-02-15T00:00:00Z') });
    assert.equal(result.valid, false);
    assert.ok(result.issues.some((i) => i.entry === 3 && /in the future/.test(i.message)));
  });

  it('tolerates clock skew within the permitted window', async () => {
    const { entries } = await validLog();
    const now = new Date(Date.parse(T3) - 60_000);
    const result = await validateDidLog(entries, { now });
    assert.equal(result.valid, true, messages(result));
  });
});

describe('versionId parsing', () => {
  it('accepts a positive integer version without leading zeros', () => {
    assert.deepEqual(parseVersionId('12-QmHash'), { versionNumber: 12, entryHash: 'QmHash' });
  });

  it('rejects malformed version numbers with InvalidDocumentError', () => {
    for (const versionId of [
      '01-QmHash',
      '0-QmHash',
      '+1-QmHash',
      '1e0-QmHash',
      '1-',
      '-QmHash',
      'QmHash',
      '',
    ]) {
      assert.throws(() => parseVersionId(versionId), InvalidDocumentError, versionId);
    }
  });
});
