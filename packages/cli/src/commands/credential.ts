/**
 * Credential issuance and revocation (OTL spec 4, 5).
 */

import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  allocateIndex,
  Bitstring,
  bitstringFrom,
  buildStatusListCredential,
  statusEntryFor,
  type BitstringStatusListEntry,
  type StatusListCredential,
} from '@otl/core';
import {
  issueCredential,
  OtlHostingCredentialType,
  OtlLeiCredentialType,
  type VerifiableCredential,
} from '@otl/credentials';
import { optionalOption, requireOption, type ParsedArgs } from '../args.ts';
import { CliError } from '../errors.ts';
import type { Output } from '../output.ts';
import { chooseKey } from '../relationship-keys.ts';
import type { DidMeta, Store } from '../store.ts';

/**
 * The fragment this CLI gives credential signing keys it creates.
 *
 * Spec 3.2.1 fixes no id — a verifier finds the key through the proof's
 * `verificationMethod` and confirms it is referenced under `assertionMethod`.
 * So this is a local default for keys we mint, not a protocol constant, and a
 * credential signed with any other id is equally valid.
 */
const ISSUANCE_FRAGMENT = 'credential-issuance-key';
const DEFAULT_LIST_ID = '1';

/** Spec 5.2: how long a published status list stays usable before reissue. */
const STATUS_LIST_LIFETIME_MS = 60 * 60 * 1000;

/**
 * Read `--list-id`, which becomes a path component under `export/` and a URL
 * segment, so it is restricted to a safe character set.
 */
function listIdOption(args: ParsedArgs): string {
  const listId = optionalOption(args, 'list-id') ?? DEFAULT_LIST_ID;
  if (!/^[A-Za-z0-9_-]{1,64}$/.test(listId)) {
    throw new CliError(`Invalid --list-id "${listId}"`, {
      hint: 'Use 1 to 64 letters, digits, hyphens or underscores.',
    });
  }
  return listId;
}

const statusListPath = (store: Store, meta: DidMeta, listId: string) =>
  join(store.exportDir(meta.scid), '.well-known', 'status-lists', listId);

const statusListUrlFor = (meta: DidMeta, listId: string) =>
  `https://${meta.domain}/.well-known/status-lists/${listId}`;

const issuedIndexPath = (store: Store, meta: DidMeta) => join(store.didDir(meta.scid), 'issued.json');

interface IssuedIndex {
  readonly [credentialId: string]: {
    readonly index: number;
    readonly listId: string;
    readonly subject: string;
  };
}

const readIssued = (store: Store, meta: DidMeta): IssuedIndex => {
  const path = issuedIndexPath(store, meta);
  return existsSync(path) ? (JSON.parse(readFileSync(path, 'utf8')) as IssuedIndex) : {};
};

function loadStatusList(store: Store, meta: DidMeta, listId: string): Bitstring {
  const path = statusListPath(store, meta, listId);
  if (!existsSync(path)) return Bitstring.create();
  return bitstringFrom(JSON.parse(readFileSync(path, 'utf8')) as StatusListCredential);
}

async function publishStatusList(
  store: Store,
  meta: DidMeta,
  listId: string,
  bitstring: Bitstring,
  requestedKey?: string,
): Promise<StatusListCredential> {
  // Spec 5.2: a status list is signed by a key under the issuer's
  // assertionMethod, as credentials are.
  const { fragment, keyLabel } = await issuanceKey(store, meta, requestedKey);
  const credential = await buildStatusListCredential({
    issuer: meta.did,
    statusListCredentialUrl: statusListUrlFor(meta, listId),
    bitstring,
    provider: store.keyProvider(meta.scid),
    keyLabel,
    verificationMethod: `${meta.did}#${fragment}`,
    validFrom: new Date().toISOString(),
    validUntil: new Date(Date.now() + STATUS_LIST_LIFETIME_MS).toISOString(),
    ttl: 300_000,
  });
  store.writeExportArtifact(meta.scid, join('status-lists', listId), credential);
  return credential;
}

/**
 * The credential signing key to use (spec 3.2.1, 3.3).
 *
 * Chosen from the keys the current document references under
 * `assertionMethod`, never by name: `--key` picks one explicitly, otherwise the
 * key `credential add-issuance-key` added most recently is used, so that after
 * adding a new key during a rotation, issuance moves to it.
 */
const issuanceKey = (store: Store, meta: DidMeta, requested?: string) =>
  chooseKey(store, meta, 'assertionMethod', {
    ...(requested !== undefined ? { requested } : {}),
    ...(meta.issuanceKeyFragment !== undefined ? { preferred: meta.issuanceKeyFragment } : {}),
    hint: 'Add one first: otl credential add-issuance-key',
  });

/**
 * Add a credential signing key under `assertionMethod` (spec 3.2.1).
 *
 * `--label` chooses the fragment and defaults to `#credential-issuance-key`.
 * What makes the key authoritative is the `assertionMethod` reference, not its
 * name.
 */
export async function cmdAddIssuanceKey(args: ParsedArgs, store: Store, out: Output): Promise<void> {
  const { didAddKey } = await import('./did.ts');
  const meta = store.resolveMeta(optionalOption(args, 'did'));

  const fragment = optionalOption(args, 'label') ?? ISSUANCE_FRAGMENT;

  if (meta.keyLabels[fragment] !== undefined) {
    throw new CliError(`${meta.did} already has a #${fragment}`);
  }

  await didAddKey(
    { ...args, options: { ...args.options, label: fragment, purpose: 'assertionMethod' } },
    store,
    out,
  );

  const updated = store.readMeta(meta.scid);
  store.writeMeta({
    ...updated,
    keyLabels: { ...updated.keyLabels, [fragment]: fragment },
    issuanceKeyFragment: fragment,
  });
}

/**
 * Allocate a status-list slot, mint a credential into it, and record it.
 *
 * Everything around the `issueCredential` call is type-agnostic: slot
 * allocation, publishing the signed list, and the private issued-index. Each
 * credential type supplies only `mint`, so adding a type stays a registration
 * rather than a change to the issuing machinery (spec 4.1-4.5).
 */
async function issueAndRecord(
  store: Store,
  meta: DidMeta,
  listId: string,
  subject: string,
  out: Output,
  mint: (credentialStatus: BitstringStatusListEntry) => Promise<VerifiableCredential>,
  requestedKey?: string,
): Promise<void> {
  const bitstring = loadStatusList(store, meta, listId);
  const issued = readIssued(store, meta);
  const taken = new Set(
    Object.values(issued)
      .filter((e) => e.listId === listId)
      .map((e) => e.index),
  );

  // Spec 5.1: random assignment, so the list cannot be read as an issuance
  // timeline.
  const index = allocateIndex(bitstring, (candidate) => taken.has(candidate));

  const credential = await mint(statusEntryFor(statusListUrlFor(meta, listId), index));
  const statusList = await publishStatusList(store, meta, listId, bitstring, requestedKey);

  // The issuance index stays private, deliberately. It maps credential ids to
  // status-list positions and subjects, which is exactly the correlation the
  // bitstring design exists to prevent (spec 5.1's random index assignment
  // would be pointless if the mapping were published alongside it). It is
  // written under the DID directory, never under export/.
  const { writeFileSync } = await import('node:fs');
  writeFileSync(
    issuedIndexPath(store, meta),
    `${JSON.stringify({ ...issued, [credential.id]: { index, listId, subject } }, null, 2)}\n`,
    { mode: 0o600 },
  );

  if (out.json) {
    out.data({ credential, statusList });
  } else {
    out.success(`Issued ${credential.id} to ${subject}`);
    out.data(credential);
  }
}

/** Issue an OtlLeiCredential (spec 4.8-4.10). */
export async function cmdIssue(args: ParsedArgs, store: Store, out: Output): Promise<void> {
  const meta = store.resolveMeta(optionalOption(args, 'did'));
  const requestedKey = optionalOption(args, 'key');
  const { fragment, keyLabel } = await issuanceKey(store, meta, requestedKey);

  const lei = requireOption(args, 'lei', 'The 20-character ISO 17442 code');
  const gleifFile = optionalOption(args, 'gleif-file');
  const subject = requireOption(args, 'subject', 'The recipient did:webvh');
  const listId = listIdOption(args);
  const validUntil = optionalOption(args, 'valid-until');

  await issueAndRecord(store, meta, listId, subject, out, (credentialStatus) =>
    issueCredential({
      type: new OtlLeiCredentialType(),
      input: {
        lei,
        // A local Level 1 record instead of the live GLEIF API. For tests,
        // demos and air-gapped issuance. The record is validated against spec
        // 4.9 either way, so this bypasses the lookup, not the checks.
        ...(gleifFile !== undefined && gleifFile !== ''
          ? {
              gleif: {
                fetch: async () => ({
                  ok: true,
                  status: 200,
                  json: async () => JSON.parse(readFileSync(gleifFile, 'utf8')) as unknown,
                }),
              },
            }
          : {}),
      },
      issuer: meta.did,
      subject,
      provider: store.keyProvider(meta.scid),
      keyLabel,
      verificationMethod: `${meta.did}#${fragment}`,
      // Omitted deliberately when absent: OtlLeiCredentialType defaults it to
      // the registration's own nextRenewalDate (spec 4.8).
      ...(validUntil !== undefined ? { validUntil } : {}),
      credentialStatus: [credentialStatus],
    }),
    requestedKey,
  );
}

/**
 * Issue an OtlHostingCredential (spec 4.12-4.17).
 *
 * The provider asserts it operates the subject's DID, names it by the common
 * name the provider knows it by, and, optionally, names the watchers for it. Watchers are carried here rather than only in the DID's
 * own log because the log is controlled by the DID Management Key: after a
 * takeover the attacker rewrites that list, but cannot revoke this credential
 * (spec 2.4, 4.17).
 */
export async function cmdIssueHosting(args: ParsedArgs, store: Store, out: Output): Promise<void> {
  const meta = store.resolveMeta(optionalOption(args, 'did'));
  const requestedKey = optionalOption(args, 'key');
  const { fragment, keyLabel } = await issuanceKey(store, meta, requestedKey);

  const subject = requireOption(args, 'subject', 'The hosted did:webvh');
  // Spec 4.14 requires it: a provider that has done 4.12's due diligence
  // knows who the participant is, and a verifier has nothing else to show a
  // person. It is a label, never an identifier — the DID is the identifier.
  const commonName = requireOption(args, 'common-name', 'The name the participant is known by');
  const listId = listIdOption(args);
  const validUntil = optionalOption(args, 'valid-until');

  // Comma-separated rather than a repeated flag: ParsedArgs.options is a flat
  // record, so `--watchers a --watchers b` would silently keep only the last.
  // `trust add --type` splits the same way.
  const watchersOption = optionalOption(args, 'watchers');
  const watchers = watchersOption
    ?.split(',')
    .map((w) => w.trim())
    .filter((w) => w.length > 0);

  await issueAndRecord(store, meta, listId, subject, out, (credentialStatus) =>
    issueCredential({
      type: new OtlHostingCredentialType(),
      input: { commonName, ...(watchers === undefined ? {} : { watchers }) },
      issuer: meta.did,
      subject,
      provider: store.keyProvider(meta.scid),
      keyLabel,
      verificationMethod: `${meta.did}#${fragment}`,
      // Spec 4.13 does not require validUntil for this type; honoured if given.
      ...(validUntil !== undefined ? { validUntil } : {}),
      credentialStatus: [credentialStatus],
    }),
    requestedKey,
  );
}

/** Print the current revocation list. */
export async function cmdStatusList(args: ParsedArgs, store: Store, out: Output): Promise<void> {
  const meta = store.resolveMeta(optionalOption(args, 'did'));
  const listId = listIdOption(args);
  const path = statusListPath(store, meta, listId);

  if (!existsSync(path)) {
    throw new CliError(`${meta.did} has published no status list ${listId}`, {
      hint: 'A list is created when the first credential is issued.',
    });
  }

  const credential = JSON.parse(readFileSync(path, 'utf8')) as StatusListCredential;
  if (out.json) {
    out.data(credential);
    return;
  }

  const revoked = bitstringFrom(credential).setIndices();
  out.print(statusListUrlFor(meta, listId));
  out.print(`  entries: ${bitstringFrom(credential).length}`);
  out.print(`  revoked: ${revoked.length === 0 ? 'none' : revoked.join(', ')}`);
  const validUntil = credential.validUntil;
  if (validUntil !== undefined) {
    const expired = Date.parse(validUntil) <= Date.now();
    out.print(`  valid until: ${validUntil}${expired ? ' (EXPIRED)' : ''}`);
    if (expired) {
      out.warn(
        'This list has expired, so verifiers reject every credential that points at it (spec 5.2).\n' +
          `  Re-sign it with: otl credential refresh-status --list-id ${listId}`,
      );
    }
  }
}

/**
 * Re-sign a status list with a fresh validity window, leaving every bit as it
 * is. Spec 5.2 has the issuer publish a new version before `validUntil`, and a
 * verifier rejects every credential that points at an expired list, so an
 * issuer runs this on a schedule shorter than the list lifetime.
 */
export async function cmdRefreshStatus(args: ParsedArgs, store: Store, out: Output): Promise<void> {
  const meta = store.resolveMeta(optionalOption(args, 'did'));
  const requestedKey = optionalOption(args, 'key');
  await issuanceKey(store, meta, requestedKey); // fail before touching anything
  const listId = listIdOption(args);

  if (!existsSync(statusListPath(store, meta, listId))) {
    throw new CliError(`${meta.did} has published no status list ${listId}`, {
      hint: 'A list is created when the first credential is issued.',
    });
  }

  const statusList = await publishStatusList(
    store,
    meta,
    listId,
    loadStatusList(store, meta, listId),
    requestedKey,
  );
  if (out.json) {
    out.data(statusList);
  } else {
    out.success(`Re-signed ${statusListUrlFor(meta, listId)}, valid until ${String(statusList.validUntil)}`);
    out.print('  Publish the export directory again so verifiers see the new version.');
  }
}

/** Revoke a credential by setting its bit and republishing (spec 5). */
export async function cmdRevoke(args: ParsedArgs, store: Store, out: Output): Promise<void> {
  const meta = store.resolveMeta(optionalOption(args, 'did'));
  const requestedKey = optionalOption(args, 'key');
  await issuanceKey(store, meta, requestedKey); // fail before touching anything

  const credentialId = requireOption(args, 'credential', 'The credential id, e.g. urn:uuid:...');
  const issued = readIssued(store, meta);
  const record = issued[credentialId];

  if (!record) {
    throw new CliError(`This DID has no record of issuing "${credentialId}"`, {
      hint: 'Only the issuer can revoke, and only credentials it has issued.',
    });
  }

  const bitstring = loadStatusList(store, meta, record.listId);
  const alreadyRevoked = bitstring.get(record.index);
  bitstring.set(record.index, true); // idempotent by construction
  const statusList = await publishStatusList(store, meta, record.listId, bitstring, requestedKey);

  if (out.json) {
    out.data({ credentialId, index: record.index, alreadyRevoked, statusList });
  } else {
    out.success(
      alreadyRevoked
        ? `${credentialId} was already revoked (index ${record.index})`
        : `Revoked ${credentialId} (index ${record.index})`,
    );
  }
}
