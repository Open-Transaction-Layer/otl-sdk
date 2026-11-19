/**
 * DID lifecycle commands (OTL spec 2, 3).
 */

import { join } from 'node:path';
import {
  addKey as addKeyToLog,
  appendEntry,
  addService as addServiceToLog,
  createDid,
  deactivate as deactivateLog,
  keyFromKeyInfo,
  parseVersionId,
  validateDidLog,
  type ServiceEntry,
} from '@otl/core';
import { KeyAlreadyExistsError, type Curve, type KeyInfo } from '@otl/keys';
import { flag, optionalOption, requireOption, type ParsedArgs } from '../args.ts';
import { CliError } from '../errors.ts';
import type { Output } from '../output.ts';
import type { DidMeta, Store } from '../store.ts';

const MANAGEMENT_LABEL = (n: number) => `did-management-${n}`;

/** Parse a `--curve` option. Ed25519 is the default (spec 3.1.1 permits both). */
function parseCurve(value: string | undefined, fallback: Curve = 'Ed25519'): Curve {
  if (value === undefined) return fallback;
  const normalized = value.toLowerCase().replace(/[^a-z0-9]/g, '');
  if (normalized === 'ed25519') return 'Ed25519';
  if (normalized === 'p256' || normalized === 'secp256r1') return 'P-256';
  if (normalized === 'x25519') return 'X25519';
  throw new CliError(`Unknown curve "${value}"`, { hint: 'Use ed25519, p256 or x25519' });
}

export async function didCreate(args: ParsedArgs, store: Store, out: Output): Promise<void> {
  const domain = requireOption(args, 'domain', 'For example: --domain vasp.example.com');
  const versionTime = optionalOption(args, 'time') ?? new Date().toISOString();

  const assertionCurve = parseCurve(optionalOption(args, 'curve'));
  if (assertionCurve === 'X25519') {
    throw new CliError('X25519 is a key-agreement curve and cannot sign', {
      hint: 'did create makes a signing key, so use --curve ed25519 or --curve p256.',
    });
  }

  // The SCID is not known until the genesis entry is hashed, so keys are
  // generated in a temporary location and moved once it is.
  const scratch = `pending-${Date.now()}`;
  const provider = store.keyProvider(scratch);
  const preRotation = store.preRotationProvider(scratch);

  if (!store.preRotationIsSeparate) {
    out.warn(
      'WARNING: OTL_PREROTATION_PASSPHRASE is unset, so the committed pre-rotation key is\n' +
        '  protected by the same secret as the live key. Spec 3.2.2 makes the DID Management Key the\n' +
        '  highest-leverage key in the Identity layer, and sharing a passphrase weakens its protection.',
    );
  }

  // did:webvh 1.0 permits only eddsa-jcs-2022 for log-entry proofs, so these
  // are Ed25519 regardless of --curve, which governs document keys only.
  const management = await provider.generateKey(MANAGEMENT_LABEL(0), 'Ed25519');
  const next = await preRotation.generateKey(MANAGEMENT_LABEL(1), 'Ed25519');

  const documentKeys = [];
  if (!flag(args, 'no-assertion-key')) {
    const assertion = await provider.generateKey('assertion-key', assertionCurve);
    documentKeys.push(keyFromKeyInfo('assertion-key', assertion, ['assertionMethod', 'authentication']));
  }

  const created = await createDid({
    domain,
    provider: combined(provider, preRotation),
    managementKeyLabel: management.handle.label,
    preRotationKeyLabel: next.handle.label,
    versionTime,
    keys: documentKeys,
  });

  // Move the scratch directories under the now-known SCID.
  const { renameSync, mkdirSync } = await import('node:fs');
  mkdirSync(store.didDir(created.scid), { recursive: true, mode: 0o700 });
  for (const sub of ['keys', 'prerotation']) {
    renameSync(join(store.didDir(scratch), sub), join(store.didDir(created.scid), sub));
  }
  store.removeDid(scratch);

  const meta: DidMeta = {
    did: created.did,
    scid: created.scid,
    domain,
    createdAt: versionTime,
    currentUpdateKeyLabel: MANAGEMENT_LABEL(1),
    nextKeyLabel: MANAGEMENT_LABEL(1),
    keyLabels: Object.fromEntries(documentKeys.map((k) => [k.fragment, k.fragment])),
    rotationCount: 1,
  };
  store.writeMeta(meta);
  store.writeLog(created.scid, [created.entry]);
  store.setActiveDid(created.did);

  if (out.json) {
    out.data({ did: created.did, scid: created.scid, exportDir: store.exportDir(created.scid) });
  } else {
    out.success(`Created ${created.did}`);
    out.print(`  SCID    ${created.scid}`);
    out.print(`  Publish ${store.exportDir(created.scid)}/.well-known/ at https://${domain}/.well-known/`);
  }
}

/**
 * Combine the live and pre-rotation stores behind one provider.
 *
 * Genesis needs to read the committed key's *public* half while it lives in the
 * separate store. This wrapper is deliberately local to creation and rotation:
 * nothing else gets a handle that can reach the pre-rotation directory.
 */
function combined(
  live: ReturnType<Store['keyProvider']>,
  preRotation: ReturnType<Store['preRotationProvider']>,
) {
  const both = Object.create(live) as typeof live;
  both.getKey = async (label: string) => {
    try {
      return await live.getKey(label);
    } catch {
      return preRotation.getKey(label);
    }
  };
  both.sign = (label: string, message: Uint8Array) => live.sign(label, message);
  return both;
}

export async function didList(_args: ParsedArgs, store: Store, out: Output): Promise<void> {
  const dids = store.listDids();
  const active = store.config().activeDid;

  if (out.json) {
    out.data(dids.map((meta) => ({ ...meta, active: meta.did === active })));
    return;
  }
  if (dids.length === 0) {
    out.print('No local DIDs. Create one with: otl did create --domain <domain>');
    return;
  }
  for (const meta of dids) {
    out.print(`${meta.did === active ? '*' : ' '} ${meta.did}`);
  }
}

export async function didShow(args: ParsedArgs, store: Store, out: Output): Promise<void> {
  const meta = store.resolveMeta(optionalOption(args, 'did'));
  const entries = store.readLog(meta.scid);

  const version = optionalOption(args, 'version');
  const entry =
    version === undefined
      ? entries[entries.length - 1]
      : entries.find((e) => parseVersionId(e.versionId).versionNumber === Number(version));

  if (!entry) throw new CliError(`DID ${meta.did} has no version ${version}`);
  out.data(entry.state);
}

export async function didAddKey(args: ParsedArgs, store: Store, out: Output): Promise<void> {
  const meta = store.resolveMeta(optionalOption(args, 'did'));
  const label = requireOption(args, 'label', 'The verification method fragment, e.g. --label agreement-key');
  const curve = parseCurve(optionalOption(args, 'curve'));
  const purposes = (optionalOption(args, 'purpose') ?? defaultPurposeFor(curve))
    .split(',')
    .map((p) => p.trim());

  const current = store.readLog(meta.scid).at(-1);
  const fragment = `#${label.replace(/^#/, '')}`;
  if ((current?.state.verificationMethod ?? []).some((m) => m.id === `${meta.did}${fragment}`)) {
    throw new CliError(`${meta.did} already has a verification method ${fragment}`, {
      hint: 'Choose a different --label.',
    });
  }

  // A key left behind by an earlier run that failed before publishing is
  // reused, so that retrying the command completes the update.
  const key = await generateOrReuse(store.keyProvider(meta.scid), label, curve);
  const entry = await withRotation(args, store, meta, out, (rotation) =>
    addKeyToLog({
      did: meta.did,
      previousEntry: rotation.previousEntry,
      provider: rotation.provider,
      signingKeyLabel: rotation.signingKeyLabel,
      nextKeyLabel: rotation.nextKeyLabel,
      versionTime: rotation.versionTime,
      keys: [keyFromKeyInfo(label, key, purposes as never)],
    }),
  );

  out.json ? out.data(entry.state) : out.success(`Added #${label} — now at version ${entry.versionId}`);
}

const defaultPurposeFor = (curve: Curve): string => (curve === 'X25519' ? 'keyAgreement' : 'assertionMethod');

export async function didAddService(args: ParsedArgs, store: Store, out: Output): Promise<void> {
  const meta = store.resolveMeta(optionalOption(args, 'did'));
  const file = optionalOption(args, 'file');
  // Deliberately not --json: that is the global output-format flag, and the
  // two would silently overwrite each other.
  const inline = optionalOption(args, 'service');

  if (file === undefined && inline === undefined) {
    throw new CliError('Provide the service entry with --file <path> or --service <json>');
  }

  let service: ServiceEntry;
  try {
    const { readFileSync } = await import('node:fs');
    service = JSON.parse(inline ?? readFileSync(requireOption(args, 'file'), 'utf8')) as ServiceEntry;
  } catch (cause) {
    throw new CliError('Service entry is not valid JSON', { cause });
  }

  const entry = await withRotation(args, store, meta, out, (rotation) =>
    addServiceToLog({
      did: meta.did,
      previousEntry: rotation.previousEntry,
      provider: rotation.provider,
      signingKeyLabel: rotation.signingKeyLabel,
      nextKeyLabel: rotation.nextKeyLabel,
      versionTime: rotation.versionTime,
      service,
    }),
  );

  out.json
    ? out.data(entry.state)
    : out.success(`Added service ${service.id} — now at version ${entry.versionId}`);
}

/**
 * Rotate the DID Management Key without changing anything else.
 *
 * Takes no input. The committed key is revealed and promoted, and a fresh
 * commitment is generated. The document is republished unchanged, so the only
 * difference between versions is the key that may sign the next one.
 *
 * Under the rotate-every-entry policy `did add-key` and `did add-service`
 * already rotate as a side effect; this command exists for a rotation with no
 * accompanying document change — a scheduled rotation, or a response to a
 * suspected compromise.
 */
export async function didRotate(args: ParsedArgs, store: Store, out: Output): Promise<void> {
  const meta = store.resolveMeta(optionalOption(args, 'did'));

  const entry = await withRotation(args, store, meta, out, (rotation) =>
    appendEntry({
      previousEntry: rotation.previousEntry,
      // Republished verbatim: a rotation changes keys, not the document.
      state: rotation.previousEntry.state,
      provider: rotation.provider,
      signingKeyLabel: rotation.signingKeyLabel,
      nextKeyLabel: rotation.nextKeyLabel,
      versionTime: rotation.versionTime,
    }),
  );

  if (out.json) {
    out.data({ rotated: true, versionId: entry.versionId, updateKeys: entry.parameters.updateKeys });
  } else {
    out.success(`Rotated the DID Management Key — now at version ${entry.versionId}`);
  }
}

export async function didDeactivate(args: ParsedArgs, store: Store, out: Output): Promise<void> {
  const meta = store.resolveMeta(optionalOption(args, 'did'));
  if (!flag(args, 'yes')) {
    throw new CliError(`Deactivating ${meta.did} is permanent`, {
      hint: 'Re-run with --yes to confirm. A deactivated DID can never publish another version.',
    });
  }

  const entry = await withRotation(args, store, meta, out, (rotation) =>
    deactivateLog({
      did: meta.did,
      previousEntry: rotation.previousEntry,
      provider: rotation.provider,
      signingKeyLabel: rotation.signingKeyLabel,
      nextKeyLabel: rotation.nextKeyLabel,
      versionTime: rotation.versionTime,
    }),
  );

  out.json
    ? out.data({ deactivated: true, versionId: entry.versionId })
    : out.success(`Deactivated ${meta.did}`);
}

export async function didValidateLocal(args: ParsedArgs, store: Store, out: Output): Promise<void> {
  const meta = store.resolveMeta(optionalOption(args, 'did'));
  const result = await validateDidLog(store.readLog(meta.scid), { expectedDid: meta.did });

  if (out.json) {
    out.data({ valid: result.valid, issues: result.issues, versionCount: result.versionCount });
  } else if (result.valid) {
    out.success(`${meta.did} is valid across ${result.versionCount} version(s)`);
  } else {
    out.print(`${meta.did} FAILED validation:`);
    for (const issue of result.issues) {
      out.print(`  - ${issue.entry !== undefined ? `[entry ${issue.entry}] ` : ''}${issue.message}`);
    }
  }
  if (!result.valid) throw new CliError('Local DID log failed validation', { exitCode: 2 });
}

// ---------------------------------------------------------------------------

interface RotationContext {
  readonly previousEntry: import('@otl/core').DidLogEntry;
  readonly provider: ReturnType<Store['keyProvider']>;
  readonly signingKeyLabel: string;
  readonly nextKeyLabel: string;
  readonly versionTime: string;
}

/**
 * Run an update that consumes the committed key and commits a fresh one.
 *
 * Every state-changing command goes through here, because under the
 * rotate-every-entry policy every entry rotates the DID Management Key: the
 * entry is signed by the key the previous entry committed to, and commits to a
 * newly generated offline key. See the note on `RotationPolicy` in
 * `@otl/core`.
 */
async function withRotation(
  args: ParsedArgs,
  store: Store,
  meta: DidMeta,
  out: Output,
  run: (context: RotationContext) => Promise<import('@otl/core').DidLogEntry>,
): Promise<import('@otl/core').DidLogEntry> {
  const entries = store.readLog(meta.scid);
  const previousEntry = entries.at(-1);
  if (previousEntry === undefined) {
    throw new CliError('The DID log is empty', { hint: 'Nothing can be appended to a log with no entries.' });
  }
  const versionTime = optionalOption(args, 'time') ?? new Date().toISOString();

  const live = store.keyProvider(meta.scid);
  const preRotation = store.preRotationProvider(meta.scid);

  // The committed key is promoted into the live store to sign this entry, and a
  // fresh commitment is generated in the offline store.
  const signingKeyLabel = meta.currentUpdateKeyLabel;
  await preRotation.getKey(signingKeyLabel).catch(() => {
    throw new CliError(`Committed key "${signingKeyLabel}" is missing from the pre-rotation store`, {
      hint: 'Without it the log cannot be extended; the DID is effectively frozen.',
    });
  });

  // An earlier run that failed after generating this commitment but before
  // writing the entry leaves the key behind, and it is reused so that the
  // retry can proceed rather than leaving the DID unable to update.
  const nextKeyLabel = MANAGEMENT_LABEL(meta.rotationCount + 1);
  await generateOrReuse(preRotation, nextKeyLabel, 'Ed25519');

  const provider = signingThrough(live, preRotation);
  const entry = await run({ previousEntry, provider, signingKeyLabel, nextKeyLabel, versionTime });

  store.appendLogEntry(meta.scid, entry);
  store.writeMeta({
    ...meta,
    currentUpdateKeyLabel: nextKeyLabel,
    nextKeyLabel,
    rotationCount: meta.rotationCount + 1,
  });

  out.warn(
    `Rotated the DID Management Key (now ${nextKeyLabel}). Every update rotates it under the ` +
      `rotate-every-entry policy, because whoever holds this key controls the whole document (OTL spec 3.2.2).`,
  );
  return entry;
}

/**
 * Generate a key, or return the existing one when a previous run already
 * generated it under this label. A key on a different curve is refused.
 */
async function generateOrReuse(
  provider: {
    generateKey(label: string, curve: Curve): Promise<KeyInfo>;
    getKey(label: string): Promise<KeyInfo>;
  },
  label: string,
  curve: Curve,
): Promise<KeyInfo> {
  try {
    return await provider.generateKey(label, curve);
  } catch (error) {
    if (!(error instanceof KeyAlreadyExistsError)) throw error;
    const existing = await provider.getKey(label);
    if (existing.curve !== curve) {
      throw new CliError(`Key "${label}" already exists on curve ${existing.curve}, not ${curve}`, {
        hint: 'Choose a different label.',
      });
    }
    return existing;
  }
}

/** A provider that can also sign with, and read, the committed key. */
function signingThrough(
  live: ReturnType<Store['keyProvider']>,
  preRotation: ReturnType<Store['preRotationProvider']>,
): ReturnType<Store['keyProvider']> {
  const merged = Object.create(live) as ReturnType<Store['keyProvider']>;
  merged.getKey = async (label) => live.getKey(label).catch(() => preRotation.getKey(label));
  merged.sign = async (label, message) => {
    // Only a missing key falls back to the pre-rotation store. A failure from
    // `live.sign` itself must propagate rather than being retried elsewhere.
    const liveHasKey = await live.getKey(label).then(
      () => true,
      () => false,
    );
    return liveHasKey ? live.sign(label, message) : preRotation.sign(label, message);
  };
  return merged;
}
