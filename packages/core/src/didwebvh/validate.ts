/**
 * DID log validation (OTL spec 2.2, 2.3, 3.2.2).
 *
 * This is the component that decides whether a counterparty's identity is real.
 * Everything else in the Identity layer rests on it, so it reports every
 * failure it finds rather than throwing on the first, and it recomputes hashes
 * from scratch rather than trusting anything the log asserts about itself.
 *
 * ## Which key authorizes an entry
 *
 * did:webvh makes this depend on whether pre-rotation is active, which is easy
 * to get backwards:
 *
 *  - First entry — always self-authorizing: "For the first log entry the active
 *    `updateKeys` list is the one in that first log entry." Its authority comes
 *    from the SCID, which commits to those keys.
 *  - Pre-rotation active — "the active list is the `updateKeys` from the
 *    **current** log entry to be verified", with the pre-rotation check
 *    (against the previous entry's `nextKeyHashes`) providing the authority.
 *  - Pre-rotation inactive — "the active list is the most recent `updateKeys`
 *    **before** the log entry to be verified."
 *
 * By default this implementation requires pre-rotation in every entry
 * (`requirePreRotation`), so a log it accepts always takes the second branch.
 * The third is implemented as well, because a validator that could not
 * evaluate a log with pre-rotation disabled would silently accept it.
 */

import { fromPublicKeyMultibase, type PublicKey } from '@otl/keys';
import { canonicalizeToBytes } from '../jcs.ts';
import { hashToBase58 } from '../multihash.ts';
import { isProofObject, proofsOf, verifyProof, type DataIntegrityProof } from '../proof.ts';
import { deriveKeyHash, parseVersionId, toPlaceholders } from './hashing.ts';
import { DIDWEBVH_1_0_PROFILE, profileForMethod, type MethodProfile } from './profile.ts';
import {
  GENESIS_BOUND_KEYS_PROPERTY,
  SCID_PLACEHOLDER,
  type DidDocument,
  type DidLogEntry,
  type VerificationMethod,
} from './types.ts';

export interface ValidationIssue {
  /** 1-based log entry the issue was found in; absent for whole-log issues. */
  readonly entry?: number;
  readonly message: string;
  /**
   * True when the log was refused because it uses a feature this
   * implementation does not verify, rather than because anything is wrong
   * with it.
   *
   * The distinction matters to an operator: "this DID may be perfectly valid,
   * we cannot check it" is a different problem from "this DID is forged". The
   * outcome is the same — refusal, because accepting an unverifiable log would
   * be failing open — but the remedy is not.
   */
  readonly unsupported?: boolean;
  /**
   * Set when the log contradicts a version this verifier already validated,
   * rather than being malformed in itself. `rollback`: shorter than a version
   * we have seen. `fork`: a different version sits where we saw one.
   */
  readonly kind?: 'rollback' | 'fork';
}

/**
 * The newest version of a DID's log that a verifier has validated.
 *
 * `versionId` is enough to pin the history: it embeds the version number and
 * its hash commits to every earlier entry, so a log carrying the same
 * `versionId` at the same position has the same history behind it.
 *
 * Keyed by SCID, not by DID string, because the SCID is what identifies the
 * DID: a portable DID may change domain and must still extend the same head.
 */
export interface KnownDidHead {
  readonly scid: string;
  /** The DID as it stood at this version. Informational. */
  readonly did: string;
  readonly versionNumber: number;
  readonly versionId: string;
}

export interface ValidationResult {
  readonly valid: boolean;
  readonly issues: readonly ValidationIssue[];
  /**
   * True when every reason for refusal was an unsupported feature. The log is
   * not known to be bad — only unverifiable here.
   */
  readonly unverifiable?: boolean;
  /** Present when the log was well-formed enough to determine them. */
  readonly did?: string;
  readonly scid?: string;
  readonly versionCount?: number;
  readonly deactivated?: boolean;
  /** Resolved document from the final entry. Only trustworthy when `valid`. */
  readonly document?: DidDocument;
  /**
   * The head this log establishes. Present ONLY when `valid`: an invalid log
   * must never become something later logs are measured against.
   */
  readonly head?: KnownDidHead;
  /** Present when `valid`: how the log relates to `known`. */
  readonly continuity?: 'new' | 'unchanged' | 'extended';
}

export interface ValidateOptions {
  /** When supplied, the log must resolve to exactly this DID. */
  readonly expectedDid?: string;
  /**
   * Require did:webvh pre-rotation to be active in every entry, which is this
   * implementation's policy and defaults to true. Disable only to inspect a
   * plain did:webvh log.
   */
  readonly requirePreRotation?: boolean;
  /**
   * Accept a log declaring a widened method profile.
   *
   * Off by default: a log announcing anything other than `did:webvh:1.0` is
   * not resolvable by stock tooling, and silently accepting one would hide
   * that from the operator.
   */
  readonly allowedProfiles?: readonly MethodProfile[];
  /**
   * The newest version already validated for this DID. The log must contain it
   * at its position, or validation fails: a log may only grow, so a shorter
   * one is a rollback and a different entry at the same position is a fork
   * (threat T-RES-02).
   *
   * This can only tighten validation, never loosen it. Callers rarely supply it
   * directly; `@otl/resolver` looks it up from a `DidHeadMemory`.
   */
  readonly known?: KnownDidHead;
  /**
   * The current time, against which a `versionTime` in the future is refused.
   * Defaults to the system clock; supply it to make validation reproducible.
   */
  readonly now?: Date;
}

/**
 * How far ahead of `now` a `versionTime` may be before it is refused, to
 * tolerate ordinary clock skew between the publisher and the verifier.
 */
export const MAX_VERSION_TIME_SKEW_MS = 5 * 60 * 1000;

/** UTC or offset ISO 8601 date-time, as did:webvh writes `versionTime`. */
const ISO_8601_DATE_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/;

/** A non-null, non-array object: the only shape whose members can be read safely. */
const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

const isStringArray = (value: unknown): value is readonly string[] =>
  Array.isArray(value) && value.every((v) => typeof v === 'string');

/** Parse a `did.jsonl` document into entries. */
export function parseDidLog(jsonl: string): DidLogEntry[] {
  const entries: DidLogEntry[] = [];
  const lines = jsonl.split('\n');

  for (const [index, line] of lines.entries()) {
    const trimmed = line.trim();
    if (trimmed.length === 0) continue;
    try {
      entries.push(JSON.parse(trimmed) as DidLogEntry);
    } catch (cause) {
      throw new SyntaxError(`did.jsonl line ${index + 1} is not valid JSON`, { cause });
    }
  }
  return entries;
}

export async function validateDidLog(
  entries: readonly DidLogEntry[],
  options: ValidateOptions = {},
): Promise<ValidationResult> {
  const { expectedDid, requirePreRotation = true } = options;
  const issues: ValidationIssue[] = [];
  const add = (message: string, entry?: number) =>
    issues.push(entry === undefined ? { message } : { entry, message });
  const addUnsupported = (message: string, entry: number) =>
    issues.push({ entry, message, unsupported: true });

  const genesis = entries[0];
  if (genesis === undefined) return { valid: false, issues: [{ message: 'DID log is empty' }] };
  // Log lines are parsed JSON, so the declared entry type is checked rather
  // than trusted before any member is read.
  if (!isWellShapedEntry(genesis)) {
    add('Genesis entry is not an object carrying a parameters object', 1);
    return { valid: false, issues };
  }
  const nowMs = (options.now ?? new Date()).getTime();

  // ---- SCID -------------------------------------------------------------
  const declaredScid = genesis.parameters.scid;
  if (typeof declaredScid !== 'string' || declaredScid.length === 0) {
    add('Genesis entry has no parameters.scid', 1);
    return { valid: false, issues };
  }

  const recomputedScid = recomputeScid(genesis, declaredScid);
  if (recomputedScid !== declaredScid) {
    add(
      `SCID mismatch: the genesis entry hashes to "${recomputedScid}" but declares "${declaredScid}". ` +
        `The genesis document has been altered.`,
      1,
    );
  }

  // The declared method selects which algorithms the log's proofs may use.
  // An unrecognized value is rejected rather than defaulted: guessing would
  // mean verifying under rules the log never claimed.
  const allowed = options.allowedProfiles ?? [DIDWEBVH_1_0_PROFILE];
  const declaredProfile = profileForMethod(genesis.parameters.method);
  const profile =
    declaredProfile !== undefined && allowed.some((p) => p.method === declaredProfile.method)
      ? declaredProfile
      : undefined;

  if (profile === undefined) {
    add(
      `Genesis entry declares method "${String(genesis.parameters.method)}", which is not among ` +
        `the accepted profiles (${allowed.map((p) => p.method).join(', ')})`,
      1,
    );
  }

  // Log lines are parsed JSON, so `state` is checked rather than trusted even
  // though the declared type says it is always present.
  const genesisState = genesis.state as DidLogEntry['state'] | undefined;
  const did = genesisState?.id;
  if (typeof did !== 'string') {
    add('Genesis entry state has no id', 1);
    return { valid: false, issues, scid: declaredScid };
  }
  if (!did.startsWith(`did:webvh:${declaredScid}:`)) {
    add(`DID "${did}" does not embed the declared SCID`, 1);
  }
  if (expectedDid !== undefined && did !== expectedDid) {
    add(`Log resolves to "${did}" but "${expectedDid}" was requested`);
  }

  // ---- Per-entry --------------------------------------------------------
  let previous: DidLogEntry | undefined;
  let previousTime: { readonly text: string; readonly ms: number } | undefined;
  let inheritedUpdateKeys: readonly string[] = [];
  let deactivated = false;
  const portable = genesis.parameters.portable === true;

  for (const [index, entry] of entries.entries()) {
    const number = index + 1;

    if (deactivated) {
      add('Entry follows a deactivated DID; no further entries are permitted', number);
    }

    if (!isWellShapedEntry(entry)) {
      add('Entry is not an object carrying a parameters object', number);
      continue;
    }

    // Version numbering and hash chain.
    let parsed: { versionNumber: number; entryHash: string };
    try {
      parsed = parseVersionId(entry.versionId);
    } catch (error) {
      add((error as Error).message, number);
      continue;
    }
    if (parsed.versionNumber !== number) {
      add(`versionId declares version ${parsed.versionNumber} but is at position ${number}`, number);
    }

    const previousVersionId = previous ? previous.versionId : declaredScid;
    const recomputedHash = recomputeEntryHash(entry, previousVersionId);
    if (recomputedHash !== parsed.entryHash) {
      add(
        `Entry hash mismatch: recomputed "${recomputedHash}" but versionId carries "${parsed.entryHash}". ` +
          `The entry or its predecessor has been altered.`,
        number,
      );
    }

    // versionTime must parse, must strictly increase along the log, and must
    // not lie in the future beyond ordinary clock skew.
    const versionTime: unknown = entry.versionTime;
    const timeMs =
      typeof versionTime === 'string' && ISO_8601_DATE_TIME.test(versionTime)
        ? Date.parse(versionTime)
        : Number.NaN;
    if (Number.isNaN(timeMs)) {
      add(`versionTime "${String(versionTime)}" is not a valid ISO 8601 date-time`, number);
    } else {
      if (previousTime !== undefined && timeMs <= previousTime.ms) {
        add(
          `versionTime "${String(versionTime)}" does not follow the previous entry's ` +
            `"${previousTime.text}"; versionTime must strictly increase`,
          number,
        );
      }
      if (timeMs > nowMs + MAX_VERSION_TIME_SKEW_MS) {
        add(`versionTime "${String(versionTime)}" is in the future`, number);
      }
      previousTime = { text: String(versionTime), ms: timeMs };
    }

    // updateKeys and nextKeyHashes are read as string lists below.
    const malformedList = (['updateKeys', 'nextKeyHashes'] as const).filter(
      (name) => entry.parameters[name] !== undefined && !isStringArray(entry.parameters[name]),
    );
    if (malformedList.length > 0) {
      for (const name of malformedList) add(`parameters.${name} must be an array of strings`, number);
      continue;
    }

    // Entry-1-only parameters.
    if (number > 1) {
      if (entry.parameters.scid !== undefined) add('scid MUST appear in the genesis entry only', number);
      if (entry.parameters.genesisBoundKeys !== undefined) {
        add('genesisBoundKeys MUST appear in the genesis entry only', number);
      }
      // Portability may be switched OFF later, but never back ON.
      if (entry.parameters.portable === true) {
        add('portable MUST NOT be enabled after the genesis entry', number);
      }
    }

    // Pre-rotation.
    const preRotationWasActive = (previous?.parameters.nextKeyHashes ?? []).length > 0;
    const updateKeys =
      entry.parameters.updateKeys ?? (preRotationWasActive ? undefined : inheritedUpdateKeys);

    if (updateKeys === undefined) {
      add(
        preRotationWasActive
          ? 'updateKeys MUST be explicit in every entry while pre-rotation is active'
          : 'No active updateKeys for this entry',
        number,
      );
      previous = entry;
      continue;
    }

    // An explicitly empty updateKeys is a terminal state, not an error: it
    // says no future entry can ever be authorized. Several implementations
    // (dart, rust, java) emit exactly this on deactivation. The entry itself
    // is still verified against whichever keys were active before it.
    const terminal = updateKeys.length === 0;

    if (requirePreRotation && !terminal && (entry.parameters.nextKeyHashes ?? []).length === 0) {
      add(
        'nextKeyHashes is empty or absent; pre-rotation is required in every entry, so a ' +
          'commitment to the next update key must always be present',
        number,
      );
    }

    if (number > 1 && preRotationWasActive && !terminal) {
      const committed = previous?.parameters.nextKeyHashes ?? [];
      for (const key of updateKeys) {
        if (!committed.includes(deriveKeyHash(key))) {
          add(
            `updateKey "${truncate(key)}" was not committed by the previous entry's nextKeyHashes. ` +
              `Under pre-rotation every update key must be committed in advance, including retained ones.`,
            number,
          );
        }
      }
    }

    // Which keys authorize this entry. See the module comment.
    const activeUpdateKeys = terminal
      ? inheritedUpdateKeys // a terminal entry is authorized by the keys before it
      : number === 1
        ? updateKeys
        : preRotationWasActive
          ? updateKeys
          : inheritedUpdateKeys;

    await verifyEntryProof(entry, activeUpdateKeys, profile ?? DIDWEBVH_1_0_PROFILE, number, add);

    // A portable DID may move between domains, keeping its SCID (which is
    // what actually identifies it). A non-portable one may not move at all.
    const entryState = entry.state as DidLogEntry['state'] | undefined;
    const stateId = entryState?.id;
    if (typeof stateId !== 'string' || !stateId.startsWith(`did:webvh:${declaredScid}:`)) {
      add(
        `Entry state id "${String(stateId)}" does not carry the declared SCID; ` +
          `the SCID identifies the DID and cannot change`,
        number,
      );
    } else if (!portable && stateId !== did) {
      add(
        `Entry state id "${stateId}" differs from "${did}", but this DID is not portable. ` +
          `Set portable: true in the genesis entry to permit a domain move.`,
        number,
      );
    }

    // We do not implement witness verification. Silently ignoring a witness
    // requirement would accept a log whose threshold was never met, so this
    // fails closed instead. OTL does not use witnesses.
    // A null witness, like an absent or empty one, declares no requirement.
    const witness: unknown = entry.parameters.witness;
    if (witness !== undefined && witness !== null && !isRecord(witness)) {
      add('parameters.witness must be an object', number);
    } else if (isRecord(witness) && Object.keys(witness).length > 0) {
      addUnsupported(
        'This entry declares a witness requirement, which this implementation does not verify. ' +
          'Refusing rather than accepting a log whose witness threshold may not be met. ' +
          'The log may be entirely valid; we cannot tell.',
        number,
      );
    }

    if (entry.parameters.deactivated === true) deactivated = true;
    if (!terminal) inheritedUpdateKeys = updateKeys;
    previous = entry;
  }

  // ---- Genesis-bound keys (optional OTL extension) ----------------------
  const last = entries.at(-1);
  const latest = last !== undefined && isWellShapedEntry(last) && isRecord(last.state) ? last : genesis;
  // A malformed final entry has already been reported above, so the check is
  // only meaningful, and only run, against a final entry that has a document.
  if (latest === last) issues.push(...checkGenesisBoundKeys(genesis, latest));

  // ---- Continuity with what we have already validated -------------------
  if (options.known !== undefined) {
    issues.push(...checkContinuity(entries, options.known, declaredScid));
  }

  const valid = issues.length === 0;
  return {
    valid,
    issues,
    ...(issues.length > 0 && issues.every((i) => i.unsupported === true) ? { unverifiable: true } : {}),
    did,
    scid: declaredScid,
    versionCount: entries.length,
    deactivated,
    document: latest.state,
    ...(valid
      ? {
          head: {
            scid: declaredScid,
            did: typeof latest.state.id === 'string' ? latest.state.id : did,
            versionNumber: entries.length,
            versionId: latest.versionId,
          },
          continuity:
            options.known === undefined
              ? ('new' as const)
              : options.known.versionNumber === entries.length
                ? ('unchanged' as const)
                : ('extended' as const),
        }
      : {}),
  };
}

/**
 * A log may only grow. Having seen version N, a verifier must refuse a log
 * shorter than N (truncation, including un-deactivating a DID by cutting the
 * deactivation off) and a log with a different entry at position N (a fork).
 * Both are internally consistent, so nothing inside the log can reveal them.
 */
function checkContinuity(
  entries: readonly DidLogEntry[],
  known: KnownDidHead,
  scid: string,
): ValidationIssue[] {
  // A stored head can be corrupted. Failing closed beats silently skipping.
  if (
    !Number.isInteger(known.versionNumber) ||
    known.versionNumber < 1 ||
    typeof known.versionId !== 'string'
  ) {
    return [{ message: 'The previously validated head is malformed, so continuity cannot be checked' }];
  }
  if (known.scid !== scid) {
    return [
      {
        kind: 'fork',
        message:
          `The previously validated head is for SCID "${known.scid}", but this log's SCID is "${scid}"; ` +
          `it does not contain the version already validated`,
      },
    ];
  }
  if (entries.length < known.versionNumber) {
    return [
      {
        kind: 'rollback',
        message:
          `The log has ${entries.length} version(s), but version ${known.versionNumber} ` +
          `("${known.versionId}") was already validated. A log may only grow: a shorter one is a ` +
          `rollback or truncation, not a newer state.`,
      },
    ];
  }
  const actual = entries[known.versionNumber - 1]?.versionId;
  if (actual !== known.versionId) {
    return [
      {
        kind: 'fork',
        message:
          `Version ${known.versionNumber} of this log is "${actual}", but "${known.versionId}" was ` +
          `already validated at that position. The history has been rewritten or forked; ` +
          `refusing rather than following it.`,
      },
    ];
  }
  return [];
}

/**
 * Recompute the SCID the way a third party does: strip the proof, put the
 * placeholder back everywhere the SCID appears, and re-hash.
 */
function recomputeScid(genesis: DidLogEntry, declaredScid: string): string {
  const { proof: _proof, ...rest } = genesis as unknown as Record<string, unknown>;
  const preliminary = toPlaceholders({ ...rest, versionId: SCID_PLACEHOLDER }, declaredScid);
  return hashToBase58(canonicalizeToBytes(preliminary));
}

/** True when `entry` is an object whose `parameters` is an object, so its members can be read. */
function isWellShapedEntry(entry: unknown): entry is DidLogEntry {
  return isRecord(entry) && isRecord(entry['parameters']);
}

function recomputeEntryHash(entry: DidLogEntry, previousVersionId: string): string {
  const { proof: _proof, ...rest } = entry as unknown as Record<string, unknown>;
  return hashToBase58(canonicalizeToBytes({ ...rest, versionId: previousVersionId }));
}

async function verifyEntryProof(
  entry: DidLogEntry,
  activeUpdateKeys: readonly string[],
  profile: MethodProfile,
  number: number,
  add: (message: string, entry?: number) => void,
): Promise<void> {
  const proofs = proofsOf(entry as unknown as Record<string, unknown>);
  if (proofs.length === 0) {
    add('Entry carries no proof', number);
    return;
  }

  for (const proof of proofs) {
    if (!isProofObject(proof)) {
      add('Proof entry is not an object', number);
      continue;
    }

    // The profile fixes the permitted cryptosuites, and anything else is
    // rejected rather than attempted -- a resolver that tries an unexpected
    // algorithm is a downgrade oracle.
    if (!profile.logProofCryptosuites.includes(proof.cryptosuite)) {
      add(
        `Proof declares cryptosuite "${proof.cryptosuite}"; profile "${profile.method}" ` +
          `permits only ${profile.logProofCryptosuites.join(', ')}`,
        number,
      );
      continue;
    }

    const multikey = multikeyFromVerificationMethod(proof);
    if (multikey === undefined) {
      add(`Proof verificationMethod "${proof.verificationMethod}" is not a did:key reference`, number);
      continue;
    }
    if (!activeUpdateKeys.includes(multikey)) {
      add(
        `Entry is signed by "${truncate(multikey)}", which is not in the active updateKeys. ` +
          `Only a key authorized by the log itself may publish a version.`,
        number,
      );
      continue;
    }

    let publicKey: PublicKey;
    try {
      publicKey = fromPublicKeyMultibase(multikey);
    } catch (error) {
      add(`Could not decode update key: ${(error as Error).message}`, number);
      continue;
    }

    const result = await verifyProof({
      document: entry as unknown as Record<string, unknown>,
      publicKey,
      verificationMethod: proof.verificationMethod,
    });
    if (!result.verified) add(`Proof does not verify: ${result.reason}`, number);
  }
}

/** `did:key:z6Mk…#z6Mk…` → `z6Mk…` */
function multikeyFromVerificationMethod(proof: DataIntegrityProof): string | undefined {
  const verificationMethod: unknown = proof.verificationMethod;
  if (typeof verificationMethod !== 'string') return undefined;
  const match = /^did:key:(z[1-9A-HJ-NP-Za-km-z]+)(?:#.*)?$/.exec(verificationMethod);
  return match?.[1];
}

/**
 * Read the genesis-bound designation from the genesis entry.
 *
 * Genesis-bound keys are an optional OTL extension (see
 * {@link GENESIS_BOUND_KEYS_PROPERTY}). The genesis *document* is checked
 * first, because that is the conformant placement, and the `parameters` form
 * second. Both are read from version 1 and nowhere else, because the current
 * document cannot be trusted to self-report which of its keys are
 * genesis-bound.
 *
 * Checking the designation has three outcomes: unchanged, removed and
 * substituted. A genesis-bound key missing from the current document is a
 * rejection, NOT a fallback to "this DID never had one", because treating
 * disappearance as absence would let a compromised DID Management Key strip
 * the protection by deletion alone, without forging anything.
 */
function declaredGenesisBoundKeys(genesis: DidLogEntry): string[] {
  const fromDocument = (genesis.state as Record<string, unknown>)[GENESIS_BOUND_KEYS_PROPERTY];
  if (Array.isArray(fromDocument)) return fromDocument.filter((v): v is string => typeof v === 'string');
  const fromParameters: unknown = genesis.parameters.genesisBoundKeys;
  return Array.isArray(fromParameters)
    ? fromParameters.filter((v): v is string => typeof v === 'string')
    : [];
}

/** Fragment of a bare `#name` or an absolute `did:…#name` reference. */
const fragmentOf = (reference: string): string => reference.slice(reference.lastIndexOf('#') + 1);

function checkGenesisBoundKeys(genesis: DidLogEntry, current: DidLogEntry): ValidationIssue[] {
  const declared = declaredGenesisBoundKeys(genesis);
  if (declared.length === 0) return [];

  const issues: ValidationIssue[] = [];
  const genesisMethods = verificationMethodsOf(genesis.state);
  const currentMethods = verificationMethodsOf(current.state);

  for (const raw of declared) {
    const fragment = fragmentOf(raw);
    const inGenesis = genesisMethods.find((m) => m.id.endsWith(`#${fragment}`));
    const inCurrent = currentMethods.find((m) => m.id.endsWith(`#${fragment}`));

    if (!inGenesis) {
      issues.push({
        entry: 1,
        message: `genesisBoundKeys names "#${fragment}", which is not in the genesis document`,
      });
      continue;
    }

    if (!inCurrent) {
      issues.push({
        message:
          `Genesis-bound key "#${fragment}" has been removed from the current document. ` +
          `This is a rejection, not a fallback: a key designated genesis-bound ` +
          `cannot hand off to another signer by disappearing.`,
      });
      continue;
    }

    if (keyMaterialOf(inGenesis) !== keyMaterialOf(inCurrent)) {
      issues.push({
        message:
          `Genesis-bound key "#${fragment}" carries different key material than the genesis document, ` +
          `which is an unauthorized substitution.`,
      });
    }
  }

  // A later document may carry the property forward — documents are republished
  // wholesale — but declaring a DIFFERENT set is exactly what an attacker would
  // do to mislead a verifier that read the wrong version.
  if (current !== genesis) {
    const currentDeclared = (current.state as Record<string, unknown>)[GENESIS_BOUND_KEYS_PROPERTY];
    if (Array.isArray(currentDeclared)) {
      const from = (list: readonly unknown[]) =>
        list
          .filter((v): v is string => typeof v === 'string')
          .map(fragmentOf)
          .sort()
          .join(',');
      if (from(currentDeclared) !== from(declared)) {
        issues.push({
          message:
            `The current document declares a different genesisBoundKeys set than the genesis entry. ` +
            `Only version 1 governs; a later declaration cannot add or remove designations.`,
        });
      }
    }
  }

  return issues;
}

/** The document's verification methods that carry a string `id`; anything else is ignored. */
function verificationMethodsOf(document: DidDocument): VerificationMethod[] {
  const methods: unknown = document.verificationMethod;
  return Array.isArray(methods)
    ? methods.filter((m): m is VerificationMethod => isRecord(m) && typeof m['id'] === 'string')
    : [];
}

function keyMaterialOf(method: {
  publicKeyMultibase?: string;
  publicKeyJwk?: Record<string, string>;
}): string {
  const multibase = method.publicKeyMultibase;
  if (multibase !== undefined && multibase !== '') return `multibase:${multibase}`;
  if (method.publicKeyJwk) return `jwk:${canonicalizeToBytes(method.publicKeyJwk).toString()}`;
  return 'none';
}

const truncate = (value: string): string =>
  value.length <= 16 ? value : `${value.slice(0, 12)}…${value.slice(-4)}`;
