/**
 * DID creation — the genesis entry (OTL spec 2.2, 3.2.2).
 *
 * The sequence matters and is easy to get subtly wrong:
 *
 *   1. Build the entry with `{SCID}` everywhere the SCID will appear.
 *   2. SCID  = base58btc(multihash(JCS(that entry)))
 *   3. Substitute the real SCID throughout.
 *   4. entryHash = base58btc(multihash(JCS(entry with versionId set to the
 *      bare SCID)))   <- versionId is the SCID here, not `1-…`
 *   5. Set versionId = `1-{entryHash}`.
 *   6. Sign the finished entry with the DID Management Key.
 *
 * Step 4 is the one worth re-reading: the hash is taken over the entry as it
 * stood *before* its own versionId existed, which is what makes the versionId
 * a commitment to the entry rather than part of it.
 */

import type { KeyProvider } from '@otl/keys';
import { toPublicKeyMultibase } from '@otl/keys';
import { InvalidDocumentError } from '../errors.ts';
import { createProof } from '../proof.ts';
import { buildDidDocument, type DocumentKey } from './document.ts';
import { deriveEntryHash, deriveKeyHash, deriveScid, formatVersionId, fromPlaceholders } from './hashing.ts';
import { DIDWEBVH_1_0_PROFILE, explainCurveRejection, type MethodProfile } from './profile.ts';
import {
  GENESIS_BOUND_KEYS_PROPERTY,
  OTL_IDENTITY_CONTEXT,
  SCID_PLACEHOLDER,
  type GenesisBoundPlacement,
  type DidLogEntry,
  type DidDocument,
  type DidLogParameters,
  type ServiceEntry,
} from './types.ts';

export interface CreateDidOptions {
  /** Domain the DID resolves from, e.g. `vasp.example.com`. Optional `:path` segments allowed. */
  readonly domain: string;
  readonly provider: KeyProvider;
  /** Label of the DID Management Key; its curve must be permitted by `profile`. */
  readonly managementKeyLabel: string;
  /**
   * Label of the pre-rotation key, whose hash is committed now. This
   * implementation keeps did:webvh pre-rotation permanently active by default,
   * so every entry commits to the key that signs the next one.
   */
  readonly preRotationKeyLabel: string;
  /** Verification methods to publish in the genesis document. */
  readonly keys?: readonly DocumentKey[];
  readonly service?: readonly ServiceEntry[];
  /**
   * Fragments to designate genesis-bound, an optional OTL extension described
   * at {@link GENESIS_BOUND_KEYS_PROPERTY}. Declared in entry 1 only.
   */
  readonly genesisBoundKeys?: readonly string[];
  /**
   * Where the designation is written. Defaults to `'document'`.
   *
   * `'parameters'` writes it into the log entry's `parameters` instead, which
   * did:webvh forbids because its parameter set is closed by a MUST. It is
   * offered so that form can be generated for comparison, not for publication.
   */
  readonly genesisBoundPlacement?: GenesisBoundPlacement;
  /** UTC ISO 8601. Supplied by the caller so creation is reproducible in tests. */
  readonly versionTime: string;
  readonly portable?: boolean;
  /**
   * Which algorithms log-entry proofs may use. Defaults to stock did:webvh 1.0.
   *
   * A widened profile announces itself in `parameters.method`, so a stock
   * resolver rejects the log rather than mis-processing it — see
   * {@link MethodProfile}.
   */
  readonly profile?: MethodProfile;
}

export interface CreatedDid {
  readonly did: string;
  readonly scid: string;
  readonly entry: DidLogEntry;
}

/**
 * Check a key against the profile's permitted curves.
 *
 * Done before any work happens, so an unusable configuration is a clear message
 * rather than a DID nobody can resolve, discovered later.
 */
function assertCurvePermitted(
  profile: MethodProfile,
  curve: import('@otl/keys').Curve,
  label: string,
  role: string,
): void {
  const problem = explainCurveRejection(profile, curve, `${role} ("${label}")`);
  if (problem !== undefined) throw new InvalidDocumentError(problem);
}

/**
 * Validate a domain and encode it as did:webvh method-specific id segments.
 *
 * A port is percent-encoded, because `:` is the segment separator in a DID:
 * `localhost:8443` becomes `localhost%3A8443`, which is one segment rather
 * than two. Accepting the readable form and encoding it here means callers
 * never have to know that.
 */
export function encodeDomain(domain: string): string {
  if (domain.length === 0) throw new InvalidDocumentError('Domain must not be empty');
  if (domain.includes('/')) {
    throw new InvalidDocumentError(
      `Domain "${domain}" must not contain "/" — express path segments with ":"`,
    );
  }

  // A single trailing `:digits` is a port; anything else colon-separated is a
  // path segment and is left alone.
  const withPort = /^([A-Za-z0-9.-]+):(\d{1,5})$/.exec(domain);
  if (withPort) {
    const port = Number(withPort[2]);
    if (port < 1 || port > 65535) {
      throw new InvalidDocumentError(`Port ${port} in "${domain}" is out of range`);
    }
    return `${withPort[1]}%3A${withPort[2]}`;
  }

  return domain;
}

export async function createDid(options: CreateDidOptions): Promise<CreatedDid> {
  const {
    domain,
    provider,
    managementKeyLabel,
    preRotationKeyLabel,
    keys = [],
    service,
    genesisBoundKeys,
    genesisBoundPlacement = 'document',
    versionTime,
    portable,
    profile = DIDWEBVH_1_0_PROFILE,
  } = options;

  const managementKey = await provider.getKey(managementKeyLabel);
  const preRotationKey = await provider.getKey(preRotationKeyLabel);
  assertCurvePermitted(profile, managementKey.curve, managementKeyLabel, 'DID Management Key');
  assertCurvePermitted(profile, preRotationKey.curve, preRotationKeyLabel, 'pre-rotation key');

  if (genesisBoundKeys) assertGenesisBoundKeysExist(genesisBoundKeys, keys);

  const placeholderDid = `did:webvh:${SCID_PLACEHOLDER}:${encodeDomain(domain)}`;

  const parameters: DidLogParameters = {
    method: profile.method,
    scid: SCID_PLACEHOLDER,
    updateKeys: [toPublicKeyMultibase(managementKey.publicKey)],
    // This implementation's policy: pre-rotation is active from the genesis
    // entry onward, so a non-empty commitment is always present.
    nextKeyHashes: [deriveKeyHash(toPublicKeyMultibase(preRotationKey.publicKey))],
    ...(portable !== undefined ? { portable } : {}),
    // Only written here when the `parameters` placement is explicitly
    // requested, because did:webvh forbids undefined properties in `parameters`.
    ...(genesisBoundPlacement === 'parameters' && genesisBoundKeys && genesisBoundKeys.length > 0
      ? { genesisBoundKeys: [...genesisBoundKeys].sort() }
      : {}),
  };

  const preliminary: DidLogEntry = {
    versionId: SCID_PLACEHOLDER,
    versionTime,
    parameters,
    state: withGenesisBoundKeys(
      buildDidDocument({ did: placeholderDid, keys, ...(service ? { service } : {}) }),
      placeholderDid,
      genesisBoundPlacement === 'document' ? genesisBoundKeys : undefined,
    ),
  };

  const scid = deriveScid(preliminary);
  const did = `did:webvh:${scid}:${encodeDomain(domain)}`;

  // Every {SCID} occurrence resolves at once — in versionId, parameters.scid,
  // and throughout the document's ids and controllers.
  const substituted = fromPlaceholders(preliminary, scid);

  // The entry hash is taken with versionId set to the bare SCID (entry 1's
  // stand-in for "the previous versionId").
  const entryHash = deriveEntryHash(substituted, scid);
  const unsigned: DidLogEntry = { ...substituted, versionId: formatVersionId(1, entryHash) };

  const signed = (await createProof({
    document: unsigned as unknown as Record<string, unknown>,
    provider,
    keyLabel: managementKeyLabel,
    verificationMethod: `did:key:${toPublicKeyMultibase(managementKey.publicKey)}#${toPublicKeyMultibase(managementKey.publicKey)}`,
    proofPurpose: 'assertionMethod',
    // Spec 3.2.2 shows log-entry proofs as an array, and at least one
    // reference implementation rejects a bare object outright.
    proofFormat: 'array',
  })) as unknown as DidLogEntry;

  return { did, scid, entry: signed };
}

/**
 * Attach the genesis-bound designation to the genesis document.
 *
 * Fragments are expanded to absolute DID URLs, matching how every other
 * verification-method reference in a DID document is written
 * (`authentication`, `assertionMethod`), so the document stays internally
 * consistent. The OTL context is appended because DID 1.1 §6.2.3 has conforming
 * JSON-LD consumers drop terms the `@context` does not define.
 */
function withGenesisBoundKeys(
  document: DidDocument,
  did: string,
  fragments: readonly string[] | undefined,
): DidDocument {
  if (!fragments || fragments.length === 0) return document;

  const contexts = document['@context'];
  return {
    ...document,
    '@context': [...contexts, OTL_IDENTITY_CONTEXT],
    [GENESIS_BOUND_KEYS_PROPERTY]: [...fragments]
      .map((f) => `${did}#${f.startsWith('#') ? f.slice(1) : f}`)
      .sort(),
  };
}

function assertGenesisBoundKeysExist(
  genesisBoundKeys: readonly string[],
  keys: readonly DocumentKey[],
): void {
  const fragments = new Set(keys.map((k) => k.fragment));
  for (const raw of genesisBoundKeys) {
    const fragment = raw.startsWith('#') ? raw.slice(1) : raw;
    if (!fragments.has(fragment)) {
      throw new InvalidDocumentError(
        `genesisBoundKeys names "#${fragment}", which is not a verification method in the genesis document`,
      );
    }
  }
}
