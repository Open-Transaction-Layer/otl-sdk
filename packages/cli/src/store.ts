/**
 * On-disk state.
 *
 * ```
 * ~/.otl/
 * ├─ config.json                 active DID
 * ├─ trust/perimeter.json        spec 6.1
 * └─ dids/<scid>/
 *    ├─ meta.json                labels, fragments, the next committed key
 *    ├─ log.jsonl                the authoritative log
 *    ├─ keys/                    live keys
 *    ├─ prerotation/             committed keys, separate passphrase
 *    └─ export/                  exactly what gets published
 * ```
 *
 * Two invariants this module exists to hold:
 *
 *  - **Nothing secret is ever written under `export/`.** That directory is
 *    uploaded verbatim, and a test walks it asserting no key material.
 *  - **Pre-rotation keys live in their own store under their own passphrase**,
 *    reachable by exactly one code path. Spec 3.2.2 requires the DID
 *    Management System to be treated as at least as sensitive as any key it
 *    manages. A separate passphrase-protected directory on the same disk is a
 *    weak form of that separation, which the CLI says out loud rather than
 *    burying in documentation.
 */

import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import { type KeyProvider } from '@otl/keys';
import { FileKeyProvider } from '@otl/keys-dev';
import { parseDidLog, type DidLogEntry } from '@otl/core';
import { TrustPerimeter, type TrustPerimeterData } from '@otl/credentials';
import { CliError } from './errors.ts';

export interface DidMeta {
  readonly did: string;
  readonly scid: string;
  readonly domain: string;
  readonly createdAt: string;
  /** Label of the key that may sign the next entry. */
  readonly currentUpdateKeyLabel: string;
  /** Label of the key committed for the entry after that. */
  readonly nextKeyLabel: string;
  /** Verification method fragment to provider key label. */
  readonly keyLabels: Readonly<Record<string, string>>;
  /** How many update keys have been consumed, for naming the next one. */
  readonly rotationCount: number;
  /**
   * Fragment of the credential signing key chosen by
   * `credential add-issuance-key`. Absent until one is added.
   */
  readonly issuanceKeyFragment?: string;
}

export interface StoreOptions {
  readonly root?: string;
  readonly passphrase?: string;
  readonly preRotationPassphrase?: string;
}

export class Store {
  readonly root: string;
  readonly #passphrase: string;
  readonly #preRotationPassphrase: string;

  constructor(options: StoreOptions = {}) {
    this.root = options.root ?? process.env['OTL_HOME'] ?? join(homedir(), '.otl');

    this.#passphrase = options.passphrase ?? process.env['OTL_KEYSTORE_PASSPHRASE'] ?? '';
    // Falls back to the main passphrase with a warning rather than silently
    // sharing one secret: see `preRotationIsSeparate`.
    this.#preRotationPassphrase =
      options.preRotationPassphrase ?? process.env['OTL_PREROTATION_PASSPHRASE'] ?? this.#passphrase;

    mkdirSync(this.root, { recursive: true, mode: 0o700 });
  }

  /** False when the pre-rotation store shares the live store's passphrase. */
  get preRotationIsSeparate(): boolean {
    return this.#preRotationPassphrase !== this.#passphrase;
  }

  requirePassphrase(): void {
    if (this.#passphrase.length === 0) {
      throw new CliError('No keystore passphrase configured', {
        hint:
          'Set OTL_KEYSTORE_PASSPHRASE, and OTL_PREROTATION_PASSPHRASE to a different value ' +
          'so the committed pre-rotation key is not protected by the same secret as the live key.',
      });
    }
  }

  // ---- paths ------------------------------------------------------------

  didDir = (scid: string): string => join(this.root, 'dids', scid);
  exportDir = (scid: string): string => join(this.didDir(scid), 'export');
  logPath = (scid: string): string => join(this.didDir(scid), 'log.jsonl');
  metaPath = (scid: string): string => join(this.didDir(scid), 'meta.json');

  // ---- key providers ----------------------------------------------------

  keyProvider(scid: string): KeyProvider & { generateKey: FileKeyProvider['generateKey'] } {
    this.requirePassphrase();
    return new FileKeyProvider({
      directory: join(this.didDir(scid), 'keys'),
      passphrase: this.#passphrase,
    });
  }

  /**
   * The committed-key store.
   *
   * Reached by `did create` and `did rotate` and nothing else. Kept under a
   * separate passphrase so that compromising the live keystore does not also
   * hand over the key that authorises the next rotation.
   */
  preRotationProvider(scid: string): FileKeyProvider {
    this.requirePassphrase();
    return new FileKeyProvider({
      directory: join(this.didDir(scid), 'prerotation'),
      passphrase: this.#preRotationPassphrase,
    });
  }

  // ---- DID records ------------------------------------------------------

  listDids(): DidMeta[] {
    const dir = join(this.root, 'dids');
    if (!existsSync(dir)) return [];
    return readdirSync(dir)
      .filter((scid) => existsSync(this.metaPath(scid)))
      .map((scid) => this.readMeta(scid));
  }

  readMeta(scid: string): DidMeta {
    const path = this.metaPath(scid);
    if (!existsSync(path)) throw new CliError(`No local DID with SCID "${scid}"`);
    return JSON.parse(readFileSync(path, 'utf8')) as DidMeta;
  }

  writeMeta(meta: DidMeta): void {
    writeJson(this.metaPath(meta.scid), meta);
  }

  /** Resolve a DID, SCID or the active DID to its metadata. */
  resolveMeta(reference?: string): DidMeta {
    const dids = this.listDids();
    if (reference === undefined) {
      const active = this.config().activeDid;
      if (active === undefined) {
        const [only] = dids;
        if (dids.length === 1 && only !== undefined) return only;
        throw new CliError('No DID selected', {
          hint: dids.length === 0 ? 'Create one with: otl did create --domain <domain>' : 'Pass --did <did>',
        });
      }
      reference = active;
    }
    const found = dids.find((meta) => meta.did === reference || meta.scid === reference);
    if (!found) throw new CliError(`No local DID matching "${reference}"`);
    return found;
  }

  readLog(scid: string): DidLogEntry[] {
    const path = this.logPath(scid);
    if (!existsSync(path)) throw new CliError(`No DID log at ${path}`);
    return parseDidLog(readFileSync(path, 'utf8'));
  }

  /** Append an entry to the log and refresh the published tree. */
  appendLogEntry(scid: string, entry: DidLogEntry): void {
    const entries = existsSync(this.logPath(scid)) ? this.readLog(scid) : [];
    this.writeLog(scid, [...entries, entry]);
  }

  writeLog(scid: string, entries: readonly DidLogEntry[]): void {
    const path = this.logPath(scid);
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    writeFileSync(path, entries.map((e) => JSON.stringify(e)).join('\n') + '\n', { mode: 0o600 });
    this.writeExport(scid, entries);
  }

  /**
   * Write the publishable tree.
   *
   * This is what an operator uploads. This method overwrites `did.jsonl` and
   * `did.json` under `.well-known/` and leaves every other file in the export
   * directory, such as the whois presentation and status lists written by
   * `writeExportArtifact`, in place.
   */
  writeExport(scid: string, entries: readonly DidLogEntry[]): void {
    const dir = this.exportDir(scid);
    const wellKnown = join(dir, '.well-known');
    mkdirSync(wellKnown, { recursive: true, mode: 0o755 });

    writeFileSync(join(wellKnown, 'did.jsonl'), entries.map((e) => JSON.stringify(e)).join('\n') + '\n');
    const current = entries[entries.length - 1];
    if (current) writeJson(join(wellKnown, 'did.json'), current.state, 0o644);
  }

  writeExportArtifact(scid: string, relativePath: string, value: unknown): string {
    const path = join(this.exportDir(scid), '.well-known', relativePath);
    writeJson(path, value, 0o644);
    return path;
  }

  /**
   * Credentials this DID holds as a *subject*, awaiting publication.
   *
   * Distinct from the issuance index, which records credentials this DID has
   * issued to others. A participant is usually both, and conflating the two
   * would publish an issuer's records as if they were its own attestations.
   */
  heldCredentialsDir(scid: string): string {
    return join(this.didDir(scid), 'credentials');
  }

  addHeldCredential(scid: string, id: string, credential: unknown): string {
    // Credential ids are `urn:uuid:…`; keep the uuid and drop the scheme so the
    // filename is not attacker-controlled.
    const safe = id
      .replace(/^urn:uuid:/, '')
      .replace(/[^A-Za-z0-9._-]/g, '_')
      .slice(0, 80);
    const path = join(this.heldCredentialsDir(scid), `${safe === '' ? 'credential' : safe}.json`);
    writeJson(path, credential);
    return path;
  }

  heldCredentials(scid: string): unknown[] {
    const dir = this.heldCredentialsDir(scid);
    if (!existsSync(dir)) return [];
    return readdirSync(dir)
      .filter((f) => f.endsWith('.json'))
      .sort()
      .map((f) => JSON.parse(readFileSync(join(dir, f), 'utf8')) as unknown);
  }

  removeDid(scid: string): void {
    rmSync(this.didDir(scid), { recursive: true, force: true });
  }

  // ---- config and trust -------------------------------------------------

  config(): { activeDid?: string } {
    const path = join(this.root, 'config.json');
    return existsSync(path) ? (JSON.parse(readFileSync(path, 'utf8')) as { activeDid?: string }) : {};
  }

  setActiveDid(did: string): void {
    writeJson(join(this.root, 'config.json'), { ...this.config(), activeDid: did });
  }

  trustPerimeter(): TrustPerimeter {
    const path = join(this.root, 'trust', 'perimeter.json');
    if (!existsSync(path)) return new TrustPerimeter();
    return TrustPerimeter.fromJSON(JSON.parse(readFileSync(path, 'utf8')) as TrustPerimeterData);
  }

  saveTrustPerimeter(perimeter: TrustPerimeter): void {
    writeJson(join(this.root, 'trust', 'perimeter.json'), perimeter.toJSON());
  }
}

function writeJson(path: string, value: unknown, mode = 0o600): void {
  mkdirSync(dirname(path), { recursive: true, mode: mode === 0o600 ? 0o700 : 0o755 });
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`, { mode });
}
