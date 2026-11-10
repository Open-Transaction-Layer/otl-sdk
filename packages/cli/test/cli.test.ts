import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { promisify } from 'node:util';
import { validateDidLog, parseDidLog } from '@otl/core';
import { defaultRegistry, TrustPerimeter } from '@otl/credentials';
import { FileKeyProvider } from '@otl/keys-dev';
import { verifyWhois, type VerifiablePresentation } from '@otl/resolver';
import { parseArgs } from '../src/args.ts';

const exec = promisify(execFile);
const BIN = join(import.meta.dirname, '..', 'src', 'bin.ts');

interface RunResult {
  readonly code: number;
  readonly stdout: string;
  readonly stderr: string;
}

/**
 * Drive the real binary in a child process.
 *
 * Exercises argument parsing, the dispatcher, exit codes and stream routing —
 * none of which is covered by calling `run()` in-process.
 */
async function otl(home: string, ...args: string[]): Promise<RunResult> {
  try {
    // The child needs the same resolution condition the test runner was given,
    // or it resolves the workspace packages to dist and fails whenever the
    // build has not run. Inheriting it is wrong, because execArgv is not
    // passed down to a child spawned with execFile. The same goes for type
    // stripping, which Node only enables by default from 22.18, so without the
    // flag the child cannot load the .ts entry point on the 22.12 floor. That
    // flag makes Node print an ExperimentalWarning to stderr, which the real
    // tool never does once it is built, so it is silenced here to keep stderr
    // identical to what a user would see.
    const { stdout, stderr } = await exec(
      process.execPath,
      [
        '--experimental-strip-types',
        '--disable-warning=ExperimentalWarning',
        '--conditions=otl-source',
        BIN,
        ...args,
      ],
      {
        env: {
          ...process.env,
          OTL_HOME: home,
          OTL_KEYSTORE_PASSPHRASE: 'test-keystore-passphrase',
          OTL_PREROTATION_PASSPHRASE: 'a-different-prerotation-passphrase',
        },
      },
    );
    return { code: 0, stdout, stderr };
  } catch (error) {
    const e = error as { code?: number; stdout?: string; stderr?: string };
    return { code: e.code ?? 1, stdout: e.stdout ?? '', stderr: e.stderr ?? '' };
  }
}

const freshHome = () => mkdtempSync(join(tmpdir(), 'otl-cli-'));
// `T` appears only in the return position on purpose: the caller states the
// shape of the CLI's JSON output it expects, and the helper does not validate it.
// eslint-disable-next-line @typescript-eslint/no-unnecessary-type-parameters -- see above
const json = <T>(result: RunResult): T => JSON.parse(result.stdout) as T;

describe('CLI - help and errors', () => {
  it('prints usage with no arguments', async () => {
    const result = await otl(freshHome());
    assert.equal(result.code, 0);
    assert.match(result.stdout, /OTL Identity layer tool/);
  });

  it('reports an unknown command without a stack trace', async () => {
    const result = await otl(freshHome(), 'nonsense');
    assert.equal(result.code, 1);
    assert.match(result.stderr, /Unknown command/);
    // A stack frame is an indented "at" line, whereas the bare substring "at "
    // also appears in ordinary prose such as "might change at any time".
    assert.doesNotMatch(result.stderr, /^\s+at\s/m, 'expected no stack trace');
  });

  it('reports a missing required option as an instruction', async () => {
    const result = await otl(freshHome(), 'did', 'create');
    assert.equal(result.code, 1);
    assert.match(result.stderr, /Missing required option --domain/);
    assert.match(result.stderr, /vasp\.example\.com/);
  });
});

describe('CLI - argument parsing', () => {
  it('never lets a boolean flag consume the following positional argument', () => {
    const parsed = parseArgs(['resolve', '--json', 'did:webvh:abc:example.com', '--yes', 'extra']);
    assert.deepEqual(parsed.command, ['resolve']);
    assert.equal(parsed.options['json'], true);
    assert.equal(parsed.options['yes'], true);
    assert.deepEqual(parsed.positional, ['did:webvh:abc:example.com', 'extra']);
  });

  it('still lets a value-taking option consume its value', () => {
    const parsed = parseArgs(['did', 'create', '--domain', 'example.com', '--no-assertion-key']);
    assert.equal(parsed.options['domain'], 'example.com');
    assert.equal(parsed.options['no-assertion-key'], true);
    assert.deepEqual(parsed.positional, []);
  });
});

describe('CLI - did create', () => {
  it('refuses an X25519 signing key', async () => {
    const result = await otl(freshHome(), 'did', 'create', '--domain', 'x.example.com', '--curve', 'x25519');
    assert.equal(result.code, 1);
    assert.match(result.stderr, /cannot sign/);
  });

  it('creates a DID and writes a publishable tree', async () => {
    const home = freshHome();
    const result = await otl(home, 'did', 'create', '--domain', 'vasp.example.com', '--json');
    assert.equal(result.code, 0, result.stderr);

    const created = json<{ did: string; scid: string; exportDir: string }>(result);
    assert.match(created.did, /^did:webvh:[1-9A-HJ-NP-Za-km-z]{46}:vasp\.example\.com$/);
    assert.ok(existsSync(join(created.exportDir, '.well-known', 'did.jsonl')));
    assert.ok(existsSync(join(created.exportDir, '.well-known', 'did.json')));
  });

  it('warns that keys are non-production', async () => {
    const result = await otl(freshHome(), 'did', 'create', '--domain', 'x.example.com', '--json');
    assert.match(result.stderr, /NON-PRODUCTION/);
  });

  it('produces a log that validates independently', async () => {
    const home = freshHome();
    const created = json<{ scid: string }>(
      await otl(home, 'did', 'create', '--domain', 'vasp.example.com', '--json'),
    );
    const log = readFileSync(join(home, 'dids', created.scid, 'log.jsonl'), 'utf8');
    const result = await validateDidLog(parseDidLog(log));
    assert.equal(result.valid, true, result.issues.map((i) => i.message).join('; '));
  });

  it('keeps pre-rotation keys in a separate store', async () => {
    // Spec 3.2.2 requires the DID Management System to be treated as at least
    // as sensitive as any key it manages. A separate directory under a
    // separate passphrase is a weak form of that separation, and sharing one
    // store would give none.
    const home = freshHome();
    const created = json<{ scid: string }>(
      await otl(home, 'did', 'create', '--domain', 'vasp.example.com', '--json'),
    );
    const didDir = join(home, 'dids', created.scid);

    const live = readdirSync(join(didDir, 'keys'));
    const committed = readdirSync(join(didDir, 'prerotation'));

    assert.ok(live.includes('did-management-0.json'), 'the signing key is live');
    assert.ok(committed.includes('did-management-1.json'), 'the committed key is not');
    assert.ok(!live.includes('did-management-1.json'), 'the committed key must not be in the live store');
  });
});

describe('CLI - export tree contains no secrets', () => {
  it('publishes only did.json and did.jsonl', async () => {
    const home = freshHome();
    const created = json<{ scid: string; exportDir: string }>(
      await otl(home, 'did', 'create', '--domain', 'vasp.example.com', '--json'),
    );

    const files = walk(created.exportDir);
    assert.deepEqual(files.sort(), ['.well-known/did.json', '.well-known/did.jsonl']);
  });

  it('never writes key material under export/', async () => {
    // The invariant the whole publication design rests on: this directory is
    // uploaded verbatim.
    const home = freshHome();
    const created = json<{ exportDir: string }>(
      await otl(home, 'did', 'create', '--domain', 'vasp.example.com', '--json'),
    );

    for (const file of walk(created.exportDir)) {
      const contents = readFileSync(join(created.exportDir, file), 'utf8');
      assert.ok(!contents.includes('ciphertext'), `${file} contains wrapped key material`);
      assert.ok(!contents.includes('pbkdf2'), `${file} contains key-derivation parameters`);
      assert.ok(!/"privateKey"/.test(contents), `${file} contains a privateKey member`);
    }
  });

  function walk(dir: string, prefix = ''): string[] {
    if (!existsSync(dir)) return [];
    return readdirSync(dir).flatMap((name) => {
      const full = join(dir, name);
      return statSync(full).isDirectory() ? walk(full, `${prefix}${name}/`) : [`${prefix}${name}`];
    });
  }
});

describe('CLI - updates rotate the management key', () => {
  it('adds a service and advances to version 2', async () => {
    const home = freshHome();
    await otl(home, 'did', 'create', '--domain', 'vasp.example.com', '--json');

    const service = JSON.stringify({
      id: '#whois',
      type: 'OtlWhois',
      serviceEndpoint: 'https://vasp.example.com/.well-known/whois.vp',
    });
    const result = await otl(home, 'did', 'add-service', '--service', service, '--json');
    assert.equal(result.code, 0, result.stderr);
    // Every update rotates the management key under this policy.
    assert.match(result.stderr, /Rotated the DID Management Key/);

    const validated = await otl(home, 'did', 'validate', '--json');
    assert.equal(validated.code, 0, validated.stderr);
    assert.equal(json<{ valid: boolean; versionCount: number }>(validated).versionCount, 2);
  });

  it('rotates without changing the document', async () => {
    const home = freshHome();
    await otl(home, 'did', 'create', '--domain', 'vasp.example.com', '--json');
    const before = json<Record<string, unknown>>(await otl(home, 'did', 'show', '--json'));

    const rotated = await otl(home, 'did', 'rotate', '--json');
    assert.equal(rotated.code, 0, rotated.stderr);

    const after = json<Record<string, unknown>>(await otl(home, 'did', 'show', '--json'));
    assert.deepEqual(after, before, 'a rotation must change keys, not the document');

    const validated = await otl(home, 'did', 'validate', '--json');
    assert.equal(json<{ valid: boolean }>(validated).valid, true);
  });

  it('rejects a service endpoint that is not HTTPS', async () => {
    const home = freshHome();
    await otl(home, 'did', 'create', '--domain', 'vasp.example.com', '--json');
    const service = JSON.stringify({ id: '#x', type: 'X', serviceEndpoint: 'http://insecure.example' });
    const result = await otl(home, 'did', 'add-service', '--service', service);
    assert.equal(result.code, 1);
    assert.match(result.stderr, /https/);
  });

  it('adds a key and keeps the log valid', async () => {
    const home = freshHome();
    await otl(home, 'did', 'create', '--domain', 'vasp.example.com', '--json');
    const added = await otl(
      home,
      'did',
      'add-key',
      '--label',
      'agreement-key',
      '--curve',
      'x25519',
      '--json',
    );
    assert.equal(added.code, 0, added.stderr);

    const document = json<{
      verificationMethod: { id: string; type: string; publicKeyMultibase?: string }[];
    }>(await otl(home, 'did', 'show', '--json'));
    const agreement = document.verificationMethod.find((m) => m.id.endsWith('#agreement-key'));

    // Asserted via the multicodec prefix rather than the type string: z6LS is
    // the x25519-pub multicodec, so this proves the key really is on the curve
    // requested, where the type name only claims it.
    assert.ok(agreement?.type.startsWith('X25519'), `unexpected type ${agreement?.type}`);
    assert.ok(agreement?.publicKeyMultibase?.startsWith('z6LS'), 'expected an x25519-pub multikey');

    assert.equal(json<{ valid: boolean }>(await otl(home, 'did', 'validate', '--json')).valid, true);
  });
});

describe('CLI - a failed update can be retried', () => {
  it('reuses a committed key left behind by an earlier failed rotation', async () => {
    const home = freshHome();
    const created = json<{ scid: string }>(
      await otl(home, 'did', 'create', '--domain', 'vasp.example.com', '--json'),
    );
    // An earlier run generated the next commitment and then failed before
    // writing the entry, so the key exists but the log does not use it.
    await new FileKeyProvider({
      directory: join(home, 'dids', created.scid, 'prerotation'),
      passphrase: 'a-different-prerotation-passphrase',
    }).generateKey('did-management-2', 'Ed25519');

    const rotated = await otl(home, 'did', 'rotate', '--json');
    assert.equal(rotated.code, 0, rotated.stderr);
    assert.equal(json<{ valid: boolean }>(await otl(home, 'did', 'validate', '--json')).valid, true);

    const log = parseDidLog(readFileSync(join(home, 'dids', created.scid, 'log.jsonl'), 'utf8'));
    assert.equal(log.length, 2);
  });

  it('reuses a document key left behind by an earlier failed add-key', async () => {
    const home = freshHome();
    const created = json<{ scid: string }>(
      await otl(home, 'did', 'create', '--domain', 'vasp.example.com', '--json'),
    );
    const leftover = await new FileKeyProvider({
      directory: join(home, 'dids', created.scid, 'keys'),
      passphrase: 'test-keystore-passphrase',
    }).generateKey('agreement-key', 'X25519');

    const added = await otl(home, 'did', 'add-key', '--label', 'agreement-key', '--curve', 'x25519');
    assert.equal(added.code, 0, added.stderr);

    const document = json<{ verificationMethod: { id: string; publicKeyMultibase?: string }[] }>(
      await otl(home, 'did', 'show', '--json'),
    );
    const agreement = document.verificationMethod.find((m) => m.id.endsWith('#agreement-key'));
    const { toPublicKeyMultibase } = await import('@otl/keys');
    assert.equal(agreement?.publicKeyMultibase, toPublicKeyMultibase(leftover.publicKey));
  });

  it('refuses to add a key whose fragment the document already has', async () => {
    const home = freshHome();
    await otl(home, 'did', 'create', '--domain', 'vasp.example.com', '--json');
    const result = await otl(home, 'did', 'add-key', '--label', 'assertion-key');
    assert.equal(result.code, 1);
    assert.match(result.stderr, /already has a verification method/);
  });
});

describe('CLI - deactivation', () => {
  it('requires explicit confirmation', async () => {
    const home = freshHome();
    await otl(home, 'did', 'create', '--domain', 'vasp.example.com', '--json');
    const refused = await otl(home, 'did', 'deactivate');
    assert.equal(refused.code, 1);
    assert.match(refused.stderr, /--yes/);
  });

  it('deactivates with --yes and the log stays valid', async () => {
    const home = freshHome();
    await otl(home, 'did', 'create', '--domain', 'vasp.example.com', '--json');
    const result = await otl(home, 'did', 'deactivate', '--yes', '--json');
    assert.equal(result.code, 0, result.stderr);
    assert.equal(json<{ valid: boolean }>(await otl(home, 'did', 'validate', '--json')).valid, true);
  });
});

describe('CLI - trust perimeter', () => {
  it('starts empty and records what is added', async () => {
    const home = freshHome();
    const empty = await otl(home, 'trust', 'list');
    assert.match(empty.stdout, /empty/);

    await otl(home, 'trust', 'add', '--did', 'did:webvh:QmScid:lou.example.org', '--note', 'GLEIF LOU');
    const listed = await otl(home, 'trust', 'list');
    assert.match(listed.stdout, /lou\.example\.org/);
    assert.match(listed.stdout, /OtlLeiCredential/);
    assert.match(listed.stdout, /GLEIF LOU/);
  });

  it('warns when an issuer is removed entirely', async () => {
    const home = freshHome();
    await otl(home, 'trust', 'add', '--did', 'did:webvh:QmScid:lou.example.org');
    const removed = await otl(home, 'trust', 'remove', '--did', 'did:webvh:QmScid:lou.example.org');
    assert.match(removed.stderr, /compromised trust anchor/);
  });
});

describe('CLI - credentials', () => {
  it('refuses to issue before an issuance key exists', async () => {
    const home = freshHome();
    await otl(home, 'did', 'create', '--domain', 'lou.example.org', '--json');
    const result = await otl(
      home,
      'credential',
      'issue',
      '--lei',
      '00000000000000000098',
      '--subject',
      'did:webvh:QmX:vasp.example.com',
    );
    assert.equal(result.code, 1);
    assert.match(result.stderr, /add-issuance-key/);
  });

  it('lets the issuer choose the signing key fragment (spec 3.2.1)', async () => {
    // The spec fixes no id: authority comes from the assertionMethod
    // reference, not from the name. An issuer that wants #vc-key-1 is
    // conformant, so the CLI must not refuse it.
    const home = freshHome();
    await otl(home, 'did', 'create', '--domain', 'lou.example.org', '--json');
    const result = await otl(home, 'credential', 'add-issuance-key', '--label', 'my-own-key');
    assert.equal(result.code, 0, result.stderr);

    const resolved = await otl(home, 'did', 'show', '--json');
    assert.match(resolved.stdout, /my-own-key/);

    const issued = await otl(
      home,
      'credential',
      'issue-hosting',
      '--subject',
      'did:webvh:QmTestScidForHostedParticipant0001:vasp.example.com',
      '--common-name',
      'Example VASP',
      '--json',
    );
    assert.equal(issued.code, 0, issued.stderr);
    const { credential } = JSON.parse(issued.stdout) as {
      credential: { proof: { verificationMethod: string } };
    };
    assert.match(credential.proof.verificationMethod, /#my-own-key$/);
  });

  it('adds an issuance key and reports no status list yet', async () => {
    const home = freshHome();
    await otl(home, 'did', 'create', '--domain', 'lou.example.org', '--json');
    const added = await otl(home, 'credential', 'add-issuance-key', '--json');
    assert.equal(added.code, 0, added.stderr);

    const listed = await otl(home, 'credential', 'status-list');
    assert.equal(listed.code, 1);
    assert.match(listed.stderr, /no status list/);
  });

  it('issues an OtlHostingCredential with watchers (spec 4.12-4.15)', async () => {
    const home = freshHome();
    const created = await otl(home, 'did', 'create', '--domain', 'hosting.example.org', '--json');
    assert.equal(created.code, 0, created.stderr);
    await otl(home, 'credential', 'add-issuance-key', '--json');

    const subject = 'did:webvh:QmTestScidForHostedParticipant0001:vasp.example.com';
    const issued = await otl(
      home,
      'credential',
      'issue-hosting',
      '--subject',
      subject,
      '--common-name',
      'Example VASP',
      '--watchers',
      'https://watcher-a.example.net,https://watcher-b.example.com',
      '--json',
    );
    assert.equal(issued.code, 0, issued.stderr);

    const { credential } = JSON.parse(issued.stdout) as {
      credential: {
        type: string[];
        credentialSubject: { id: string; commonName: string; watchers?: string[] };
        credentialStatus?: unknown[];
        validUntil?: string;
      };
    };

    assert.deepEqual(credential.type, ['VerifiableCredential', 'OtlHostingCredential']);
    assert.equal(credential.credentialSubject.id, subject);
    assert.equal(credential.credentialSubject.commonName, 'Example VASP');
    assert.deepEqual(credential.credentialSubject.watchers, [
      'https://watcher-a.example.net',
      'https://watcher-b.example.com',
    ]);
    // Spec 4.13 requires a revocation pointer; 4.13 does NOT require validUntil.
    assert.equal(credential.credentialStatus?.length, 1);
    assert.equal(credential.validUntil, undefined);
  });

  it('issues a hosting credential with no watchers at all', async () => {
    const home = freshHome();
    await otl(home, 'did', 'create', '--domain', 'hosting.example.org', '--json');
    await otl(home, 'credential', 'add-issuance-key', '--json');

    const issued = await otl(
      home,
      'credential',
      'issue-hosting',
      '--subject',
      'did:webvh:QmTestScidForHostedParticipant0001:vasp.example.com',
      '--common-name',
      'Example VASP',
      '--json',
    );
    assert.equal(issued.code, 0, issued.stderr);

    const { credential } = JSON.parse(issued.stdout) as {
      credential: { credentialSubject: { watchers?: string[] } };
    };
    assert.equal(credential.credentialSubject.watchers, undefined);
  });

  it('refuses to issue a hosting credential without a common name (spec 4.14)', async () => {
    const home = freshHome();
    await otl(home, 'did', 'create', '--domain', 'hosting.example.org', '--json');
    await otl(home, 'credential', 'add-issuance-key', '--json');

    const issued = await otl(
      home,
      'credential',
      'issue-hosting',
      '--subject',
      'did:webvh:QmTestScidForHostedParticipant0001:vasp.example.com',
    );
    assert.equal(issued.code, 1);
    assert.match(issued.stderr, /common-name/);
  });

  it('refuses a non-HTTPS watcher at issuance (spec 4.14)', async () => {
    const home = freshHome();
    await otl(home, 'did', 'create', '--domain', 'hosting.example.org', '--json');
    await otl(home, 'credential', 'add-issuance-key', '--json');

    const issued = await otl(
      home,
      'credential',
      'issue-hosting',
      '--subject',
      'did:webvh:QmTestScidForHostedParticipant0001:vasp.example.com',
      '--common-name',
      'Example VASP',
      '--watchers',
      'http://watcher-a.example.net',
    );
    assert.equal(issued.code, 1);
    assert.match(issued.stderr, /https/);
  });
});

describe('CLI - status list ids', () => {
  it('refuses a --list-id that could escape the export tree', async () => {
    const home = freshHome();
    await otl(home, 'did', 'create', '--domain', 'lou.example.org', '--json');
    await otl(home, 'credential', 'add-issuance-key', '--json');
    for (const bad of ['../../keys', 'a/b', '']) {
      const result = await otl(home, 'credential', 'status-list', `--list-id=${bad}`);
      assert.equal(result.code, 1, bad);
      assert.match(result.stderr, /Invalid --list-id/, bad);
    }
  });
});

describe('CLI - whois publish', () => {
  it('signs a presentation that verifies against the holder authentication key', async () => {
    const home = freshHome();
    const created = json<{ did: string; exportDir: string }>(
      await otl(home, 'did', 'create', '--domain', 'vasp.example.com', '--json'),
    );
    const published = await otl(home, 'whois', 'publish', '--allow-empty', '--json');
    assert.equal(published.code, 0, published.stderr);

    const wellKnown = join(created.exportDir, '.well-known');
    const presentation = JSON.parse(
      readFileSync(join(wellKnown, 'whois.vp'), 'utf8'),
    ) as VerifiablePresentation;

    // Serve the export tree in place of the network, so the verifier
    // validates the real log the CLI wrote.
    const fetch = (async (input: string | URL) => {
      const path = join(wellKnown, new URL(String(input)).pathname.replace(/^\/\.well-known\//, ''));
      return existsSync(path) ? new Response(readFileSync(path)) : new Response(null, { status: 404 });
    }) as typeof globalThis.fetch;

    const result = await verifyWhois({
      did: created.did,
      presentation,
      registry: defaultRegistry(),
      trustPerimeter: new TrustPerimeter(),
      resolveAssertionKey: () => Promise.reject(new Error('no credentials to check')),
      fetchStatusList: () => Promise.reject(new Error('no credentials to check')),
      fetchOptions: { fetch },
    });
    assert.equal(result.presentationVerified, true, result.presentationIssue);
  });
});

describe('CLI - resolve and validate are separate', () => {
  it('warns that resolve performs no validation', async () => {
    // Fails to fetch, but the warning must be emitted regardless: the
    // distinction is the point of having two commands.
    const result = await otl(
      freshHome(),
      'resolve',
      'did:webvh:QmScid1111111111111111111111111111111111111111:nonexistent.invalid',
    );
    assert.match(result.stderr, /performs no validation/);
  });
});

describe('CLI - export', () => {
  it('lists the files to upload', async () => {
    const home = freshHome();
    await otl(home, 'did', 'create', '--domain', 'vasp.example.com', '--json');
    const result = await otl(home, 'export');
    assert.equal(result.code, 0, result.stderr);
    assert.match(result.stdout, /did\.jsonl/);
    assert.match(result.stdout, /https:\/\/vasp\.example\.com\/\.well-known\//);
  });
});

describe('CLI - serve', () => {
  it('refuses to serve without TLS and explains how to get it', async () => {
    // Resolution is HTTPS-only with no bypass, so serve asks for a certificate
    // rather than the CLI growing an insecure mode.
    const home = freshHome();
    await otl(home, 'did', 'create', '--domain', 'vasp.example.com', '--json');
    const result = await otl(home, 'serve');
    assert.equal(result.code, 1);
    assert.match(result.stderr, /--cert/);
    assert.match(result.stderr, /openssl req/);
  });
});
