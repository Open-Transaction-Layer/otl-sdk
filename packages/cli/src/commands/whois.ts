/**
 * Holding and publishing credentials (OTL spec 4.4).
 *
 * A participant is usually both an issuer and a subject. These commands cover
 * the *subject* side: keeping credentials others have issued to you, and
 * publishing them as a Verifiable Presentation at `/.well-known/whois.vp`.
 */

import { readFileSync } from 'node:fs';
import { createProof } from '@otl/core';
import { defaultRegistry } from '@otl/credentials';
import { flag, optionalOption, requireOption, type ParsedArgs } from '../args.ts';
import { CliError } from '../errors.ts';
import type { Output } from '../output.ts';
import { chooseKey } from '../relationship-keys.ts';
import type { Store } from '../store.ts';

/** Store a credential issued to us by someone else. */
export async function cmdCredentialAdd(args: ParsedArgs, store: Store, out: Output): Promise<void> {
  const meta = store.resolveMeta(optionalOption(args, 'did'));
  const file = requireOption(args, 'file', 'Path to the credential JSON');

  let credential: { id?: string; type?: unknown; credentialSubject?: { id?: string } };
  try {
    credential = JSON.parse(readFileSync(file, 'utf8')) as typeof credential;
  } catch (cause) {
    throw new CliError(`${file} is not valid JSON`, { cause });
  }

  if (typeof credential.id !== 'string') {
    throw new CliError('Credential has no "id"; refusing to store it');
  }

  // Spec 4.4 lets a presentation carry mixed types, but storing a credential
  // issued to someone else would publish a claim that is not about us.
  const subject = credential.credentialSubject?.id;
  if (subject !== meta.did) {
    throw new CliError(`This credential names "${String(subject)}" as its subject, not ${meta.did}`, {
      hint: 'Only the subject of a credential may present it. Use --did to select another local DID.',
    });
  }

  const type = defaultRegistry().identify(credential);
  const path = store.addHeldCredential(meta.scid, credential.id, credential);

  out.json
    ? out.data({ stored: credential.id, type: type?.typeName ?? null, path })
    : out.success(
        `Stored ${credential.id}${type ? ` (${type.typeName})` : ' (type not recognized — it will still be published)'}`,
      );
}

/** List credentials held for publication. */
export async function cmdCredentialHeld(args: ParsedArgs, store: Store, out: Output): Promise<void> {
  const meta = store.resolveMeta(optionalOption(args, 'did'));
  const held = store.heldCredentials(meta.scid) as { id?: string; issuer?: string; type?: string[] }[];

  if (out.json) {
    out.data(held);
    return;
  }
  if (held.length === 0) {
    out.print('No credentials held. Add one with: otl credential add --file <path>');
    return;
  }
  for (const credential of held) {
    out.print(`${credential.id}`);
    out.print(`  type:   ${(credential.type ?? []).join(', ')}`);
    out.print(`  issuer: ${credential.issuer}`);
  }
}

/**
 * Build and publish the whois presentation (spec 4.4).
 *
 * The presentation carries each credential with its issuer's proof intact, and
 * adds the holder's own proof over the whole envelope — proving the holder is
 * presenting them, not merely replaying credentials found elsewhere.
 */
export async function cmdWhoisPublish(args: ParsedArgs, store: Store, out: Output): Promise<void> {
  const meta = store.resolveMeta(optionalOption(args, 'did'));
  const credentials = store.heldCredentials(meta.scid);

  if (credentials.length === 0 && !flag(args, 'allow-empty')) {
    throw new CliError('No credentials held, so the presentation would be empty', {
      hint: 'Add one with `otl credential add --file <path>`, or pass --allow-empty.',
    });
  }

  // Spec 6.3: a presentation is signed by a key the holder's `authentication`
  // references. Which one is the holder's choice (spec 3.3): `--vp-key` picks
  // one, otherwise the most recently added key this store holds.
  const requested = optionalOption(args, 'vp-key');
  const { fragment, keyLabel } = await chooseKey(store, meta, 'authentication', {
    ...(requested !== undefined ? { requested } : {}),
    hint: 'Add one with: otl did add-key --label <fragment>',
  });
  const provider = store.keyProvider(meta.scid);

  const presentation = await createProof({
    document: {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      type: ['VerifiablePresentation'],
      holder: meta.did,
      verifiableCredential: credentials,
    },
    provider,
    keyLabel,
    verificationMethod: `${meta.did}#${fragment}`,
    proofPurpose: 'authentication',
  });

  const path = store.writeExportArtifact(meta.scid, 'whois.vp', presentation);

  if (out.json) {
    out.data({ holder: meta.did, credentials: credentials.length, path, vpKey: fragment });
  } else {
    out.success(`Published a presentation with ${credentials.length} credential(s)`);
    out.print(`  ${path}`);
    out.print(`  serve at https://${meta.domain}/.well-known/whois.vp`);
    out.print('');
    out.print(
      `Advertise it: otl did add-service --service '${JSON.stringify({
        id: '#whois',
        type: 'OtlWhois',
        serviceEndpoint: `https://${meta.domain}/.well-known/whois.vp`,
      })}'`,
    );
  }
}
