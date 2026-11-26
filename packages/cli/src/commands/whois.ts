/**
 * Holding and publishing credentials (OTL spec 4.4).
 *
 * A participant is usually both an issuer and a subject. These commands cover
 * the *subject* side: keeping credentials others have issued to you, and
 * publishing them as a Verifiable Presentation at `/.well-known/whois.vp`.
 */

import { readFileSync } from 'node:fs';
import { createProof } from '@open-transaction-layer/core';
import { defaultRegistry } from '@open-transaction-layer/credentials';
import { flag, optionalOption, requireOption, type ParsedArgs } from '../args.ts';
import { CliError } from '../errors.ts';
import type { Output } from '../output.ts';
import type { Store } from '../store.ts';

/**
 * Fragment used to sign the presentation itself.
 *
 * **Provisional.** Spec 6.3 requires the key that signs a presentation to be
 * under the holder's DID and listed in the holder's `authentication`, and a
 * verifier refuses any other key. Which key the holder uses is left to
 * whichever other layer defines the holder's general-purpose signing key, so
 * this default is a convention of this tool. It is overridable with
 * `--vp-key`, and every publication says so on stderr.
 */
const PROVISIONAL_VP_KEY = 'assertion-key';

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
  const keyLabel = optionalOption(args, 'vp-key') ?? PROVISIONAL_VP_KEY;
  const credentials = store.heldCredentials(meta.scid);

  if (credentials.length === 0 && !flag(args, 'allow-empty')) {
    throw new CliError('No credentials held, so the presentation would be empty', {
      hint: 'Add one with `otl credential add --file <path>`, or pass --allow-empty.',
    });
  }

  const provider = store.keyProvider(meta.scid);
  await provider.getKey(keyLabel).catch(() => {
    throw new CliError(`No key "${keyLabel}" in this DID`, {
      hint: `Add one with: otl did add-key --label ${keyLabel}`,
    });
  });

  const presentation = await createProof({
    document: {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      type: ['VerifiablePresentation'],
      holder: meta.did,
      verifiableCredential: credentials,
    },
    provider,
    keyLabel,
    verificationMethod: `${meta.did}#${keyLabel}`,
    proofPurpose: 'authentication',
  });

  const path = store.writeExportArtifact(meta.scid, 'whois.vp', presentation);

  out.warn(
    'NOTE: the presentation signing key is PROVISIONAL. Spec 6.3 requires it to be listed in your\n' +
      "  DID's authentication but leaves the choice of key to another layer.\n" +
      `  Signed with #${keyLabel}; override with --vp-key.`,
  );

  if (out.json) {
    out.data({ holder: meta.did, credentials: credentials.length, path, vpKey: keyLabel });
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
