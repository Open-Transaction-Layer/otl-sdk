/**
 * Signing, verification and encryption commands.
 */

import { signRaw, verifyRaw } from '@otl/core';
import { decrypt, encrypt } from '@otl/jwe';
import type { PublicKey } from '@otl/keys';
import { resolveRelationshipKeys, resolveVerificationKey } from '@otl/resolver';
import { optionalOption, requireOption, type ParsedArgs } from '../args.ts';
import { CliError } from '../errors.ts';
import type { Output } from '../output.ts';
import type { Store } from '../store.ts';
import { fetchOptionsFrom } from './remote.ts';

const readMessage = async (args: ParsedArgs, option = 'message'): Promise<Uint8Array> => {
  const inline = optionalOption(args, option);
  const file = optionalOption(args, 'file');
  if (inline !== undefined) return new TextEncoder().encode(inline);
  if (file !== undefined) {
    const { readFileSync } = await import('node:fs');
    return new Uint8Array(readFileSync(file));
  }
  throw new CliError(`Provide the message with --${option} <text> or --file <path>`);
};

export async function cmdSign(args: ParsedArgs, store: Store, out: Output): Promise<void> {
  const meta = store.resolveMeta(optionalOption(args, 'did'));
  const keyLabel = requireOption(args, 'key', 'The key label, e.g. --key authentication-key');
  const message = await readMessage(args);

  const signature = await signRaw({ message, provider: store.keyProvider(meta.scid), keyLabel });

  out.warn(
    'NOTE: this is a detached raw signature, not a spec-conformant DataIntegrityProof.\n' +
      '  It carries no verificationMethod, proofPurpose or document binding.',
  );
  out.json ? out.data({ signature, keyLabel, did: meta.did }) : out.print(signature);
}

export async function cmdVerify(args: ParsedArgs, _store: Store, out: Output): Promise<void> {
  const did = requireOption(args, 'did');
  const keyLabel = requireOption(args, 'key');
  const signature = requireOption(args, 'signature');
  const message = await readMessage(args);

  // A key counts only when the DID designated it for signing, so a key held
  // for some other purpose is never accepted.
  const relationship = optionalOption(args, 'relationship') ?? 'assertionMethod';
  if (relationship !== 'assertionMethod' && relationship !== 'authentication') {
    throw new CliError(`Invalid --relationship "${relationship}"`, {
      hint: 'Use assertionMethod or authentication.',
    });
  }

  // Resolution validates the log to genesis before returning a key, so a
  // signature can never be checked against an unvalidated document.
  const publicKey = await resolveVerificationKey(did, keyLabel, {
    ...fetchOptionsFrom(args),
    relationship,
  });
  const verified = verifyRaw({ message, signature, publicKey });

  out.json ? out.data({ verified, did, keyLabel }) : out.print(verified ? 'verified' : 'NOT VERIFIED');
  if (!verified) throw new CliError('Signature did not verify', { exitCode: 2 });
}

/** Key-agreement curves the envelope supports (spec 3.1.1). */
const SUPPORTED_AGREEMENT_CURVES: ReadonlySet<string> = new Set(['X25519', 'P-256']);

export async function cmdEncrypt(args: ParsedArgs, _store: Store, out: Output): Promise<void> {
  const did = requireOption(args, 'did', 'The recipient DID');
  const requested = optionalOption(args, 'key');
  const message = await readMessage(args);

  // Only a key the recipient designated for key agreement may receive
  // (spec 3.3). Without --key, any keyAgreement key of a type this tool
  // supports will do: the recipient decides which keys it offers.
  let recipientPublicKey: PublicKey;
  let recipientKeyId: string;
  if (requested !== undefined) {
    recipientKeyId = requested.startsWith('did:') ? requested : `${did}#${requested.replace(/^#/, '')}`;
    recipientPublicKey = await resolveVerificationKey(did, recipientKeyId, {
      ...fetchOptionsFrom(args),
      relationship: 'keyAgreement',
    });
  } else {
    const candidates = await resolveRelationshipKeys(did, 'keyAgreement', fetchOptionsFrom(args));
    const chosen = candidates.find((k) => SUPPORTED_AGREEMENT_CURVES.has(k.publicKey.curve));
    if (chosen === undefined) {
      throw new CliError(`${did} lists no keyAgreement key of a supported type`, {
        hint: 'Supported: X25519 and P-256 (spec 3.1.1).',
      });
    }
    recipientKeyId = chosen.id;
    recipientPublicKey = chosen.publicKey;
  }

  const sender = optionalOption(args, 'sender');
  const jwe = encrypt({
    plaintext: message,
    recipientPublicKey,
    recipientKeyId,
    ...(sender !== undefined && sender !== '' ? { senderInfo: sender } : {}),
  });

  out.warn(
    'NOTE: the encryption envelope is PROVISIONAL — OTL spec 3.1.1 defines key types but no\n' +
      '  envelope, so interoperability with another implementation is not guaranteed. The message is\n' +
      '  confidential but NOT sender-authenticated; sign it separately if origin matters.',
  );
  out.json ? out.data({ jwe }) : out.print(jwe);
}

export async function cmdDecrypt(args: ParsedArgs, store: Store, out: Output): Promise<void> {
  const meta = store.resolveMeta(optionalOption(args, 'did'));
  const keyLabel = requireOption(args, 'key');
  const jwe = optionalOption(args, 'jwe') ?? new TextDecoder().decode(await readMessage(args, 'jwe'));

  const plaintext = await decrypt({ jwe, provider: store.keyProvider(meta.scid), keyLabel });
  const text = new TextDecoder().decode(plaintext);

  out.json ? out.data({ plaintext: text }) : out.print(text);
}
