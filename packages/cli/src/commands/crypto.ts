/**
 * Signing, verification and encryption commands.
 */

import { signRaw, verifyRaw } from '@open-transaction-layer/core';
import { decrypt, encrypt } from '@open-transaction-layer/jwe';
import { resolveVerificationKey } from '@open-transaction-layer/resolver';
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
  const keyLabel = requireOption(args, 'key', 'The key label, e.g. --key assertion-key');
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

export async function cmdEncrypt(args: ParsedArgs, _store: Store, out: Output): Promise<void> {
  const did = requireOption(args, 'did', 'The recipient DID');
  const keyLabel = requireOption(args, 'key', 'The recipient keyAgreement key fragment');
  const message = await readMessage(args);

  // Only a key the recipient designated for key agreement may receive.
  const recipientPublicKey = await resolveVerificationKey(did, keyLabel, {
    ...fetchOptionsFrom(args),
    relationship: 'keyAgreement',
  });

  const sender = optionalOption(args, 'sender');
  const jwe = encrypt({
    plaintext: message,
    recipientPublicKey,
    recipientKeyId: `${did}#${keyLabel.replace(/^#/, '')}`,
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
