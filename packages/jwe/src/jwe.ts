/**
 * Message encryption for the OTL Identity layer.
 *
 * ## Status: PROVISIONAL — this envelope is not in the spec
 *
 * OTL spec 3.1.1 specifies key-agreement *key types* (X25519 via RFC 8037,
 * P-256 via RFC 7518) but says nothing about the envelope: no key-derivation
 * function, no content-encryption algorithm, no wire format. Two fully
 * conformant implementations therefore cannot exchange an encrypted message.
 *
 * This module implements JWE Compact Serialization with ECDH-ES and A256GCM,
 * which covers both curves using only existing standards (RFC 7516, 7518,
 * 8037) and introduces no new machinery. It is a proposal, not a
 * specification, and the format may change if the specification defines an
 * envelope. Interoperability with another implementation should not be
 * expected unless the spec defines the envelope.
 *
 * ## What ECDH-ES does and does not give you
 *
 * The sender uses a fresh ephemeral keypair, so the message is confidential to
 * the recipient — but it is **not authenticated**. Anyone who knows the
 * recipient's published keyAgreement key can produce a valid ciphertext.
 * Sender authentication requires a separate signature over the plaintext
 * (`signRaw` from `@open-transaction-layer/core`), which the caller must add if it is needed.
 */

import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';
import {
  agreeEphemeral,
  toPublicKeyJwk,
  fromPublicKeyJwk,
  type KeyProvider,
  type PublicKey,
} from '@open-transaction-layer/keys';
import { supportsKeyAgreement } from '@open-transaction-layer/keys';
import { EncryptionError } from './errors.ts';

/** Key-agreement algorithm. Direct derivation: no wrapped content key. */
export const JWE_ALG = 'ECDH-ES';
/** Content encryption: AES-256-GCM. */
export const JWE_ENC = 'A256GCM';

const CEK_BYTES = 32;
const GCM_IV_BYTES = 12;
const GCM_TAG_BYTES = 16;

const b64u = (bytes: Uint8Array): string => Buffer.from(bytes).toString('base64url');
const unb64u = (text: string): Uint8Array => new Uint8Array(Buffer.from(text, 'base64url'));

interface JweHeader {
  readonly alg: string;
  readonly enc: string;
  readonly epk?: Record<string, string>;
  readonly apu?: string;
  readonly apv?: string;
  readonly kid?: string;
}

/**
 * Concat KDF (NIST SP 800-56A, as profiled by RFC 7518 §4.6.2).
 *
 * Exported so it can be tested in isolation: the length-prefixing property
 * below cannot be observed through {@link encrypt}/{@link decrypt}, because the
 * protected header is authenticated and a tampered header fails on the GCM tag
 * before the KDF is ever reached.
 *
 * One SHA-256 round suffices for the key sizes used here. The length-prefixed encoding of every component is what stops a
 * shift between adjacent fields producing the same input — so `apu`/`apv` are
 * bound to the derived key rather than merely accompanying it.
 */
export function concatKdf(
  sharedSecret: Uint8Array,
  algorithmId: string,
  partyUInfo: Uint8Array,
  partyVInfo: Uint8Array,
  keyBytes: number = CEK_BYTES,
): Uint8Array {
  const be32 = (value: number): Uint8Array => {
    const buffer = new Uint8Array(4);
    new DataView(buffer.buffer).setUint32(0, value, false);
    return buffer;
  };
  const lengthPrefixed = (bytes: Uint8Array): Uint8Array =>
    Uint8Array.from([...be32(bytes.length), ...bytes]);

  const input = Uint8Array.from([
    ...be32(1), // round counter
    ...sharedSecret,
    ...lengthPrefixed(new TextEncoder().encode(algorithmId)),
    ...lengthPrefixed(partyUInfo),
    ...lengthPrefixed(partyVInfo),
    ...be32(keyBytes * 8), // keydatalen in bits
    // SuppPrivInfo is empty and contributes nothing.
  ]);

  // One SHA-256 round covers keyBytes <= 32, which is every case here; the
  // parameter exists so the function can be checked against RFC 7518's
  // published 128-bit vector.
  return new Uint8Array(createHash('sha256').update(input).digest()).slice(0, keyBytes);
}

export interface EncryptOptions {
  readonly plaintext: Uint8Array | string;
  /** Recipient's published keyAgreement key. */
  readonly recipientPublicKey: PublicKey;
  /** Recipient key id, e.g. `did:webvh:{scid}:vasp.example.com#agreement-key`. */
  readonly recipientKeyId?: string;
  /** Sender identifier, bound into the derived key as `apu`. */
  readonly senderInfo?: string;
}

/** Encrypt to a recipient's key agreement key. Returns JWE Compact Serialization. */
export function encrypt(options: EncryptOptions): string {
  const { plaintext, recipientPublicKey, recipientKeyId, senderInfo } = options;

  const { ephemeralPublicKey, sharedSecret } = agreeEphemeral(recipientPublicKey);

  const partyUInfo = senderInfo === undefined ? new Uint8Array(0) : new TextEncoder().encode(senderInfo);
  const partyVInfo =
    recipientKeyId === undefined ? new Uint8Array(0) : new TextEncoder().encode(recipientKeyId);

  const header: JweHeader = {
    alg: JWE_ALG,
    enc: JWE_ENC,
    epk: toPublicKeyJwk(ephemeralPublicKey),
    ...(senderInfo !== undefined ? { apu: b64u(partyUInfo) } : {}),
    ...(recipientKeyId !== undefined ? { apv: b64u(partyVInfo), kid: recipientKeyId } : {}),
  };

  const contentKey = concatKdf(sharedSecret, JWE_ENC, partyUInfo, partyVInfo);
  const protectedHeader = b64u(new TextEncoder().encode(JSON.stringify(header)));

  const iv = randomBytes(GCM_IV_BYTES);
  const cipher = createCipheriv('aes-256-gcm', contentKey, iv);
  // The protected header is authenticated, so alg, enc and epk cannot be
  // rewritten without invalidating the tag.
  cipher.setAAD(Buffer.from(protectedHeader, 'ascii'));

  const body = typeof plaintext === 'string' ? new TextEncoder().encode(plaintext) : plaintext;
  const ciphertext = Buffer.concat([cipher.update(body), cipher.final()]);

  // ECDH-ES derives the content key directly, so the encrypted-key segment is
  // empty — five segments, the second of which is blank.
  return [
    protectedHeader,
    '',
    b64u(new Uint8Array(iv)),
    b64u(new Uint8Array(ciphertext)),
    b64u(new Uint8Array(cipher.getAuthTag())),
  ].join('.');
}

export interface DecryptOptions {
  readonly jwe: string;
  readonly provider: KeyProvider;
  /** Label of the recipient's keyAgreement key within the provider. */
  readonly keyLabel: string;
}

/** Decrypt a JWE Compact message with a key held by the provider. */
export async function decrypt(options: DecryptOptions): Promise<Uint8Array> {
  const { jwe, provider, keyLabel } = options;

  if (!supportsKeyAgreement(provider)) {
    throw new EncryptionError(
      `Provider "${provider.id}" cannot perform key agreement, so it cannot decrypt. ` +
        `Some backends have no ECDH primitive at all — Azure Key Vault, for one.`,
    );
  }

  const segments = jwe.split('.');
  if (segments.length !== 5) {
    throw new EncryptionError(
      `Not a JWE Compact Serialization: expected 5 dot-separated segments, got ${segments.length}`,
    );
  }
  const [protectedHeader, encryptedKey, ivSegment, ciphertextSegment, tagSegment] = segments as [
    string,
    string,
    string,
    string,
    string,
  ];

  if (encryptedKey !== '') {
    throw new EncryptionError(`Expected an empty encrypted-key segment for ${JWE_ALG} direct key agreement`);
  }

  let header: JweHeader;
  try {
    header = JSON.parse(new TextDecoder().decode(unb64u(protectedHeader))) as JweHeader;
  } catch (cause) {
    throw new EncryptionError('JWE protected header is not valid JSON', { cause });
  }

  // Checked before any cryptographic work: an unexpected algorithm is a
  // downgrade attempt, not something to try and see whether it happens to work.
  if (header.alg !== JWE_ALG) {
    throw new EncryptionError(`Unsupported JWE alg "${header.alg}"; expected "${JWE_ALG}"`);
  }
  if (header.enc !== JWE_ENC) {
    throw new EncryptionError(`Unsupported JWE enc "${header.enc}"; expected "${JWE_ENC}"`);
  }
  if (header.epk === undefined) {
    throw new EncryptionError('JWE header carries no ephemeral public key (epk)');
  }

  let ephemeralPublicKey: PublicKey;
  try {
    ephemeralPublicKey = fromPublicKeyJwk(header.epk);
  } catch (cause) {
    throw new EncryptionError('JWE header epk is not a valid public key', { cause });
  }

  for (const field of ['apu', 'apv'] as const) {
    if (header[field] !== undefined && typeof header[field] !== 'string') {
      throw new EncryptionError(`JWE header ${field} must be a base64url string`);
    }
  }

  const iv = unb64u(ivSegment);
  const tag = unb64u(tagSegment);
  if (iv.length !== GCM_IV_BYTES) {
    throw new EncryptionError(`JWE IV must be ${GCM_IV_BYTES} bytes, got ${iv.length}`);
  }
  if (tag.length !== GCM_TAG_BYTES) {
    throw new EncryptionError(`JWE authentication tag must be ${GCM_TAG_BYTES} bytes, got ${tag.length}`);
  }

  let sharedSecret: Uint8Array;
  try {
    sharedSecret = await provider.deriveSharedSecret(keyLabel, ephemeralPublicKey);
  } catch (cause) {
    throw new EncryptionError(`Key agreement with key "${keyLabel}" failed`, { cause });
  }
  const contentKey = concatKdf(
    sharedSecret,
    JWE_ENC,
    header.apu === undefined ? new Uint8Array(0) : unb64u(header.apu),
    header.apv === undefined ? new Uint8Array(0) : unb64u(header.apv),
  );

  try {
    const decipher = createDecipheriv('aes-256-gcm', contentKey, iv, { authTagLength: GCM_TAG_BYTES });
    decipher.setAAD(Buffer.from(protectedHeader, 'ascii'));
    decipher.setAuthTag(tag);
    return new Uint8Array(Buffer.concat([decipher.update(unb64u(ciphertextSegment)), decipher.final()]));
  } catch (cause) {
    // A GCM tag failure is indistinguishable between wrong key, wrong
    // recipient and tampering — and must stay that way, so the message says
    // nothing an attacker could use as an oracle.
    throw new EncryptionError(
      'Could not decrypt: the message was not encrypted to this key, or has been altered',
      { cause },
    );
  }
}

/** Convenience: decrypt and decode as UTF-8. */
export const decryptToString = async (options: DecryptOptions): Promise<string> =>
  new TextDecoder().decode(await decrypt(options));
