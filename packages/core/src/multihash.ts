/**
 * Multihash + base58btc, as did:webvh uses them for SCIDs, entry hashes and
 * pre-rotation key commitments.
 *
 * Note the encoding is **plain base58btc, not multibase** — there is no `z`
 * prefix. A did:webvh SCID is 46 base58btc characters, which is exactly a
 * 34-byte SHA-256 multihash (2 prefix bytes + 32 digest bytes) encoded. This
 * differs from `publicKeyMultibase` in a DID document, which *is* multibase and
 * does carry the `z`. Mixing the two up produces values that look plausible and
 * verify nowhere.
 */

import { createHash } from 'node:crypto';
import { base58btcEncode } from '@otl/keys';

/** Multihash prefix for sha2-256: code 0x12, digest length 0x20. */
const SHA2_256_MULTIHASH_PREFIX = Uint8Array.from([0x12, 0x20]);

/**
 * SHA-256 multihash of `bytes`.
 *
 * did:webvh 1.0 permits SHA-256 and nothing else: "Permitted hash algorithms:
 * SHA-256 (multihash code 0x12) only. Any other algorithm MUST cause resolution
 * to terminate." So there is deliberately no algorithm parameter here.
 */
export function multihashSha256(bytes: Uint8Array): Uint8Array {
  const digest = createHash('sha256').update(bytes).digest();
  return Uint8Array.from([...SHA2_256_MULTIHASH_PREFIX, ...digest]);
}

/** `base58btc(multihash(bytes, sha2-256))` — the did:webvh hash primitive. */
export const hashToBase58 = (bytes: Uint8Array): string => base58btcEncode(multihashSha256(bytes));

/** Same, over the UTF-8 encoding of a string. */
export const hashStringToBase58 = (text: string): string => hashToBase58(new TextEncoder().encode(text));
