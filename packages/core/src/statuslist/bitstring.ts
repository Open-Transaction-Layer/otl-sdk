/**
 * W3C Bitstring Status List bitstrings (OTL spec 5.2).
 *
 * A status list is one long row of bits, one per issued credential. A verifier
 * fetches the whole list and reads a single index, so the issuer never learns
 * which credential was being checked — the privacy property that motivates the
 * design over a simple list of revoked identifiers.
 *
 * Bit order is most-significant-first within each byte: index 0 is the top bit
 * of byte 0, index 7 the bottom bit of byte 0, index 8 the top bit of byte 1.
 * Getting this backwards yields a list that decodes cleanly and reports the
 * wrong credential as revoked.
 */

import { gunzipSync, gzipSync } from 'node:zlib';
import { fromMultibaseBase64url, toMultibaseBase64url } from '@otl/keys';
import { InvalidDocumentError } from '../errors.ts';

/**
 * Minimum list length required by OTL spec 5.2: "Minimum 131,072 entries."
 *
 * The floor exists for privacy, not capacity — a short list would narrow the
 * anonymity set a given index sits in.
 */
export const MINIMUM_ENTRIES = 131_072;

/**
 * Ceiling on a decoded list, 64x the spec's floor.
 *
 * The spec sets a minimum and no maximum, so a correctly formed GZIP payload of
 * a few kilobytes can decompress to gigabytes of zeroes — a list is almost
 * entirely zero, which is the best case for the compressor. The HTTP layer caps
 * the *compressed* response, which does not bound this at all. Enforced as a
 * decompression limit rather than a post-hoc length check, so the memory is
 * never allocated (threat analysis T-REV-01).
 */
export const MAXIMUM_ENTRIES = MINIMUM_ENTRIES * 64;
const MAXIMUM_LIST_BYTES = MAXIMUM_ENTRIES / 8;

/** Offset of the advisory OS byte in a GZIP header (RFC 1952 section 2.3). */
const GZIP_OS_BYTE_OFFSET = 9;
/** RFC 1952 OS code 3: Unix. */
const GZIP_OS_UNIX = 0x03;

export class Bitstring {
  readonly #bytes: Uint8Array;

  private constructor(bytes: Uint8Array) {
    this.#bytes = bytes;
  }

  /** A fresh all-zero (nothing revoked) list. */
  static create(entries: number = MINIMUM_ENTRIES): Bitstring {
    if (!Number.isInteger(entries) || entries < MINIMUM_ENTRIES) {
      throw new InvalidDocumentError(
        `A status list must hold at least ${MINIMUM_ENTRIES} entries (spec 5.2), got ${entries}`,
      );
    }
    if (entries % 8 !== 0) {
      throw new InvalidDocumentError(`Entry count must be a multiple of 8, got ${entries}`);
    }
    return new Bitstring(new Uint8Array(entries / 8));
  }

  /** Number of entries this list can hold. */
  get length(): number {
    return this.#bytes.length * 8;
  }

  get(index: number): boolean {
    this.#assertInRange(index);
    return ((this.#byteAt(index >>> 3) >>> (7 - (index & 7))) & 1) === 1;
  }

  set(index: number, value: boolean): void {
    this.#assertInRange(index);
    const byte = index >>> 3;
    const mask = 1 << (7 - (index & 7));
    const current = this.#byteAt(byte);
    this.#bytes[byte] = value ? current | mask : current & ~mask;
  }

  /** Indices currently set. Cheap enough in practice: revocation is sparse. */
  setIndices(): number[] {
    const indices: number[] = [];
    for (let byte = 0; byte < this.#bytes.length; byte++) {
      if (this.#bytes[byte] === 0) continue; // skip the overwhelmingly common case
      for (let bit = 0; bit < 8; bit++) {
        const index = byte * 8 + bit;
        if (this.get(index)) indices.push(index);
      }
    }
    return indices;
  }

  /** GZIP, then multibase base64url with the `u` prefix (spec 5.2). */
  encode(): string {
    const compressed = gzipSync(this.#bytes, { level: 9 });

    // Normalize the GZIP header's advisory OS byte. Node derives it from the
    // build platform, so the identical list would otherwise encode differently
    // on macOS and Linux — meaning a republished-but-unchanged status list
    // would appear to have changed. MTIME is already zero.
    //
    // Only metadata is touched; the deflate stream is untouched and any
    // decompressor ignores this byte. Byte-for-byte equality with another
    // implementation's output is not required by the spec (verifiers compare
    // the decoded bitstring, not the encoding), but reproducibility of our own
    // output across platforms is worth having.
    compressed[GZIP_OS_BYTE_OFFSET] = GZIP_OS_UNIX;

    return toMultibaseBase64url(new Uint8Array(compressed));
  }

  /** Inverse of {@link encode}: strip `u`, base64url-decode, GZIP-decompress. */
  static decode(encodedList: string): Bitstring {
    let compressed: Uint8Array;
    try {
      compressed = fromMultibaseBase64url(encodedList);
    } catch (cause) {
      throw new InvalidDocumentError(`encodedList is not multibase base64url (expected a leading "u")`, {
        cause,
      });
    }

    let bytes: Uint8Array;
    try {
      bytes = new Uint8Array(gunzipSync(compressed, { maxOutputLength: MAXIMUM_LIST_BYTES }));
    } catch (cause) {
      // Node reports the limit as ERR_BUFFER_TOO_LARGE; say which it was, since
      // "not valid GZIP" would send an operator looking for the wrong fault.
      if ((cause as { code?: string } | undefined)?.code === 'ERR_BUFFER_TOO_LARGE') {
        throw new InvalidDocumentError(
          `encodedList decompresses past the ${MAXIMUM_ENTRIES}-entry maximum this implementation accepts`,
          { cause },
        );
      }
      throw new InvalidDocumentError('encodedList is not valid GZIP data', { cause });
    }

    if (bytes.length * 8 < MINIMUM_ENTRIES) {
      throw new InvalidDocumentError(
        `Status list holds ${bytes.length * 8} entries; spec 5.2 requires at least ${MINIMUM_ENTRIES}`,
      );
    }
    return new Bitstring(bytes);
  }

  /**
   * The byte at `offset`. Callers have already range-checked the index, so a
   * missing byte cannot happen; if it ever did, throwing is the safe outcome
   * because reading it as 0 would report a revoked credential as not revoked.
   */
  #byteAt(offset: number): number {
    const byte = this.#bytes[offset];
    if (byte === undefined) throw new InvalidDocumentError(`Status list byte ${offset} is out of range`);
    return byte;
  }

  #assertInRange(index: number): void {
    if (!Number.isInteger(index) || index < 0 || index >= this.length) {
      throw new InvalidDocumentError(`Status list index ${index} is out of range (0..${this.length - 1})`);
    }
  }
}
