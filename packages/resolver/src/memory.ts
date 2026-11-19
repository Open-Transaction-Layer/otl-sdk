/**
 * Which version of each DID's log we have already validated (threat T-RES-02).
 *
 * A log that was valid when we saw it stays validly signed forever, so a
 * truncated or forked copy of it is also internally consistent. Nothing inside
 * a log can reveal that it is older than one we have seen, so rejecting a
 * rollback needs memory across resolutions. Injected rather than owned here,
 * for the same reason `StatusListMemory` is: this package should not own
 * storage. The default is per-process; a long-lived verifier should persist it.
 *
 * ## What an implementer provides
 *
 * Only this interface. The SDK looks the head up, checks the fetched log
 * against it, and records the new head itself, and only after the log has
 * validated. Callers never pass a head explicitly, and never need to decide
 * when to record one.
 *
 *  - `lastAccepted` returns the highest head recorded for the SCID.
 *  - `record` MUST NOT replace a head with a lower `versionNumber`. When the
 *    `versionNumber` is equal, keep the existing record. Both rules make
 *    concurrent verifications safe without further coordination.
 *  - Both MAY throw. A failure is propagated and the resolution fails: being
 *    unable to check for a rollback must not become "no rollback".
 *  - Dropping a record (eviction, a lost file) only loses protection for that
 *    DID until it is seen again. It never causes a false failure.
 */

import type { KnownDidHead } from '@otl/core';

export interface DidHeadMemory {
  /** Newest validated head for this SCID, if any. */
  lastAccepted(scid: string): Promise<KnownDidHead | undefined>;
  /** Called only with a head from a log that validated. Monotonic, see above. */
  record(head: KnownDidHead): Promise<void>;
}

export class InMemoryDidHeadMemory implements DidHeadMemory {
  readonly #heads = new Map<string, KnownDidHead>();

  lastAccepted(scid: string): Promise<KnownDidHead | undefined> {
    return Promise.resolve(this.#heads.get(scid));
  }

  record(head: KnownDidHead): Promise<void> {
    const previous = this.#heads.get(head.scid);
    if (previous === undefined || head.versionNumber > previous.versionNumber) {
      this.#heads.set(head.scid, head);
    }
    return Promise.resolve();
  }
}
