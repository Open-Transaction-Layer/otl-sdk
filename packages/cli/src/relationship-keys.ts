/**
 * Choosing a local key by verification relationship (OTL spec 3.3).
 *
 * A key's purpose is declared only by the relationships that reference it in
 * the current DID document, never by its fragment. So the CLI picks the key to
 * sign with from the relationship, not from a fixed name.
 */

import type { DidDocument } from '@otl/core';
import { CliError } from './errors.ts';
import type { DidMeta, Store } from './store.ts';

export type Relationship = 'assertionMethod' | 'authentication' | 'keyAgreement';

/** Fragments (without `#`) the document references under `relationship`, in document order. */
export function fragmentsUnder(document: DidDocument, relationship: Relationship): string[] {
  const entries = (document as Record<string, unknown>)[relationship];
  if (!Array.isArray(entries)) return [];
  const prefix = `${document.id}#`;
  return entries
    .map((entry: unknown) => (typeof entry === 'string' ? entry : (entry as { id?: unknown } | null)?.id))
    .filter((id): id is string => typeof id === 'string' && id.startsWith(prefix))
    .map((id) => id.slice(prefix.length));
}

export interface ChooseKeyOptions {
  /** A fragment the user asked for; it must be referenced under the relationship. */
  readonly requested?: string;
  /** A fragment to use when it is referenced and held, before any other. */
  readonly preferred?: string;
  /** Shown when the DID has no usable key. */
  readonly hint: string;
}

/**
 * The fragment of a key the current document references under `relationship`
 * and whose private half this store holds.
 *
 * Without a request or a usable preference, the last such key wins: keys are
 * appended as they are added, so during a rotation overlap (spec 3.2.1) this
 * is the new key.
 */
export async function chooseKey(
  store: Store,
  meta: DidMeta,
  relationship: Relationship,
  options: ChooseKeyOptions,
): Promise<{ readonly fragment: string; readonly keyLabel: string }> {
  const current = store.readLog(meta.scid).at(-1);
  if (current === undefined) throw new CliError(`${meta.did} has no log entries`);
  const listed = fragmentsUnder(current.state, relationship);

  const labelOf = (fragment: string) => meta.keyLabels[fragment] ?? fragment;
  const provider = store.keyProvider(meta.scid);
  const held = async (fragment: string) =>
    provider.getKey(labelOf(fragment)).then(
      () => true,
      () => false,
    );

  if (options.requested !== undefined) {
    const fragment = options.requested.replace(/^#/, '');
    if (!listed.includes(fragment)) {
      throw new CliError(`#${fragment} is not listed under ${relationship} in ${meta.did}'s document`, {
        hint: 'A key may be used only for what its verification relationships declare (spec 3.3).',
      });
    }
    if (!(await held(fragment))) {
      throw new CliError(`This store does not hold the private key for #${fragment}`);
    }
    return { fragment, keyLabel: labelOf(fragment) };
  }

  const { preferred } = options;
  if (preferred !== undefined && listed.includes(preferred) && (await held(preferred))) {
    return { fragment: preferred, keyLabel: labelOf(preferred) };
  }

  for (const fragment of [...listed].reverse()) {
    if (await held(fragment)) return { fragment, keyLabel: labelOf(fragment) };
  }
  throw new CliError(`${meta.did} has no key under ${relationship} that this store holds`, {
    hint: options.hint,
  });
}
