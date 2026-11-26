/**
 * The bundled OTL Identity JSON-LD context, and a document loader that
 * serves it from disk.
 *
 * VC 2.0 is a JSON-LD data model and a conforming consumer drops every term
 * its `@context` does not define, so a verifier that cannot resolve the OTL
 * context sees an `OtlLeiCredential` reduced to a bare subject identifier
 * with all 14 of its claims silently gone. The signature still verifies in
 * that state, because `eddsa-jcs-2022` canonicalizes the raw JSON rather
 * than the expanded form, which is what makes the failure invisible.
 *
 * The context is therefore shipped inside this package and resolved from
 * disk rather than fetched. Fetching it would make verification fail
 * whenever the host is unreachable, and it would disclose to whoever hosts
 * the context which credentials a verifier is processing and when.
 *
 * This loader deliberately does not carry the W3C contexts. Those are
 * someone else's documents to redistribute, and the ecosystem already
 * packages them; supply them through {@link BundledLoaderOptions.fallback}.
 */

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { OTL_IDENTITY_CONTEXT } from './context-url.ts';

export { OTL_IDENTITY_CONTEXT };

/** A JSON-LD document loader, matching the shape `jsonld` expects. */
export interface LoadedDocument {
  readonly contextUrl: string | null;
  readonly documentUrl: string;
  readonly document: unknown;
}

export type DocumentLoader = (url: string) => Promise<LoadedDocument>;

export interface BundledLoaderOptions {
  /**
   * Consulted for any URL this package does not bundle, which in practice
   * means the W3C contexts. Omit it and an unknown URL throws rather than
   * reaching the network, which is the safer default for a verifier.
   */
  readonly fallback?: DocumentLoader;
}

/** The parsed OTL Identity context, v1. */
export const otlIdentityContextV1 = (): Record<string, unknown> =>
  JSON.parse(
    readFileSync(join(import.meta.dirname, '..', 'contexts', 'otl-identity-v1.jsonld'), 'utf8'),
  ) as Record<string, unknown>;

/**
 * A document loader serving the bundled OTL context offline.
 *
 * @example
 * ```ts
 * import { bundledDocumentLoader } from '@open-transaction-layer/credentials/context';
 * const documentLoader = bundledDocumentLoader();
 * await jsonld.expand(credential, { documentLoader });
 * ```
 */
export const bundledDocumentLoader = (options: BundledLoaderOptions = {}): DocumentLoader => {
  const bundled = new Map<string, unknown>([[OTL_IDENTITY_CONTEXT, otlIdentityContextV1()]]);

  return async (url: string): Promise<LoadedDocument> => {
    const document = bundled.get(url);
    if (document !== undefined) return { contextUrl: null, documentUrl: url, document };
    if (options.fallback) return options.fallback(url);
    throw new Error(
      `No bundled JSON-LD context for ${url}. ` +
        'Pass a fallback loader for contexts this package does not ship, such as the W3C ones. ' +
        'Verification deliberately does not reach the network on its own.',
    );
  };
};
