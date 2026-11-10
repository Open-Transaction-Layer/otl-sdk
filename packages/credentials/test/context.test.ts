/**
 * The packaging contract for the JSON-LD context.
 *
 * jsonld.test.ts in @otl/core proves the context defines the right terms.
 * What this file proves is narrower and is about distribution: that a
 * consumer who installs @otl/credentials and nothing else can resolve the
 * context offline. Before the context moved inside this package it lived at
 * the repository root, outside every published artefact, so an installed
 * copy shipped no context at all and expansion silently dropped the payload.
 */

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import jsonld from 'jsonld';
import { OTL_IDENTITY_CONTEXT } from '@otl/core';
import { bundledDocumentLoader, otlIdentityContextV1 } from '../src/context.ts';

describe('bundled JSON-LD context', () => {
  it('ships the context as a package asset', () => {
    const context = otlIdentityContextV1()['@context'] as Record<string, unknown>;
    assert.equal(context['@protected'], true, '@protected is required by W3C registry policy');
    assert.ok(context['OtlLeiCredential'] !== undefined, 'the credential type must be defined');
    assert.ok(
      context['lei'] !== undefined,
      'terms must be defined at the top level, not scoped under the type',
    );
  });

  it('resolves the OTL context without touching the network', async () => {
    const loaded = await bundledDocumentLoader()(OTL_IDENTITY_CONTEXT);
    assert.equal(loaded.documentUrl, OTL_IDENTITY_CONTEXT);
    assert.ok((loaded.document as Record<string, unknown>)['@context'] !== undefined);
  });

  it('refuses an unbundled URL rather than silently fetching it', async () => {
    await assert.rejects(
      () => bundledDocumentLoader()('https://www.w3.org/ns/credentials/v2'),
      /No bundled JSON-LD context/,
    );
  });

  it('delegates an unbundled URL to a supplied fallback', async () => {
    const loader = bundledDocumentLoader({
      fallback: async (url) => ({ contextUrl: null, documentUrl: url, document: { marker: 1 } }),
    });
    const loaded = await loader('https://example.org/other');
    assert.deepEqual(loaded.document, { marker: 1 });
  });

  it('expands OTL terms through the packaged loader', async () => {
    const documentLoader = bundledDocumentLoader();
    // `@type` rather than `type` on purpose: the `type` alias is defined by
    // the W3C credentials context, which this loader does not bundle, so a
    // document relying on it would be testing the fallback instead of us.
    const expanded = await jsonld.expand(
      {
        '@context': [OTL_IDENTITY_CONTEXT],
        '@type': ['OtlLeiCredential'],
        lei: '00000000000000000098',
      },
      { documentLoader },
    );
    const node = expanded[0] as Record<string, unknown>;
    assert.deepEqual(node['@type'], ['https://otl.network/ns/identity#OtlLeiCredential']);
    assert.ok(
      Object.hasOwn(node, 'https://otl.network/ns/identity#lei'),
      'lei must survive expansion rather than being dropped as an undefined term',
    );
  });
});
