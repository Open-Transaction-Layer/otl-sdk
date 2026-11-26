/**
 * The two shipped providers are the conformance kit's first consumers.
 * If the kit is wrong, these fail; if a provider is wrong, these fail.
 */

import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runKeyProviderConformance } from '@open-transaction-layer/keys/conformance';
import { FileKeyProvider } from '../src/file.ts';
import { InMemoryKeyProvider } from '../src/in-memory.ts';

runKeyProviderConformance('InMemoryKeyProvider', () => new InMemoryKeyProvider());

runKeyProviderConformance(
  'FileKeyProvider',
  () =>
    new FileKeyProvider({
      directory: mkdtempSync(join(tmpdir(), 'otl-keys-conformance-')),
      passphrase: 'correct horse battery staple',
    }),
);
