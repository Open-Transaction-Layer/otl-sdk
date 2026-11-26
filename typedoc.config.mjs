/**
 * API reference configuration.
 *
 * The entry points are read from each package's `exports` map, from the
 * `otl-source` condition that points at the TypeScript source, so a new export
 * appears in the reference without editing this file.
 */

import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

const packages = join(import.meta.dirname, 'packages');
const entryPoints = [];

for (const name of readdirSync(packages).sort()) {
  const manifest = JSON.parse(readFileSync(join(packages, name, 'package.json'), 'utf8'));
  for (const target of Object.values(manifest.exports ?? {})) {
    const source = typeof target === 'object' && target !== null ? target['otl-source'] : undefined;
    if (typeof source === 'string') entryPoints.push(join('packages', name, source));
  }
}

export default {
  entryPoints,
  entryPointStrategy: 'resolve',
  tsconfig: 'tsconfig.typedoc.json',
  out: 'api-docs',
  name: 'OTL SDK',
  readme: 'none',
  excludePrivate: true,
  excludeInternal: true,
  gitRevision: 'main',
  treatWarningsAsErrors: true,
};
