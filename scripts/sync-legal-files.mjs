/**
 * Copy the root LICENSE and NOTICE into every publishable package.
 *
 * Apache-2.0 requires each distributed artefact to carry the licence and the
 * attribution notice, and npm only includes files that sit inside the package
 * directory, so a root-only LICENSE would publish six packages that claim
 * Apache-2.0 in their manifest and ship no licence text at all. The copies are
 * generated and gitignored so the root files stay the single source of truth.
 */

import { copyFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

const root = join(import.meta.dirname, '..');
const packages = join(root, 'packages');

for (const name of readdirSync(packages)) {
  const dir = join(packages, name);
  if (!statSync(dir).isDirectory()) continue;
  for (const file of ['LICENSE', 'NOTICE']) {
    copyFileSync(join(root, file), join(dir, file));
  }
  console.log(`legal files -> packages/${name}`);
}
