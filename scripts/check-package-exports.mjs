/**
 * Check that the packed packages work for a consumer.
 *
 * Each tarball in the given directory is unpacked into a scratch node_modules
 * folder, which is what an installed copy looks like. Every file that the
 * exports map, main, types and bin fields point at must exist, a condition map
 * must list `types` before `default` so TypeScript finds the declarations, and
 * every JavaScript entry point must import under plain Node resolution without
 * the `otl-source` condition that the workspace uses to run from TypeScript.
 * That catches a package that passes its own tests from source and still fails
 * for the first user who installs it.
 */

import { execFileSync } from 'node:child_process';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';

const packs = process.argv[2];
if (!packs) {
  console.error('usage: node scripts/check-package-exports.mjs <directory of tarballs>');
  process.exit(2);
}

// The workspace condition points at TypeScript sources, which tarballs never contain.
const SOURCE_CONDITION = 'otl-source';

const work = mkdtempSync(join(tmpdir(), 'otl-exports-'));
const failures = [];
const fail = (message) => failures.push(message);

/** Every file target in an exports value, with the condition names that lead to it. */
function collectTargets(value, conditions, out) {
  if (typeof value === 'string') {
    out.push({ target: value, conditions });
  } else if (Array.isArray(value)) {
    for (const item of value) collectTargets(item, conditions, out);
  } else if (value && typeof value === 'object') {
    for (const [condition, next] of Object.entries(value)) {
      if (condition !== SOURCE_CONDITION) collectTargets(next, [...conditions, condition], out);
    }
  }
  return out;
}

function checkTarget(name, where, target, dir) {
  if (!target.startsWith('./') || target.split('/').includes('..')) {
    fail(`${name}: ${where} points at ${target}, which is not a path inside the package`);
  } else if (!existsSync(join(dir, target))) {
    fail(`${name}: ${where} points at ${target}, which the tarball does not contain`);
  }
}

try {
  const modules = join(work, 'node_modules');
  const specifiers = [];

  for (const file of readdirSync(packs).filter((entry) => entry.endsWith('.tgz'))) {
    const unpacked = mkdtempSync(join(work, 'unpack-'));
    execFileSync('tar', ['-xzf', join(packs, file), '-C', unpacked]);
    const dir = join(unpacked, 'package');
    const manifest = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8'));
    const name = manifest.name;
    mkdirSync(dirname(join(modules, name)), { recursive: true });
    renameSync(dir, join(modules, name));
    const installed = join(modules, name);

    for (const field of ['main', 'types']) {
      if (manifest[field]) checkTarget(name, field, manifest[field], installed);
    }

    for (const [command, target] of Object.entries(manifest.bin ?? {})) {
      checkTarget(name, `bin ${command}`, target, installed);
      if (
        existsSync(join(installed, target)) &&
        !readFileSync(join(installed, target), 'utf8').startsWith('#!')
      ) {
        fail(`${name}: bin ${command} has no shebang line`);
      }
    }

    if (!manifest.exports || typeof manifest.exports !== 'object') {
      fail(`${name}: has no exports map`);
      continue;
    }

    for (const [subpath, value] of Object.entries(manifest.exports)) {
      const where = `exports ${subpath}`;
      if (value && typeof value === 'object' && !Array.isArray(value)) {
        const keys = Object.keys(value).filter((key) => key !== SOURCE_CONDITION);
        if (
          keys.includes('types') &&
          keys.includes('default') &&
          keys.indexOf('types') > keys.indexOf('default')
        ) {
          fail(`${name}: ${where} lists default before types, so TypeScript never reaches the declarations`);
        }
      }
      let importable = false;
      for (const { target, conditions } of collectTargets(value, [], [])) {
        checkTarget(name, where, target, installed);
        if (conditions.includes('types') && !target.endsWith('.d.ts')) {
          fail(`${name}: ${where} types target ${target} is not a declaration file`);
        }
        if (!conditions.includes('types') && /\.(?:js|mjs|cjs)$/.test(target)) importable = true;
      }
      if (importable) specifiers.push(subpath === '.' ? name : `${name}/${subpath.slice(2)}`);
    }
  }

  if (specifiers.length === 0) fail('no importable entry point found in any tarball');

  writeFileSync(
    join(work, 'smoke.mjs'),
    `const specifiers = ${JSON.stringify(specifiers)};
let failed = 0;
for (const specifier of specifiers) {
  try {
    await import(specifier);
    console.log('imported ' + specifier);
  } catch (error) {
    failed += 1;
    console.error('cannot import ' + specifier + ': ' + (error && error.message));
  }
}
process.exit(failed === 0 ? 0 : 1);
`,
  );
  try {
    execFileSync(process.execPath, ['smoke.mjs'], { cwd: work, stdio: 'inherit' });
  } catch {
    fail('at least one entry point failed to import from the unpacked tarballs');
  }
} finally {
  rmSync(work, { recursive: true, force: true });
}

if (failures.length > 0) {
  for (const message of failures) console.error(`::error::${message}`);
  process.exit(1);
}
console.log('every package entry point resolves and imports from its tarball');
