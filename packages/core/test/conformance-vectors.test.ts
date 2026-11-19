/**
 * Conformance against the official did:webvh test suite vectors.
 *
 * These are signed DID logs produced by six independent implementations —
 * dart, java, java-eecc, python, rust, ts — across 13 positive and 17 negative
 * scenarios, vendored under `test/vectors/` (see PROVENANCE.md).
 *
 * Tests written alongside this package can only check that it agrees with
 * itself, and the single-library oracle in `interop.test.ts` is lenient. This
 * corpus is neither: it was built by the working group specifically to surface
 * disagreement between implementations, and every log in it was signed by
 * another implementation's code. Among the rules it pins are that a
 * deactivation entry may carry `updateKeys: []`, that a portable DID may move
 * domain while keeping its SCID, and that a log declaring a witness
 * requirement is refused as unverifiable rather than accepted.
 *
 * Run in base did:webvh mode: OTL's own stricter rules (permanent
 * pre-rotation) would reject perfectly valid did:webvh logs, and this suite
 * tests conformance to the method, not to OTL's profile of it.
 */

import assert from 'node:assert/strict';
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { parseDidLog, validateDidLog } from '../src/index.ts';

const VECTORS = join(import.meta.dirname, 'vectors', 'didwebvh-test-suite');

interface Scenario {
  readonly name: string;
  readonly negative: boolean;
  readonly implementations: readonly string[];
}

function loadScenarios(): Scenario[] {
  return readdirSync(VECTORS)
    .filter((name) => {
      const dir = join(VECTORS, name);
      return statSync(dir).isDirectory() && existsSync(join(dir, 'script.yaml'));
    })
    .sort()
    .map((name) => {
      const dir = join(VECTORS, name);
      return {
        name,
        // The suite marks negatives in the scenario script itself.
        negative: /^negative:\s*true/m.test(readFileSync(join(dir, 'script.yaml'), 'utf8')),
        implementations: readdirSync(dir)
          .filter((impl) => existsSync(join(dir, impl, 'did.jsonl')))
          .sort(),
      };
    });
}

const scenarios = loadScenarios();

async function check(scenario: string, impl: string) {
  const log = readFileSync(join(VECTORS, scenario, impl, 'did.jsonl'), 'utf8');
  // Base did:webvh mode — see the module comment.
  return validateDidLog(parseDidLog(log), { requirePreRotation: false });
}

describe('conformance vectors - the corpus is actually present', () => {
  it('loads scenarios from every implementation', () => {
    // Guards against the whole suite silently passing because the vectors
    // moved or were never vendored.
    assert.ok(scenarios.length >= 30, `expected 30+ scenarios, found ${scenarios.length}`);
    assert.ok(
      scenarios.some((s) => s.negative),
      'expected negative scenarios',
    );
    assert.ok(
      scenarios.some((s) => !s.negative),
      'expected positive scenarios',
    );

    const logs = scenarios.reduce((n, s) => n + s.implementations.length, 0);
    assert.ok(logs >= 90, `expected 90+ signed logs, found ${logs}`);

    const impls = new Set(scenarios.flatMap((s) => s.implementations));
    assert.ok(impls.size >= 5, `expected 5+ implementations, found ${[...impls].join(', ')}`);
  });
});

describe('conformance vectors - positive scenarios validate', () => {
  for (const scenario of scenarios.filter((s) => !s.negative)) {
    for (const impl of scenario.implementations) {
      it(`${scenario.name} / ${impl}`, async () => {
        const result = await check(scenario.name, impl);

        // Witnessed logs are refused deliberately: we do not verify witness
        // thresholds, and accepting them would fail open. The refusal must be
        // declared as unverifiable rather than presented as invalid.
        if (result.unverifiable) {
          assert.ok(
            result.issues.every((i) => i.unsupported),
            'an unverifiable result must carry only unsupported-feature issues',
          );
          return;
        }

        assert.equal(
          result.valid,
          true,
          `a valid log from ${impl} was rejected: ${result.issues.map((i) => i.message).join('; ')}`,
        );
      });
    }
  }
});

describe('conformance vectors - negative scenarios are rejected', () => {
  for (const scenario of scenarios.filter((s) => s.negative)) {
    for (const impl of scenario.implementations) {
      it(`${scenario.name} / ${impl}`, async () => {
        const result = await check(scenario.name, impl);
        assert.equal(
          result.valid,
          false,
          `a log the suite marks invalid was accepted — ${scenario.name} is testing a rule we do not enforce`,
        );
      });
    }
  }
});
