// @ts-check
import eslint from '@eslint/js';
import globals from 'globals';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  {
    // Vendored third-party conformance fixtures are never linted or formatted.
    ignores: ['**/dist/', '**/node_modules/', 'packages/core/test/vectors/'],
  },

  eslint.configs.recommended,

  {
    files: ['**/*.ts'],
    extends: [tseslint.configs.strictTypeChecked],
    languageOptions: {
      parserOptions: {
        // Type information comes from the root tsconfig.json, which covers every
        // package's src/ and test/. It inherits `customConditions: ["otl-source"]`
        // from tsconfig.base.json, so workspace imports such as `@open-transaction-layer/keys`
        // resolve to their TypeScript source here exactly as they do under
        // `tsc` and `node --conditions=otl-source`, with no build step needed.
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      // --- Promises -------------------------------------------------------
      // A dropped `await` on a verification call fails open: the unresolved
      // promise is truthy and the caller proceeds as if the proof were valid.
      // These are already part of strictTypeChecked; they are repeated here so
      // that the security reason for them is recorded and a preset change
      // cannot silently drop them.
      '@typescript-eslint/no-floating-promises': [
        'error',
        {
          ignoreVoid: false,
          // node:test registers a test and returns a promise that the runner
          // itself awaits, so `describe(...)` and `it(...)` are not dropped
          // promises. `test(...)` and `t.test(...)` (subtests) are deliberately
          // NOT listed: a subtest does have to be awaited, and this repo does
          // not use the bare `test` form.
          allowForKnownSafeCalls: [{ from: 'package', package: 'node:test', name: ['describe', 'it'] }],
        },
      ],
      '@typescript-eslint/no-misused-promises': 'error',
      '@typescript-eslint/await-thenable': 'error',
      '@typescript-eslint/require-await': 'error',
      '@typescript-eslint/return-await': ['error', 'error-handling-correctness-only'],

      // --- Truthiness of security-relevant values -------------------------
      // `if (result)` on a string, number or object is how an empty signature
      // or a `0` timestamp slips through a check. Require explicit comparisons
      // for everything except plain booleans and nullable objects.
      '@typescript-eslint/strict-boolean-expressions': [
        'error',
        {
          allowString: false,
          allowNumber: false,
          allowNullableObject: true,
          allowNullableBoolean: true,
          allowNullableString: false,
          allowNullableNumber: false,
          allowAny: false,
        },
      ],

      // A new curve or cryptosuite must be handled at every `switch`, not fall
      // through to a default that quietly treats it like the others.
      '@typescript-eslint/switch-exhaustiveness-check': [
        'error',
        { considerDefaultExhaustiveForUnions: false },
      ],

      // --- Unsafe `any` flow ----------------------------------------------
      // Part of strictTypeChecked. Listed because `any` crossing a verification
      // boundary disables the compiler's help exactly where it matters most.
      '@typescript-eslint/no-unsafe-assignment': 'error',
      '@typescript-eslint/no-unsafe-argument': 'error',
      '@typescript-eslint/no-unsafe-call': 'error',
      '@typescript-eslint/no-unsafe-member-access': 'error',
      '@typescript-eslint/no-unsafe-return': 'error',

      // Numbers in template literals are harmless; everything else (undefined,
      // null, objects that stringify to "[object Object]") still errors, which
      // is the case that matters when building DIDs, URLs and proof inputs.
      '@typescript-eslint/restrict-template-expressions': ['error', { allowNumber: true }],

      // `const { proofValue, ...rest } = proof` is how a member is omitted from
      // an object without mutating it, so a rest sibling is not "unused".
      '@typescript-eslint/no-unused-vars': [
        'error',
        { ignoreRestSiblings: true, argsIgnorePattern: '^_', varsIgnorePattern: '^_' },
      ],

      // `cond ? a() : b()` as a statement is used throughout the CLI to choose
      // between JSON and human output; it is a side-effecting call, not a
      // dead expression.
      '@typescript-eslint/no-unused-expressions': ['error', { allowTernary: true }],

      // Throw Error objects so stack traces and `cause` chains survive.
      '@typescript-eslint/only-throw-error': 'error',
      '@typescript-eslint/prefer-promise-reject-errors': 'error',

      // --- Language features with no place in a crypto library ------------
      eqeqeq: ['error', 'always'],
      'no-eval': 'error',
      '@typescript-eslint/no-implied-eval': 'error',
      'no-new-func': 'error',
      'no-restricted-properties': [
        'error',
        {
          object: 'Math',
          property: 'random',
          message: 'Math.random() is not a CSPRNG. Use node:crypto (randomBytes, randomUUID).',
        },
      ],
    },
  },

  {
    // These files implement an interface whose methods return promises (the
    // `KeyProvider` contract, the conformance kit's `ConformanceCase`, the CLI's
    // `Handler` type) with bodies that happen
    // to be synchronous. Dropping `async` would turn a thrown error into a
    // synchronous throw instead of a rejection, which changes behaviour for
    // callers, so `require-await` is not meaningful here. Every other file,
    // and every function that does await, is still checked.
    files: [
      'packages/keys-dev/src/**/*.ts',
      'packages/keys/src/conformance/**/*.ts',
      'packages/cli/src/commands/**/*.ts',
    ],
    rules: { '@typescript-eslint/require-await': 'off' },
  },

  {
    // Tests index into fixtures and results they have just constructed, so
    // `values[0]!` is an assertion that the fixture is what the test built: if
    // it were not, the very next line would fail anyway. Tests also supply
    // async stubs for async interfaces without anything to await. Neither
    // pattern has a failure mode that matters in a test, so neither rule is
    // applied there; every other rule still is.
    files: ['packages/*/test/**/*.ts'],
    rules: {
      '@typescript-eslint/no-non-null-assertion': 'off',
      '@typescript-eslint/require-await': 'off',
    },
  },

  {
    // Build tooling written in plain JavaScript: no type information.
    files: ['**/*.{js,mjs}'],
    languageOptions: { globals: globals.node },
  },
);
