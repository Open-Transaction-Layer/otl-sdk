/**
 * Console output.
 *
 * Every command supports `--json` so the tool composes in a shell pipeline;
 * human output goes to stdout and diagnostics to stderr, so `otl ... > file`
 * captures data without warnings mixed in.
 */

export interface Output {
  readonly json: boolean;
  print(text: string): void;
  data(value: unknown): void;
  warn(text: string): void;
  success(text: string): void;
}

export function createOutput(json: boolean, streams = { out: process.stdout, err: process.stderr }): Output {
  return {
    json,
    print(text) {
      if (!json) streams.out.write(`${text}\n`);
    },
    data(value) {
      streams.out.write(`${JSON.stringify(value, null, json ? 0 : 2)}\n`);
    },
    warn(text) {
      streams.err.write(`${text}\n`);
    },
    success(text) {
      if (!json) streams.out.write(`${text}\n`);
    },
  };
}

/**
 * Printed whenever a non-production key provider is active.
 *
 * Goes to stderr so it cannot be mistaken for output, and is deliberately not
 * suppressible: a file-backed private key is a development affordance, and the
 * moment that stops being obvious is the moment someone ships it.
 */
export const NON_PRODUCTION_BANNER =
  'NON-PRODUCTION: keys are held in files on this machine. Bridge KeyProvider to a KMS or HSM for anything real.';
