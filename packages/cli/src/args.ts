/**
 * Minimal argument parsing.
 *
 * Hand-rolled rather than taken from a dependency: this package holds key
 * material, and the argument parser is not worth a supply-chain surface.
 */

import { CliError } from './errors.ts';

export interface ParsedArgs {
  readonly command: readonly string[];
  readonly options: Readonly<Record<string, string | boolean>>;
  readonly positional: readonly string[];
}

/**
 * Flags that never take a value. Without this list, `--json <did>` would read
 * the DID as the flag's value and drop it from the positional arguments.
 */
export const BOOLEAN_FLAGS: ReadonlySet<string> = new Set([
  'json',
  'help',
  'yes',
  'allow-empty',
  'allow-private-addresses',
  'no-authentication-key',
]);

export function parseArgs(argv: readonly string[]): ParsedArgs {
  const command: string[] = [];
  const positional: string[] = [];
  const options: Record<string, string | boolean> = {};
  let seenOption = false;

  for (let i = 0; i < argv.length; i++) {
    const token = argv[i];
    if (token === undefined) break;

    if (token === '--') {
      positional.push(...argv.slice(i + 1));
      break;
    }

    if (token.startsWith('--')) {
      seenOption = true;
      const body = token.slice(2);
      const equals = body.indexOf('=');
      if (equals !== -1) {
        options[body.slice(0, equals)] = body.slice(equals + 1);
        continue;
      }
      const next = argv[i + 1];
      // A known boolean flag, or a bare `--flag` at the end or before another
      // option, is boolean; otherwise `--flag value` consumes the value.
      if (BOOLEAN_FLAGS.has(body) || next === undefined || next.startsWith('--')) {
        options[body] = true;
      } else {
        options[body] = next;
        i++;
      }
      continue;
    }

    if (seenOption) positional.push(token);
    else command.push(token);
  }

  return { command, options, positional };
}

export function requireOption(args: ParsedArgs, name: string, hint?: string): string {
  const value = args.options[name];
  if (typeof value !== 'string' || value.length === 0) {
    throw new CliError(`Missing required option --${name}`, hint === undefined ? {} : { hint });
  }
  return value;
}

export const optionalOption = (args: ParsedArgs, name: string): string | undefined => {
  const value = args.options[name];
  return typeof value === 'string' ? value : undefined;
};

export const flag = (args: ParsedArgs, name: string): boolean => args.options[name] === true;
