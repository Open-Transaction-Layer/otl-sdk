/**
 * An error whose message is meant for the operator.
 *
 * Anything thrown as a `CliError` is printed as-is with a non-zero exit; any
 * other exception is a bug and gets a stack trace. Keeping the two apart is
 * what lets expected failures — a missing key, an invalid DID — read as
 * instructions rather than crashes.
 */
export class CliError extends Error {
  readonly exitCode: number;
  readonly hint?: string;
  constructor(message: string, options?: { exitCode?: number; hint?: string; cause?: unknown }) {
    super(message, options);
    this.name = 'CliError';
    this.exitCode = options?.exitCode ?? 1;
    if (options?.hint !== undefined) this.hint = options.hint;
  }
}
