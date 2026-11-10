/**
 * Commands that talk to other participants: resolve, validate, credential
 * fetch, and the trust perimeter that gates them (OTL spec 2.3, 4.4, 5.3, 6.1).
 */

import { defaultRegistry, OTL_LEI_CREDENTIAL } from '@otl/credentials';
import { fetchStatusList, resolveDid, resolveAssertionKey, validateDid, verifyWhois } from '@otl/resolver';
import { flag, optionalOption, requireOption, type ParsedArgs } from '../args.ts';
import { CliError } from '../errors.ts';
import type { Output } from '../output.ts';
import type { Store } from '../store.ts';

/**
 * Fetch options shared by every command that contacts another participant.
 * Server-side deployments should refuse private addresses; local development
 * needs them.
 */
export const fetchOptionsFrom = (args: ParsedArgs) => {
  const timeout = optionalOption(args, 'timeout');
  const timeoutMs = timeout !== undefined && timeout !== '' ? Number(timeout) : undefined;
  if (timeoutMs !== undefined && !(Number.isInteger(timeoutMs) && timeoutMs > 0)) {
    throw new CliError(`Invalid --timeout "${timeout}"`, { hint: 'Give a whole number of milliseconds.' });
  }
  return {
    blockPrivateAddresses: flag(args, 'block-private-addresses'),
    ...(timeoutMs !== undefined ? { timeoutMs } : {}),
  };
};

/**
 * Fetch a DID document with no validation whatsoever.
 *
 * Deliberately separate from `validate`: what comes back is whatever the domain
 * served, and proves nothing. The warning is not suppressible.
 */
export async function cmdResolve(args: ParsedArgs, _store: Store, out: Output): Promise<void> {
  const did = args.command[1] ?? requireOption(args, 'did');
  // Warned before the fetch, so the caveat still reaches the operator when the
  // fetch fails -- which is exactly when it matters most.
  out.warn('NOTE: resolve performs no validation. Use `otl validate` before trusting this document.');
  out.data(await resolveDid(did, fetchOptionsFrom(args)));
}

/** Fetch the version log and verify it to genesis. */
export async function cmdValidate(args: ParsedArgs, _store: Store, out: Output): Promise<void> {
  const did = args.command[1] ?? requireOption(args, 'did');
  const result = await validateDid(did, fetchOptionsFrom(args));

  if (out.json) {
    out.data({
      did: result.did,
      valid: result.valid,
      versionCount: result.versionCount,
      deactivated: result.deactivated,
      issues: result.issues,
    });
  } else if (result.valid) {
    out.success(`${did} is valid across ${result.versionCount} version(s)`);
    if (result.deactivated) out.print('  NOTE: this DID has been deactivated');
  } else {
    out.print(`${did} FAILED validation:`);
    for (const issue of result.issues) {
      out.print(`  - ${issue.entry !== undefined ? `[entry ${issue.entry}] ` : ''}${issue.message}`);
    }
  }

  if (!result.valid) throw new CliError('DID log failed validation', { exitCode: 2 });
}

/**
 * Fetch and validate every credential a participant publishes (spec 4.4, 5.3).
 */
export async function cmdCredentialFetch(args: ParsedArgs, store: Store, out: Output): Promise<void> {
  const did = args.command[2] ?? requireOption(args, 'did');
  const fetchOptions = fetchOptionsFrom(args);
  const perimeter = store.trustPerimeter();

  if (perimeter.issuers().length === 0) {
    out.warn(
      'WARNING: your trust perimeter is empty, so every credential will be rejected.\n' +
        '  There is no protocol-defined root of trust (spec 4.6) — add issuers you have chosen to trust:\n' +
        `  otl trust add --did <lou-did> --type ${OTL_LEI_CREDENTIAL}`,
    );
  }

  const result = await verifyWhois({
    did,
    registry: defaultRegistry(),
    trustPerimeter: perimeter,
    resolveAssertionKey: resolveAssertionKey(fetchOptions),
    fetchStatusList: fetchStatusList(fetchOptions),
    fetchOptions,
  });

  if (out.json) {
    out.data(result);
    return;
  }

  out.print(result.holder);
  out.print(
    `  presentation: ${result.presentationVerified ? 'verified' : `NOT verified — ${result.presentationIssue ?? 'unknown'}`}`,
  );
  for (const credential of result.credentials) {
    if (credential.skipped) {
      out.print('  - (unrecognized type, skipped)');
      continue;
    }
    out.print(`  - ${credential.typeName}: ${credential.valid ? 'valid' : 'INVALID'}`);
    for (const issue of credential.issues) out.print(`      ${issue}`);
  }
}

// ---------------------------------------------------------------------------
// Trust perimeter (spec 6.1)
// ---------------------------------------------------------------------------

export async function cmdTrustAdd(args: ParsedArgs, store: Store, out: Output): Promise<void> {
  const did = requireOption(args, 'did');
  const types = (optionalOption(args, 'type') ?? OTL_LEI_CREDENTIAL).split(',').map((t) => t.trim());
  const note = optionalOption(args, 'note');

  const perimeter = store.trustPerimeter();
  perimeter.addIssuer(did, types, note);
  store.saveTrustPerimeter(perimeter);

  out.json ? out.data(perimeter.toJSON()) : out.success(`Trusting ${did} for ${types.join(', ')}`);
}

export async function cmdTrustRemove(args: ParsedArgs, store: Store, out: Output): Promise<void> {
  const did = requireOption(args, 'did');
  const types = optionalOption(args, 'type')
    ?.split(',')
    .map((t) => t.trim());

  const perimeter = store.trustPerimeter();
  perimeter.removeIssuer(did, types);
  store.saveTrustPerimeter(perimeter);

  if (types === undefined) {
    out.warn(
      'Removed the issuer entirely. This is the documented response to a compromised trust anchor\n' +
        '  (spec 5.4): revocation lists cannot help there, because an attacker holding the anchor key\n' +
        '  can keep issuing valid, non-revoked credentials.',
    );
  }
  out.json ? out.data(perimeter.toJSON()) : out.success(`Removed ${did}`);
}

export async function cmdTrustList(_args: ParsedArgs, store: Store, out: Output): Promise<void> {
  const perimeter = store.trustPerimeter();
  if (out.json) {
    out.data(perimeter.toJSON());
    return;
  }
  const issuers = perimeter.issuers();
  if (issuers.length === 0) {
    out.print('Trust perimeter is empty. Nothing is trusted by default (spec 4.6).');
    return;
  }
  for (const issuer of issuers) {
    out.print(issuer.did);
    out.print(`  types: ${issuer.credentialTypes.join(', ')}`);
    if (issuer.note !== undefined && issuer.note !== '') out.print(`  note:  ${issuer.note}`);
  }
}
