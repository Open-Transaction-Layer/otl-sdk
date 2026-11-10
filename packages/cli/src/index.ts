/**
 * `@otl/cli` — NON-PRODUCTION command line tool for the OTL Identity layer.
 */

import { parseArgs, flag, type ParsedArgs } from './args.ts';
import { CliError } from './errors.ts';
import { createOutput, NON_PRODUCTION_BANNER, type Output } from './output.ts';
import { Store, type StoreOptions } from './store.ts';
import {
  didAddKey,
  didAddService,
  didCreate,
  didDeactivate,
  didList,
  didRotate,
  didShow,
  didValidateLocal,
} from './commands/did.ts';
import {
  cmdCredentialFetch,
  cmdResolve,
  cmdTrustAdd,
  cmdTrustList,
  cmdTrustRemove,
  cmdValidate,
} from './commands/remote.ts';
import { cmdDecrypt, cmdEncrypt, cmdSign, cmdVerify } from './commands/crypto.ts';
import {
  cmdAddIssuanceKey,
  cmdIssue,
  cmdIssueHosting,
  cmdRevoke,
  cmdStatusList,
} from './commands/credential.ts';
import { cmdExport, cmdServe } from './commands/publish.ts';
import { cmdCredentialAdd, cmdCredentialHeld, cmdWhoisPublish } from './commands/whois.ts';

type Handler = (args: ParsedArgs, store: Store, out: Output) => Promise<void>;

/** Commands that never touch the local keystore, so they skip the banner. */
const READ_ONLY = new Set(['resolve', 'validate', 'verify', 'encrypt', 'trust list', 'help', 'version']);

const COMMANDS: Record<string, Handler> = {
  'did create': didCreate,
  'did list': didList,
  'did show': didShow,
  'did add-key': didAddKey,
  'did add-service': didAddService,
  'did rotate': didRotate,
  'did deactivate': didDeactivate,
  'did validate': didValidateLocal,
  resolve: cmdResolve,
  validate: cmdValidate,
  sign: cmdSign,
  verify: cmdVerify,
  encrypt: cmdEncrypt,
  decrypt: cmdDecrypt,
  'credential add-issuance-key': cmdAddIssuanceKey,
  'credential issue': cmdIssue,
  'credential issue-hosting': cmdIssueHosting,
  'credential status-list': cmdStatusList,
  'credential revoke': cmdRevoke,
  'credential fetch': cmdCredentialFetch,
  'credential add': cmdCredentialAdd,
  'credential held': cmdCredentialHeld,
  'whois publish': cmdWhoisPublish,
  'trust add': cmdTrustAdd,
  'trust remove': cmdTrustRemove,
  'trust list': cmdTrustList,
  export: cmdExport,
  serve: cmdServe,
};

const HELP = `otl — OTL Identity layer tool (NON-PRODUCTION)

DID
  did create --domain <d> [--curve ed25519|p256] [--genesis-bound <fragments>]
             [--no-assertion-key] [--time <iso>]
  did list | did show [--version <n>] | did validate
  did add-key --label <l> [--curve <c>] [--purpose <p>]
  did add-service (--file <p> | --service <json>)
  did rotate                       rotate the management key, changing nothing else
  did deactivate --yes             permanent

Counterparties
  resolve <did>                    fetch the document, NO validation
  validate <did>                   fetch the log and verify it to genesis
  credential fetch <did>           fetch and validate published credentials

Credentials (issuer)
  credential add-issuance-key [--label <fragment>]
  credential issue --lei <code> --subject <did> [--list-id <id>] [--valid-until <iso>]
                                   [--gleif-file <path>]
  credential issue-hosting --subject <did> --common-name <name> [--watchers <url,url>]
                                   [--list-id <id>] [--valid-until <iso>]
  credential status-list [--list-id <id>]
  credential revoke --credential <id>

Credentials (subject)
  credential add --file <path>     store a credential issued to you
  credential held                  list what you hold
  whois publish [--vp-key <label>] [--allow-empty]
                                   sign and publish them (spec 4.4)

Trust perimeter (spec 6.1 — nothing is trusted by default)
  trust add --did <did> [--type <types>] [--note <text>]
  trust remove --did <did> [--type <types>]
  trust list

Cryptography
  sign --key <label> (--message <m> | --file <p>)
  verify --did <did> --key <label> --signature <s> (--message <m> | --file <p>)
  encrypt --did <did> --key <label> (--message <m> | --file <p>) [--sender <text>]
  decrypt --key <label> (--jwe <jwe> | --file <p>)

Publication
  export                           write the tree to upload
  serve --cert <p> --key <p> [--port <n>]
                                   serve it locally over HTTPS (default port 8443)

Global: --json  --did <did>  --block-private-addresses  --timeout <ms>
Environment: OTL_HOME, OTL_KEYSTORE_PASSPHRASE, OTL_PREROTATION_PASSPHRASE
`;

export async function run(argv: readonly string[], storeOptions: StoreOptions = {}): Promise<number> {
  const args = parseArgs(argv);
  const out = createOutput(flag(args, 'json'));

  const name = [args.command[0], args.command[1]].filter(Boolean).join(' ');
  const handler = COMMANDS[name] ?? COMMANDS[args.command[0] ?? ''];

  if (args.command.length === 0 || args.command[0] === 'help' || flag(args, 'help')) {
    out.print(HELP);
    return 0;
  }
  if (!handler) {
    out.warn(`Unknown command "${args.command.join(' ')}". Run \`otl help\` for usage.`);
    return 1;
  }

  try {
    const store = new Store(storeOptions);
    // Not suppressible: a file-backed private key is a development affordance,
    // and the moment that stops being obvious is the moment someone ships it.
    if (!READ_ONLY.has(name) && !READ_ONLY.has(args.command[0] ?? '')) {
      out.warn(NON_PRODUCTION_BANNER);
    }
    await handler(args, store, out);
    return 0;
  } catch (error) {
    if (error instanceof CliError) {
      out.warn(`error: ${error.message}`);
      if (error.hint !== undefined && error.hint !== '') out.warn(`  ${error.hint}`);
      return error.exitCode;
    }

    // Errors from the protocol packages are expected operating conditions —
    // an unreachable registry, a malformed credential, an unresolvable DID.
    // They should read as instructions, not crashes. Anything else is a bug
    // and keeps its stack trace.
    const expected = [
      'RegistryLookupError',
      'InvalidCredentialError',
      'UnknownCredentialTypeError',
      'InvalidDocumentError',
      'ResolutionError',
      'FetchError',
      'InvalidDidError',
      'KeyNotFoundError',
      'KeyAlreadyExistsError',
      'UnsupportedOperationError',
      'InvalidKeyError',
      'EncryptionError',
      'SigningError',
      'CryptosuiteMismatchError',
      'CanonicalizationError',
      'ProofError',
    ];
    if (error instanceof Error && expected.includes(error.name)) {
      out.warn(`error: ${error.message}`);
      return 1;
    }
    throw error; // a bug: let the stack trace through
  }
}

export { Store, CliError };
