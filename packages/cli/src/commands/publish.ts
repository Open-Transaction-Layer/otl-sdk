/**
 * Publication: writing the tree an operator uploads, and serving it locally.
 */

import { createReadStream, existsSync, readdirSync, statSync } from 'node:fs';
import { extname, join, normalize, resolve, sep } from 'node:path';
import { optionalOption, type ParsedArgs } from '../args.ts';
import { CliError } from '../errors.ts';
import type { Output } from '../output.ts';
import type { Store } from '../store.ts';

/** Media types by extension; anything else in the export tree is JSON. */
const CONTENT_TYPES: Readonly<Record<string, string>> = {
  '.jsonl': 'application/jsonl',
  // The VC Data Model 2.0 media type for a Verifiable Presentation (spec 4.4).
  '.vp': 'application/vp',
};

export async function cmdExport(args: ParsedArgs, store: Store, out: Output): Promise<void> {
  const meta = store.resolveMeta(optionalOption(args, 'did'));
  store.writeLog(meta.scid, store.readLog(meta.scid)); // rewrites the export tree
  const dir = store.exportDir(meta.scid);

  // The invariant this command relies on: nothing secret is ever written here.
  const leaked = findSecrets(dir);
  if (leaked.length > 0) {
    throw new CliError(`Refusing to report an export tree containing key material: ${leaked.join(', ')}`);
  }

  if (out.json) {
    out.data({ did: meta.did, exportDir: dir, files: listFiles(dir) });
    return;
  }
  out.success(`Export tree for ${meta.did}`);
  out.print(`  ${dir}`);
  for (const file of listFiles(dir)) out.print(`    ${file}`);
  out.print('');
  out.print(`Upload the contents so that:`);
  out.print(`  https://${meta.domain}/.well-known/did.jsonl  serves did.jsonl`);
  out.print(`  https://${meta.domain}/.well-known/did.json   serves did.json`);
}

function listFiles(dir: string, prefix = ''): string[] {
  if (!existsSync(dir)) return [];
  return readdirSync(dir).flatMap((name) => {
    const full = join(dir, name);
    return statSync(full).isDirectory() ? listFiles(full, `${prefix}${name}/`) : [`${prefix}${name}`];
  });
}

/** Names that would indicate key material reached the publishable tree. */
const findSecrets = (dir: string): string[] =>
  listFiles(dir).filter((file) => /(^|\/)(keys|prerotation|issued)\b|\.pem$|\.key$/.test(file));

/**
 * Serve the export tree over HTTPS for local testing.
 *
 * TLS material must be supplied. The resolver enforces HTTPS with certificate
 * verification and has no bypass flag, by design — so rather than adding one
 * for local convenience, `serve` asks for a certificate and prints how to make
 * a throwaway one.
 */
export async function cmdServe(args: ParsedArgs, store: Store, out: Output): Promise<void> {
  const meta = store.resolveMeta(optionalOption(args, 'did'));
  const port = Number(optionalOption(args, 'port') ?? 8443);
  const certPath = optionalOption(args, 'cert');
  const keyPath = optionalOption(args, 'key');
  const root = resolve(store.exportDir(meta.scid));

  if (certPath === undefined || keyPath === undefined) {
    throw new CliError('serve requires --cert <path> and --key <path>', {
      hint:
        'Resolution is HTTPS-only with no bypass, so a local server needs TLS. Generate a\n' +
        '  throwaway pair with:\n' +
        '    openssl req -x509 -newkey rsa:2048 -nodes -days 30 \\\n' +
        `      -subj "/CN=${meta.domain}" -keyout otl-dev.key -out otl-dev.crt\n` +
        '  then point clients at it with NODE_EXTRA_CA_CERTS=otl-dev.crt.',
    });
  }

  const { readFileSync } = await import('node:fs');
  const { createServer: createTlsServer } = await import('node:https');

  const handler = (request: { url?: string }, response: import('node:http').ServerResponse) => {
    const [path = '/'] = (request.url ?? '/').split('?');
    let requested: string;
    try {
      requested = decodeURIComponent(path);
    } catch {
      // A malformed percent-encoding is the client's error, not the server's.
      response.writeHead(400).end('Bad request');
      return;
    }

    // Resolve against the root and confirm containment, so a traversal
    // sequence cannot reach outside the export tree.
    const target = resolve(join(root, normalize(requested)));
    if (target !== root && !target.startsWith(root + sep)) {
      response.writeHead(403).end('Forbidden');
      return;
    }
    if (!existsSync(target) || statSync(target).isDirectory()) {
      response.writeHead(404).end('Not found');
      return;
    }

    response.writeHead(200, {
      'content-type': CONTENT_TYPES[extname(target)] ?? 'application/json',
      'cache-control': 'no-store',
    });
    createReadStream(target).pipe(response);
  };

  const server = createTlsServer(
    { cert: readFileSync(certPath), key: readFileSync(keyPath) },
    handler as never,
  );

  await new Promise<void>((resolvePromise) =>
    server.listen(port, () => {
      resolvePromise();
    }),
  );
  out.success(`Serving ${root} at https://localhost:${port}`);
  out.print(`  https://localhost:${port}/.well-known/did.jsonl`);
  out.print('Press Ctrl+C to stop.');
}
