/**
 * Ambient declarations for the independent VC implementation used as a
 * conformance oracle in `vc-interop.test.ts`.
 *
 * These packages ship no type declarations. Declaring them loosely is
 * acceptable here precisely because we are not building on them: they are a
 * second opinion, exercised only from tests, and the assertions compare
 * concrete values rather than relying on their types. Typing them properly
 * would be work in service of code we deliberately do not depend on.
 */

declare module '@digitalbazaar/data-integrity' {
  // eslint-disable-next-line @typescript-eslint/no-extraneous-class -- an ambient class must be declared as a class so that `new` type-checks
  export class DataIntegrityProof {
    constructor(options: { signer?: unknown; date?: string; cryptosuite: unknown });
  }
}

declare module '@digitalbazaar/eddsa-jcs-2022-cryptosuite' {
  export function createSignCryptosuite(): unknown;
  export function createVerifyCryptosuite(): unknown;
}

declare module '@digitalbazaar/ed25519-multikey' {
  export function generate(options: { controller: string; id: string }): Promise<{
    signer(): unknown;
    export(options: { publicKey?: boolean; secretKey?: boolean }): Promise<Record<string, unknown>>;
  }>;
}

declare module 'jsonld-signatures' {
  const jsigs: {
    sign(document: unknown, options: Record<string, unknown>): Promise<unknown>;
    verify(
      document: unknown,
      options: Record<string, unknown>,
    ): Promise<{ verified: boolean; error?: unknown }>;
    purposes: { AssertionProofPurpose: new (options?: Record<string, unknown>) => unknown };
  };
  export default jsigs;
}

declare module 'jsonld' {
  const jsonld: {
    expand(input: unknown, options?: Record<string, unknown>): Promise<Record<string, unknown>[]>;
    toRDF(input: unknown, options?: Record<string, unknown>): Promise<unknown>;
  };
  export default jsonld;
}
