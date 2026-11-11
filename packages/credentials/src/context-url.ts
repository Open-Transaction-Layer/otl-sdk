/**
 * The URL OTL credentials name in `@context` to define their own terms.
 *
 * Because `@context` is covered by the signature, this URL can never change
 * once a credential has been signed against it, and the document it serves
 * can never change either. It is served from the `otl.network` domain, with
 * the files kept in the OTL-owned `otl-contexts` repository on GitHub Pages.
 *
 * Credentials issued before this URL is published are disposable proof of
 * concept artefacts, so moving to a different identifier later, such as a
 * w3id.org permanent identifier, costs a reissue rather than a migration.
 */
export const OTL_IDENTITY_CONTEXT = 'https://otl.network/contexts/identity/v1';
