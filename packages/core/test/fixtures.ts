/**
 * Shared test fixtures.
 *
 * ## Why the LEIs here are all zeros
 *
 * A real LEI is a 20-character high-entropy alphanumeric, which secret
 * scanners reliably flag as a credential. Rather than suppress the scanner —
 * it is doing the right thing on the shape it sees — test fixtures use
 * synthetic LEIs built from an all-zero prefix. They carry correct ISO 17442
 * (ISO 7064 MOD 97-10) check digits, so they pass validation, and they are
 * unmistakably not a real registration.
 *
 * Use `syntheticLei()` when a test needs more than one.
 */

/** ISO 17442 check digits: letters map A=10..Z=35, whole string ≡ 1 (mod 97). */
function checkDigits(prefix18: string): string {
  // Array.from rather than a spread: these are ASCII, so code points are characters.
  const digits = Array.from(prefix18, (c) => (/[0-9]/.test(c) ? c : (c.charCodeAt(0) - 55).toString())).join(
    '',
  );
  const remainder = Array.from(`${digits}00`).reduce((acc, d) => (acc * 10 + Number(d)) % 97, 0);
  return String(98 - remainder).padStart(2, '0');
}

/** A structurally valid but obviously synthetic LEI. `n` varies the prefix. */
export function syntheticLei(n = 0): string {
  const prefix = String(n).padStart(18, '0');
  return prefix + checkDigits(prefix);
}

export const TEST_LEI = syntheticLei(0);

export const TEST_ISSUER_DID = 'did:webvh:QmTestScidIssuer:lou.example.org';
export const TEST_SUBJECT_DID = 'did:webvh:QmTestScidSubject:participant.example';
export const TEST_ISSUANCE_KEY = `${TEST_ISSUER_DID}#credential-issuance-key`;
