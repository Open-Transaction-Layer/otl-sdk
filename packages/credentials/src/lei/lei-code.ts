/**
 * ISO 17442 Legal Entity Identifier codes.
 *
 * 20 characters: an 18-character prefix plus two check digits, validated with
 * ISO 7064 MOD 97-10 — the same scheme as IBAN. Checking locally means an
 * obvious typo never becomes a GLEIF API call, and never reaches a credential.
 */

/** Letters map A=10 ... Z=35, then the whole string must be 1 mod 97. */
function toDigits(value: string): string {
  let digits = '';
  for (const character of value) {
    digits += /[0-9]/.test(character) ? character : String(character.charCodeAt(0) - 55); // 'A'.charCodeAt(0) === 65
  }
  return digits;
}

/** Incremental mod 97, since the expanded digit string exceeds Number range. */
const mod97 = (digits: string): number => {
  let accumulator = 0;
  for (const digit of digits) accumulator = (accumulator * 10 + Number(digit)) % 97;
  return accumulator;
};

export function isValidLei(lei: string): boolean {
  if (!/^[0-9A-Z]{18}[0-9]{2}$/.test(lei)) return false;
  return mod97(toDigits(lei)) === 1;
}

/** The two check digits for an 18-character prefix. */
export function leiCheckDigits(prefix18: string): string {
  if (!/^[0-9A-Z]{18}$/.test(prefix18)) {
    throw new Error('LEI prefix must be 18 uppercase alphanumeric characters');
  }
  return String(98 - mod97(`${toDigits(prefix18)}00`)).padStart(2, '0');
}

/** Explain why an LEI is invalid, for an operator-facing message. */
export function explainInvalidLei(lei: string): string | undefined {
  if (lei.length !== 20) return `LEI must be exactly 20 characters, got ${lei.length}`;
  if (!/^[0-9A-Z]{18}[0-9]{2}$/.test(lei)) {
    return 'LEI must be 18 uppercase alphanumeric characters followed by 2 check digits';
  }
  if (mod97(toDigits(lei)) !== 1) {
    return `LEI check digits are invalid (ISO 17442 / ISO 7064 MOD 97-10); expected "${leiCheckDigits(lei.slice(0, 18))}"`;
  }
  return undefined;
}
