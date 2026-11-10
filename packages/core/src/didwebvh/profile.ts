/**
 * Method profiles — which algorithms a DID log's proofs may use.
 *
 * OTL builds *on top of* did:webvh and is free to widen the algorithm set. The
 * constraint worth respecting is not the curve but the label: `did:webvh:` and
 * `method: "did:webvh:1.0"` are a claim about which rules apply. did:webvh 1.0
 * says resolvers "MUST verify the proof's `cryptosuite` property; an absent,
 * mismatched, or non-conformant `cryptosuite` MUST cause the entry to be
 * rejected" — so a log signed with anything other than `eddsa-jcs-2022` while
 * claiming that method is not an extension, it is an identifier that lies.
 *
 * A profile therefore pairs the permitted algorithms with the `method` value
 * that announces them. Widening the set is fine; widening it silently is not.
 *
 * ## The trade-off
 *
 * | | `did:webvh:1.0` | A widened profile |
 * |---|---|---|
 * | Resolvable by stock did:webvh tooling | yes | no |
 * | Watchers (spec 2.4) can verify | yes | no — they are third-party software |
 * | Resolvable by non-OTL tooling built on did:webvh | yes | no |
 *
 * There is no custody argument for widening. AWS KMS supports Ed25519 via the
 * ECC_NIST_EDWARDS25519 key spec (signing and verification), so the DID
 * Management Key can live in KMS under the stock profile. Widening is therefore
 * a choice about algorithm agility, not a workaround for a custody constraint.
 */

import type { Curve } from '@otl/keys';
import type { CryptosuiteName } from '../cryptosuite.ts';

export interface MethodProfile {
  /** Value written to `parameters.method`, announcing which rules apply. */
  readonly method: string;
  /** Cryptosuites permitted for log-entry proofs. */
  readonly logProofCryptosuites: readonly CryptosuiteName[];
  /** Curves permitted for update keys, implied by the cryptosuites. */
  readonly logProofCurves: readonly Curve[];
  /** True when a stock did:webvh 1.0 resolver will accept logs in this profile. */
  readonly interoperable: boolean;
}

/** Stock did:webvh 1.0. The default, and the only profile third parties resolve. */
export const DIDWEBVH_1_0_PROFILE: MethodProfile = {
  method: 'did:webvh:1.0',
  logProofCryptosuites: ['eddsa-jcs-2022'],
  logProofCurves: ['Ed25519'],
  interoperable: true,
};

/**
 * A widened profile permitting P-256 log-entry proofs.
 *
 * **The `method` value here is a placeholder.** If OTL adopts this, the working
 * group assigns the real identifier; what matters is that it is *not*
 * `did:webvh:1.0`, so a stock resolver rejects the log rather than
 * mis-processing it.
 *
 * Ed25519 is permitted alongside P-256 so a single deployment can mix — an
 * issuer custodying its management key in KMS and its credential-issuance key
 * elsewhere, or the reverse.
 */
export const OTL_EXTENDED_PROFILE: MethodProfile = {
  method: 'did:webvh:1.0-otl-ecdsa',
  logProofCryptosuites: ['eddsa-jcs-2022', 'ecdsa-jcs-2019'],
  logProofCurves: ['Ed25519', 'P-256'],
  interoperable: false,
};

export const PROFILES: Readonly<Record<string, MethodProfile>> = {
  'did:webvh:1.0': DIDWEBVH_1_0_PROFILE,
  [OTL_EXTENDED_PROFILE.method]: OTL_EXTENDED_PROFILE,
};

/** Look up the profile a log declares, or undefined if it is unrecognized. */
export const profileForMethod = (method: string | undefined): MethodProfile | undefined =>
  method === undefined ? undefined : PROFILES[method];

/** Explain why a curve is not permitted, or undefined if it is. */
export function explainCurveRejection(
  profile: MethodProfile,
  curve: Curve,
  role: string,
): string | undefined {
  if (profile.logProofCurves.includes(curve)) return undefined;

  const base =
    `The ${role} uses ${curve}, which profile "${profile.method}" does not permit for ` +
    `log-entry proofs (allowed: ${profile.logProofCurves.join(', ')}).`;

  if (profile.interoperable && curve === 'P-256') {
    return (
      `${base}\n` +
      `  did:webvh 1.0 permits only eddsa-jcs-2022, and a resolver MUST reject anything else.\n` +
      `  Most managed backends can hold an Ed25519 key for this purpose — AWS KMS supports it\n` +
      `  via the ECC_NIST_EDWARDS25519 key spec. If OTL genuinely needs P-256 log proofs, use a\n` +
      `  profile that announces it in parameters.method rather than publishing a P-256 log under\n` +
      `  did:webvh:1.0 — see MethodProfile.`
    );
  }
  return base;
}
