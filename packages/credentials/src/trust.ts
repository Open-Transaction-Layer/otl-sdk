/**
 * Trust perimeter (OTL spec 6.1).
 *
 * "Each participant independently defines their own trust perimeter — the set
 * of claim types and the specific trusted issuer DIDs they choose to
 * recognize." There is no protocol-defined root of trust: adding an LOU is a
 * local configuration change, not a network event (spec 4.6, 4.11).
 *
 * Deliberately a plain data structure with no network access. Whether to trust
 * an issuer is an operator decision, and nothing here should ever acquire the
 * ability to make it automatically.
 */

export interface TrustedIssuer {
  /** did:webvh of the issuer. */
  readonly did: string;
  /** Credential types this issuer is trusted to issue, e.g. `OtlLeiCredential`. */
  readonly credentialTypes: readonly string[];
  /** Free-text operator note: who they are, why they were added, when. */
  readonly note?: string;
}

export interface TrustPerimeterData {
  readonly issuers: readonly TrustedIssuer[];
  /** DIDs trusted as counterparties regardless of who vouches for them (6.1). */
  readonly allowedCounterparties?: readonly string[];
  /** DIDs refused regardless of what credentials they hold (6.1). */
  readonly deniedCounterparties?: readonly string[];
}

export class TrustPerimeter {
  readonly #issuers = new Map<string, Set<string>>();
  readonly #notes = new Map<string, string>();
  readonly #allowed = new Set<string>();
  readonly #denied = new Set<string>();

  constructor(data: TrustPerimeterData = { issuers: [] }) {
    for (const issuer of data.issuers) {
      this.#issuers.set(issuer.did, new Set(issuer.credentialTypes));
      if (issuer.note !== undefined) this.#notes.set(issuer.did, issuer.note);
    }
    for (const did of data.allowedCounterparties ?? []) this.#allowed.add(did);
    for (const did of data.deniedCounterparties ?? []) this.#denied.add(did);
  }

  /** Add an issuer, or extend the credential types an existing one may issue. */
  addIssuer(did: string, credentialTypes: readonly string[], note?: string): this {
    const existing = this.#issuers.get(did) ?? new Set<string>();
    for (const type of credentialTypes) existing.add(type);
    this.#issuers.set(did, existing);
    if (note !== undefined) this.#notes.set(did, note);
    return this;
  }

  /**
   * Remove an issuer entirely, or only certain credential types.
   *
   * Full removal is the documented recovery path for a compromised trust
   * anchor (spec 5.4): revocation lists are useless there, because an attacker
   * holding the anchor's signing key can keep issuing valid, non-revoked
   * credentials. The only remedy is to stop trusting them.
   */
  removeIssuer(did: string, credentialTypes?: readonly string[]): this {
    if (credentialTypes === undefined) {
      this.#issuers.delete(did);
      this.#notes.delete(did);
      return this;
    }
    const existing = this.#issuers.get(did);
    if (!existing) return this;
    for (const type of credentialTypes) existing.delete(type);
    if (existing.size === 0) {
      this.#issuers.delete(did);
      this.#notes.delete(did);
    }
    return this;
  }

  /** Is this issuer trusted for this credential type? */
  trusts(issuerDid: string, credentialType: string): boolean {
    return this.#issuers.get(issuerDid)?.has(credentialType) ?? false;
  }

  allowCounterparty(did: string): this {
    this.#denied.delete(did);
    this.#allowed.add(did);
    return this;
  }

  denyCounterparty(did: string): this {
    this.#allowed.delete(did);
    this.#denied.add(did);
    return this;
  }

  isDenied(did: string): boolean {
    return this.#denied.has(did);
  }

  isExplicitlyAllowed(did: string): boolean {
    return this.#allowed.has(did);
  }

  issuers(): TrustedIssuer[] {
    return [...this.#issuers.entries()].map(([did, types]) => {
      const note = this.#notes.get(did);
      return {
        did,
        credentialTypes: [...types].sort(),
        ...(note !== undefined ? { note } : {}),
      };
    });
  }

  toJSON(): TrustPerimeterData {
    return {
      issuers: this.issuers(),
      allowedCounterparties: [...this.#allowed].sort(),
      deniedCounterparties: [...this.#denied].sort(),
    };
  }

  static fromJSON(data: TrustPerimeterData): TrustPerimeter {
    return new TrustPerimeter(data);
  }
}
