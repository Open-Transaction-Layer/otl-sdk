# OTL Identity Layer — Security and Threat Analysis

- **Status:** Draft for review
- **Scope:** OTL Identity layer (Layer 1): did:webvh / did:web identifiers, W3C Verifiable Credentials, Bitstring Status List revocation, trust anchor management
- **Based on:** OTL Identity Layer Technical Specification v0.5 (with editorial fixes applied), did:webvh DID Method Specification v1.0, OTL Risk Committee Prep, Bridging Environments with OTL, OTL Key Management
- **Date:** October 2026

---

## 1. Purpose and Scope

This document identifies attack vectors against the OTL Identity layer and proposes mitigations. It has two audiences:

1. **Spec-refinement partners**, for whom Sections 5.1 to 5.6 and Section 7 describe protocol-level threats and proposed normative changes that apply to every OTL implementer.
2. **Fireblocks security and risk stakeholders**, for whom Section 5.7 and Section 6 describe threats specific to the Fireblocks-hosted deployment model decided by the OTL Risk Committee (DID management, address claim, and credential issuance keys held in KMS and accessed through a Nitro enclave).

Out of scope: the Session, Transport, Messaging, and Application layers, except where an Identity-layer weakness propagates into them (for example, verifiable address validation). Out of scope also: generic web, cloud, and application security controls that are not specific to OTL.

Section references of the form "§x.y" refer to the OTL Identity Layer Specification unless stated otherwise.

---

## 2. System Overview

### 2.1 Components

| Component | Description |
|---|---|
| Participant DID | did:webvh (strongly recommended) or did:web identifier hosted on the participant's domain. For did:webvh, the DID document is derived from an append-only, hash-chained log (`did.jsonl`) whose genesis entry is bound to the identifier by the SCID. |
| DID Management Key | Key(s) listed in the did:webvh `updateKeys` parameter. Signs every log entry and can change any key, service, or parameter in the DID. |
| Witnesses | did:key identities whose threshold of proofs (`did-witness.json`) is required before a log entry is valid. Not defined in the OTL spec; used in the Fireblocks design. |
| Watchers | Services that retrieve, cache, and (in the OTL profile proposed by Fireblocks) sign observations of every log version. |
| Credential Issuer | Entity holding a did:webvh and a dedicated `#credential-issuance-key` that signs VCs and status lists (§3.2.1, §4.2). |
| OtlLeiCredential | VC binding a DID to an ISO 17442 LEI and GLEIF Level 1 data. Issued by an LOU (spec) or, in the Fireblocks deployment, by a Fireblocks authority DID. |
| whois VP | Verifiable Presentation published by the holder, containing the credentials it chooses to disclose (§4.4). |
| Bitstring Status List | Issuer-signed, GZIP-compressed bitstring credential used for revocation (§5). |
| Trust perimeter | Each verifier's local configuration of trusted issuer DIDs, credential types, and allow/deny lists (§6.1). |

### 2.2 Assets

| Asset | Why it matters |
|---|---|
| DID Management Keys (current and past) | Control of the identity; see Appendix A for what each key class enables. |
| Credential issuance keys | Control of legal-entity attribution for every subject the issuer vouches for, and of revocation. |
| Address claim keys (data layer) | Directly attest payment destinations; compromise leads to misdirected funds. |
| DID log and witness file integrity | Basis for every key lookup. |
| Hosting infrastructure (DNS, TLS certificates, web servers) | Controls what verifiers retrieve. |
| Trust perimeter configuration | Root of every trust decision a verifier makes. |
| Status list freshness | Determines whether revocations take effect. |
| Resolver and verifier infrastructure | Fetches attacker-supplied URLs; sits close to transaction systems. |
| Metadata about who resolves whom | Reveals commercial relationships and payment intent. |

---

## 3. Trust Assumptions

1. Cryptographic primitives (Ed25519, P-256, SHA-256, X25519) are secure when correctly implemented and parameter-validated.
2. TLS and the WebPKI authenticate hosts, subject to the known limits of domain-validated certificate issuance.
3. Domain control establishes cryptographic identity only; it says nothing about the legal entity (§2.5).
4. Legal-entity attribution is only as strong as the issuer's off-protocol verification process (LEI data is public; the DID-to-LEI binding is an operational decision).
5. Trust decisions are local (P5). There is no protocol-defined root; each verifier's perimeter configuration is assumed to be correct and integrity-protected.
6. Compromise recovery for trust anchors and DIDs is out-of-band (§5.4) and is assumed to be timely. This document treats that assumption as a risk.

---

## 4. Attacker Model

| ID | Attacker | Capabilities |
|---|---|---|
| A1 | Network attacker | Observes and manipulates traffic; cannot break TLS. |
| A2 | Domain or host controller | Controls what a participant's domain serves (DNS hijack, mis-issued certificate, web server or CDN compromise, dangling DNS, rogue proxy or cache). Holds no keys. |
| A3 | Past-key holder | Holds a DID Management Key that was active at some earlier log entry. |
| A4 | Current-key holder | Holds a key in the active `updateKeys`. |
| A5 | Malicious counterparty | Controls its own DID, domain, and whois; crafts DIDs, credentials, and URLs presented to verifiers. |
| A6 | Compromised or malicious issuer / trust anchor | Holds an issuer's `#credential-issuance-key`. |
| A7 | Insider | Cloud administrator, operator, compliance approver, or developer with access to enclave images, KMS policies, configuration, or approval devices. |
| A8 | Curious observer | Host, issuer, proxy, or watcher operator that learns from resolution and status-list traffic. |

Distinguishing A3 from A4 matters: they enable different attacks (Appendix A).

---

## 5. Threat Catalogue

Each threat lists the attacker classes involved, the attack, its impact, mitigations that already exist in the spec or design, and the remaining gap with recommendations. Severity is a first-pass qualitative rating (H / M / L) combining impact and likelihood; it is intended for discussion, not as a final risk score.

### 5.1 Control of the DID (Keys and Log)

#### T-DID-01 — Fork of the DID log using a past management key — **H**

- **Attacker:** A3 (optionally with A2 to serve the fork)
- **Attack:** Each log entry is signed by a key from the previous entry's `updateKeys`. Anyone holding a key that was authorised at entry *k*, even if it was rotated out later, can sign an alternative entry *k+1′* with a different `state` and attacker-chosen `updateKeys`, and then extend that branch indefinitely.
- **Impact:** An alternative, cryptographically valid history in which every key is attacker-controlled. Combined with A2, verifiers who have no prior state accept the fork; on its own, it supports false disputes ("Fireblocks signed this address").
- **Existing mitigations:** Witnesses must not sign two children of one parent. Watchers can detect divergence. The Fireblocks design adds witnesses and a credential-prescribed watcher set (Risk Committee Mitigations 1.2, 1.3).
- **Gaps and recommendations:**
  - The OTL spec mentions neither witnesses nor fork detection, so a verifier following the spec alone cannot detect a fork. Define an OTL witness profile (threshold, independence requirements) and make it REQUIRED for issuers and for DIDs used in high-value flows.
  - Require verifiers to cache the highest verified `versionId` per DID and fail on any divergence.
  - Rotated-out keys remain fork-capable for as long as they exist. Treat their destruction as a control with evidence; KMS deletion has a waiting period, so rotated-out keys need immediate disablement plus a deny policy.

#### T-DID-02 — Current management key compromise: undetectable takeover — **H**

- **Attacker:** A4
- **Attack:** The active DID Management Key can sign the next canonical log entry. The attacker rotates every key and service, replaces `watchers`, sets `ttl` to its maximum, and sets `updateKeys` to keys only they hold, locking out the legitimate operator.
- **Impact:** Complete identity takeover that extends the real log. Witnesses co-sign it because it validly extends the log they hold, and they do not check content or customer consent. Verifiers see an ordinary key rotation (§5.4).
- **Existing mitigations:** None at the protocol level. §3.2.2 requires the DID Management System to be treated as at least as sensitive as any key it manages.
- **Gaps and recommendations:**
  - Custody of the management key is the decisive control. Require dual control or an independent approval for every log entry, with the approval bound to the exact entry content.
  - Give witnesses a content policy for high-impact changes (rotation of address claim keys, service endpoint changes, `updateKeys` changes, deactivation): require an independent approval artefact rather than only checking log extension.
  - Notify the customer and alert operations on every published log entry, so an unexpected rotation is noticed within minutes.

#### T-DID-03 — Abuse of DID parameters after takeover — **M**

- **Attacker:** A3 on a fork, A4 on the canonical log
- **Attack:** Beyond replacing keys and services, an attacker can:
  - Replace the `watchers` parameter (a new value replaces the active set), so the key the watchers guard against controls the watcher list.
  - Set `ttl` up to 2^31 seconds so verifiers cache poisoned state long after recovery, or `0` to force load.
  - Deactivate the DID or set `updateKeys: []`, permanently destroying or freezing it.
  - Add `PathHandler` services or override `#whois` / `#files` to redirect retrieval to attacker hosts.
- **Gaps and recommendations:** Verifiers MUST cap `ttl` locally (for example at 300 seconds for high-value flows), and MUST NOT accept `#whois` / `#files` overrides pointing outside the DID's own origin. The authoritative watcher set must come from outside the DID log (as the Risk Committee design does through the hosting credential).

#### T-DID-04 — Key reuse across purposes — **M**

- **Attacker:** A3, A4, A6
- **Attack:** did:webvh allows an `updateKeys` key to also appear as a `verificationMethod`. A key used for routine signing is then also the identity's master key.
- **Recommendation:** The DID Management Key MUST NOT appear in any verification relationship, and no key may serve more than one OTL purpose. Verifiers SHOULD reject DIDs that violate this.

#### T-DID-05 — Rotation back to a previously used key — **M**

- **Attacker:** A3, A7
- **Attack:** If the signing system does not remember every key it has ever published, a rotation can reintroduce a previously rotated-out, possibly compromised key. The Risk Committee `Rotate Key` precondition ("the key must not yet exist") is ambiguous.
- **Recommendation:** The enclave keeps the full key history per DID and rejects any previously published key. Define `Rotate Key` precisely: the key type must exist, the new key must never have been published, and exactly one key per type exists afterwards.

#### T-DID-06 — Witness unavailability blocks emergency rotation — **M**

- **Attacker:** A1/A2 against witness infrastructure, A7
- **Attack:** Every update requires k-of-n witness proofs. Taking down n−k+1 witnesses blocks all updates, including the emergency rotation needed during an incident. Witnesses are static did:key identities, and replacing a witness requires a threshold of the existing set.
- **Recommendation:** Size k and n for availability, place witnesses in independent failure domains (including at least one outside Fireblocks), and document an emergency procedure.

#### T-DID-07 — Witnesses share fate with the controller — **M**

- **Attacker:** A7
- **Attack:** All witnesses in the Fireblocks design are Fireblocks-operated, sharing administrators, CI/CD, and cloud accounts. A single insider or pipeline compromise can satisfy the threshold.
- **Recommendation:** At least one witness operated by an independent party, with its own approval policy.

### 5.2 Resolution, Transport, and Domain

#### T-RES-01 — SSRF and network-boundary abuse through resolution — **H**

- **Attacker:** A5
- **Attack:** DIDs, issuer DIDs, `statusListCredential` URLs, JSON-LD contexts, and service endpoints are attacker-supplied URLs that the verifier fetches. did:webvh reports that all four reviewed implementations were vulnerable to at least one of: automatic redirects, IP-literal hosts, percent-encoding case handling, or traversal after decoding. A verifier running inside a core network or VPC (as in the Bridging design) exposes internal services.
- **Recommendation:** Run all resolution through an egress-restricted resolver service in a DMZ. Implement the did:webvh resolver hardening list in full (no automatic redirects, IP-literal rejection before and after decoding, case-insensitive percent decoding, size caps, timeouts, HTTPS only). Resolve DNS once and connect to that address to defeat rebinding.

#### T-RES-02 — Rollback to a stale or truncated log — **H**

- **Attacker:** A2
- **Attack:** The host (or a CDN or cache) serves an older valid prefix of the log, so the verifier accepts a key that was rotated out because it was compromised. Default `ttl` of 3600 seconds lets stale state persist after an incident even without an attacker.
- **Recommendation:** Verifiers MUST store the highest verified `versionId` per DID and fail on a shorter log; define a maximum staleness for high-value flows; cross-check against the prescribed watchers.

#### T-RES-03 — Split view — **H**

- **Attacker:** A2 alone (serving different valid prefixes to different audiences); A2 with A3/A4 (serving forks)
- **Attack:** Targeted verifiers see a different DID state from everyone else.
- **Existing mitigations:** Watchers (SHOULD, §2.4); witnesses (Fireblocks design only).
- **Recommendation:** For high-value interactions, verifiers MUST compare the retrieved log against at least one independent watcher and fail on divergence.

#### T-RES-04 — First contact has no fork detection — **M**

- **Attacker:** A2 with A3
- **Attack:** A verifier resolving a DID for the first time has no cached state, so cache-based fork and rollback detection gives no protection.
- **Recommendation:** On first contact, require watcher corroboration, or mandatory witnesses for the DID class being trusted.

#### T-RES-05 — Stripping the hosting / watcher credential — **M**

- **Attacker:** A2 with A3/A4
- **Attack:** The Fireblocks design prescribes the authoritative watcher set in a Fireblocks-issued hosting credential. Disclosure in the whois VP is the holder's choice (§4.4), so an attacker who has taken over a DID simply omits that credential while keeping the LEI credential.
- **Recommendation:** Verifiers must decide from out-of-band knowledge (for example, a configured domain suffix) that a DID is Fireblocks-hosted and fail closed without the credential. Define the hosting credential type in the spec (§4.7 currently lists only OtlLeiCredential).

#### T-RES-06 — Downgrade to did:web — **M**

- **Attacker:** A2
- **Attack:** A participant publishing both did:webvh and a parallel did:web exposes an unverifiable path; a verifier accepting the did:web form loses history and rotation guarantees.
- **Recommendation:** Verifiers MUST reject did:web for issuers and trust anchors (§4.2 already requires issuers to hold a did:webvh) and SHOULD prefer the did:webvh form whenever both exist.

#### T-RES-07 — WebPKI and DNS weaknesses — **M**

- **Attacker:** A2
- **Attack:** Domain-validated certificate mis-issuance (for example via BGP hijack and ACME), DNS hijack, or dangling DNS records give domain control. A wildcard certificate for a shared hosting domain is a single high-value key for every hosted DID.
- **Recommendation:** DNSSEC, CAA records, Certificate Transparency monitoring, removal of dangling records, and per-DID or short-lived certificates where practical.

#### T-RES-08 — Resolver denial of service and amplification — **M**

- **Attacker:** A5
- **Attack:** Oversized or slowly streamed logs, logs with many entries, and whois presentations containing many credentials (see T-VC-06).
- **Recommendation:** Byte and entry-count caps per DID, operation timeouts, concurrency and rate limits, especially for previously unseen DIDs.

#### T-RES-09 — Untrusted time — **L**

- **Attacker:** A1, A7
- **Attack:** `versionTime` tolerance, credential `validFrom`, and verifiable-address expiry all depend on clocks. Enclaves typically derive time from the host, so a host-controlled clock can skew expiry checks and the `versionTime` the enclave signs.
- **Recommendation:** Confirm the enclave's time source; bound acceptable drift; avoid security decisions inside the enclave that depend on host-supplied time alone.

### 5.3 Credential Verification (§4, §5.3)

#### T-VC-01 — Credential replay through missing subject binding — **H**

- **Attacker:** A5
- **Attack:** VCs are public. The §5.3 validation steps check proof, revocation, and trust perimeter, but not that `credentialSubject.id` equals the VP `holder` and the DID being authenticated. An attacker copies another entity's LEI credential into their own whois VP.
- **Recommendation:** Add to §5.3 as MUST: `credentialSubject.id` == VP `holder` == authenticated DID; the VP proof verifies against the holder's DID; `type` contains the expected credential type; `validFrom` is not in the future; the issuer DID uses did:webvh; issuer ≠ subject, compared across `alsoKnownAs` forms (a string comparison alone is bypassed by a did:web alias).

#### T-VC-02 — Undefined DID document version for verifying credentials — **H**

- **Attacker:** A6, or availability failure
- **Attack:** §3.3 says a key is valid only while present in the *current* DID document. Taken literally, rotating `#credential-issuance-key` invalidates every credential and status list it ever signed. If verifiers instead verify against the historical version, a holder of a compromised issuance key can backdate `validFrom`.
- **Recommendation:** Decide explicitly. One workable option: verify against the version current at verification time, require issuers to re-sign outstanding credentials before retiring a key, and support an overlap period in which old and new issuance keys are both listed.

#### T-VC-03 — Expiry not enforced by verifiers — **M**

- **Attacker:** A5 (benefiting from issuer inaction)
- **Attack:** OtlLeiCredential has no `validUntil`. Expiry lives in `registration.nextRenewalDate` and is enforced only if the issuing LOU revokes. Verifiers are not required to check the date.
- **Recommendation:** Issuers MUST set `validUntil` no later than `nextRenewalDate`; verifiers MUST reject expired credentials independently of revocation.

#### T-VC-04 — Network fetches before the trust check — **H**

- **Attacker:** A5
- **Attack:** §5.3 resolves the issuer DID and fetches the status list (steps 1–2) before checking whether the issuer is trusted (step 3). Any attacker-crafted credential triggers fetches to attacker-chosen hosts, enabling SSRF, DoS, and tracking.
- **Recommendation:** Reorder: check issuer DID and credential type against the trust perimeter first, then perform network I/O.

#### T-VC-05 — No scoping of issuers to credential types — **M**

- **Attacker:** A6
- **Attack:** An issuer trusted for one claim (for example "hosted on Fireblocks") can also issue LEI credentials, and verifiers that trust the issuer DID accept both.
- **Recommendation:** The trust perimeter MUST be keyed on (issuer DID, credential type), not on issuer DID alone.

#### T-VC-06 — whois amplification — **M**

- **Attacker:** A5
- **Attack:** A whois VP may contain many credentials, each with a distinct issuer and status URL. Combined with T-VC-04, one resolution fans out into hundreds of fetches.
- **Recommendation:** Cap credentials processed per VP; process only recognised types from trusted issuers.

#### T-VC-07 — Stale or weak attributes — **M**

- **Attacker:** A5
- **Attack:** Credentials are snapshots. Name changes, mergers, and LEI status changes (lapsed, retired, merged, annulled) before the renewal date are not reflected. `corroborationLevel: PENDING` credentials can be issued and nothing tells verifiers to reject them. There is no LEI registration-status field.
- **Recommendation:** Add a registration-status field; require revocation on any status change, not only lapse; verifiers in high-assurance flows SHOULD require `FULLY_CORROBORATED`.

#### T-VC-08 — Absence of negative evidence — **L**

- **Attacker:** A5
- **Attack:** Holders choose what to disclose and will omit unfavourable credentials (for example a failed audit attestation).
- **Recommendation:** Verifier policy should require positive credentials and treat absence as absence, never as a pass.

#### T-VC-09 — Delegation is invisible to verifiers — **M**

- **Attacker:** A7 (at a provider)
- **Attack:** §2 lets participants delegate protocol participation to a software provider, but nothing expresses the delegation. Verifiers cannot tell a self-operated DID from a provider-operated one, or factor the provider's security into their trust decision.
- **Recommendation:** Define a hosting / delegation credential type, issued by the provider and bound to the SCID, and let verifiers apply policy based on it.

#### T-VC-10 — Opaque trust signals for anonymous participants — **L**

- **Attacker:** A5, malicious wallet or provider
- **Attack:** §7.2 envisages dApps consuming an opaque pass/fail from a wallet or provider. A malicious or compromised provider, or UI spoofing, defeats the check.
- **Recommendation:** Document this as a trust delegation in §7 and encourage local verification where feasible.

### 5.4 Revocation (Bitstring Status List)

#### T-REV-01 — Status list rollback — **H**

- **Attacker:** A2, including the privacy proxy recommended in §5.3 or any cache
- **Attack:** `validFrom`, `ttl`, and `validUntil` are optional and there is no sequence number. An older, validly signed list in which a revoked credential's bit is still 0 can be replayed indefinitely.
- **Recommendation:** Require `validFrom` and `validUntil` on status list credentials; verifiers MUST reject lists older than a configured maximum age and MUST NOT accept a list older than one previously seen.

#### T-REV-02 — Status list not bound to the credential issuer — **M**

- **Attacker:** A6, or an attacker who later controls the status-list host (for example an expired domain)
- **Attack:** §5.3 step 2 verifies the status list's own proof but does not say against whom. A list signed by a different DID could be accepted.
- **Recommendation:** State in §5.3 that the status list `issuer` MUST equal the VC `issuer` and the proof MUST be by that issuer's designated status-list key (see T-REV-05). The W3C Bitstring Status List algorithm may already cover part of this; OTL should state it explicitly.

#### T-REV-03 — Decompression bomb — **M**

- **Attacker:** A5, A6
- **Attack:** The spec sets a minimum list length but no maximum; a tiny GZIP payload can decompress to gigabytes.
- **Recommendation:** Cap both compressed and decompressed size, and stream-decompress with a hard limit.

#### T-REV-04 — Availability versus freshness — **M**

- **Attacker:** A1/A2 against the issuer's status endpoint
- **Attack:** §5.3 fails closed when a status list cannot be fetched, so a DoS against one issuer (for example the Fireblocks authority) halts validation for every counterparty. Failing open instead enables T-REV-01. With a 5-minute `ttl`, there is also an inherent revocation latency window.
- **Recommendation:** Define the policy per risk tier: fail closed for high-value transfers, bounded stale use for informational display. Host status lists on resilient, cache-friendly infrastructure.

#### T-REV-05 — Shared key for credentials and status lists bypasses approval — **H**

- **Attacker:** A7, or compromise of the automation that publishes status lists
- **Attack:** §5.2 signs status lists with `#credential-issuance-key`, the key §3.2.1 justifies as low-frequency and high-assurance. Status lists need frequent automated signing. In the Fireblocks design, LEI issuance requires compliance approval. If the enclave auto-signs status lists with the same key, a payload shaped like a status list but carrying additional types (for example `["VerifiableCredential", "OtlLeiCredential", "BitstringStatusListCredential"]`) could obtain an LEI credential signature without approval unless the enclave enforces a strict schema. Whoever can sign status lists can also revoke every credential (DoS).
- **Recommendation:** Introduce a separate status-list signing key, or have the enclave enforce an exact schema for status lists. Verifiers SHOULD reject credentials whose `type` mixes credential and status-list types.

#### T-REV-06 — Correlation through status checks — **L**

- **Attacker:** A8
- **Attack:** Random `statusListIndex` assignment is only a SHOULD; small lists or per-subject lists enable correlation. The recommended proxy becomes a party that sees all lookups.
- **Recommendation:** Make random index assignment a MUST; prohibit holder-specific status list URLs (as did:webvh's privacy considerations already require).

### 5.5 Trust Anchors and Trust Perimeter

#### T-TA-01 — Tampering with trust perimeter configuration — **H**

- **Attacker:** A7
- **Attack:** Inserting one attacker-controlled issuer DID into a verifier's trust perimeter defeats all attribution. The Bridging design hardcodes the other environments' authority DIDs, making that configuration a high-value target.
- **Recommendation:** Pin full DIDs including SCID; require `portable: false` for pinned anchors (currently only SHOULD NOT in §3.4); place configuration under dual-control change management with signed artefacts and alerting on change.

#### T-TA-02 — Unscoped cross-environment issuers — **H**

- **Attacker:** A6 (one environment's authority), A7
- **Attack:** In the Bridging design each environment trusts the others' authority DIDs for all claims. A compromised US authority can attest "Fireblocks-hosted" or LEI credentials for DIDs hosted in EU or CH, so a compromise in one environment crosses the regulatory segregation boundary.
- **Recommendation:** Apply name-constraint style rules: an environment's authority is trusted only for DIDs under that environment's hosting domain.

#### T-TA-03 — No on-protocol response to anchor or issuer compromise — **H**

- **Attacker:** A6
- **Attack:** An attacker holding an issuer key can issue unlimited credentials and sign status lists showing them as unrevoked. §5.4 relies on an unspecified out-of-band channel. A "distrust credentials issued after time T" cut-off fails because the attacker backdates `validFrom`.
- **Recommendation:** Define the incident channel (at minimum, contact points and response expectations). Consider a credential transparency mechanism (for example watcher-signed first-seen timestamps for issued credentials) so cut-offs can rely on independently observed issuance times.

#### T-TA-04 — Spoofed compromise reports — **M**

- **Attacker:** A5
- **Attack:** §5.4 recovery has the legitimate operator ask issuers out-of-band to revoke or reissue. An attacker impersonates a victim and requests revocation of the victim's credentials.
- **Recommendation:** Issuers maintain authenticated revocation-request procedures with pre-registered contacts, and publish time-to-revoke commitments.

#### T-TA-05 — LEI credentials from non-LOU issuers — **M**

- **Attacker:** Confusion rather than a specific attacker; exploitable by A6/A7
- **Attack:** §4.6 and §4.8 define LOUs as the issuers of OtlLeiCredential, but the Fireblocks deployment has a Fireblocks authority DID issue it. Verifiers cannot distinguish "a GLEIF-accredited LOU attested this" from "Fireblocks compliance attested this", and `registration.managingLou` is then inconsistent with `issuer`.
- **Recommendation:** Either define a separate credential type for operator-attested LEI bindings, or define how `issuer` and `managingLou` relate and what verifiers should conclude from each.

#### T-TA-06 — Fraudulent DID-to-LEI binding — **H**

- **Attacker:** A5 (social engineering), A7 (insider)
- **Attack:** LEI data is public, so the only control is the issuer's verification of who controls the DID. In the Fireblocks design this is a compliance approval on a phone. Weak points: onboarding fraud, insider collusion, approval fatigue, a gap between what the approver sees and what is signed, replay of an approval for a different DID, and single-approver decisions. Multiple DIDs per LEI, or competing issuers for the same LEI, can produce conflicting claims.
- **Recommendation:** Quorum approval; approval payloads that display and bind DID, LEI, and legal name, with nonce and expiry; enclave rejects approvals not bound to the exact request; monitoring for multiple DIDs per LEI.

### 5.6 Cryptography and Parsing

#### T-CRY-01 — Algorithm and key-type confusion — **H**

- **Attacker:** A5
- **Attack:** §3.1.1 lets the signer choose the algorithm and suggests verifiers support "any JWK-representable curve". Without an allowlist and binding between cryptosuite and key type, verifiers may accept weak curves, invalid points, or a cryptosuite inconsistent with the key. The weakest accepted option sets the security floor.
- **Recommendation:** Normative allowlist (Ed25519, P-256 for VCs; X25519, P-256 for key agreement); verifiers MUST bind `eddsa-jcs-2022` to Ed25519 keys and `ecdsa-jcs-2019` to P-256 keys, and MUST validate points.

#### T-CRY-02 — Key-purpose confusion and JWS header trust — **M**

- **Attacker:** A5
- **Attack:** A signature is accepted because the key appears anywhere in the DID document rather than under the intended relationship and id. For verifiable addresses, the JWS `kid` and `alg` headers are attacker-controlled.
- **Recommendation:** Verifiers MUST require the key under the expected verification relationship (`assertionMethod` for credential issuance) with the expected fragment id and key type. The `kid` DID MUST match the claimed signer; `alg` MUST be determined by the key type, never by the header.

#### T-CRY-03 — JSON-LD context handling — **M**

- **Attacker:** A5
- **Attack:** §4.3 allows additional contexts. Remote context loading creates SSRF and substitution risk; term redefinition can change meaning for processors that interpret JSON-LD.
- **Recommendation:** Static context allowlist, no remote context loading, and processing as plain JSON against a strict schema (the JCS cryptosuites do not require JSON-LD processing).

#### T-CRY-04 — Parser differentials — **M**

- **Attacker:** A5
- **Attack:** Duplicate JSON keys, number serialisation differences under JCS, multi-typed credentials, and `credentialSubject` as an array can cause the signer, verifier, and display layer to read different values.
- **Recommendation:** Reject duplicate keys; strict schemas per credential type; conformance test vectors for the spec-refinement track.

#### T-CRY-05 — Display spoofing — **M**

- **Attacker:** A5
- **Attack:** `legalName`, `otherNames`, and DID domain labels displayed to operators can use homoglyphs, bidirectional override characters, or look-alike names.
- **Recommendation:** Normalise and sanitise displayed strings; always display LEI and DID alongside names.

### 5.7 Fireblocks-Hosted Deployment

#### T-FB-01 — Enclave state rollback — **H**

- **Attacker:** A7 (control of the parent instance)
- **Attack:** Nitro enclaves have no persistent storage, so the "latest document version per SCID" comes from the untrusted parent. A malicious parent presents an older version as current and the enclave signs a fork.
- **Recommendation:** Anchor the latest version outside the parent's control (witness proofs, a monotonic counter, or a signed head stored externally), and have witnesses enforce one child per parent.

#### T-FB-02 — KMS and enclave governance — **H**

- **Attacker:** A7
- **Attack:** Changing a KMS key policy, adding a PCR value to the allow-list (which is effectively the root key), tampering with the enclave image supply chain, or granting oneself the signer role (Risk Committee Threat 2).
- **Recommendation:** Dual control on key policy and PCR allow-list changes; reproducible enclave builds; immutable logging with alerting; authenticated callers for every enclave operation.

#### T-FB-03 — Signing oracle within allowed rules — **M**

- **Attacker:** A7, or a compromised product service
- **Attack:** A compromised internal service can push many valid-looking atomic changes (`Add Service`, `Add Key`) across many customers within the enclave's rules.
- **Recommendation:** Per-DID and global rate limits, anomaly detection, strict service-type allowlists and endpoint patterns, and customer notification on document changes.

#### T-FB-04 — Hosting namespace abuse — **M**

- **Attacker:** A5, A7
- **Attack:** The enclave validates the pattern `*.otl.fireblocks.com` while examples use `otl-network.fireblocks.com`; a loose wildcard match can accept deeper labels. Customer-derived subdomain names invite squatting, reserved-name abuse, and internationalised look-alikes. Reusing a subdomain after offboarding causes misattribution; dangling records enable takeover.
- **Recommendation:** Exact label-count matching, a reserved-name list, ASCII-only labels for hosted DIDs, no subdomain reuse, and DNS hygiene monitoring.

#### T-FB-05 — Offboarding and portability — **M**

- **Attack:** With `portable: false`, hosted DIDs are permanently tied to the Fireblocks domain. On customer exit, the hosting credential, watcher records, and DID state need defined handling, or the DID continues to claim Fireblocks safeguarding.
- **Recommendation:** Define an offboarding procedure: revoke the hosting credential, deactivate the DID, notify watchers, and decide how the customer obtains a new identity.

#### T-FB-06 — Split-horizon resolution across environments — **M**

- **Attacker:** A7, misconfiguration
- **Attack:** Cross-environment traffic over VPN and public resolution can return different views of the same DID.
- **Recommendation:** Watchers cross-check internal and public views and alert on divergence.

#### T-FB-07 — Inconsistent internal design documents — **M**

- **Attack surface:** Implementers following inconsistent documents will build inconsistent controls.
  - The Bridging document puts issuer DIDs in a keyless MPC workspace with phone approvals; the Risk Committee decision puts them in KMS with the enclave validating compliance signatures.
  - The Risk Committee verification procedure ("each version signed by the previous version's key") omits the entryHash chain, `versionTime` monotonicity, SCID consistency across entries, and witness verification.
  - Implementation endpoints use `whois.json`; the corrected spec and did:webvh use `whois.vp`.
- **Recommendation:** Reconcile the documents and point verifier implementations at the did:webvh resolution algorithm plus the OTL additions in Section 7, rather than a summary.

### 5.8 Privacy

#### T-PRV-01 — Resolution metadata reveals relationships — **M**

- **Attacker:** A8
- **Attack:** As host of all customer DIDs, Fireblocks sees which external parties resolve which customer, which reveals payment intent and commercial relationships. Issuers see status-list fetches.
- **Recommendation:** Caching-friendly responses (CDN), minimal access logging with retention limits, and support for watcher-based resolution.

#### T-PRV-02 — Customer enumeration — **M**

- **Attacker:** Any observer
- **Attack:** Certificate Transparency logs, public DID logs, and whois presentations enumerate Fireblocks customers and publish the customer-to-LEI link.
- **Recommendation:** Confirm customer consent for public listing; prefer certificates that do not disclose per-customer names; consider opaque subdomain labels.

#### T-PRV-03 — Long-term correlation — **L**

- **Attacker:** A8
- **Attack:** Static DIDs and status-list access patterns allow correlation of activity over time.
- **Recommendation:** Accept as inherent for institutional identities; avoid putting unnecessary endpoints or personal data in DID documents.

---

## 6. Architectural Risk: Concentration of Control

This is not an attack vector in itself but determines the impact of several threats above.

Under the Risk Committee decision, Fireblocks controls the DID management keys, the hosting domain and TLS certificates, the credential issuance keys, the status lists, all witnesses, and all but one watcher for every hosted identity. A single breach of the hosting environment, or a single malicious insider with sufficient access, can therefore affect all hosted identities at once (T-DID-02, T-FB-01, T-FB-02, T-TA-06).

This contrasts with the spec's design principles that no single operator sits in the resolution path for any other participant (P3, P4), and with the earlier proposal to hold DID management keys as customer-owned MPC keys (Risk Committee Mitigation 1.1).

Recommendations:

1. State the concentration explicitly in the risk acceptance, together with the compensating controls relied upon.
2. Introduce independence where it is cheapest: at least one independent witness, independent watchers, and dual control on every use of the DID management keys.
3. Keep the customer-controlled management key option on the roadmap, and have the hosting credential state which custody model applies so verifiers can price it in (T-VC-09).

---

## 7. Proposed Normative Changes to the Specification

These are the protocol-level changes recommended for the spec-refinement track. Each would be marked "Proposed" in the next draft.

| # | Section | Proposed change | Threats addressed |
|---|---|---|---|
| 1 | §5.3 | Check issuer DID and credential type against the trust perimeter before any network I/O. | T-VC-04, T-VC-06, T-RES-01 |
| 2 | §5.3 | Add MUST checks: subject == holder == authenticated DID; VP proof; `type`; `validFrom`; `validUntil`; issuer method is did:webvh; issuer ≠ subject across aliases. | T-VC-01, T-VC-03 |
| 3 | §3.3 / §4 | Define which DID document version verifies a credential, and the issuance key rotation procedure. | T-VC-02 |
| 4 | §4.9 | Require `validUntil` ≤ `nextRenewalDate`; add a registration-status field; require revocation on any LEI status change. | T-VC-03, T-VC-07 |
| 5 | §6.1 | Key the trust perimeter on (issuer DID, credential type); allow domain scoping of issuers. | T-VC-05, T-TA-02 |
| 6 | §5.2 / §5.3 | Require status list `validFrom` / `validUntil`, maximum age, monotonic acceptance, issuer equality, and size caps. | T-REV-01, T-REV-02, T-REV-03 |
| 7 | §3.2 | Introduce a separate status-list signing key, or require strict schema separation. | T-REV-05 |
| 8 | §3.1.1 / §6.3 | Algorithm allowlist; cryptosuite-to-key-type binding; point validation; key under the expected relationship and id. | T-CRY-01, T-CRY-02 |
| 9 | §2 / §3.2 | Verifiers cache the highest verified `versionId`; cap `ttl`; reject off-origin `#whois` / `#files` overrides; forbid key reuse across purposes. | T-RES-02, T-DID-03, T-DID-04 |
| 10 | New section | OTL witness and watcher profile: when required, independence requirements, verifier behaviour on divergence, first-contact policy. | T-DID-01, T-RES-03, T-RES-04 |
| 11 | §4.7 | Define hosting / delegation credential type, including the authoritative watcher set and custody model. | T-RES-05, T-VC-09 |
| 12 | §4.3 / §6.3 | Static context allowlist, no remote context loading, strict schemas, reject duplicate keys. | T-CRY-03, T-CRY-04 |
| 13 | §5.4 | Define minimum incident-channel expectations and authenticated revocation-request procedures. | T-TA-03, T-TA-04 |
| 14 | §4.6 / §4.8 | Clarify LEI credentials issued by non-LOU operators. | T-TA-05 |
| 15 | New section | Resolver hardening requirements (reference did:webvh security considerations as normative for OTL verifiers). | T-RES-01, T-RES-08 |

---

## 8. Open Questions

1. Which DID document version should verify a credential, and how should issuance key rotation work in practice? (T-VC-02)
2. Should witnesses be mandatory for issuers and for DIDs used in payment flows, and who outside Fireblocks operates one? (T-DID-01, T-DID-07)
3. Which approval policy governs each use of a DID management key, given that compromise of the current key is an undetectable takeover? (T-DID-02)
4. What is the fail-closed / fail-open policy per transfer risk tier when status lists are unreachable? (T-REV-04)
5. Will Fireblocks-issued LEI credentials use the OtlLeiCredential type, or a distinct type? (T-TA-05)
6. How many compliance approvers are required for an LEI binding, and what exactly does the approval device display? (T-TA-06)
7. What share of address-risk management does Fireblocks assume versus require of customers (open item from the Risk Committee)?

---

## 9. Priority Summary

| Priority | Threats | Rationale |
|---|---|---|
| 1 — Verifier correctness | T-VC-01, T-VC-02, T-VC-04, T-CRY-01, T-CRY-02, T-RES-02 | Cheap to fix in spec text and verifier code; failures here undermine every other control. |
| 2 — Revocation integrity | T-REV-01, T-REV-02, T-REV-03, T-REV-05 | Revocation is the routine compromise response; rollback or key sharing silently disables it. |
| 3 — Key custody and fork resistance | T-DID-01, T-DID-02, T-FB-01, T-FB-02 | Determines whether a key compromise is detectable and containable. |
| 4 — Trust anchor lifecycle and scoping | T-TA-01, T-TA-02, T-TA-03, T-TA-06, T-VC-05 | Largest blast radius; mostly configuration and policy work. |
| 5 — Systemic risk acceptance | Section 6 | Needs an explicit decision rather than an engineering fix. |

---

## Appendix A — What Each Management Key Class Enables

| Key held by attacker | Can extend canonical log? | Can fork? | Detectable by |
|---|---|---|---|
| Past key (authorised at entry *k*, since rotated out) | No | Yes, from entry *k+1* | Witnesses (refuse second child), watchers, verifier caches of later versions |
| Current key (in the active `updateKeys`) | Yes | Yes | Only witness content policies, customer notification, or out-of-band review; log extension itself is valid |
| Domain control only (A2) | No | No, but can serve truncated or per-audience prefixes | Verifier caches, watchers |

Implications: protection against management key compromise rests on custody and approval of the current key, on destroying rotated-out keys, and on fork detection by witnesses or watchers. Nothing in the log itself distinguishes a legitimate rotation from one made with a stolen current key.