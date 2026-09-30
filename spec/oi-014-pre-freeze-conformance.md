# OI-014 Pre-Freeze Conformance Matrix

**Status:** DRAFT — pre-freeze review  
**Scope:** OI-014 DelegationGrant v1 core semantics and candidate wire schema  
**Cross-language checkpoint:** DG01-DG07 and DGI01-DGI31 independently verified in Python and Java

## 1. Positive-path coverage

| Vector | Requirement exercised | Status |
|---|---|---|
| DG01 | Direct registration; current DelegationPolicy; canonical GrantBytes/GrantId; registry-domain binding; revision-1 ACTIVE record | COVERED |
| DG02 | Threshold DelegationPolicy; canonical method/proof ordering | COVERED |
| DG03 | PRESERVE_EXISTING DelegationPolicy rotation; unchanged delegation generation; existing grant survives without record mutation | COVERED |
| DG04 | Individual grantor revocation through current ControllerPolicy; exact-next revision; previous RecordHash; terminal REVOKED | COVERED |
| DG05 | INVALIDATE_EXISTING generation change; ACTIVE record unchanged; grant unusable by generation mismatch | COVERED |
| DG06 | Child issuance; same rootGrantor; issuer=parent delegate; explicit redelegation; strict attenuation; current AuthenticationAuthority; parent RecordHash binding | COVERED |
| DG07 | OPENIDENTITY delegate relinquishment through current AuthenticationAuthority; terminal REVOKED | COVERED |

## 2. Core attack coverage

| Vector | Attack / invariant | Stable error | Status |
|---|---|---|---|
| DGI01 | Rotated-out DelegationPolicy / historical-state backdating | UNAUTHORIZED_GRANT_REGISTRATION | COVERED |
| DGI02 | Wrong root delegation generation | INVALID_DELEGATION_GENERATION | COVERED |
| DGI03 | Cross-registry registration-proof replay | CROSS_DOMAIN_PROOF | COVERED |
| DGI04 | Stale parent RecordHash | INVALID_PREVIOUS_RECORD_HASH | COVERED |
| DGI05 | Child capability escalation | CAPABILITY_ESCALATION | COVERED |
| DGI06 | Child issuance from REVOKED parent | PARENT_GRANT_UNUSABLE | COVERED |
| DGI07 | Child changes rootGrantor | ROOT_GRANTOR_MISMATCH | COVERED |
| DGI08 | Child issuer != parent delegate | ISSUER_PARENT_DELEGATE_MISMATCH | COVERED |
| DGI09 | Child lifetime widening | CHILD_TIME_WIDENING | COVERED |
| DGI10 | Possession without explicit redelegation authority | REDELEGATION_NOT_AUTHORIZED | COVERED |
| DGI11 | Capability profile substitution | PROFILE_SUBSTITUTION | COVERED |
| DGI12 | Duplicate REGISTER after terminal REVOKED state | TERMINAL_GRANT_STATE | COVERED |
| DGI13 | expiresAt <= registeredAt | GRANT_EXPIRED_AT_REGISTRATION | COVERED |
| DGI14 | notBefore >= expiresAt | INVALID_TIME_RANGE | COVERED |
| DGI15 | Revocation proof bound to stale root StateHash | INVALID_ROOT_STATE_HASH | COVERED |
| DGI16 | Revocation proof substituted as relinquishment | CROSS_DOMAIN_PROOF | COVERED |
| DGI17 | Grant revision skip | INVALID_GRANT_REVISION | COVERED |
| DGI18 | registryDomain mutation within record chain | REGISTRY_DOMAIN_MISMATCH | COVERED |
| DGI19 | ControllerPolicy used as delegate AuthenticationAuthority | INVALID_REGISTRATION_PROOF | COVERED |
| DGI20 | Stale delegate AuthenticationPolicy / StateHash | INVALID_ROOT_STATE_HASH* | COVERED; ERROR NAME REVIEW |
| DGI21 | Wrong delegate authentication generation | INVALID_AUTHENTICATION_GENERATION | COVERED |
| DGI22 | OPENIDENTITY delegate AuthenticationPolicy absent | INVALID_REGISTRATION_PROOF | COVERED |
| DGI23 | DEACTIVATED delegate attempts child issuance | INVALID_REGISTRATION_PROOF | COVERED |
| DGI24 | Child-issuance proof substituted as relinquishment | CROSS_DOMAIN_PROOF | COVERED |
| DGI25 | Required parent GrantBytes unavailable | PARENT_GRANT_NOT_FOUND | COVERED |
| DGI26 | Supplied parent bytes do not hash to committed parentGrantId | PARENT_GRANT_NOT_FOUND | COVERED |
| DGI27 | Parent authoritative record from wrong registryDomain | REGISTRY_DOMAIN_MISMATCH | COVERED |
| DGI28 | Ancestor root delegation generation invalidated | PARENT_GRANT_UNUSABLE | COVERED |
| DGI29 | Ancestor expired at exclusive upper boundary | PARENT_GRANT_UNUSABLE | COVERED |
| DGI30 | Profile maximum chain depth exceeded | DELEGATION_DEPTH_EXCEEDED | COVERED |
| DGI31 | Delegation cycle | DELEGATION_CYCLE | COVERED |

* DGI20 currently uses INVALID_ROOT_STATE_HASH although the stale state belongs to the delegate rather than rootGrantor. This should be resolved before freeze.

## 3. Release-blocking gaps before byte freeze

### G1 — delegate StateHash error taxonomy

The stable error taxonomy distinguishes delegation generation from authentication generation, but does not distinguish rootGrantor StateHash mismatch from delegate authentication StateHash mismatch.

Recommended resolution:

    INVALID_ROOT_STATE_HASH
    INVALID_DELEGATE_STATE_HASH

DGI20 should use INVALID_DELEGATE_STATE_HASH.

### G2 — current DelegationPolicy revocation positive path

DG04 proves ControllerPolicy emergency revocation. The specification also permits current DelegationPolicy revocation, but no positive vector currently proves that authorization path.

Add one positive vector before freeze.

### G3 — profile descriptor wire schema

Vectors use deterministic vector-local ProfileDescriptor maps to derive ProfileHash, but the candidate CDDL defines ProfileRef without a normative ProfileDescriptor CDDL.

Before freeze, either:

1. define the core ProfileDescriptor canonical wire schema; or
2. explicitly move ProfileDescriptor encoding to a separate profile-registry specification and remove any implication that OI-014 core freezes those descriptor bytes.

A profileHash cannot be independently interoperable without an unambiguous canonical descriptor representation.

### G4 — PROFILE_PRINCIPAL proof envelope

Core CDDL now concretely defines OPENIDENTITY child/relinquishment proof collections using AuthenticationPolicy method signatures. PROFILE_PRINCIPAL remains semantically profile-owned, but the same child-registration-request structure cannot represent both models without an explicit tagged proof union.

Before freeze define a wire-level delegate-proof union, for example:

    delegate-proof =
        openidentity-delegate-proof /
        profile-principal-proof

and bind both forms to the same core OI-014 signing purpose.

### G5 — stable error coverage / naming pass

Several stable errors are defined but not yet exercised, including malformed GrantId/RecordHash/ProfileHash cases, unknown profile, duplicate capability set, resource widening, revision overflow, and hash-collision/integrity handling.

Not every parser error needs a dedicated frozen vector, but security-significant stable errors should either:
- receive concrete vectors; or
- be explicitly classified as structural/parser/profile-suite coverage outside the core cryptographic vector set.

## 4. Important non-blocking integration coverage

These should not block the core OI-014 v1 semantic freeze if their boundaries remain explicit:

- OAuth/OIDC mapping profile;
- Active Directory / enterprise profile;
- AI-agent principal/capability profile;
- blockchain registry profile;
- selective-disclosure / zero-knowledge privacy profile;
- registry federation/migration;
- profile distribution/resolution protocol.

## 5. Current freeze assessment

**NOT READY TO BYTE-FREEZE YET.**

The core architecture is coherent and has strong cross-language evidence, but G1-G4 affect normative interoperability and should be resolved before candidate bytes are frozen.

Recommended order:

1. G1 delegate StateHash error naming.
2. G2 DelegationPolicy revocation positive vector.
3. G3 ProfileDescriptor canonical representation.
4. G4 delegate-proof tagged union.
5. G5 final security/error vector gap pass.
6. Re-run Python + Java.
7. Only then create a pre-freeze gate/checksum candidate.
