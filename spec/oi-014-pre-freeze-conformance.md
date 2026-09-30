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
| DGI20 | Stale delegate AuthenticationPolicy / StateHash | INVALID_DELEGATE_STATE_HASH | COVERED |
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

### G1 — delegate StateHash error taxonomy — RESOLVED\n\n`INVALID_DELEGATE_STATE_HASH` is distinct from `INVALID_ROOT_STATE_HASH`; DGI20 uses the delegate-specific error.\n\n### G2 — current DelegationPolicy revocation positive path — RESOLVED\n\nDG08 proves current DelegationPolicy B can revoke a surviving grant originally registered by historical policy A after PRESERVE_EXISTING rotation. Python and Java verification pass.\n\n### G3 — profile descriptor wire schema — RESOLVED

OI-014 now defines a canonical ProfileDescriptor envelope containing descriptorVersion, profileKind, semanticSpecHash, maxGrantLifetime, maxDelegationDepth, and deterministic profile-owned parameter bytes.

DG01-DG08 and DGI01-DGI31 use the canonical descriptor envelope and independently reconstruct it in Python and Java.

### G4 — PROFILE_PRINCIPAL proof envelope — DESIGN RESOLVED; VECTOR MIGRATION REQUIRED

OI-014 now defines a tagged DelegateProof union: OPENIDENTITY carries current StateHash/authentication generation/AuthenticationPolicy proofs; PROFILE_PRINCIPAL carries exact principal ProfileRef plus canonical profile-owned proofContext/proofBytes.

Before G4 is fully closed, DG06/DG07 request bytes must migrate to the tagged OPENIDENTITY proof envelope and at least one PROFILE_PRINCIPAL positive/negative vector pair must prove the alternate branch.

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
