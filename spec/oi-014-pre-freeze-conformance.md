# OI-014 Pre-Freeze Conformance Matrix

**Status:** RELEASE RECORD — OI-014 v1 FROZEN-NORMATIVE  
**Scope:** OI-014 DelegationGrant v1 frozen core semantics and wire schema  
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

### G4 — PROFILE_PRINCIPAL proof envelope — RESOLVED

The tagged DelegateProof union is implemented. DG06/DG07 exercise the OPENIDENTITY branch; DG09 exercises PROFILE_PRINCIPAL; DGI32 rejects profile/proof substitution. Python and Java independently verify the resulting bytes.

### G5 — stable error coverage / naming pass — RESOLVED

Security-significant semantic gaps received concrete vectors through DGI39, including unknown/mismatched profiles, profile lifetime, resource widening, revision overflow, inactive rootGrantor, and absent DelegationPolicy.

Remaining stable errors are classified as follows:

**Structural/parser validation**
- INVALID_DELEGATION_GRANT
- INVALID_GRANT_VERSION
- INVALID_ROOT_GRANTOR
- INVALID_ISSUER
- INVALID_DELEGATE
- INVALID_CAPABILITY_SET
- INVALID_RESOURCE_CONSTRAINT
- INVALID_NONCE
- INVALID_GRANT_ID
- INVALID_REGISTRY_DOMAIN
- RECORD_HASH_MISMATCH
- INVALID_REVOCATION_PROOF
- INVALID_RELINQUISHMENT_PROOF

These are tested by schema/parser/unit suites rather than requiring cryptographic semantic vectors.

**Runtime lookup/state outcomes**
- GRANT_ALREADY_REGISTERED
- GRANT_REVOKED
- GRANT_NOT_REGISTERED
- PARENT_GRANT_REQUIRED
- UNAUTHORIZED_REVOCATION
- UNAUTHORIZED_RELINQUISHMENT

Core semantic vectors already exercise the underlying authorization/state invariants; API/runtime suites map concrete lookup/action outcomes to these labels.

**Fault-injection-only defensive branches**
- GRANT_HASH_COLLISION
- RECORD_HASH_COLLISION

Conformance suites MUST NOT fabricate false SHA-256 collisions. Implementations should test these branches by dependency/fault injection while production behavior assumes SHA-256 collision resistance.

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

**FROZEN-NORMATIVE v1.**

G1-G5 are resolved. DG01-DG09 and DGI01-DGI39 pass independent Python and Java verification.

Release evidence:

1. Run the unified OI-014 pre-freeze gate.
2. Confirm no frozen v0.1 artifact/checksum changed.
3. Confirm worktree contains only intentional OI-014 draft changes.
4. Review exact generated OI-014 bundle diff.
5. Only then create an OI-014 byte-freeze candidate/checksum.
6. Re-run independent Python + Java verification against the candidate before any normative/frozen status change.
