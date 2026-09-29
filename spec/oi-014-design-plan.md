# OI-014 DelegationGrant Design and Conformance Plan

**Status:** Design draft  
**Owning specification:** `spec/delegation-grants.md`

## Phase 1 — semantic decisions

Resolve before assigning wire labels:

- grant time model and expiry — **RESOLVED:** uint64 Unix seconds, finite expiresAt required, inclusive lower/exclusive upper boundary, profile maximum lifetime;
- capability identifier model — **RESOLVED:** immutable profileId + opaque capabilityId; no core textual hierarchy;
- resource constraint ownership/subset rules — **RESOLVED:** profile-owned deterministic resource validity/coverage semantics, bound per capability;
- delegate principal type model — **RESOLVED:** native OPENIDENTITY plus profile-defined external/workload principal; AI agents are profiles, not core types;
- direct-grant maximum lifetime;
- subdelegation enablement;
- registration/status ordering model — **RESOLVED:** per-GrantId uint64 revision + previous RecordHash;
- revocation authorization — **RESOLVED:** current ControllerPolicy or current DelegationPolicy may revoke; delegate may relinquish; historical registration authority has no continuing privilege;
- GrantId hash profile;
- public/private registration privacy model;
- resolution/discovery boundary.

## Phase 2 — threat model

Attack the design for:

- backdated grants from rotated-out keys;
- registration races;
- revoke/register races;
- generation rollback/substitution;
- grantor StateHash substitution;
- cross-domain signatures;
- duplicate effective DelegationPolicy keys;
- capability escalation;
- resource widening;
- lifetime extension;
- parent substitution;
- parent revocation bypass;
- delegation cycles;
- excessive chain depth / denial of service;
- delegate identity/key substitution;
- deactivation/recovery resurrection;
- replay across identities, registries, or profiles;
- public-registry privacy leakage.

## Phase 3 — canonical wire model

Only after Phases 1–2:

- DelegationGrant CDDL;
- delegate principal CDDL;
- grant authorization proof envelope;
- RegisteredGrant / registration receipt;
- revocation/status transaction;
- canonical ordering rules;
- signing domains;
- stable errors.

## Phase 4 — conformance vectors

Create a new OI-014 vector namespace rather than extending V3xx root-state vectors.

Proposed namespaces:

    DG01...    valid DelegationGrant / registration / use
    DGI01...   invalid/security cases

Vectors must be independently reconstructed in Python and Java before freeze.

## Phase 5 — integration profiles

After core OI-014 semantics freeze:

- OAuth/OIDC capability mapping;
- Active Directory / enterprise mapping;
- AI-agent delegation profile;
- optional blockchain/network registration profile.

Profiles must narrow/map OI-014 authority and must not redefine GrantId, generation binding, registration, attenuation, or revocation semantics.

## Immediate decision order

1. Registration/status ordering model — **RESOLVED:** per-GrantId revision chain; REGISTER = revision 1, ACTIVE -> REVOKED, REVOKED terminal.
2. Revocation authorization — **RESOLVED:** current grantor ControllerPolicy or DelegationPolicy; delegate relinquishment is separately domain-separated.
3. Time model — **RESOLVED:** whole UTC Unix seconds; finite expiry required; profile-defined bounded skew and maximum lifetime.
4. Capability/resource model — **RESOLVED:** profile-owned capability semantics with core exact identity/canonical set rules and deterministic attenuation.
5. Delegate principal model — **RESOLVED:** principal identity separated from authentication proof; OPENIDENTITY native, other principals profile-defined.
6. Subdelegation model.
7. GrantId/hash model.
8. Privacy/network boundary.

This order is deliberate: later choices depend on how authoritative grant state is serialized and ordered.
