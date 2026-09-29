# OI-014 DelegationGrant Design and Conformance Plan

**Status:** Design draft  
**Owning specification:** `spec/delegation-grants.md`

## Phase 1 — semantic decisions

Resolve before assigning wire labels:

- grant time model and expiry;
- capability identifier model;
- resource constraint ownership/subset rules;
- delegate principal type model;
- direct-grant maximum lifetime;
- subdelegation enablement;
- registration/status ordering model;
- revocation authorization;
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

1. Registration/status ordering model.
2. Revocation authorization.
3. Time model.
4. Capability/resource model.
5. Delegate principal model.
6. Subdelegation model.
7. GrantId/hash model.
8. Privacy/network boundary.

This order is deliberate: later choices depend on how authoritative grant state is serialized and ordered.
