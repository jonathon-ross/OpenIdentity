# OI-014 — DelegationGrant and Authoritative Registration

**Status:** Design draft; non-normative  
**Protocol dependency:** ProtocolVersion 2 / IdentityState v3 candidate  
**Purpose:** Define constrained delegation without transferring root identity authority

## 1. Security objective

OI-014 lets an OpenIdentity grant limited authority to another principal, service, device, or AI agent without giving that delegate the grantor's ControllerPolicy, RecoveryPolicy, AssertionPolicy, AuthenticationPolicy, or DelegationPolicy authority.

Delegation is capability-like and explicitly constrained. A delegate receives only the authority described by a registered DelegationGrant.

A DelegationGrant is **not authoritative merely because it carries a valid signature**. It becomes usable only through authoritative registration while its issuing DelegationPolicy is current.

This registration requirement prevents a rotated-out delegation key from manufacturing a new grant later and backdating it to a historical state in which that key was authorized.

## 2. Relationship to IdentityState v3

IdentityState v3 contains:

    DelegationAuthority {
        generation,
        DelegationPolicy?
    }

DelegationPolicy authorizes creation/registration of DelegationGrants. It does not itself identify a delegate or grant an application capability.

Registration:

- requires an ACTIVE grantor IdentityState v3;
- uses the current DelegationPolicy;
- binds the grant to the current DelegationAuthority.generation;
- creates a separate authoritative grant record;
- does not increment the grantor IdentityState sequence;
- does not change the grantor StateHash.

Generation changes invalidate prior-generation grants according to the v3 rules.

## 3. Principals

A grant has exactly one grantor and one delegate.

The grantor is an OpenIdentity Identity ID.

The delegate is identified by a typed principal reference. OI-014 MUST support an OpenIdentity Identity ID delegate. Additional principal types, such as workload/service or AI-agent identifiers, may be defined by profiles without changing the meaning of existing principal types.

A delegate reference is not proof of possession. Use of a grant MUST include authentication appropriate to the delegate principal/profile.

## 4. Canonical DelegationGrant

The initial logical grant contains:

    DelegationGrant {
        version
        grantor
        delegate
        capabilities
        resources?
        notBefore?
        expiresAt
        parentGrantId?
        nonce
    }

The exact integer labels and CDDL are deliberately deferred until the semantic model in this document is reviewed.

### version

Identifies the DelegationGrant object version, independent of root operation protocolVersion.

### grantor

The permanent OpenIdentity Identity ID whose DelegationPolicy authorizes registration.

### delegate

Typed reference to the principal receiving authority.

### capabilities

A non-empty, canonically ordered set of capability identifiers.

Capabilities are positive grants. Absence means no authority. Wildcards, negative permissions, and implicit capability inheritance are not defined by the core OI-014 draft.

### resources

Optional constraints identifying resources, audiences, tenants, objects, or other targets to which the capabilities apply.

A profile defining resource syntax MUST also define deterministic comparison and subset rules.

### notBefore

Optional lower validity boundary. Absence means the grant may be used immediately after authoritative registration, subject to registration time and all other constraints.

### expiresAt

Required upper validity boundary. OI-014 grants are not perpetual.

Time representation and clock-skew rules must be fixed before the wire format is frozen.

### parentGrantId

Present only for delegated/subdelegated authority. It binds the child to one authoritative parent grant.

### nonce

Grantor-chosen entropy preventing accidental semantic duplication and allowing two intentionally distinct grants with otherwise identical constraints.

## 5. Canonical bytes and GrantId

GrantBytes are deterministic RFC 8949 CBOR encoding of the complete DelegationGrant.

GrantId is content-derived from the exact GrantBytes using the OpenIdentity multihash profile:

    GrantBytes = deterministicCBOR(DelegationGrant)
    digest     = SHA-256(GrantBytes)
    GrantId    = 0x12 || 0x20 || digest

A future cryptographic-agility revision may generalize the permitted GrantId multihash algorithms. The initial OI-014 profile uses SHA2-256 to match current StateHash infrastructure.

Registration metadata such as registration time, registry location, status, and bound delegation generation is not included in GrantBytes and therefore does not change GrantId.

## 6. Delegation authorization signature

Registration requires DelegationPolicy authorization over the exact GrantBytes and the exact grantor state context.

The signing input MUST be domain-separated from root operations and from DelegationPolicy proof of possession.

Proposed signing structure:

    [
      "OpenIdentity Delegation Grant",
      1,
      GrantBytes,
      grantorStateHash,
      delegationGeneration,
      verificationMethodId
    ]

The grantorStateHash MUST identify the exact current ACTIVE IdentityState used during registration.

delegationGeneration MUST equal that state's DelegationAuthority.generation.

The verification method MUST be a current member of that state's DelegationPolicy and the complete policy threshold MUST be satisfied.

Historical DelegationPolicy membership is insufficient for new registration.

## 7. Authoritative registration

A registration processor SHALL:

1. obtain the current authoritative grantor IdentityState;
2. require IdentityState v3 and status ACTIVE;
3. require a present DelegationPolicy;
4. deterministically encode and validate GrantBytes;
5. require grant.grantor to equal the current Identity ID;
6. validate time/expiry constraints;
7. validate capability/resource syntax under the applicable profile;
8. derive GrantId;
9. construct the exact delegation-grant signing input using current StateHash and current delegation generation;
10. verify the complete current DelegationPolicy threshold;
11. if parentGrantId is present, validate the parent and attenuation rules;
12. atomically establish at most one authoritative registration record for that GrantId;
13. bind the record to the current delegation generation and current grantor StateHash.

Registration MUST NOT mutate IdentityState, consume root sequence, or change StateHash.

## 8. RegisteredGrant record

Conceptually:

    RegisteredGrant {
        grantId
        grantBytes
        grantorStateHash
        delegationGeneration
        registeredAt
        status
        parentGrantId?
    }

The authoritative network/registry representation may differ, but it MUST preserve these semantics.

Initial statuses are expected to include ACTIVE and REVOKED. Additional terminal or suspension statuses require explicit semantics before inclusion.

## 9. Grant usability

A registered grant is usable only if all of the following hold:

- its registration is authoritative;
- its status permits use;
- the grantor identity is currently ACTIVE;
- the grant's bound delegation generation equals the grantor's current DelegationAuthority.generation;
- current time satisfies registration/notBefore/expiry constraints;
- the requested capability is explicitly granted;
- the requested resource is within the grant's resource constraints;
- the acting principal is the grant's delegate;
- delegate authentication satisfies the applicable profile;
- every parent grant, if any, remains usable.

A current DelegationPolicy signature is **not** required each time an already-registered grant is used. Generation binding provides planned survival/invalidation behavior across policy rotations.

## 10. Generation semantics

A registered grant binds to generation N.

If DelegationPolicy rotates with PRESERVE_EXISTING and generation remains N, already-registered generation-N grants remain generation-compatible.

If any transition changes generation N -> N+1, every grant bound to N becomes unusable without individually rewriting those grants.

Generation-changing transitions include:

- SET_DELEGATION_POLICY with INVALIDATE_EXISTING;
- DelegationPolicy removal;
- RESET_DELEGATIONS;
- RECOVER.

DEACTIVATE makes grants unusable while the identity is deactivated even though it does not itself increment generation. RECOVER increments generation before returning ACTIVE, so pre-deactivation grants do not resurrect.

## 11. Revocation

OI-014 requires individual grant revocation in addition to generation-wide invalidation.

Revocation changes authoritative registration/status state, not root IdentityState.

Revocation MUST NOT decrement or reuse a delegation generation.

A revoked GrantId MUST NOT become ACTIVE again. Re-granting equivalent authority requires a distinct new grant/nonce and new authoritative registration.

The exact revocation transaction/wire record will be specified with the registration CDDL.

## 12. Subdelegation and attenuation

Subdelegation is explicit, never ambient.

A child grant MUST reference exactly one parentGrantId and MUST satisfy all parent constraints.

At minimum:

- child grantor MUST be the authenticated delegate of the parent grant;
- parent MUST explicitly include a capability permitting delegation/subdelegation;
- child capabilities MUST be a subset of parent capabilities;
- child resource scope MUST be equal to or narrower than parent scope;
- child notBefore MUST NOT precede the parent's effective lower boundary;
- child expiresAt MUST NOT exceed parent expiresAt;
- child cannot remove constraints imposed by the parent;
- parent revocation, expiry, generation invalidation, or unusability makes the child unusable.

Profiles MAY prohibit subdelegation entirely.

The core protocol MUST NOT infer transitive authority merely because A delegated to B and B delegated to C.

## 13. AI-agent delegation

An AI agent is not a special source of authority. It is a delegate principal operating under the same grant model.

An AI-agent profile may define:

- agent/workload identifier format;
- key/attestation binding;
- tool/API capability vocabulary;
- resource/audience restrictions;
- spending or transaction limits;
- human-approval requirements;
- maximum lifetime;
- subdelegation prohibition;
- audit metadata.

Those constraints narrow a grant; they do not expand the grantor's underlying authority.

The core OI-014 model should therefore support AI agents without embedding model vendor, runtime, OAuth provider, blockchain, or payment-network assumptions into GrantBytes.

## 14. OAuth/OIDC and enterprise mapping boundary

OAuth scopes, resource indicators, token audiences, Active Directory permissions, cloud IAM actions, and similar systems may be mapped to OI-014 capabilities/resources by profiles.

Such mappings are interoperability layers. They MUST NOT silently redefine core GrantId, generation, registration, revocation, or attenuation semantics.

An OAuth access token or AD token may be evidence used by an integration profile, but it is not itself an authoritative OpenIdentity DelegationGrant unless the profile defines a verifiable binding to a registered grant.

## 15. Registry / blockchain boundary

OI-014 defines authoritative registration semantics, not one storage technology.

A conforming registry may use a blockchain, database, replicated log, transparency service, or another mechanism provided it preserves:

- atomic registration;
- unique GrantId handling;
- immutable registration evidence;
- status/revocation ordering;
- current-state/generation binding at registration;
- historical lookup sufficient for audit;
- no backdating that bypasses current DelegationPolicy validation.

A blockchain transaction is therefore one possible registration mechanism, not part of GrantBytes itself.

## 16. Stable security invariants

The following are release-blocking invariants:

1. Offline signature alone never makes a grant authoritative.
2. Registration always validates the current ACTIVE grantor state.
3. Historical DelegationPolicy keys cannot create new authoritative grants.
4. Grant registration never changes root IdentityState or sequence.
5. GrantId commits to exact canonical GrantBytes.
6. Registration binds to exact grantor StateHash and delegation generation.
7. Generation invalidation cannot be bypassed by timestamps or historical-state references.
8. Revoked grants cannot reactivate.
9. Child grants cannot exceed parent authority or lifetime.
10. Deactivation makes grants unusable; recovery cannot resurrect old-generation grants.
11. Delegate authentication is distinct from grantor delegation authorization.
12. Capability/resource profiles may narrow semantics but cannot expand core authority.

## 17. Required conformance work

Before OI-014 can become a frozen candidate, vectors should cover at least:

Positive:
- direct grant registration;
- threshold DelegationPolicy registration;
- PRESERVE_EXISTING rotation with prior registered grant still usable;
- individual revocation;
- constrained child grant;
- generation change invalidating prior grants.

Invalid/security:
- offline unregistered grant use;
- registration signed by rotated-out delegation key;
- historical-StateHash/backdating attempt;
- wrong delegation generation;
- wrong grantor;
- wrong delegate authentication;
- expired/not-yet-valid grant;
- unauthorized capability/resource;
- registration while grantor DEACTIVATED;
- registration with absent DelegationPolicy;
- duplicate/unauthorized delegation authorization proofs;
- cross-domain proof substitution;
- child capability escalation;
- child resource widening;
- child expiry beyond parent;
- child of revoked/invalidated parent;
- revoked grant reactivation attempt.

## 18. Open design questions before wire freeze

The following require deliberate decisions before assigning final CDDL labels:

1. exact time representation and clock-skew semantics;
2. core capability identifier format;
3. generic resource-constraint representation versus profile-owned resource syntax;
4. delegate principal type registry;
5. whether direct grants require a maximum protocol-level lifetime;
6. whether subdelegation is core-enabled or profile-opt-in;
7. authoritative registration/status transaction format;
8. revocation authorization model;
9. whether registration records need their own monotonic sequence/version;
10. whether GrantId remains SHA2-256-only in the first release or uses a general Multihash bound;
11. privacy implications of public registration and whether commitments/private registries are allowed;
12. resolution/discovery API semantics for registered grants.

No CDDL should be frozen until these questions are resolved.
