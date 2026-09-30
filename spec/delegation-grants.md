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

## 3A. Delegate principal model

OI-014 separates principal identity from proof/authentication mechanism.

The logical delegate reference is:

    DelegatePrincipal {
        principalType
        principalProfile?
        principalId
    }

The final wire encoding will use registered integer/type identifiers and bounded deterministic byte representations. The semantic model is fixed before those labels are assigned.

### Native OpenIdentity principal

Core OI-014 defines one native principal type:

    OPENIDENTITY

For OPENIDENTITY:

- `principalProfile` is absent;
- `principalId` is exactly the permanent 32-byte OpenIdentity Identity ID;
- the delegate's identity remains independent of its current keys;
- delegate authentication is evaluated against the applicable current OpenIdentity authority/profile at grant-use time rather than embedding one delegate key into the grant.

A grant to an OpenIdentity principal therefore survives legitimate delegate key rotation unless another grant constraint says otherwise.

### Profile-defined external/workload principal

Non-OpenIdentity principals use a profile-defined principal type:

    PROFILE_PRINCIPAL

For PROFILE_PRINCIPAL:

- `principalProfile` is required and identifies immutable principal semantics;
- `principalId` is opaque to core OI-014;
- the profile defines canonical principalId syntax and equality;
- the profile defines how the principal proves control at grant-use or relinquishment time;
- the profile defines any attestation, workload, runtime, issuer, audience, tenant, or key-binding requirements.

Core OI-014 MUST NOT guess the meaning of an unknown principal profile.

Examples of profile-defined principals may include workloads, services, devices, OAuth/OIDC subjects, cloud workload identities, hardware-backed agents, or AI-agent runtimes. These are examples, not core principal types.

### AI agents

AI_AGENT is deliberately not a core principal type.

An AI agent normally combines several concepts:

    stable agent/workload identity
    + runtime or deployment identity
    + authentication key and/or attestation
    + capability constraints

Those details evolve faster than the core protocol. An AI-agent profile should therefore define a PROFILE_PRINCIPAL representation and proof requirements without changing OI-014's principal model.

This permits different agent systems to interoperate with the same DelegationGrant semantics while keeping model vendor, runtime vendor, attestation technology, and key format outside the core.

### Principal identity versus proof material

`principalId` identifies the delegate. It MUST NOT be treated as interchangeable with a public key unless the owning profile explicitly defines a key-as-principal identity.

Proof material authenticates the principal; it does not implicitly redefine the principal.

A profile that permits authentication-key rotation MUST define how continuity of the same principalId is established.

A profile that uses attestations MUST define which attestation claims are identity-bearing and which are merely contextual.

### Canonical equality

Two DelegatePrincipal values are the same principal only when their canonical principal identities are equal under the applicable principal type/profile.

For OPENIDENTITY this is exact equality of the 32-byte Identity ID.

For PROFILE_PRINCIPAL, equality is defined by the immutable principal profile and MUST be deterministic.

Text display names, DNS names, account labels, model names, user-facing agent names, or aliases MUST NOT be used as principal equality unless a profile explicitly makes them canonical identity material.

### Delegate authentication at grant use

Possession of GrantBytes is not delegate authentication.

To use a grant, the requester MUST prove it is the exact DelegatePrincipal named by the grant using the proof mechanism defined for that principal type/profile.

The grant-use verifier MUST bind the authenticated principal to the grant's canonical DelegatePrincipal before evaluating capabilities/resources.

Authentication evidence MUST NOT expand grant authority. It proves who is acting; the registered grant defines what that principal may do.

### Delegate relinquishment

The relinquishment proof defined by OI-014 MUST authenticate the exact current DelegatePrincipal under its applicable proof profile.

For OPENIDENTITY delegates, a later wire/profile decision will specify which OpenIdentity authority purpose authenticates relinquishment. OI-014 MUST NOT silently assume ControllerPolicy merely because it is root authority.

For PROFILE_PRINCIPAL delegates, the principal profile defines the relinquishment proof binding.

### Principal profile versioning

A principalProfile MUST identify immutable semantics sufficiently to prevent a later profile revision from changing:

- principalId equality;
- proof/control requirements;
- key-rotation continuity;
- attestation identity meaning;
- relinquishment authorization.

An incompatible change requires a new profile identity/version.

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

## 4A. Time model

OI-014 uses integer Unix-epoch seconds for protocol time values.

A protocol timestamp is the number of whole seconds elapsed since 1970-01-01T00:00:00Z. It is UTC by definition and carries no timezone, locale, fractional-second, floating-point, or textual-date representation.

The wire type will be an unsigned integer. Values MUST fit the final CDDL integer range selected for OI-014; the initial design targets uint64.

### Grant interval

Every DelegationGrant MUST contain `expiresAt`.

`notBefore` is optional.

If `notBefore` is absent, the effective lower boundary is authoritative registration time.

If `notBefore` is present:

    notBefore < expiresAt

MUST hold.

Registration MUST reject a grant when `expiresAt <= registeredAt`. A registry MUST NOT create an authoritative ACTIVE registration for a grant that is already expired at authoritative registration time.

If `notBefore > registeredAt`, the grant may be registered ACTIVE but is not yet usable until the lower boundary is reached.

### Boundary semantics

Let `t` be the protocol evaluation time after any profile-permitted clock-skew treatment.

A grant satisfies its time interval exactly when:

    effectiveNotBefore <= t < expiresAt

The lower boundary is inclusive. The expiration boundary is exclusive.

At `t == expiresAt`, the grant is expired and unusable.

Expiration does not require an explicit REVOKED transition. Expiry and REVOKED status are independent reasons a grant is unusable.

### Authoritative registration time

`registeredAt` belongs to RegisteredGrantState, not GrantBytes.

The authoritative registry establishes `registeredAt` according to its network/profile time source. A submitter-supplied timestamp MUST NOT become authoritative registration time merely because it appears in transport metadata.

The registration mechanism MUST provide a deterministic authoritative `registeredAt` value for the accepted record and preserve it in RecordBytes.

### Clock skew

Core OI-014 defines exact protocol boundaries and does not silently widen them for clock skew.

A deployment/integration profile MAY define a bounded clock-skew allowance for request evaluation, but it MUST:

- specify the maximum allowance explicitly;
- apply it consistently;
- never change GrantBytes, GrantId, RecordBytes, RecordHash, `notBefore`, `expiresAt`, or `registeredAt`;
- never make an expired grant authoritative at registration;
- never extend a child grant beyond its parent's canonical `expiresAt`;
- never use skew to bypass REVOKED status or generation invalidation.

A verifier that does not implement a profile-defined skew uses the exact canonical boundaries.

### Maximum lifetime

Core OI-014 requires finite expiration but does not impose one universal maximum grant lifetime.

Every deployment/profile that permits grant registration MUST define a maximum lifetime appropriate to its risk domain. Registration MUST reject grants exceeding that profile maximum.

This lets high-risk profiles, such as AI-agent or payment authority, require short-lived grants while enterprise profiles may deliberately permit longer delegation.

A profile maximum narrows OI-014. It cannot permit perpetual grants or remove the required `expiresAt`.

### Subdelegation time attenuation

For a child grant:

- child `expiresAt <= parent.expiresAt`;
- the child's effective lower boundary MUST NOT precede the parent's effective lower boundary;
- a child cannot become usable while its parent is not yet usable;
- parent expiration immediately makes the child unusable even if the child's own fields would otherwise permit use.

Clock-skew policy MUST NOT turn these canonical subset requirements into broader child authority.

## 4B. Capability and resource model

OI-014 core treats capability meaning as profile-owned. The core protocol defines canonical capability identity, ordering, duplication, and attenuation rules but does not assign application semantics to names such as read, write, approve, send, transfer, or administer.

### Capability reference

A capability is identified by the pair:

    CapabilityRef {
        profileId
        capabilityId
    }

`profileId` identifies the capability profile that owns the identifier space and semantics.

`capabilityId` is opaque to OI-014 core. Equality in the core protocol is exact canonical equality of both fields.

The final wire representation will use deterministic byte/text forms with explicit length bounds. Human-readable examples do not determine the eventual encoding.

A profile MUST define:

- its stable profileId;
- every capabilityId it recognizes;
- the authority represented by each capability;
- whether any semantic implication relationships exist between its capabilities;
- resource-constraint syntax, if resources are used;
- deterministic resource equality/subset rules;
- its maximum grant lifetime;
- any additional constraints required for registration/use.

Unknown profiles or capability identifiers MUST NOT be guessed, prefix-matched, or silently interpreted.

### No ambient hierarchy

Core OI-014 defines no hierarchy from spelling.

For example, none of these relationships exist merely because of their text:

    "read" < "admin"
    "calendar.read" < "calendar.*"
    "invoice.approve.small" < "invoice.approve"
    "tool:email.send" < "tool:*"

Wildcards and prefix/suffix matching are not core semantics.

A profile MAY define implication or wildcard behavior, but it MUST do so explicitly and deterministically. A verifier that does not understand the required profile semantics cannot safely conclude that an implied capability is authorized.

### Canonical capability set

A DelegationGrant contains a non-empty set of CapabilityRef values.

The set MUST:

- use deterministic canonical ordering;
- contain no duplicate CapabilityRef;
- contain no semantically duplicate aliases when the owning profile declares them equivalent;
- contain only identifiers valid under the referenced profile.

The exact ordering rule will be frozen with the wire encoding. The design target is unsigned bytewise lexicographic ordering over each CapabilityRef's canonical encoded identity.

### Direct capability evaluation

A request is authorized only when the requested capability is covered by a grant according to the owning profile.

Core exact-match profiles simply require exact CapabilityRef membership.

Profiles defining implication MUST provide a deterministic function equivalent to:

    covers(grantedCapability, requestedCapability) -> boolean

Profiles MUST NOT allow this function to create authority outside the profile's declared capability universe.

### Resources

Resources are optional and profile-owned.

A capability profile may define a resource constraint representation for capabilities in its namespace. Examples might identify an API audience, tenant, account, repository, document, bucket/object prefix, payment account, tool, or other target.

Core OI-014 does not assign universal meaning to arbitrary resource strings.

A profile supporting resources MUST define deterministic functions equivalent to:

    resourceValid(resourceConstraint) -> boolean
    resourceCovers(parentConstraint, childConstraint) -> boolean
    resourceAllows(constraint, requestedResource) -> boolean

The representation and functions MUST be deterministic enough for independent implementations to reach the same result.

If a profile declares a capability resource-scoped, omission of a required resource constraint MUST be rejected rather than interpreted as unrestricted authority.

If a profile declares a capability unscoped, attaching an undefined resource field MUST NOT silently change its meaning.

### Capability/resource binding

Resource constraints apply to specific capabilities, not globally by implication.

The logical grant model is therefore refined to:

    DelegatedCapability {
        capability: CapabilityRef
        resourceConstraint?
    }

    DelegationGrant {
        ...
        capabilities: non-empty set<DelegatedCapability>
        ...
    }

Two entries with the same CapabilityRef but different resource constraints are distinct only when the profile explicitly permits multiple independently constrained entries. Otherwise registration MUST reject ambiguous duplicates.

### Attenuation

A child grant cannot expand authority.

For every child DelegatedCapability there MUST exist at least one parent DelegatedCapability that covers it according to the same capability profile.

At minimum:

    parent capability covers child capability
    AND
    parent resource constraint covers child resource constraint

A child MUST NOT switch a capability into a different profile merely because two profiles use similar names.

If deterministic attenuation cannot be established, child registration MUST fail closed.

Profiles may impose stronger attenuation rules.

### Multi-profile grants

A single grant MAY contain capabilities from multiple profiles if the registration environment supports all required profiles.

Each entry is validated independently under its owning profile.

Registration MUST fail if a required profile is unknown or unsupported. Implementations MUST NOT drop unknown capability entries and register only the subset they understand because doing so would change the signed GrantBytes semantics.

### Profile versioning

A profileId MUST identify semantics immutably enough that later profile changes cannot retroactively broaden an already-registered grant.

An incompatible capability or resource semantic change requires a new profile identity/version.

Registries and verifiers MUST evaluate a registered grant using the profile semantics identified by its GrantBytes, not whatever newer profile happens to exist at evaluation time.

## 5. Canonical bytes and GrantId

GrantBytes are deterministic RFC 8949 CBOR encoding of the complete DelegationGrant.

GrantId is content-derived from the exact GrantBytes using the OpenIdentity multihash profile:

    GrantBytes = deterministicCBOR(DelegationGrant)
    digest     = SHA-256(GrantBytes)
    GrantId    = 0x12 || 0x20 || digest

A future cryptographic-agility revision may generalize the permitted GrantId multihash algorithms. The initial OI-014 profile uses SHA2-256 to match current StateHash infrastructure.

Registration metadata such as registration time, registry location, status, and bound delegation generation is not included in GrantBytes and therefore does not change GrantId.

## 5A. GrantId and RecordHash hash profile

OI-014 v1 fixes both GrantId and RegisteredGrantState RecordHash to the SHA2-256 Multihash profile.

The exact construction is:

    digest     = SHA-256(canonicalBytes)
    identifier = 0x12 || 0x20 || digest

where:

- `0x12` is the Multihash code for SHA2-256;
- `0x20` is the 32-byte digest length;
- `digest` is exactly 32 bytes.

For grants:

    GrantId = 0x12 || 0x20 || SHA-256(GrantBytes)

For registered grant-state records:

    RecordHash = 0x12 || 0x20 || SHA-256(RecordBytes)

This deliberately matches the current OpenIdentity StateHash construction.

### One algorithm in OI-014 v1

Multihash framing does not make the initial OI-014 profile algorithm-agile.

A conforming OI-014 v1 implementation MUST emit and accept only:

    algorithm code = 0x12
    digest length  = 0x20

for GrantId and RecordHash.

An identifier using another Multihash algorithm code or digest length is invalid under OI-014 v1 even if the implementation knows how to compute that algorithm.

Implementations MUST NOT negotiate, substitute, upgrade, or downgrade the hash algorithm during registration, lookup, parent-chain validation, revocation, or grant use.

### Identifier equality

GrantId equality is exact byte equality of the complete 34-byte Multihash.

RecordHash equality is exact byte equality of the complete 34-byte Multihash.

Implementations MUST NOT compare only the digest bytes while ignoring the Multihash prefix.

Implementations MUST NOT treat alternate hashes of the same canonical bytes as aliases for one GrantId or RecordHash.

This prevents a registry from representing one grant under multiple algorithm-derived identities.

### Canonical input

GrantId is computed only from exact canonical GrantBytes.

RecordHash is computed only from exact canonical RecordBytes.

A verifier MUST NOT hash:

- decoded object models with implementation-dependent ordering;
- JSON projections;
- transport envelopes;
- proof collections not defined as part of the canonical object;
- registry metadata outside RecordBytes;
- textual/display encodings of identifiers.

A verifier reconstructs the applicable deterministic CBOR bytes and hashes those exact bytes.

### Collision handling

A registry MUST NOT establish two semantically different canonical GrantBytes under the same GrantId.

If submitted GrantBytes hash to an already-known GrantId, the registry MUST compare exact canonical GrantBytes.

- If the bytes are identical, the submission refers to the same immutable grant intent and is handled according to registration/replay rules.
- If the bytes differ, the registry MUST fail closed and surface a hash-collision/integrity error. It MUST NOT overwrite, merge, or choose one object silently.

The analogous rule applies to RecordHash and RecordBytes.

### Future hash agility

A future OpenIdentity protocol/OI-014 revision MAY permit additional Multihash algorithms.

Such a revision MUST define:

- exactly which algorithms are permitted;
- whether identifiers created under different algorithms may coexist;
- migration and lookup semantics;
- parentGrantId behavior across hash profiles;
- collision/alias handling;
- whether an existing grant can ever acquire a new identifier.

OI-014 v1 implementations MUST NOT anticipate that future revision by accepting additional algorithms today.

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

## 8A. RegisteredGrant state history

Authoritative grant registration/status uses a per-GrantId monotonic revision chain. It is independent of the grantor IdentityState sequence.

The canonical logical state is:

    RegisteredGrantState {
        grantId
        revision
        previousRecordHash
        status
        grantBytes
        grantorStateHash
        delegationGeneration
        registeredAt
    }

REGISTER establishes:

    revision = 1
    previousRecordHash = nil
    status = ACTIVE

A later grant-state transition MUST use:

    revision = current.revision + 1
    previousRecordHash = RecordHash(current)

The initial OI-014 state machine permits ACTIVE -> REVOKED. REVOKED is terminal. A revoked GrantId MUST NOT be reactivated, re-registered, or assigned a later ACTIVE revision.

RecordBytes are deterministic CBOR encoding of the complete RegisteredGrantState. The initial RecordHash profile is:

    RecordBytes = deterministicCBOR(RegisteredGrantState)
    RecordHash  = 0x12 || 0x20 || SHA-256(RecordBytes)

GrantId and RecordHash serve different purposes. GrantId identifies immutable grant intent derived from GrantBytes. RecordHash identifies one exact authoritative registration/status state for that GrantId.

Registration metadata is therefore outside GrantBytes but cryptographically committed by RecordHash.

### Ordering and replay

A grant-state processor MUST validate revision and previousRecordHash against the same authoritative predecessor it uses to establish the successor.

A stale, duplicate, skipped, or replayed revision MUST NOT become authoritative.

Once one successor becomes authoritative for revision N+1, competing transitions referencing revision N are stale and MUST NOT later be applied.

The registry/consensus mechanism that chooses among otherwise-valid competing successors is outside OI-014, but it MUST establish at most one authoritative successor from a particular RegisteredGrantState.

Revision MUST NOT wrap. If current revision is 2^64 - 1, no further grant-state transition is representable.

### Separation from root state

Grant revision:

- is scoped to one GrantId;
- is not the grantor IdentityState sequence;
- does not alter grantor StateHash;
- does not alter DelegationAuthority.generation;
- does not order records belonging to other GrantIds.

A grantor may therefore have many independently evolving grant records without serializing all grant activity through the root identity state machine.

## 8B. Privacy-preserving registration and disclosure

OI-014 separates **grant authority content** from **authoritative registration evidence**.

A registry does not need to publish GrantBytes in order to establish that a particular GrantId was authoritatively registered.

### Full/private grant

GrantBytes contain the authority-bearing grant semantics, including:

- grantor;
- delegate;
- capabilities and resource constraints;
- time bounds;
- parentGrantId when applicable;
- nonce.

GrantId commits to those exact bytes.

GrantBytes MAY be held privately by the grantor, delegate, relying party, enterprise registry, encrypted object store, wallet, agent runtime, or another authorized distribution mechanism.

A public registry MUST NOT require publication of GrantBytes merely to satisfy core OI-014 registration semantics.

### Minimal authoritative registration state

The core registration state SHOULD minimize public disclosure.

The privacy-preserving logical anchor is:

    RegisteredGrantState {
        grantId
        revision
        previousRecordHash
        status
        grantorStateHash
        delegationGeneration
        registeredAt
    }

GrantBytes are not required to be embedded in the public RegisteredGrantState.

The grantor Identity ID, delegate identity, capabilities, resources, expiry, and parent relationship are already committed by GrantId through GrantBytes and therefore need not be duplicated in a public anchor merely for integrity.

A deployment MAY store additional indexed metadata privately or publicly, but such metadata is outside the canonical minimal registration state unless a future profile explicitly makes it canonical.

### Registration validation still sees the full grant

Privacy-preserving storage does not weaken registration validation.

Before establishing revision 1, the registration processor MUST possess the exact GrantBytes and perform the complete OI-014 registration checks, including:

- recompute GrantId;
- validate grantor identity against the current authoritative IdentityState;
- validate current ACTIVE status;
- validate current DelegationPolicy;
- validate delegation-generation binding;
- validate time/profile/capability/resource constraints;
- validate parent grant and attenuation when applicable;
- verify the grant authorization proof.

Only after successful validation may the registry publish/store the minimal authoritative anchor.

### Grant use / selective disclosure

A relying party evaluating a grant MUST obtain sufficient grant material to reconstruct the exact canonical GrantBytes.

The verifier SHALL:

1. deterministically encode/reconstruct GrantBytes;
2. recompute GrantId;
3. require exact GrantId equality with the authoritative registration record;
4. validate RecordHash/revision/status as applicable;
5. validate the current grantor/delegation-generation usability conditions;
6. evaluate the disclosed grant semantics and delegate authentication.

A party that possesses only a GrantId and registration anchor cannot infer or exercise undisclosed capabilities from core OI-014.

Core v1 does not define partial-field zero-knowledge disclosure. If a verifier cannot reconstruct the complete GrantBytes committed by GrantId, it cannot independently prove that the disclosed subset is the registered grant.

A future privacy profile MAY define commitment trees, selective-disclosure proofs, or zero-knowledge representations, but it MUST preserve an unambiguous binding to the authoritative registered grant and MUST NOT silently reinterpret the OI-014 v1 GrantId.

### Public versus private registries

OI-014 supports both.

A **public anchor registry** may expose only canonical registration/status records and RecordHashes.

A **private full registry** may additionally retain GrantBytes and searchable grant metadata.

A hybrid deployment may anchor RecordHash or RegisteredGrantState in a public blockchain/transparency log while retaining GrantBytes privately.

Storage location does not change grant semantics.

### Correlation minimization

Core OI-014 intentionally does not require the minimal public registration anchor to duplicate:

- grantor Identity ID;
- delegate principal;
- capability identifiers;
- resource constraints;
- expiresAt/notBefore;
- parentGrantId.

Those values remain cryptographically committed by GrantId.

`grantorStateHash` is retained because registration authorization is bound to one exact authoritative grantor state. Deployments should recognize that StateHash itself may still permit correlation when an observer has access to identity-state history.

A stronger privacy profile MAY replace direct public exposure of some registration context with a verifiable commitment/proof mechanism, but that is outside core OI-014 v1 and must not weaken current-state/generation validation.

### Resolution and availability

GrantId commitment proves integrity, not availability.

A registry that stores only minimal anchors is not required by core OI-014 to make GrantBytes publicly retrievable.

Grant distribution and authorized retrieval are separate concerns.

Profiles SHOULD define how relying parties obtain GrantBytes or an approved privacy-preserving proof when the registry does not store full grants.

Failure to retrieve required grant material means the verifier cannot authorize use; it MUST fail closed rather than infer grant contents from metadata.

### Revocation privacy

Revocation changes the RegisteredGrantState for GrantId and therefore can be publicly visible without revealing GrantBytes.

A public observer may learn that an opaque GrantId changed from ACTIVE to REVOKED. Core OI-014 accepts this limited leakage.

A privacy profile requiring hidden status relationships needs an additional cryptographic construction and is outside the initial core.

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

## 11A. Revocation authorization

Revocation authority is evaluated at the time of revocation. Historical authority that originally registered a grant does not retain special revocation power merely because it created that grant.

An ACTIVE grant may become REVOKED through either grantor revocation or delegate relinquishment.

### Grantor revocation

Either of the following current authorities may revoke any ACTIVE grant whose grantor is the identity they currently govern:

1. the grantor's current ControllerPolicy; or
2. the grantor's current DelegationPolicy.

The grantor IdentityState MUST be current and authoritative. ControllerPolicy revocation provides a root/emergency path. DelegationPolicy revocation provides the ordinary delegation-management path.

If DelegationPolicy A registered grant G and later rotates to DelegationPolicy B with PRESERVE_EXISTING, G may remain usable, but B—not A—is the DelegationPolicy authority that may subsequently revoke G. A historical or rotated-out DelegationPolicy has no continuing revocation authority.

If the current DelegationPolicy is absent, ControllerPolicy remains able to revoke a still-recorded grant even though generation-changing policy removal will normally already make prior-generation grants unusable.

### Delegate relinquishment

The delegate MAY relinquish its own ACTIVE grant if the applicable delegate-principal profile defines a verifiable authentication/signature mechanism.

Relinquishment only reduces the delegate's authority. It MUST NOT modify the grant, transfer authority, alter the grantor IdentityState, change delegation generation, or reactivate another grant.

A parent delegate relinquishing its parent grant makes descendant grants unusable through the normal parent-usability rule.

### Domain separation

Grantor revocation and delegate relinquishment are distinct proof purposes.

Proposed grantor revocation signing structure:

    [
      "OpenIdentity Delegation Grant Revocation",
      1,
      grantId,
      currentRecordHash,
      nextRevision,
      verificationMethodId
    ]

Proposed delegate relinquishment signing structure:

    [
      "OpenIdentity Delegation Grant Relinquishment",
      1,
      grantId,
      currentRecordHash,
      nextRevision,
      delegatePrincipal
    ]

The final delegate-proof binding may include a delegate verification-method identifier or profile-specific proof context once the delegate principal model is resolved.

A signature from one revocation purpose MUST NOT be accepted for another.

### Revocation transition validation

A processor accepting ACTIVE -> REVOKED SHALL:

1. load the exact current authoritative RegisteredGrantState;
2. require status ACTIVE;
3. require nextRevision = current.revision + 1;
4. require previousRecordHash = RecordHash(current);
5. determine whether the request is grantor revocation or delegate relinquishment;
6. for grantor revocation, load the current authoritative grantor IdentityState and verify either current ControllerPolicy or current DelegationPolicy authorization under the correct domain;
7. for delegate relinquishment, verify the current grant delegate under the applicable delegate-principal profile and relinquishment domain;
8. construct the canonical REVOKED successor;
9. atomically establish at most one authoritative successor.

A stale proof over an earlier RecordHash/revision cannot revoke a later grant-state record.

### Generation invalidation versus individual revocation

Generation mismatch and individual REVOKED status are independent reasons a grant is unusable.

A generation-invalid grant need not receive an individual REVOKED record merely to become unusable. The grantor MAY still record an explicit revocation for audit/finality, using current revocation authority.

Neither generation changes nor deactivation may convert a REVOKED grant back to ACTIVE.

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

## 12A. Subdelegation authorization

Subdelegation is forbidden by default.

Holding a capability does not imply authority to delegate that capability to another principal. A parent delegate may create a child grant only when the parent grant explicitly contains profile-defined authority permitting redelegation of the relevant capability/resource envelope.

Core OI-014 deliberately does not define one ambient universal `subdelegate=true` bit. Subdelegation authority is itself expressed through capability-profile semantics so profiles can constrain what may be redelegated.

Conceptually, a profile may define authority equivalent to:

    mayRedelegate(
        delegatedCapability,
        resourceConstraint,
        childPrincipalClass?,
        additionalLimits?
    )

The exact representation belongs to the capability profile.

### Two independent authorization tests

For every child DelegatedCapability, registration MUST establish both:

1. **possession:** the parent grant itself authorizes the parent delegate for the child capability/resource; and
2. **redelegation authority:** the parent grant explicitly authorizes that delegate to redelegate that capability/resource.

Passing only one test is insufficient.

For example, a parent may be allowed to use `email.send` without being allowed to grant `email.send` to another principal.

### Strict attenuation

Subdelegation can only narrow authority.

For every child capability/resource entry:

- the parent must cover the child capability;
- the parent resource constraint must cover the child resource constraint;
- the parent's redelegation authority must cover the child capability/resource;
- child time boundaries must be within the parent boundaries;
- child profile constraints must be equal or stricter;
- the child cannot add authority from a profile unsupported by the parent;
- the child cannot convert use-only authority into redelegable authority unless the parent explicitly permits redelegation of that redelegation right.

A profile MAY forbid redelegating subdelegation authority itself. High-risk profiles SHOULD do so unless multi-level delegation is a deliberate requirement.

### No implicit transitivity

If A grants authority to B and B grants authority to C, C receives only the authority explicitly present in its registered child grant.

C does not inherit all of A's or B's capabilities.

Likewise:

    A -> B
    B -> C

does not imply:

    A -> C

for any capability not explicitly authorized by the child grant and validated through the complete parent chain.

### Parent-chain binding

A child grant MUST contain exactly one `parentGrantId`.

At child registration, the parent MUST be an authoritative, usable registered grant.

The child registration record MUST preserve the parentGrantId binding.

At use time, every ancestor required by the chain MUST remain usable. A revoked, expired, generation-invalid, deactivated, or otherwise unusable ancestor makes all descendants unusable.

A child MUST NOT be re-parented after registration. Equivalent authority under a different parent requires a new grant and GrantId.

### Cycle prevention

The parent chain MUST be acyclic.

A child registration MUST be rejected if its GrantId already appears anywhere in the proposed ancestor chain.

More generally, a registry MUST NOT establish a parent relationship that would make a RegisteredGrant an ancestor of itself.

Because GrantId is content-derived and parentGrantId is part of GrantBytes, changing the parent produces different GrantBytes and a different GrantId.

### Chain depth

Core OI-014 requires every registration profile to define a finite maximum delegation-chain depth.

Direct grants from the root OpenIdentity grantor are depth 1. A child of a depth-1 grant is depth 2, and so on.

Registration MUST reject a child whose resulting depth exceeds the profile maximum.

A multi-profile child grant MUST satisfy the most restrictive applicable chain-depth limit.

Core OI-014 does not define one universal depth because risk and operational requirements vary by profile, but an unbounded profile is not conforming.

### Child grant authorization

A child grant is still registered through authoritative OI-014 registration.

The parent delegate must authenticate as the parent grant's DelegatePrincipal and provide the proof required by the applicable subdelegation profile.

The original root grantor's current DelegationPolicy does not need to sign each child unless the applicable profile explicitly requires co-authorization.

This preserves useful delegated autonomy while ensuring every child is traceable to a registered parent and cannot exceed the parent's authority.

### Generation relationship

A child remains transitively dependent on its parent.

If the root grant's bound delegation generation becomes invalid, the root grant becomes unusable and every descendant becomes unusable even if child records themselves have not changed.

A child grant MUST NOT substitute a newer root generation to escape an invalidated parent chain.

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

1. **RESOLVED:** uint64 whole Unix-epoch seconds UTC; required finite expiresAt; optional notBefore; interval is effectiveNotBefore <= t < expiresAt; profile-defined bounded skew may affect evaluation only;
2. **RESOLVED:** capability identity is (profileId, capabilityId); capabilityId is opaque to core; no implicit textual hierarchy;
3. **RESOLVED:** resources and deterministic coverage/subset semantics are profile-owned; core binds resource constraints to individual capabilities and fails closed when attenuation cannot be established;
4. **RESOLVED:** core supports native OPENIDENTITY and extensible PROFILE_PRINCIPAL; AI agents/workloads are profile-defined, not core types; principal identity is separate from proof material;
5. **RESOLVED:** core requires finite expiry but no universal maximum; every registration profile MUST define and enforce a maximum lifetime;
6. **RESOLVED:** subdelegation is forbidden by default and requires explicit profile-defined redelegation authority for the capability/resource being passed; every profile defines finite maximum chain depth;
7. authoritative registration/status transaction format;
8. **RESOLVED:** current grantor ControllerPolicy or current DelegationPolicy may revoke; the delegate may relinquish its own grant under a profile-defined proof; historical grant-signing authority has no continuing revocation privilege;
9. **RESOLVED:** registration records use a per-GrantId uint64 revision and exact previous RecordHash chain; REVOKED is terminal;
10. **RESOLVED:** OI-014 v1 GrantId and RecordHash are exactly SHA2-256 Multihash (0x12 0x20 + 32-byte digest); alternate algorithms are invalid until a future protocol revision;
11. **RESOLVED:** core separates private/full GrantBytes from a minimal authoritative registration anchor; public registries need not expose grantor/delegate/capability/resource/time/parent fields; GrantId commits to full semantics;
12. resolution/discovery API semantics for registered grants — grant availability remains profile/deployment-owned; core requires fail-closed verification when full committed grant material cannot be obtained.

No CDDL should be frozen until these questions are resolved.
