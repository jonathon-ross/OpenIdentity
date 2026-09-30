# OI-014 — DelegationGrant and Authoritative Registration

**Status:** Design draft; non-normative  
**Protocol dependency:** ProtocolVersion 2 / IdentityState v3 candidate  
**Purpose:** Define constrained delegation without transferring root identity authority
**Draft wire schema:** `spec/cddl/openidentity-delegation-v1.cddl`

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

- requires an ACTIVE rootGrantor IdentityState v3;
- uses the current DelegationPolicy;
- binds the grant to the current DelegationAuthority.generation;
- creates a separate authoritative grant record;
- does not increment the rootGrantor IdentityState sequence;
- does not change the rootGrantor StateHash.

Generation changes invalidate prior-generation grants according to the v3 rules.

## 3. Principals

A grant has exactly one **rootGrantor**, one **issuer**, and one **delegate**.

`rootGrantor` is the permanent OpenIdentity Identity ID from whose DelegationAuthority the delegation chain originates.

`issuer` is the principal immediately issuing this grant. For a direct grant, issuer is the rootGrantor OpenIdentity principal and registration is authorized by the rootGrantor's current DelegationPolicy. For a child grant, issuer is the authenticated DelegatePrincipal of the parent grant and registration is authorized by the parent's explicit redelegation authority.

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

For OPENIDENTITY delegates, the current AuthenticationAuthority authenticates relinquishment under the dedicated OI-014 relinquishment domain and current-state/generation binding defined in Section 3B.

For PROFILE_PRINCIPAL delegates, the principal profile defines the relinquishment proof binding.

### Principal profile versioning

A principalProfile MUST identify immutable semantics sufficiently to prevent a later profile revision from changing:

- principalId equality;
- proof/control requirements;
- key-rotation continuity;
- attestation identity meaning;
- relinquishment authorization.

An incompatible change requires a new profile identity/version.

## 3B. OPENIDENTITY delegate authentication purpose

For a DelegatePrincipal of type OPENIDENTITY, OI-014 uses the delegate identity's **current AuthenticationAuthority** to authenticate actions performed in the delegate role.

This applies to:

- issuing a child grant as the authenticated parent delegate;
- relinquishing a grant held by that delegate;
- grant-use profiles that require core OpenIdentity identity authentication unless the capability profile deliberately defines an additional proof.

ControllerPolicy is not the ordinary delegate-authentication authority. DelegationPolicy is not the delegate-authentication authority merely because the action concerns delegation.

The separation is:

    WHO is acting?
        current AuthenticationAuthority

    WHAT may that principal redelegate/use?
        authoritative DelegationGrant + capability/profile constraints

### Current-state binding

An OPENIDENTITY delegate proof MUST bind to the exact current authoritative delegate IdentityState context.

For child issuance, the core signing input is refined to include:

    delegateStateHash
    authenticationGeneration
    verificationMethodId

Proposed signing structure:

    [
      "OpenIdentity Delegation Child Grant",
      1,
      registryDomain,
      childGrantBytes,
      parentGrantId,
      currentParentRecordHash,
      delegateStateHash,
      authenticationGeneration,
      verificationMethodId
    ]

The verification method MUST satisfy the delegate's current AuthenticationPolicy.

`delegateStateHash` MUST equal the exact current authoritative StateHash of the OPENIDENTITY delegate.

`authenticationGeneration` MUST equal that state's AuthenticationAuthority.generation.

A proof over a historical delegate state is stale even if the same authentication key remains present later.

### AuthenticationPolicy absence and status

An OPENIDENTITY delegate cannot authenticate a new child-issuance or relinquishment action when:

- its current IdentityState is DEACTIVATED;
- its current AuthenticationPolicy is absent;
- the proof does not satisfy the current AuthenticationPolicy;
- the submitted authentication generation is not current.

Being named as a grant delegate does not itself create an AuthenticationPolicy or bypass these conditions.

### Authentication generation

A generation-preserving AuthenticationPolicy rotation may allow existing downstream authentication trust according to the applicable profile, but every **new OI-014 delegate proof** MUST satisfy the current AuthenticationPolicy and bind the current delegate StateHash/generation.

If AuthenticationAuthority generation changes, previously prepared OI-014 delegate proofs are stale.

This authentication generation is distinct from the rootGrantor's delegation generation. The former proves freshness of the acting delegate's identity authentication; the latter controls continued usability of the delegation chain.

### OPENIDENTITY relinquishment

Relinquishment by an OPENIDENTITY delegate uses the same current AuthenticationAuthority but a distinct signing domain:

    [
      "OpenIdentity Delegation Grant Relinquishment",
      1,
      registryDomain,
      grantId,
      currentRecordHash,
      nextRevision,
      delegateStateHash,
      authenticationGeneration,
      verificationMethodId
    ]

A child-issuance AuthenticationPolicy signature MUST NOT be accepted as a relinquishment signature, or vice versa.

For PROFILE_PRINCIPAL delegates, the cryptographically pinned principal profile continues to define equivalent current-control/freshness semantics and MUST bind the applicable OI-014 core signing input.

## 4. Canonical DelegationGrant

The initial logical grant contains:

    DelegationGrant {
        version
        rootGrantor
        issuer
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

### rootGrantor

The permanent OpenIdentity Identity ID whose DelegationAuthority is the root security generation for the complete delegation chain.

For a direct grant, rootGrantor is also the issuer.

For every child grant, rootGrantor MUST equal the parent's rootGrantor exactly. A child cannot change delegation roots.

### issuer

The principal immediately authorizing issuance of this grant.

For a direct grant, issuer is the OPENIDENTITY principal corresponding to rootGrantor and the current root DelegationPolicy authorizes registration.

For a child grant, issuer MUST equal the parent grant's delegate and must authenticate under that principal's applicable proof profile. The parent grant's explicit redelegation authority, not the issuer's unrelated root identity authority, constrains child issuance.

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
        profile: ProfileRef(CAPABILITY)
        capabilityId
    }

`profile` is a cryptographically pinned ProfileRef(CAPABILITY) identifying the immutable descriptor that owns the capability identifier space and semantics.

`capabilityId` is opaque to OI-014 core. Equality in the core protocol is exact canonical equality of both fields.

The final wire representation will use deterministic byte/text forms with explicit length bounds. Human-readable examples do not determine the eventual encoding.

A profile MUST define:

- its immutable ProfileRef/profileHash;
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

A ProfileRef MUST cryptographically identify immutable semantics through its profileHash so later profile changes cannot retroactively broaden an already-registered grant.

An incompatible capability or resource semantic change necessarily produces a new profileHash and therefore a new ProfileRef.

Registries and verifiers MUST evaluate a registered grant using the profile semantics identified by its GrantBytes, not whatever newer profile happens to exist at evaluation time.

## 4C. Cryptographically pinned profile semantics

Profile identity is security-critical. OI-014 MUST NOT rely on a mutable human-readable profile name, URL, registry entry, package version, or vendor label as the sole identifier of capability or principal semantics.

The core logical reference is refined to:

    ProfileRef {
        profileKind
        profileHash
    }

where `profileKind` distinguishes the semantic class of profile, such as capability/resource semantics or external-principal semantics, and `profileHash` is a SHA2-256 Multihash commitment to the exact canonical profile descriptor.

The initial profile hash construction is:

    ProfileBytes = deterministic canonical encoding of ProfileDescriptor
    profileHash  = 0x12 || 0x20 || SHA-256(ProfileBytes)

As with GrantId and RecordHash, OI-014 v1 accepts only the SHA2-256 Multihash profile.

Human-readable profile names, versions, URIs, package coordinates, or vendor identifiers MAY appear inside the descriptor or resolution metadata, but they are not substitutes for profileHash.

### ProfileDescriptor

A profile descriptor defines the immutable semantics required by OI-014 to interpret the profile.

A capability/resource profile descriptor MUST commit, directly or by immutable referenced material, to at least:

- the recognized capability identifier universe or deterministic identifier rules;
- capability coverage/implication semantics;
- resource-constraint encoding and validation rules;
- resource coverage/subset semantics;
- redelegation semantics;
- maximum grant lifetime;
- maximum delegation-chain depth;
- any profile-specific registration/use constraints.

A principal profile descriptor MUST commit to at least:

- canonical principalId syntax;
- principal equality semantics;
- authentication/control proof requirements;
- key-rotation continuity rules;
- attestation identity semantics when applicable;
- relinquishment authorization/proof rules.

A descriptor may reference external specifications only when the reference is immutable and unambiguous. A mutable "latest" URL or mutable package tag is insufficient for security semantics.

### Resolution and verification

Before interpreting a profile-owned field, a conforming registry/verifier SHALL:

1. obtain the ProfileDescriptor or an equivalent immutable representation;
2. reconstruct its canonical ProfileBytes;
3. recompute profileHash;
4. require exact equality with the ProfileRef;
5. require the expected profileKind;
6. evaluate the grant using those pinned semantics.

If the profile cannot be resolved or its hash does not verify, processing MUST fail closed.

A verifier MUST NOT substitute a locally newer descriptor merely because it has the same display name.

### CapabilityRef refinement

The capability identity becomes:

    CapabilityRef {
        profile: ProfileRef(CAPABILITY)
        capabilityId
    }

Two capabilities from descriptors with different profileHash values are different capability identities even if their human-readable names and capabilityId bytes are identical.

A child grant cannot switch profileHash during attenuation unless the parent profile semantics explicitly define and cryptographically pin a safe cross-profile mapping. Core OI-014 v1 defines no implicit cross-profile mapping.

### PROFILE_PRINCIPAL refinement

A profile-defined principal becomes:

    DelegatePrincipal {
        principalType = PROFILE_PRINCIPAL
        principalProfile: ProfileRef(PRINCIPAL)
        principalId
    }

Two external principals interpreted under different principal-profile hashes are not the same canonical principal merely because their principalId/display strings match.

### Registry consistency

Registries do not get to redefine profile semantics.

If Registry A and Registry B process the same GrantBytes, the embedded ProfileRefs require both to evaluate the same pinned profile descriptors.

A registry MAY refuse to support a profile. It MUST NOT accept the grant while silently applying different semantics.

### Profile evolution

Any incompatible semantic change produces different ProfileBytes and therefore a different profileHash.

Compatible editorial changes that do not affect canonical ProfileBytes may be published as explanatory material, but normative semantic changes require a new ProfileRef.

There is no in-place mutation of the semantics identified by an existing profileHash.

A migration from Profile A to Profile B requires a new DelegationGrant/GrantId unless a future profile-migration mechanism explicitly defines otherwise.

### Profile-descriptor availability

Content addressing proves descriptor integrity, not availability.

Deployments/profiles MUST provide a way for conforming registries and relying parties to obtain required descriptors.

A profile descriptor may be distributed through an OpenIdentity registry, HTTPS, package artifact, content-addressed store, application bundle, or another mechanism, provided the verifier checks the exact profileHash before use.

Unavailable required profile semantics cause fail-closed behavior.

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

## 5B. Nonce, duplicate registration, and re-granting

`nonce` distinguishes intentionally separate grant intents that would otherwise have identical authority semantics.

Because nonce is inside GrantBytes, changing nonce changes GrantId.

### Nonce requirements

The nonce MUST be present in every DelegationGrant.

The final wire profile MUST define a fixed or bounded byte length and minimum entropy requirement before freeze.

Nonce is not a timestamp, sequence number, registry revision, or authorization proof. It MUST NOT be interpreted as ordering information.

Grantors/issuers SHOULD generate nonce values with sufficient randomness to make accidental GrantId reuse negligible.

A registry MUST NOT rewrite, normalize, generate, or replace a submitted nonce after the grant authorization proof has been created because doing so changes GrantBytes and invalidates the authorization.

### Duplicate registration of the same GrantId

Within one registryDomain, authoritative registration of a GrantId is a one-time creation event.

If `(registryDomain, GrantId)` already has an authoritative RegisteredGrantState history, another REGISTER request for that same GrantId MUST NOT:

- create another revision-1 history;
- create a later ACTIVE revision;
- refresh `registeredAt`;
- extend validity;
- erase REVOKED status;
- replace grantorStateHash or delegationGeneration;
- reset previousRecordHash;
- otherwise treat replayed registration as a new grant.

An exact duplicate submission MAY return/idempotently reference the already-existing authoritative record, but it does not create new authoritative state.

If the existing history is REVOKED, REGISTER for the same GrantId remains rejected/terminal.

### Re-granting equivalent authority

Revocation is scoped to GrantId, not to semantic equivalence classes such as "same grantor + delegate + capabilities."

A current authorized issuer MAY intentionally create a new grant containing equivalent authority by using a distinct nonce, producing different GrantBytes and a different GrantId.

That new grant requires the complete current registration process and fresh authorization applicable to its issuance path.

For a direct grant, the new registration MUST be authorized by the rootGrantor's current DelegationPolicy and bound to the current rootGrantor StateHash/current delegation generation.

For a child grant, the new registration MUST be authorized by the current usable parent chain, current authenticated parent delegate, and current explicit redelegation authority.

A historical signature over an earlier grant does not authorize the new GrantBytes because the nonce/GrantId differ.

### Revocation bypass resistance

The ability to issue a new equivalent grant is not a bypass of GrantId revocation when current authority deliberately authorizes the new grant.

Conversely, a party that no longer has current issuance authority MUST NOT regain authority merely by changing nonce.

In particular:

- a rotated-out DelegationPolicy key cannot mint a replacement direct grant;
- a revoked/expired/generation-invalid parent cannot mint a replacement child grant;
- a former delegate that no longer authenticates as the current parent delegate cannot mint a child;
- copying capabilities/resources/time fields from a revoked grant conveys no registration authority.

### Semantic duplicate policy

Core OI-014 does not require registries to reject two different GrantIds merely because their disclosed grant semantics appear equivalent.

Determining semantic equivalence across profile-owned capabilities/resources can be complex and profile-dependent, and treating equivalence as identity would undermine content-addressed GrantId semantics.

Profiles MAY impose stronger duplicate-authority policies, quotas, approval workflows, or uniqueness constraints, but those are additional registration rules. They MUST NOT merge distinct GrantIds or cause one grant's revocation status to be silently applied to another.

### registeredAt immutability

For revision 1, `registeredAt` is established exactly once.

Later status revisions preserve the original registration time as part of the grant-state history semantics. A replay, mirror, migration, or status transition MUST NOT refresh it to make an old grant appear newly registered.

If a future migration profile needs destination-observation time, that value must be a distinct field and MUST NOT replace the original authoritative registeredAt.

## 6. Delegation authorization signature

Direct registration requires the rootGrantor's current DelegationPolicy authorization over the exact GrantBytes, registryDomain, rootGrantor state context, and delegation generation. Child registration instead requires authenticated issuer authority derived from the exact usable parent grant and its explicit redelegation semantics.

The signing input MUST be domain-separated from root operations and from DelegationPolicy proof of possession.

Proposed signing structure:

    [
      "OpenIdentity Delegation Grant",
      1,
      registryDomain,
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

1. obtain the current authoritative rootGrantor IdentityState;
2. require IdentityState v3 and status ACTIVE;
3. require a present DelegationPolicy;
4. deterministically encode and validate GrantBytes;
5. for a direct grant, require grant.rootGrantor to equal the current Identity ID and grant.issuer to identify that same OpenIdentity principal;
6. validate time/expiry constraints;
7. validate capability/resource syntax under the applicable profile;
8. derive GrantId;
9. for a direct grant, construct the exact delegation-grant signing input using current rootGrantor StateHash and current delegation generation;
10. for a direct grant, verify the complete current DelegationPolicy threshold;
11. if parentGrantId is present, require rootGrantor equality with the parent, require issuer equality with the parent's delegate, authenticate that issuer, and validate parent redelegation/attenuation rules;
12. atomically establish at most one authoritative registration record for that GrantId;
13. bind the record to the current root delegation generation and current rootGrantor StateHash.

Registration MUST NOT mutate IdentityState, consume root sequence, or change StateHash.

## 8. RegisteredGrantState

OI-014 has one canonical logical authoritative registration/status object: `RegisteredGrantState`.

It is intentionally a minimal commitment/status record. GrantBytes and parentGrantId remain in the immutable private/full grant committed by GrantId and are not duplicated in the canonical registration state.

The complete logical fields and transition semantics are defined below.

## 8A. RegisteredGrant state history

Authoritative grant registration/status uses a per-(registryDomain, GrantId) monotonic revision chain. It is independent of the rootGrantor IdentityState sequence.

The canonical logical state is:

    RegisteredGrantState {
        registryDomain
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

- is scoped to one (registryDomain, GrantId);
- is not the rootGrantor IdentityState sequence;
- does not alter rootGrantor StateHash;
- does not alter DelegationAuthority.generation;
- does not order records belonging to other GrantIds.

A rootGrantor may therefore have many independently evolving grant records without serializing all grant activity through the root identity state machine.

## 8B. Privacy-preserving registration and disclosure

OI-014 separates **grant authority content** from **authoritative registration evidence**.

A registry does not need to publish GrantBytes in order to establish that a particular GrantId was authoritatively registered.

### Full/private grant

GrantBytes contain the authority-bearing grant semantics, including:

- rootGrantor;
- issuer;
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

The rootGrantor Identity ID, issuer/delegate identities, capabilities, resources, expiry, and parent relationship are already committed by GrantId through GrantBytes and therefore need not be duplicated in a public anchor merely for integrity.

A deployment MAY store additional indexed metadata privately or publicly, but such metadata is outside the canonical minimal registration state unless a future profile explicitly makes it canonical.

### Registration validation still sees the full grant

Privacy-preserving storage does not weaken registration validation.

Before establishing revision 1, the registration processor MUST possess the exact GrantBytes and perform the complete OI-014 registration checks, including:

- recompute GrantId;
- validate rootGrantor identity against the current authoritative IdentityState;
- validate direct issuer equality or child issuer/parent-delegate equality;
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
5. validate the current rootGrantor/root-delegation-generation usability conditions;
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

- rootGrantor Identity ID;
- issuer principal;
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

## 8C. Registry-domain binding and cross-registry replay

GrantId identifies immutable grant intent and is intentionally portable across registries.

Authoritative registration state is **not** portable by default.

Every RegisteredGrantState belongs to exactly one immutable `registryDomain`.

### RegistryDomain

`registryDomain` is a canonical identifier for the authority domain whose ordering/finality rules determine which registration/status record is authoritative.

It identifies an authority domain, not merely a network endpoint or server hostname.

Examples of possible profile-defined authority domains include:

- one specific OpenIdentity registry deployment;
- one blockchain network plus one specific registration contract/program identity;
- one enterprise trust domain;
- one replicated-log authority.

The final encoding/registry for `registryDomain` will be defined before wire freeze.

A registry profile MUST define how its canonical registryDomain is derived and compared.

### Record binding

`registryDomain` is included in RegisteredGrantState and therefore in RecordBytes and RecordHash.

Two otherwise identical registration records in different registry domains have different RecordHashes.

A revision chain MUST remain in one registryDomain. A successor whose registryDomain differs from its predecessor is invalid.

### Registration authorization domain

Direct grant registration authorization MUST also bind to the intended registryDomain.

The proposed direct grant signing structure is refined to:

    [
      "OpenIdentity Delegation Grant",
      1,
      registryDomain,
      GrantBytes,
      grantorStateHash,
      delegationGeneration,
      verificationMethodId
    ]

A signature authorizing registration in Registry A MUST NOT authorize registration in Registry B.

Child-registration proofs likewise MUST bind the intended registryDomain in their eventual signing structure.

### Status-transition domains

Grantor revocation and delegate relinquishment signing structures MUST include the current RegisteredGrantState's registryDomain.

This prevents a status proof prepared for one authority domain from being replayed against an independently registered copy in another.

### Same GrantId in multiple registries

Core OI-014 permits the same GrantId to be registered independently in more than one registryDomain only when the deployment/profile intentionally allows that behavior.

Each registration is a separate authoritative state history:

    (registryDomain A, GrantId) -> revision chain A
    (registryDomain B, GrantId) -> revision chain B

Revocation in A does not cryptographically mutate B.

A relying-party profile MUST therefore define which registryDomain or set of registryDomains it trusts and, if multiple are trusted, how status is combined.

Core OI-014 MUST NOT silently treat ACTIVE in one registry as overriding REVOKED in another, or vice versa.

High-assurance profiles SHOULD avoid ambiguous multi-registry authority by naming exactly one authoritative registryDomain or defining explicit federation rules.

### Cross-registry copying

Copying RecordBytes from Registry A into Registry B does not create an authoritative B record because the embedded registryDomain remains A.

Re-encoding the record with registryDomain B changes RecordBytes/RecordHash and requires fresh B-domain registration authorization.

A transport bridge or blockchain mirror may reproduce A-domain records without becoming a new authority domain if it preserves the exact A-domain bytes and the relying party still evaluates authority as Registry A.

### Registry migration/federation

Migration of an authoritative grant history from one registryDomain to another is not implicit.

A future federation/migration profile must define:

- authorization to migrate;
- treatment of existing ACTIVE/REVOKED status;
- revision/history continuity;
- conflict handling;
- whether both domains remain authoritative;
- relying-party trust semantics.

Core OI-014 v1 does not infer migration from copied records.

## 9. Grant usability

A registered grant is usable only if all of the following hold:

- its registration is authoritative;
- its status permits use;
- the rootGrantor identity is currently ACTIVE;
- the grant's bound delegation generation equals the rootGrantor's current DelegationAuthority.generation;
- current time satisfies registration/notBefore/expiry constraints;
- the requested capability is explicitly granted;
- the requested resource is within the grant's resource constraints;
- the acting principal is the grant's delegate;
- delegate authentication satisfies the applicable profile;
- every parent grant, if any, remains usable.

A current DelegationPolicy signature is **not** required each time an already-registered grant is used. Generation binding provides planned survival/invalidation behavior across policy rotations.

## 10. Generation semantics

Every grant chain is rooted in the rootGrantor's delegation generation N. A direct registered grant records that generation; child grants inherit the same root generation transitively through their parent chain and MUST NOT substitute another generation.

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

Either of the following current authorities may revoke any ACTIVE grant whose rootGrantor is the identity they currently govern:

1. the rootGrantor's current ControllerPolicy; or
2. the rootGrantor's current DelegationPolicy.

The rootGrantor IdentityState MUST be current and authoritative. ControllerPolicy revocation provides a root/emergency path. DelegationPolicy revocation provides the ordinary delegation-management path.

If DelegationPolicy A registered grant G and later rotates to DelegationPolicy B with PRESERVE_EXISTING, G may remain usable, but B—not A—is the DelegationPolicy authority that may subsequently revoke G. A historical or rotated-out DelegationPolicy has no continuing revocation authority.

If the current DelegationPolicy is absent, ControllerPolicy remains able to revoke a still-recorded grant even though generation-changing policy removal will normally already make prior-generation grants unusable.

### Delegate relinquishment

The delegate MAY relinquish its own ACTIVE grant if the applicable delegate-principal profile defines a verifiable authentication/signature mechanism.

Relinquishment only reduces the delegate's authority. It MUST NOT modify the grant, transfer authority, alter the rootGrantor IdentityState, change delegation generation, or reactivate another grant.

A parent delegate relinquishing its parent grant makes descendant grants unusable through the normal parent-usability rule.

### Domain separation

Grantor revocation and delegate relinquishment are distinct proof purposes.

Proposed grantor revocation signing structure:

    [
      "OpenIdentity Delegation Grant Revocation",
      1,
      registryDomain,
      grantId,
      currentRecordHash,
      nextRevision,
      currentGrantorStateHash,
      verificationMethodId
    ]

Proposed delegate relinquishment signing structure:

    [
      "OpenIdentity Delegation Grant Relinquishment",
      1,
      registryDomain,
      grantId,
      currentRecordHash,
      nextRevision,
      delegatePrincipal
    ]

The final delegate-proof binding may include a delegate verification-method identifier or profile-specific proof context once the delegate principal model is resolved.

For grantor revocation, `currentGrantorStateHash` MUST equal the exact current authoritative rootGrantor IdentityState used to evaluate ControllerPolicy or DelegationPolicy authorization. A proof over a historical grantor state is stale even if the same verification key remains present later.

A signature from one revocation purpose MUST NOT be accepted for another.

### Revocation transition validation

A processor accepting ACTIVE -> REVOKED SHALL:

1. load the exact current authoritative RegisteredGrantState;
2. require status ACTIVE;
3. require nextRevision = current.revision + 1;
4. require previousRecordHash = RecordHash(current);
5. determine whether the request is grantor revocation or delegate relinquishment;
6. for grantor revocation, load the current authoritative rootGrantor IdentityState, require the proof's currentGrantorStateHash to equal that exact StateHash, and verify either current ControllerPolicy or current DelegationPolicy authorization under the correct domain;
7. for delegate relinquishment, verify the current grant delegate under the applicable delegate-principal profile and relinquishment domain;
8. construct the canonical REVOKED successor;
9. atomically establish at most one authoritative successor.

A stale proof over an earlier RecordHash/revision cannot revoke a later grant-state record.

### Generation invalidation versus individual revocation

Generation mismatch and individual REVOKED status are independent reasons a grant is unusable.

A generation-invalid grant need not receive an individual REVOKED record merely to become unusable. The rootGrantor MAY still record an explicit revocation for audit/finality, using current revocation authority.

Neither generation changes nor deactivation may convert a REVOKED grant back to ACTIVE.

## 12. Subdelegation and attenuation

Subdelegation is explicit, never ambient.

A child grant MUST reference exactly one parentGrantId and MUST satisfy all parent constraints.

At minimum:

- child rootGrantor MUST equal parent rootGrantor;
- child issuer MUST equal the authenticated delegate of the parent grant;
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

The rootGrantor's current DelegationPolicy does not sign each child by default. Child issuance is authorized by the authenticated parent delegate plus explicit parent redelegation authority. The entire chain nevertheless remains dependent on the rootGrantor's current ACTIVE status and root delegation generation.

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

Those constraints narrow a grant; they do not expand the rootGrantor's underlying authority.

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
1a. Every grant has one immutable rootGrantor; child issuer authority derives only through an authoritative parent chain and cannot switch delegation roots.
2. Registration always validates the current ACTIVE rootGrantor state.
3. Historical DelegationPolicy keys cannot create new authoritative grants.
4. Grant registration never changes root IdentityState or sequence.
5. GrantId commits to exact canonical GrantBytes.
6. Registration binds to exact rootGrantor StateHash and root delegation generation.
7. Generation invalidation cannot be bypassed by timestamps or historical-state references.
8. Revoked grants cannot reactivate.
9. Child grants cannot exceed parent authority or lifetime.
10. Deactivation makes grants unusable; recovery cannot resurrect old-generation grants.
11. Delegate authentication is distinct from rootGrantor/direct-registration or parent-issuer delegation authorization.
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
- wrong rootGrantor or child issuer;
- wrong delegate authentication;
- expired/not-yet-valid grant;
- unauthorized capability/resource;
- registration while rootGrantor DEACTIVATED;
- registration with absent DelegationPolicy;
- duplicate/unauthorized delegation authorization proofs;
- cross-domain proof substitution;
- child capability escalation;
- child resource widening;
- child expiry beyond parent;
- child of revoked/invalidated parent;
- revoked grant reactivation attempt;
- duplicate REGISTER replay attempting to refresh registeredAt or create a second ACTIVE history;
- nonce-changed replacement grant signed by historical/rotated-out authority.

## 17A. Stable core error taxonomy

The initial OI-014 conformance profile uses stable semantic error labels. Wire/API transport mapping is deployment-owned, but independent implementations must agree on the underlying rejection class.

Initial core errors:

    INVALID_DELEGATION_GRANT
    INVALID_GRANT_VERSION
    INVALID_ROOT_GRANTOR
    INVALID_ISSUER
    INVALID_DELEGATE
    INVALID_CAPABILITY_SET
    INVALID_RESOURCE_CONSTRAINT
    UNKNOWN_PROFILE
    PROFILE_HASH_MISMATCH
    INVALID_TIME_RANGE
    GRANT_EXPIRED_AT_REGISTRATION
    PROFILE_LIFETIME_EXCEEDED
    INVALID_NONCE

    INVALID_GRANT_ID
    GRANT_HASH_COLLISION
    INVALID_REGISTRY_DOMAIN
    GRANT_ALREADY_REGISTERED
    GRANT_REVOKED
    GRANT_NOT_REGISTERED

    ROOT_GRANTOR_NOT_ACTIVE
    DELEGATION_POLICY_ABSENT
    INVALID_ROOT_STATE_HASH
    INVALID_DELEGATION_GENERATION
    INVALID_AUTHENTICATION_GENERATION
    UNAUTHORIZED_GRANT_REGISTRATION
    INVALID_REGISTRATION_PROOF
    CROSS_DOMAIN_PROOF

    PARENT_GRANT_REQUIRED
    PARENT_GRANT_NOT_FOUND
    PARENT_GRANT_UNUSABLE
    ROOT_GRANTOR_MISMATCH
    ISSUER_PARENT_DELEGATE_MISMATCH
    REDELEGATION_NOT_AUTHORIZED
    CAPABILITY_ESCALATION
    RESOURCE_SCOPE_WIDENING
    CHILD_TIME_WIDENING
    PROFILE_SUBSTITUTION
    DELEGATION_CYCLE
    DELEGATION_DEPTH_EXCEEDED

    INVALID_GRANT_REVISION
    INVALID_PREVIOUS_RECORD_HASH
    RECORD_HASH_MISMATCH
    RECORD_HASH_COLLISION
    REVISION_OVERFLOW
    REGISTRY_DOMAIN_MISMATCH

    UNAUTHORIZED_REVOCATION
    INVALID_REVOCATION_PROOF
    UNAUTHORIZED_RELINQUISHMENT
    INVALID_RELINQUISHMENT_PROOF
    TERMINAL_GRANT_STATE

A verifier SHOULD report the most specific stable error it can determine without weakening validation ordering or leaking deployment-sensitive information.

Profiles may define additional profile-specific errors, but they MUST NOT redefine the meaning of these core labels.

## 18. Open design questions before wire freeze

The following require deliberate decisions before assigning final CDDL labels:

1. **RESOLVED:** uint64 whole Unix-epoch seconds UTC; required finite expiresAt; optional notBefore; interval is effectiveNotBefore <= t < expiresAt; profile-defined bounded skew may affect evaluation only;
2. **RESOLVED:** capability identity is (ProfileRef(CAPABILITY), capabilityId); capabilityId is opaque to core; no implicit textual hierarchy;
3. **RESOLVED:** resources and deterministic coverage/subset semantics are profile-owned; core binds resource constraints to individual capabilities and fails closed when attenuation cannot be established;
4. **RESOLVED:** core supports native OPENIDENTITY and extensible PROFILE_PRINCIPAL; AI agents/workloads are profile-defined, not core types; principal identity is separate from proof material;
5. **RESOLVED:** core requires finite expiry but no universal maximum; every registration profile MUST define and enforce a maximum lifetime;
6. **RESOLVED:** subdelegation is forbidden by default and requires explicit profile-defined redelegation authority for the capability/resource being passed; every profile defines finite maximum chain depth;
7. authoritative registration/status transaction format;
8. **RESOLVED:** current rootGrantor ControllerPolicy or current rootGrantor DelegationPolicy may revoke; the delegate may relinquish its own grant under a profile-defined proof; historical grant-signing authority has no continuing revocation privilege;
9. **RESOLVED:** registration records use a per-(registryDomain, GrantId) uint64 revision and exact previous RecordHash chain; REVOKED is terminal;
10. **RESOLVED:** OI-014 v1 GrantId and RecordHash are exactly SHA2-256 Multihash (0x12 0x20 + 32-byte digest); alternate algorithms are invalid until a future protocol revision;
11. **RESOLVED:** core separates private/full GrantBytes from a minimal authoritative registration anchor; public registries need not expose grantor/delegate/capability/resource/time/parent fields; GrantId commits to full semantics;
12. resolution/discovery API semantics for registered grants — grant availability remains profile/deployment-owned; core requires fail-closed verification when full committed grant material cannot be obtained.

No CDDL should be frozen until these questions are resolved.
