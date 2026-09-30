# OI-016 Delegated Subject Token — Design Plan

**Status:** FROZEN-NORMATIVE v1
**Target:** protocol-neutral binding of one exact OI-014 delegation path to one exact OI-015 authentication ceremony
**Depends on:** OI-014 DelegationGrant v1 (FROZEN-NORMATIVE), OI-015 Authentication Assertion v1 (FROZEN-NORMATIVE)

## 1. Purpose

OI-014 proves constrained delegated authority from a rootGrantor to a terminal delegate. OI-015 proves current authentication and verifier-bound intent for an actor.

OI-016 binds one exact OI-014 path to one exact OI-015 assertion without redefining either frozen primitive.

Core OI-016 contains no OAuth scope, resource, client, JWT, DPoP, or access-token semantics.

## 2. Normative model

    DelegationEvidence {
        version
        registryDomain
        grants[]
    }

    GrantEvidence {
        grantBytes
        grantId
    }

    DelegatedSubjectToken {
        version
        delegationEvidence
        actorAssertionId
    }

Wire labels are not frozen.

## 3. Grant evidence

For every GrantEvidence the verifier recomputes the frozen OI-014 SHA2-256 Multihash GrantId from exact GrantBytes and requires exact equality with grantId.

GrantBytes provide immutable authority content. Current usability is never inferred from embedded bytes alone.

## 4. One ordered path

grants[] is one root-to-terminal path.

For each child:

    child.parentGrantId == previous.grantId

The first grant satisfies OI-014 direct/root semantics. Every path element has the same rootGrantor. Independent paths are not combined.

rootGrantor and terminalDelegate are derived from GrantBytes and are not duplicated.

## 5. DelegationEvidenceId

    DelegationEvidenceBytes =
        deterministicCBOR(DelegationEvidence)

    DelegationEvidenceId =
        0x12 || 0x20 || SHA-256(DelegationEvidenceBytes)

This identifies exact immutable evidence. It does not prove current usability.

## 6. Current-state verification

For every embedded grant, the verifier resolves current RegisteredGrantState at:

    (registryDomain, GrantId)

and performs the complete frozen OI-014 use-time algorithm, including current status/revision, revocation or relinquishment, root delegation generation, root ACTIVE status, time validity, profiles, attenuation, and ancestor usability.

Failure to obtain required authoritative material fails closed.

Historical RecordBytes do not override current registry state.

## 7. Excluded historical transition material

Core OI-016 does not require registration requests, registration signatures, historical DelegationPolicy proofs, child-registration DelegateProofs, revocation proofs, relinquishment proofs, or historical RecordBytes merely to establish use-time authority.

These authorize or describe registry transitions; they are not required by frozen OI-014's relying-party use-time algorithm.

## 8. actorAssertionId

actorAssertionId is the normative OI-015 AssertionId derived from exact OI-015 AssertionBytes.

The verifier independently verifies OI-015, derives AssertionId, and requires:

    OI016.actorAssertionId == AssertionId(OI015)

It also requires:

    OI015.identity == OI016.terminalDelegate

OI-016 does not duplicate OI-015 authentication fields or proofs.

## 9. External-protocol binding

When OI-016 is exercised through an integration profile, that profile MUST include DelegationEvidenceId in the OI-015 contextBytes.

Thus:

    OI-015 contextHash
        commits to
    DelegationEvidenceId + external protocol context

while:

    OI-016 actorAssertionId
        commits to
    exact OI-015 assertion

This prevents delegation swapping and authentication swapping without circular hashing.

## 10. DelegatedSubjectTokenId

Normative derived identifier:

    DelegatedSubjectTokenBytes =
        deterministicCBOR(DelegatedSubjectToken)

    DelegatedSubjectTokenId =
        0x12 || 0x20 || SHA-256(DelegatedSubjectTokenBytes)

It is content identity only, not replay prevention or current authorization proof.

## 11. Verification outline

1. parse OI-016 deterministically;
2. validate version and bounded path;
3. recompute every GrantId;
4. validate root/direct semantics;
5. validate every parentGrantId edge;
6. validate rootGrantor and issuer/delegate relationships;
7. derive rootGrantor, terminalDelegate, DelegationEvidenceId;
8. perform complete current OI-014 use-time verification;
9. independently verify supplied OI-015;
10. derive OI-015 AssertionId;
11. require actorAssertionId equality;
12. require OI-015 identity equals terminalDelegate;
13. require the integration-profile OI-015 context to bind exact DelegationEvidenceId.

## 12. Security properties

Changing any GrantBytes, GrantId, order, parent, or registryDomain changes or invalidates DelegationEvidence.

A different valid OI-015 assertion has a different AssertionId and cannot be substituted.

Historically valid delegation evidence cannot bypass current OI-014 revocation, relinquishment, generation invalidation, deactivation, expiration, or ancestor invalidation.

OI-016 v1 represents one path only and does not union authority from independent paths.

OI-016 binding is not single-use replay protection; OI-015 nonce/replay rules and integration-profile policy remain required.

## 13. Privacy

OI-016 reveals complete GrantBytes for the selected path to the verifier. Only the path required for the operation should be disclosed. Unrelated grants must not be included.

OI-016 v1 does not provide selective disclosure or zero-knowledge delegation proofs.

## 14. Stable errors

    INVALID_DELEGATED_SUBJECT_TOKEN
    INVALID_DELEGATED_SUBJECT_VERSION
    INVALID_DELEGATION_EVIDENCE
    EMPTY_DELEGATION_PATH
    DELEGATION_PATH_TOO_DEEP
    INVALID_GRANT_EVIDENCE
    GRANT_ID_MISMATCH
    INVALID_ROOT_GRANT
    PARENT_GRANT_MISMATCH
    ROOT_GRANTOR_MISMATCH
    ISSUER_DELEGATE_MISMATCH
    DELEGATION_EVIDENCE_TOO_LARGE
    DELEGATION_STATE_UNAVAILABLE
    DELEGATION_NOT_CURRENTLY_USABLE
    ACTOR_ASSERTION_ID_MISMATCH
    ACTOR_IDENTITY_MISMATCH
    DELEGATION_CONTEXT_MISMATCH

## 15. Positive vector plan

- DS01 — one direct grant plus matching OI-015 actor assertion;
- DS02 — two-grant root-to-child path;
- DS03 — path at maximum normative v1 depth;
- DS04 — maximum constructed valid evidence-size boundary fixture at or below the total ceiling;
- DS05 — registryDomain boundary/representation case;
- DS06 — integration fixture proving DelegationEvidenceId is committed by OI-015 contextHash.

## 16. Adversarial vector plan

- DSI01 unsupported version;
- DSI02 empty path;
- DSI03 excessive depth;
- DSI04 mutated GrantBytes with unchanged GrantId;
- DSI05 unsupported GrantId hash profile;
- DSI06 child parentGrantId mismatch;
- DSI07 rootGrantor changes mid-path;
- DSI08 child issuer differs from parent delegate;
- DSI09 reordered grants;
- DSI10 historical path now revoked;
- DSI11 ancestor relinquished;
- DSI12 root delegation generation invalidated;
- DSI13 root identity deactivated;
- DSI14 expired ancestor;
- DSI15 missing authoritative current record;
- DSI16 actorAssertionId mismatch;
- DSI17 OI-015 identity differs from terminal delegate;
- DSI18 OI-015 context binds another DelegationEvidenceId;
- DSI19 different valid OI-015 assertion substituted;
- DSI20 evidence exceeds maximum size;
- DSI21 independent paths spliced;
- DSI22 duplicated path element/cycle.

## 17. OAuth integration profile

RFC 8693 integration is a profile over frozen OI-016 and OI-015:

    subject_token = OI-016 DelegatedSubjectToken
    actor_token   = OI-015 SecuredAuthenticationAssertion

The OAuth profile, not core OI-016, defines token-type identifiers, transport encoding, contextBytes, capability-to-scope mapping, resource mapping, JWT sub/act projection, DPoP policy, metadata, errors, and output-token lifetime.

## 18. Pre-CDDL bounds — RESOLVED

OI-016 distinguishes frozen OI-014 semantic bounds from OI-016 transport/conformance ceilings.

### 18.1 registryDomain

OI-016 reuses the frozen OI-014 v1 representation exactly:

    registryDomain = bstr .size (1..128)

No normalization or reinterpretation is permitted.

### 18.2 GrantBytes

Frozen OI-014 v1 does not define one universal maximum encoded GrantBytes length. Its capability collection is non-empty but not globally count-bounded, while individual profile-owned fields have their own bounds.

OI-016 therefore defines a v1 envelope ceiling:

    len(grantBytes) <= 65,536 bytes

This is an OI-016 interoperability/DoS bound, not a change to OI-014 semantics.

An integration profile MAY impose a smaller ceiling. It MUST NOT enlarge the OI-016 v1 ceiling.

A valid OI-014 grant larger than this remains a valid OI-014 grant but cannot be transported through OI-016 v1.

### 18.3 Path depth

OI-014 capability profiles already commit to maxDelegationDepth. OI-016 MUST enforce every applicable frozen OI-014 profile depth rule.

In addition, OI-016 v1 defines a hard envelope ceiling:

    1 <= grants.length <= 16

The effective permitted depth is the minimum of:

    OI-016 hard ceiling
    all applicable OI-014 profile maxDelegationDepth values
    any smaller integration-profile limit

OI-016 MUST NOT use its ceiling to authorize a depth forbidden by OI-014.

### 18.4 Total DelegationEvidenceBytes

OI-016 v1 defines:

    len(DelegationEvidenceBytes) <= 1,048,576 bytes

This is checked on exact deterministic CBOR bytes.

Profiles MAY impose smaller limits and SHOULD do so when their deployment does not require large grants.

### 18.5 Why both per-grant and total limits

A per-grant limit prevents one pathological grant from dominating parser/memory cost.

A total evidence limit prevents a path of individually legal grants from creating an unbounded subject token.

The path-count limit separately bounds verification work and authoritative registry lookups.

### 18.6 Boundary behavior

Exact maximum values are valid:

    registryDomain length = 128
    grantBytes length = 65,536
    grants.length = 16
    DelegationEvidenceBytes length = 1,048,576, when a valid structural encoding can reach it

One unit above each applicable limit is invalid.

Test vectors MUST pin exact boundaries where reachable. For aggregate encoded-size ceilings, conformance MUST at minimum pin a maximum constructed valid fixture below/equal to the ceiling and an invalid fixture above it; the review MUST NOT assume that every integer encoded size is reachable under all simultaneous structural bounds.

## 19. Commitment model — RESOLVED

Questions 1-4 were reviewed together because they determine which exact bytes OI-016 identifies and whether any redundant cryptographic layer is justified.

### 19.1 DelegationEvidenceId — normative derived identifier

**Decision:** DelegationEvidenceId is normative and derived, but is not serialized inside DelegationEvidence.

    DelegationEvidenceId =
        0x12 || 0x20 ||
        SHA-256(DelegationEvidenceBytes)

It is required because integration profiles need a compact, stable commitment to the exact OI-014 evidence path without copying the complete path into OI-015 contextBytes.

Changing registryDomain, grant order, GrantBytes, or serialized GrantId changes DelegationEvidenceBytes and therefore DelegationEvidenceId.

A verifier MUST derive it from exact deterministic bytes and MUST NOT trust a transport-supplied value.

### 19.2 DelegatedSubjectTokenId — normative derived identifier

**Decision:** DelegatedSubjectTokenId is also normative and derived, but is not serialized inside DelegatedSubjectToken.

    DelegatedSubjectTokenId =
        0x12 || 0x20 ||
        SHA-256(DelegatedSubjectTokenBytes)

It is useful for audit correlation, replay caches, diagnostics, integration bindings, and test vectors.

It is content identity only. It MUST NOT substitute for OI-014 current-state validation, OI-015 verification, nonce consumption, or integration replay policy.

Having both IDs is not redundant:

    DelegationEvidenceId
        identifies immutable delegation evidence independent of actor ceremony

    DelegatedSubjectTokenId
        identifies the final evidence + actorAssertionId pairing

### 19.3 GrantId remains serialized

**Decision:** each GrantEvidence serializes both exact GrantBytes and GrantId even though GrantId is derivable.

The verifier MUST recompute GrantId and require exact equality.

This deliberate redundancy buys several properties:

- each path element has an explicit content-addressed checkpoint;
- child parentGrantId can be compared directly to the previous serialized-and-recomputed GrantId;
- registry lookup keys are explicit without requiring consumers to invent an implicit intermediate representation;
- malformed/mutated GrantBytes fail locally as GRANT_ID_MISMATCH before current registry lookup;
- test vectors can pin exact per-element commitment behavior.

GrantId is only 34 bytes under frozen OI-014 v1, so the security/interoperability value outweighs the small size cost.

A verifier MUST NOT accept a supplied GrantId without recomputation.

### 19.4 OI-016 has no independent signature

**Decision:** core OI-016 v1 is not separately signed.

Its authority is already composed from:

    OI-014
        cryptographically committed grant semantics
        + authoritative current registration/status

    OI-015
        current actor authentication
        + verifier/purpose/nonce/time/context binding

OI-016 adds deterministic binding between them.

Adding a third signature raises an unanswered authority question — which principal would sign it? Requiring rootGrantor would destroy offline delegation; requiring terminal delegate would duplicate OI-015; requiring a bridge/server key would make OI-016 authority depend on an intermediary rather than OpenIdentity evidence.

Therefore:

    OI-016 = deterministic composite security token
             not a separately signed assertion

Transport integrity/confidentiality remains the integration protocol's responsibility.

### 19.5 actorAssertionId binds OI-015 AssertionId, not secured proof bytes

**Decision:** actorAssertionId is the normative OI-015 AssertionId over AssertionBytes.

It does NOT hash the complete SecuredAuthenticationAssertion proof envelope.

Rationale:

- OI-015 deliberately defines AssertionId independently of proof bytes;
- multiple valid AuthenticationPolicy proof sets may satisfy the same assertion;
- threshold policies can have different valid signer subsets;
- signature encodings/algorithms may evolve under explicit policy/version rules without changing the authenticated assertion's semantic content;
- binding proof-envelope bytes would make OI-016 identity depend on which valid proof realization happened to be transported.

The verifier still performs full OI-015 proof verification. Proofs are not ignored; they simply are not part of the cross-object identity commitment.

This permits:

    same exact OI-015 AssertionBytes
    + different valid authorized proof realization
        ->
    same AssertionId
        ->
    same OI-016 actorAssertionId binding

while:

    any change to identity/stateHash/generation/audience/purpose/time/nonce/contextHash
        ->
    different AssertionBytes
        ->
    different AssertionId
        ->
    actorAssertionId mismatch

### 19.6 Proof substitution analysis

An attacker cannot replace a valid OI-015 proof set with an unauthorized or invalid one merely because actorAssertionId excludes proof bytes.

The verifier MUST independently perform complete frozen OI-015 verification before accepting the binding.

Thus:

    actorAssertionId equality
        is necessary
        but not sufficient

and:

    full OI-015 verification
        is always required

### 19.7 No serialized derived IDs

Neither DelegationEvidenceId nor DelegatedSubjectTokenId is serialized into the object it hashes.

This avoids self-reference and redundant consistency fields.

Profiles that transmit either derived ID separately MUST require recomputation before use.

## 20. Authoritative-state resolution errors — RESOLVED

OI-016 distinguishes inability to complete authoritative verification from a conclusive current-state denial.

### 20.1 DELEGATION_STATE_UNAVAILABLE

Use:

    DELEGATION_STATE_UNAVAILABLE

when verification cannot obtain or validate required authoritative material needed to reach a current-usability conclusion.

Examples include:

- authoritative RegisteredGrantState cannot be retrieved;
- required predecessor/history material cannot be obtained when the trusted registry profile requires it;
- required current root IdentityState cannot be resolved;
- a required pinned profile descriptor is unavailable;
- the trusted registry/finality source is temporarily unavailable.

This result is **fail closed**.

It MUST NOT authorize issuance, MUST NOT be treated as ACTIVE, and MUST NOT fall back to embedded historical evidence.

It represents:

    verification incomplete -> deny

not:

    delegation valid

### 20.2 DELEGATION_NOT_CURRENTLY_USABLE

Use:

    DELEGATION_NOT_CURRENTLY_USABLE

when required authoritative material was successfully resolved and verification conclusively determines that the path cannot currently authorize use.

Examples include:

- current record is REVOKED;
- delegate relinquishment made the grant unusable;
- root delegation generation no longer matches;
- root identity is DEACTIVATED;
- grant or ancestor is expired/not yet valid;
- ancestor is currently unusable;
- current profile semantics reject use.

It represents:

    verification complete + current authority denied -> deny

### 20.3 Security rule

Both errors deny OI-016 verification.

Implementations MUST NOT retry with stale embedded status, skip an unavailable ancestor, ignore an unavailable profile, or downgrade current-state verification merely to convert UNAVAILABLE into success.

### 20.4 External error projection

Integration profiles MAY intentionally map both internal results to the same externally visible authorization error to avoid leaking sensitive registry/delegation state.

For example, an OAuth profile may return a generic token-exchange failure while logging/telemetry retains the internal distinction.

Core OI-016 defines the semantic distinction; it does not require external protocols to disclose it.

## 21. Normative v1 CDDL and conformance

All pre-CDDL questions are resolved.

Candidate CDDL and DS01 may now be created. Wire labels remain draft/non-normative until deterministic cross-language conformance and freeze review are complete.

## 22. Freeze discipline

OI-016 development MUST NOT modify frozen Protocol v2 / IdentityState v3, OI-014 v1, or OI-015 v1 bytes.

OI-016 v1 is frozen normative. Frozen v1 bytes and semantics MUST NOT change without explicit protocol/version evolution.
