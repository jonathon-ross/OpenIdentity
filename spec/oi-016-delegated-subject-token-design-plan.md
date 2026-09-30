# OI-016 Delegated Subject Token — Design Plan

**Status:** Design draft; non-normative
**Target:** protocol-neutral binding of one exact OI-014 delegation path to one exact OI-015 authentication ceremony
**Depends on:** OI-014 DelegationGrant v1 (FROZEN-NORMATIVE), OI-015 Authentication Assertion v1 (FROZEN-NORMATIVE)

## 1. Purpose

OI-014 proves constrained delegated authority from a rootGrantor to a terminal delegate. OI-015 proves current authentication and verifier-bound intent for an actor.

OI-016 binds one exact OI-014 path to one exact OI-015 assertion without redefining either frozen primitive.

Core OI-016 contains no OAuth scope, resource, client, JWT, DPoP, or access-token semantics.

## 2. Candidate model

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

Candidate derived identifier:

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

## 14. Candidate stable errors

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
    DELEGATION_NOT_CURRENTLY_USABLE
    ACTOR_ASSERTION_ID_MISMATCH
    ACTOR_IDENTITY_MISMATCH
    DELEGATION_CONTEXT_MISMATCH

## 15. Positive vector plan

- DS01 — one direct grant plus matching OI-015 actor assertion;
- DS02 — two-grant root-to-child path;
- DS03 — path at maximum candidate depth;
- DS04 — exact maximum evidence-size boundary;
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

## 18. Questions before CDDL

1. Exact v1 bounds for registryDomain, GrantBytes, path depth, and total evidence size.
2. Exact frozen OI-014 registryDomain wire representation to reuse.
3. Whether DelegationEvidenceId and DelegatedSubjectTokenId are both normative derived identifiers.
4. Whether serialized GrantId beside derivable GrantBytes earns its redundancy.
5. Whether OI-016 itself needs a signature; current direction is no.
6. Whether actorAssertionId should bind OI-015 AssertionId or complete secured OI-015 bytes; current direction is AssertionId.
7. Stable distinction between authoritative-state lookup failure and resolved-but-unusable delegation.

No OI-016 wire labels are frozen until these questions are resolved adversarially.

## 19. Freeze discipline

OI-016 development MUST NOT modify frozen Protocol v2 / IdentityState v3, OI-014 v1, or OI-015 v1 bytes.

OI-016 begins draft/non-normative and requires deterministic vectors, independent cross-language verification, checksum, and release gate before normative promotion.
