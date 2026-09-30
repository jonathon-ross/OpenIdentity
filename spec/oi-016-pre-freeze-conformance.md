# OI-016 Delegated Subject Token v1 — Pre-Freeze Conformance Review

**Status:** RELEASE RECORD — OI-016 v1 FROZEN-NORMATIVE  
**Scope:** OI-016 Delegated Subject Token v1 frozen semantics and wire schema  
**Normative CDDL:** `spec/cddl/openidentity-delegated-subject-v1.cddl`

## 1. Current evidence

The frozen normative conformance bundle contains:

- positive vectors DS01-DS06;
- adversarial vectors DSI01-DSI28;
- deterministic Python generation;
- independent Python reconstruction/verification;
- independent Java reconstruction/verification using the repository DeterministicCborWriter;
- no OI-016 checksum or byte-freeze yet.

Both Python and Java suites are green through DS01-DS06 + DSI01-DSI28.

## 2. Positive coverage

- DS01 — direct OI-014 grant evidence bound to exact OI-015 AssertionId.
- DS02 — two-grant root-to-child path; parentGrantId, issuer/delegate, rootGrantor, terminal actor binding.
- DS03 — exact 16-grant OI-016 hard path ceiling.
- DS04 — maximum constructed valid evidence envelope at/below the 1 MiB ceiling with per-grant limits respected.
- DS05 — exact 128-byte opaque registryDomain boundary.
- DS06 — integration context commits exact DelegationEvidenceId and token-exchange purpose.

## 3. Adversarial coverage

### Structure / immutable evidence

- DSI01 — unsupported OI-016 version.
- DSI02 — empty path.
- DSI03 — path above 16-grant hard ceiling.
- DSI04 — mutated GrantBytes with unchanged GrantId.
- DSI05 — unsupported GrantId Multihash code.
- DSI06 — child parentGrantId mismatch.
- DSI07 — rootGrantor changes mid-path.
- DSI08 — child issuer differs from parent delegate.
- DSI09 — otherwise-valid grants reordered.
- DSI20 — DelegationEvidenceBytes above 1 MiB.
- DSI21 — independent valid paths spliced.
- DSI22 — duplicated GrantId/path cycle.
- DSI23 — malformed top-level token structure.
- DSI24 — first path element is not a direct/root grant.
- DSI25 — empty registryDomain.
- DSI26 — registryDomain above 128 bytes.
- DSI27 — malformed GrantId length.
- DSI28 — malformed actorAssertionId length.

### Authoritative current state

All embedded immutable evidence remains valid in DSI10-DSI15.

- DSI10 — current record REVOKED.
- DSI11 — ancestor relinquished.
- DSI12 — root delegation generation invalidated.
- DSI13 — root identity DEACTIVATED.
- DSI14 — expired ancestor.
- DSI15 — required authoritative current state unavailable.

DSI10-DSI14 conclusively return DELEGATION_NOT_CURRENTLY_USABLE.

DSI15 returns DELEGATION_STATE_UNAVAILABLE.

Both classes fail closed.

### OI-015 binding

- DSI16 — actorAssertionId differs from supplied OI-015 AssertionId.
- DSI17 — authenticated OI-015 identity differs from terminal delegate.
- DSI18 — OI-015 context binds a different DelegationEvidenceId.
- DSI19 — another valid assertion from the same actor is substituted.

## 4. Stable semantic error coverage

Every currently defined stable error has direct vector coverage:

- INVALID_DELEGATED_SUBJECT_TOKEN
- INVALID_DELEGATED_SUBJECT_VERSION
- INVALID_DELEGATION_EVIDENCE
- EMPTY_DELEGATION_PATH
- DELEGATION_PATH_TOO_DEEP
- INVALID_GRANT_EVIDENCE
- GRANT_ID_MISMATCH
- INVALID_ROOT_GRANT
- PARENT_GRANT_MISMATCH
- ROOT_GRANTOR_MISMATCH
- ISSUER_DELEGATE_MISMATCH
- DELEGATION_EVIDENCE_TOO_LARGE
- DELEGATION_STATE_UNAVAILABLE
- DELEGATION_NOT_CURRENTLY_USABLE
- ACTOR_ASSERTION_ID_MISMATCH
- ACTOR_IDENTITY_MISMATCH
- DELEGATION_CONTEXT_MISMATCH

## 5. Frozen dependency boundaries

OI-016 MUST NOT modify or reinterpret:

- Protocol v2 / IdentityState v3;
- OI-014 DelegationGrant v1;
- OI-015 Authentication Assertion v1.

OI-016 uses:

    GrantBytes / GrantId
        as frozen OI-014 immutable authority evidence

    current RegisteredGrantState
        as externally resolved OI-014 current authority/status

    OI-015 AssertionId
        as exact actor-assertion semantic identity

    OI-015 contextHash
        as the integration-profile commitment to DelegationEvidenceId

## 6. Envelope bounds

Normative v1:

    registryDomain:             1..128 bytes
    GrantBytes:                 1..65,536 bytes each
    grants[]:                   1..16
    DelegationEvidenceBytes:    <= 1,048,576 bytes

OI-014 profile maxDelegationDepth remains independently mandatory. Effective path depth is the minimum of OI-016, applicable OI-014 profiles, and any smaller integration-profile limit.

Aggregate encoded-size ceilings are tested using a maximum constructed valid fixture at/below the ceiling plus an invalid above-ceiling fixture; conformance does not assume every integer encoded size is structurally reachable.

## 7. Remaining parser/runtime classification

The semantic bundle does not need to enumerate every malformed CBOR encoding.

Parser/unit suites remain responsible for cases such as:

- duplicate/unknown map labels;
- wrong CBOR major types beyond pinned top-level shape cases;
- noncanonical CBOR;
- truncated byte strings;
- malformed nested OI-014 GrantBytes parser cases already owned by OI-014;
- malformed OI-015 proof envelopes already owned by OI-015.

OI-016 requires complete frozen OI-014 and OI-015 verification rather than duplicating those suites.

## 8. Release evidence

The OI-016 v1 release boundary is:

- coverage: DS01-DS06 + DSI01-DSI28;
- deterministic Python generation and independent Python verification: PASS;
- independent Java reconstruction/verification: PASS;
- all previously frozen commitments/artifacts: unchanged;
- exact generated bundle size: 33,491 bytes;
- committed checksum: `checksums/delegated-subject-v1.json.sha256`;
- SHA-256: `0e9b8f56782ac5bca67d1694b3ff2309abe32e08a8daf22db212411ad31bb08e`;
- post-commit candidate-inclusive release gate: PASS.

## 9. Freeze status

**NOT BYTE-FROZEN. NOT NORMATIVE.**

Passing this review/gate establishes readiness to create a byte-freeze candidate. It does not itself freeze OI-016.
