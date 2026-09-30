# OI-015 Authentication Assertion v1 — Pre-Freeze Conformance Review

**Status:** DRAFT — pre-freeze review  
**Scope:** OI-015 Authentication Assertion v1 candidate semantics and wire schema  
**Candidate CDDL:** `spec/cddl/openidentity-authentication-assertion-v1.cddl`

## 1. Current evidence

The draft conformance bundle contains:

- positive vectors AA01-AA06;
- adversarial vectors AAI01-AAI31;
- deterministic Python generation;
- independent Python reconstruction/verification;
- independent Java reconstruction/verification using the repository DeterministicCborWriter rather than Python/cbor2;
- no OI-015 checksum or byte-freeze yet.

Both Python and Java suites are green through AA01-AA06 + AAI01-AAI31.

## 2. Positive coverage

- AA01 — SINGLE AuthenticationPolicy, exact current StateHash/generation, assertion/signature/secured bytes.
- AA02 — 2-of-3 THRESHOLD policy, deliberately noncanonical signing order, canonical proof ordering.
- AA03 — exact normative 300-second lifetime ceiling.
- AA04 — audience is truly opaque bytes and need not be UTF-8.
- AA05 — generation-preserving AuthenticationPolicy rotation still changes StateHash; current new-policy assertion succeeds.
- AA06 — deterministic OAuth-style context bytes are hashed into contextHash while OAuth fields remain outside core OI-015.

## 3. Adversarial coverage

### Current-state / authority

- AAI01 — historical StateHash with cryptographically valid historical signature.
- AAI02 — stale authentication generation.
- AAI03 — DEACTIVATED identity.
- AAI04 — AuthenticationPolicy absent.
- AAI20 — RESET_AUTHENTICATION/security-reset generation invalidates a prepared assertion.
- AAI25 — asserted identity differs from authoritative IdentityState identity.

### Verifier and protocol binding

- AAI05 / AAI19 — audience mismatch and cross-audience replay.
- AAI06 / AAI18 — purpose mismatch and cross-purpose replay.
- AAI07 — nonce mismatch.
- AAI08 — context substitution/contextHash mismatch.

### Time

- AAI09 — zero/invalid time range.
- AAI10 — 301-second lifetime.
- AAI11 — `verificationTime == expiresAt` is expired; upper bound is exclusive.
- AAI12 — verification before issuedAt.
- AAI30 — invalid zero range at uint64 maximum.
- AAI31 — unsigned-safe 301-second lifetime comparison near uint64 maximum.

Normative interval:

    issuedAt <= verificationTime < expiresAt
    0 < expiresAt - issuedAt <= 300

Implementations MUST validate unsigned uint64 time arithmetic without signed overflow.

### Proof-set strictness

- AAI13 — ControllerPolicy proof substitution.
- AAI14 — duplicate AuthenticationPolicy proof.
- AAI15 — threshold otherwise satisfied but unauthorized extra proof supplied.
- AAI16 — corrupted authentication signature.
- AAI17 — insufficient threshold.
- AAI26 — noncanonical proof ordering.

### Structural / wire boundaries

- AAI21 — invalid purpose grammar.
- AAI22 — nonce below 16-byte minimum.
- AAI23 — unsupported contextHash Multihash code.
- AAI24 — unsupported assertion version.
- AAI27 — nonce above 128-byte maximum.
- AAI28 — audience above 2048-byte maximum.
- AAI29 — unsupported StateHash Multihash code.

## 4. Stable semantic error coverage

Every currently defined semantic error has concrete evidence:

- INVALID_AUTHENTICATION_ASSERTION
- INVALID_ASSERTION_VERSION
- IDENTITY_MISMATCH
- IDENTITY_NOT_ACTIVE
- INVALID_STATE_HASH
- INVALID_AUTHENTICATION_GENERATION
- AUTHENTICATION_POLICY_ABSENT
- AUDIENCE_MISMATCH
- PURPOSE_MISMATCH
- NONCE_MISMATCH
- INVALID_TIME_RANGE
- ASSERTION_LIFETIME_EXCEEDED
- ASSERTION_NOT_YET_VALID
- ASSERTION_EXPIRED
- CONTEXT_HASH_MISMATCH
- INVALID_PROOF_SET
- DUPLICATE_AUTHENTICATION_PROOF
- UNAUTHORIZED_AUTHENTICATION_PROOF
- INVALID_AUTHENTICATION_SIGNATURE
- AUTHENTICATION_POLICY_NOT_SATISFIED

## 5. Remaining parser/runtime classification

The semantic bundle is not intended to enumerate every malformed CBOR representation.

Parser/unit suites remain responsible for failures such as:

- non-map top-level objects;
- missing/duplicate/unknown map labels;
- wrong CBOR major types;
- non-deterministic/non-canonical CBOR encodings;
- truncated byte strings;
- malformed signature byte lengths rejected before algorithm verification;
- malformed Multihash length/encoding in addition to the unsupported-code cases already pinned;
- purpose strings that violate CDDL length or UTF-8 decoding before semantic grammar evaluation.

Authoritative-state lookup failure is deployment/runtime behavior, not a cryptographic assertion vector. A verifier cannot establish current authentication if it cannot resolve the authoritative current IdentityState; integration APIs SHOULD expose an explicit operational failure distinct from successful authentication.

Nonce issuance, storage, consumption, and distributed replay-cache behavior are integration-profile/verifier responsibilities. Core OI-015 pins the nonce bytes and requires exact equality but does not define a universal challenge transport.

## 6. Cross-language requirements before byte freeze

Before establishing an OI-015 candidate checksum:

1. run the unified OI-015 pre-freeze gate;
2. require Python AA01-AA06 + AAI01-AAI31 PASS;
3. require Java AA01-AA06 + AAI01-AAI31 PASS;
4. confirm frozen v0.1 commitments/artifacts remain unchanged;
5. confirm Protocol v2 / IdentityState v3 checksum remains unchanged;
6. confirm OI-014 DelegationGrant v1 checksum remains unchanged;
7. review design-plan/CDDL/vector terminology and exact field labels;
8. confirm clean worktree after deterministic regeneration;
9. only then create a byte-freeze candidate checksum.

## 7. Freeze status

**NOT BYTE-FROZEN. NOT NORMATIVE.**

Passing this review/gate establishes readiness to create a byte-freeze candidate. It does not itself freeze OI-015.
