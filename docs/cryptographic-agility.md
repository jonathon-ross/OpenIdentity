# OpenIdentity Cryptographic Agility Specification

**Document:** `cryptographic-agility.md`\
**Story:** OI-002 --- Define Cryptographic Agility Model\
**Status:** Draft v0.1\
**Protocol:** OpenIdentity\
**Wire Format:** OpenIdentity Operation v2\
**Normative Keywords:** MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT,
SHOULD, SHOULD NOT, MAY

## 1. Purpose

This document defines how cryptographic authority is attached to an
OpenIdentity root identity while preserving the permanent root DID
across algorithm changes, post-quantum migration, key rotation, device
replacement, registry migration, and provider changes.

## 2. Core separation

OpenIdentity separates Root Identity, Controller Policy, Verification
Methods, Cryptographic Algorithms, Device Authentication, Recovery
Policy, and Registry. A change to any controller key or algorithm MUST
NOT change the root DID.

## 3. Cryptographic agility invariant

OpenIdentity MUST support replacement of cryptographic algorithms
without replacement of the root identity. The identity MUST NOT be
derived from a controller key or algorithm.

## 4. v0.1 cryptographic profile

OpenIdentity v0.1 SHALL support **Ed25519** as its classical component
and **ML-DSA-65** (NIST FIPS 204, category 3) as its primary
post-quantum component. Implementations SHOULD support
**SLH-DSA-SHA2-192s** for high-assurance recovery/cryptographic
diversity; it is not required for normal controller operations.

## 5. Default root controller

The default v0.1 root policy SHALL be a THRESHOLD policy with threshold
2 containing one Ed25519 VerificationMethod and one ML-DSA-65
VerificationMethod. Both proofs are required for normal root-controller
operations.

## 6. Hybrid, not proprietary composite

Hybrid authorization is expressed through independent proofs satisfying
the controller policy. OpenIdentity v0.1 MUST NOT depend on a
proprietary composite-signature format. Future standardized composite
algorithms MAY be supported as additional VerificationMethods.

## 7. Controller policies

v0.1 defines SINGLE and THRESHOLD policies. SINGLE contains exactly one
VerificationMethod. THRESHOLD MUST satisfy
`1 <= threshold <= numberOfVerificationMethods`. Verification Method IDs
MUST be unique.

## 8. VerificationMethod

A VerificationMethod consists of a 16-byte cryptographically random
Verification Method ID and a standardized `COSE_Key`. Array position
MUST NOT identify a VerificationMethod.

## 9. COSE identifiers and keys

OpenIdentity SHALL use IANA COSE algorithm identifiers where
standardized and SHALL use `COSE_Key` for public verification keys.
Proprietary algorithm numbers MUST NOT replace existing standardized
COSE identifiers.

## 10. Ed25519 profile

Ed25519 SHALL use the standardized COSE OKP/Ed25519 representation. The
public key MUST be exactly 32 bytes. Generic EdDSA/OKP representations
that do not identify Ed25519 for this profile MUST be rejected.

## 11. ML-DSA-65 profile

ML-DSA-65 SHALL use COSE algorithm identifier `-49` and AKP key type
`7`. Its raw public key MUST be exactly 1952 bytes and its signature
MUST be exactly 3309 bytes.

## 12. Future algorithms

Structurally valid unknown algorithms MUST produce
`UNSUPPORTED_ALGORITHM`, not `INVALID_IDENTITY`. Algorithm support and
retirement are verifier policy, not identity-state properties.

## 13. Root keys are not login keys

Root-controller keys MUST NOT normally be used directly for website
login. Device/application authentication SHALL be separately authorized
and specified.

## 14. Canonical operation representation

Human/API representations MAY use JSON, but signatures MUST NOT be
calculated over arbitrary JSON serialization. Canonical signed data
SHALL use RFC 8949 deterministic CBOR.

## 15. Deterministic CBOR profile

Canonical serialization semantics are defined by OI-009.

Permitted types, where defined by schema, are unsigned integers, signed
integers, byte strings, text strings, arrays, maps, and nil. Floating
point, NaN, Infinity, undefined, arbitrary simple values,
indefinite-length items, arbitrary tags, unknown map labels, and
duplicate map labels are prohibited. Definite lengths and preferred
serialization are REQUIRED.

An absent optional field MUST be omitted from its CBOR map. It MUST NOT
be encoded as `nil` unless the applicable schema explicitly assigns
semantic meaning to `nil`.

Human-readable JSON, YAML, database records, transport envelopes, and
ledger-specific representations are not authoritative signed
serialization. Cryptographically authoritative bytes are produced only
from the validated OpenIdentity data model using deterministic CBOR.

## 16. Canonical ordering

Protocol maps SHALL use integer labels. Arrays representing unordered
sets MUST have a canonical order. Verification methods and proofs MUST
be sorted by Verification Method ID using unsigned bytewise
lexicographic ordering. Duplicate IDs MUST be rejected.

## 17. Operation model

An Operation contains:

-   `1` protocolVersion
-   `2` operationType
-   `3` identity
-   `4` sequence
-   `5` previousStateHash
-   `6` payload

The identity field SHALL contain the raw 32 identifier bytes from
OI-001. The textual `did:open:z...` form MUST NOT be embedded in the
canonical signed Operation.

## 18. Version and operation codes

`protocolVersion = 1`.

Operation codes:

-   `1` CREATE
-   `2` ROTATE_CONTROLLER
-   `3` RECOVER
-   `4` DEACTIVATE
-   `5..23` reserved for future core operations

Unknown operation types MUST produce `UNSUPPORTED_OPERATION`.

## 19. Sequence and previous state

Sequence and replay state-machine semantics are defined by OI-008.

CREATE SHALL use sequence 1 and `previousStateHash = nil`.

Every subsequent authoritative state-changing operation SHALL use:

``` text
sequence = currentSequence + 1
previousStateHash = StateHash(current authoritative IdentityState)
```

Protocol v0.1 represents sequence as an unsigned 64-bit integer in the
range `1..2^64-1`. Sequence MUST NOT decrease, reset, skip, or wrap.

Sequence validation and exact predecessor StateHash binding are both
required. A stale, replayed, skipped, future, or conflicting operation
MUST NOT become authoritative merely because its signatures remain
cryptographically valid.

An invalid next sequence SHALL produce `INVALID_SEQUENCE`. An operation
that does not reference the exact current authoritative predecessor
StateHash SHALL produce `INVALID_PREVIOUS_STATE_HASH`.

OpenIdentity v0.1 SHALL support SHA2-256 Multihash for StateHash.

## 20. OperationBytes

OperationBytes are produced by schema validation, canonical collection
ordering, and deterministic RFC 8949 CBOR encoding. Every compliant
implementation MUST produce identical OperationBytes for the same
logical Operation.

## 21. Authorization SigningInput

Controller authorization signs the deterministic CBOR encoding of:

``` text
[
  "OpenIdentity Operation",
  1,
  operationBytes
]
```

All controller algorithms MUST sign the exact same SigningInput.

## 22. Proof structure

A proof contains the Verification Method ID and raw algorithm-specific
signature bytes. The algorithm is obtained from the referenced
VerificationMethod's COSE_Key.

## 23. Proof evaluation

For every proof, the verifier MUST:

1.  Parse the proof according to the v1 schema.
2.  Resolve the Verification Method ID from the applicable controller
    policy.
3.  Reject duplicate proof entries for the same Verification Method ID.
4.  Validate the referenced COSE_Key.
5.  Determine the algorithm and whether verifier policy permits it for
    the operation.
6.  Validate signature representation and algorithm-specific length.
7.  Verify the signature against the exact canonical SigningInput.
8.  Count the Verification Method ID at most once.
9.  Compare the number of distinct authorized valid proofs to the policy
    threshold.

A proof counts only if its method is authorized, structurally valid,
supported for the operation, cryptographically valid, and not already
counted.

Malformed proofs MUST cause validation failure rather than being
silently ignored. If the threshold is not met, authorization MUST fail
with `CONTROLLER_THRESHOLD_NOT_SATISFIED` or an equivalent typed error.

## 24. Duplicate and unauthorized proofs

Duplicate proofs MUST NOT satisfy multiple threshold positions and
SHOULD produce `DUPLICATE_PROOF`. A proof from a VerificationMethod
outside the applicable controller policy MUST NOT count and MAY produce
`UNAUTHORIZED_VERIFICATION_METHOD`.

## 25. CREATE field requirements

CREATE has no previous controller policy; the controller policy in its
payload authorizes creation.

CREATE SHALL have:

-   `protocolVersion = 1`
-   `operationType = 1`
-   `sequence = 1`
-   `previousStateHash = nil`
-   identity = exactly 32 raw bytes from OI-001
-   a structurally valid controller policy

For the default v0.1 profile, the policy SHOULD be 2-of-2 with exactly
one Ed25519 VerificationMethod and one ML-DSA-65 VerificationMethod.

The CREATE proof set MUST satisfy that policy. A default-profile CREATE
MUST therefore contain valid Ed25519 and ML-DSA-65 proofs over the same
canonical SigningInput.

CREATE MUST be rejected for invalid identity length, wrong sequence,
non-nil previousStateHash, malformed policy, duplicate method IDs,
invalid threshold, unsupported required algorithm, missing/invalid
required proof, or unsatisfied threshold.

## 26. ROTATE_CONTROLLER

ROTATE_CONTROLLER SHALL use operation type 2, `currentSequence + 1`, and
the valid previous-state Multihash.

The **current** authoritative controller policy authorizes the rotation.
The proposed new policy MUST NOT authorize its own installation.

The payload SHALL contain the proposed new controller policy and
proof-of-possession evidence for its new VerificationMethods.

## 27. New-controller proof of possession

Every VerificationMethod installed by ROTATE_CONTROLLER MUST provide
proof of possession unless a future specification defines a safe
exception.

The possession signing structure is:

``` text
[
  "OpenIdentity Controller Proof",
  1,
  operationBytes,
  verificationMethodId
]
```

It SHALL be deterministically CBOR encoded.

A possession proof MUST NOT be accepted as an authorization proof, and
an authorization proof MUST NOT be accepted as a possession proof.

## 28. Proof-of-possession evaluation

For every VerificationMethod in the proposed new policy, the verifier
MUST locate exactly one corresponding possession proof, validate the
proposed COSE_Key, construct the canonical Controller Proof
SigningInput, and verify the proof using the proposed public key.

ROTATE_CONTROLLER MUST fail if any required proposed VerificationMethod
lacks valid proof of possession.

## 29. RECOVER

Operation code 3 is RECOVER as defined by OI-007.

RECOVER is authorized exclusively by the RecoveryPolicy committed to by
the current authoritative IdentityState. ControllerPolicy and
AssertionPolicy MUST NOT implicitly authorize RECOVER.

The current RecoveryPolicy is revealed by the RECOVER payload and its
deterministic CBOR encoding MUST match the current `recoveryCommitment`.
Recovery authorization proofs use the dedicated `OpenIdentity Recovery`
signing domain and MUST satisfy the revealed RecoveryPolicy.

Every VerificationMethod in the replacement ControllerPolicy MUST
separately prove possession using the existing controller-proof signing
domain.

Successful RECOVER preserves the permanent identity and IdentityState
schema version, increments sequence, chains from the current StateHash,
sets status to ACTIVE, installs the replacement ControllerPolicy,
replaces `recoveryCommitment`, and preserves AssertionPolicy unchanged
when the state is v2.

RECOVER MAY apply to ACTIVE or DEACTIVATED state. Ordinary controller
authorization is not required and MUST NOT be substituted for recovery
authorization.

OI-007 v0.1 defines no protocol-level recovery delay. Recovery UX,
guardians, MPC, secret sharing, inheritance, and registry-specific
workflows remain outside the core wire protocol.

## 30. DEACTIVATE

Operation code 4 is DEACTIVATE as defined by OI-006.

DEACTIVATE is authorized by the current ControllerPolicy and transitions
an ACTIVE identity to DEACTIVATED while preserving the permanent
identity, ControllerPolicy, recoveryCommitment, IdentityState schema
version, and AssertionPolicy when present.

Ordinary controller-authorized state-changing operations MUST NOT be
applied while the current authoritative state is DEACTIVATED.

RECOVER is the only OI-007 mechanism that MAY transition a DEACTIVATED
identity back to ACTIVE, and it requires independent RecoveryPolicy
authorization.

## 31. Algorithm-specific signature requirements

Algorithm-specific validation occurs only after the common SigningInput
has been constructed. Ed25519 proofs MUST use the standardized Ed25519
signature representation. ML-DSA-65 proof signatures MUST be exactly
3309 bytes.

## 32. Failure isolation and no downgrade

Failure or lack of support for one verification method MUST NOT weaken
or reinterpret another method. A 2-of-2 policy remains 2-of-2.
Implementations MUST NOT silently reduce thresholds because an algorithm
is unavailable, deprecated, expensive, or unsupported.

## 33. Algorithm migration

Controller rotation is the normal algorithm-migration mechanism. The
current policy authorizes the new policy and the new keys prove
possession. Algorithm migration MUST NOT change the root DID.

## 34. Protocol validity vs security policy

Historical protocol validity and current security acceptability are
distinct. A verifier MAY validate an old signature historically while
refusing the same algorithm for new controller operations.

## 35. Stable error semantics

Implementations SHOULD expose stable typed errors including:

-   `UNSUPPORTED_ALGORITHM`
-   `UNSUPPORTED_OPERATION`
-   `UNSUPPORTED_PROTOCOL_FEATURE`
-   `INVALID_COSE_KEY`
-   `INVALID_SIGNATURE_FORMAT`
-   `INVALID_SIGNATURE`
-   `DUPLICATE_VERIFICATION_METHOD`
-   `DUPLICATE_PROOF`
-   `UNAUTHORIZED_VERIFICATION_METHOD`
-   `INVALID_CONTROLLER_THRESHOLD`
-   `CONTROLLER_THRESHOLD_NOT_SATISFIED`
-   `INVALID_SEQUENCE`
-   `INVALID_PREVIOUS_STATE_HASH`
-   `MISSING_PROOF_OF_POSSESSION`
-   `INVALID_PROOF_OF_POSSESSION`
-   `IDENTITY_ALREADY_EXISTS`
-   `IDENTITY_DEACTIVATED`
-   `RECOVERY_NOT_CONFIGURED`
-   `INVALID_RECOVERY_POLICY`
-   `INVALID_RECOVERY_THRESHOLD`
-   `RECOVERY_THRESHOLD_NOT_SATISFIED`
-   `DUPLICATE_RECOVERY_PROOF`
-   `UNAUTHORIZED_RECOVERY_METHOD`
-   `INVALID_RECOVERY_SIGNATURE`
-   `INVALID_RECOVERY_COMMITMENT`

`IDENTITY_ALREADY_EXISTS` is a state-transition applicability error defined
by OI-004. It MUST be returned when an otherwise valid CREATE targets an
Identity ID for which authoritative state already exists. It is not a
structural CDDL error and does not alter the frozen OI-002 v0.1
cryptographic-agility vectors.

`IDENTITY_DEACTIVATED` is a state-transition applicability error defined by
OI-006. It MUST be returned when the current authoritative IdentityState is
DEACTIVATED and an ordinary state-changing operation is not permitted in that
state. CREATE against the same deactivated identity continues to use
`IDENTITY_ALREADY_EXISTS`. RECOVER applicability is defined separately by
OI-007. `IDENTITY_DEACTIVATED` is not a structural CDDL error and does not
alter the frozen OI-002 v0.1 cryptographic-agility vectors.

OI-007 defines the recovery-specific errors as follows:

- `RECOVERY_NOT_CONFIGURED` — current authoritative state has no
  `recoveryCommitment`.
- `INVALID_RECOVERY_POLICY` — the revealed RecoveryPolicy does not match the
  committed recovery authority.
- `INVALID_RECOVERY_THRESHOLD` — RecoveryPolicy threshold semantics are
  invalid.
- `RECOVERY_THRESHOLD_NOT_SATISFIED` — valid distinct recovery proofs do not
  meet the committed policy threshold.
- `DUPLICATE_RECOVERY_PROOF` — the recovery proof collection repeats a
  RecoveryMethod ID.
- `UNAUTHORIZED_RECOVERY_METHOD` — a recovery proof claims a method absent
  from the committed RecoveryPolicy.
- `INVALID_RECOVERY_SIGNATURE` — an authorized recovery proof fails
  cryptographic verification over the required recovery signing domain.
- `INVALID_RECOVERY_COMMITMENT` — the proposed next recovery commitment is
  malformed, unsupported, or equal to the current commitment where OI-007
  requires recovery-authority rotation.

These recovery errors are OI-007 protocol/state-transition errors. Adding them
does not modify the frozen OI-002 v0.1 cryptographic-agility vector bytes.

Human-readable messages MAY vary.

## 36. Conformance vectors

OI-002 SHALL publish machine-readable byte-exact vectors covering:

-   deterministic OperationBytes;
-   authorization SigningInput;
-   controller-proof SigningInput;
-   canonical ordering;
-   valid and invalid controller policies;
-   duplicate rejection;
-   Ed25519 proof verification;
-   ML-DSA-65 proof verification;
-   hybrid threshold success/failure; and
-   proof of possession.

Expected bytes MUST be independently verified before becoming normative.

## 37. Relationship to OI-001

OI-001 defines the permanent root identifier. OI-002 MUST NOT change
that identifier format. Controller keys, algorithms, and COSE
identifiers MUST remain absent from the root DID.

## 38. Relationship to recovery

Recovery is independent from ordinary ControllerPolicy and
AssertionPolicy authority.

OI-007 defines RecoveryPolicy, recoveryCommitment, RECOVER, recovery
authorization proofs, recovery signing-domain separation,
replacement-controller proof of possession, recovery-authority
rotation, and recovery from ACTIVE or DEACTIVATED state.

Recovery UX and higher-level mechanisms such as guardians, MPC, secret
sharing, inheritance, and recovery services remain outside the core
protocol.

## 39. OI-002 protocol invariants

1.  Root identity is independent of cryptographic algorithms.
2.  Default v0.1 control is hybrid Ed25519 + ML-DSA-65.
3.  Hybrid authorization uses controller policy rather than a
    proprietary composite signature.
4.  All controller proofs sign the same canonical SigningInput.
5.  Canonical signed data uses deterministic RFC 8949 CBOR.
6.  Public verification keys use standardized COSE representations.
7.  Standardized COSE/IANA algorithm identifiers are used where
    available.
8.  Controller policies cannot be silently downgraded.
9.  Root keys are not ordinary login keys.
10. Algorithm migration does not change the root DID.
11. Unknown algorithms are unsupported rather than automatically
    malformed.
12. New controller keys prove possession before installation.

## 40. Deferred work

OI-002 intentionally defers:

-   complete recovery-policy design;
-   device/passkey authorization;
-   pairwise application identifiers;
-   credential signing/presentation;
-   registry-specific verification mechanics;
-   Solana implementation details;
-   algorithm-specific hardware storage; and
-   final deactivation semantics.

## 41. Completion criteria

OI-002 is complete when:

-   this document and `openidentity-operation-v1.cddl` agree;
-   Ed25519 and ML-DSA-65 COSE representations are fixed;
-   the default 2-of-2 hybrid profile is fixed;
-   deterministic CBOR rules are fixed;
-   authorization and possession signing structures are fixed;
-   stable validation/error semantics are documented;
-   byte-exact CBOR/signing test vectors are generated and independently
    verified; and
-   the normative vector file has a published checksum.
