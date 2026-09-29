# Protocol v2 / IdentityState v3 Implementation Guide

**Status:** Supporting documentation for the byte-frozen candidate; not independently normative  
**Candidate specification:** `spec/protocol-v2-identity-state-v3.md`  
**Normative structural schema:** `spec/cddl/openidentity-operation-v3.cddl`  
**Candidate bundle SHA-256:** `3a5cf175f0b3fb72c7f6b363d169739fffa8102e61f8a37fba2992c3f3803b3c`

This guide explains how the ProtocolVersion 2 / IdentityState v3 candidate fits together. When this guide and a normative source disagree, the specification, CDDL, frozen candidate vectors, and published checksum take precedence in that order.

## 1. What changed and what did not

OpenIdentity keeps the permanent 32-byte identity stable while allowing authority to evolve. ProtocolVersion 2 is an explicit upgrade boundary: every successful ProtocolVersion 2 state-changing operation produces IdentityState v3.

The candidate does **not** rewrite historical IdentityState v1/v2 bytes or StateHashes. ProtocolVersion 1 remains the protocol of the released v0.1.1 line. A ProtocolVersion 1 operation cannot be applied to IdentityState v3.

IdentityState v3 adds two purpose-separated derived authorities:

```text
ControllerPolicy          root state changes
RecoveryPolicy            RECOVER only
AssertionPolicy           credentials/assertions
AuthenticationAuthority   authentication
DelegationAuthority       delegation registration authority
```

AuthenticationAuthority and DelegationAuthority each contain a generation counter and an optional policy. The generation remains present when the policy is absent.

## 2. State model

Canonical v3 state labels are:

| Label | Field | Required in v3 | Meaning |
|---|---|---:|---|
| 1 | stateVersion | yes | exactly 3 |
| 2 | identity | yes | permanent 32-byte identity |
| 3 | sequence | yes | monotonically increasing state sequence |
| 4 | status | yes | ACTIVE or DEACTIVATED |
| 5 | ControllerPolicy | yes | authority for state-changing operations |
| 6 | recoveryCommitment | no | commitment to RecoveryPolicy |
| 7 | AssertionPolicy | no | credential/assertion authority |
| 8 | AuthenticationAuthority | yes | generation + optional AuthenticationPolicy |
| 9 | DelegationAuthority | yes | generation + optional DelegationPolicy |

Conceptually:

```text
IdentityState v3
├── identity
├── sequence / status
├── ControllerPolicy
├── recoveryCommitment?
├── AssertionPolicy?
├── AuthenticationAuthority
│   ├── generation
│   └── AuthenticationPolicy?
└── DelegationAuthority
    ├── generation
    └── DelegationPolicy?
```

StateHash remains:

```text
StateBytes = deterministic CBOR(IdentityState)
StateHash  = 0x12 || 0x20 || SHA-256(StateBytes)
```

## 3. Operation and proof matrix

Operation fields remain labels 1..6. SignedOperation proof collections are outside OperationBytes.

| Operation | Type | Ordinary controller auth (2) | Controller PoP (3) | Recovery auth (4) | Authentication PoP (5) | Assertion PoP (6) | Delegation PoP (7) |
|---|---:|---:|---:|---:|---:|---:|---:|
| CREATE | 1 | required | forbidden | forbidden | if installed | if installed | if installed |
| ROTATE_CONTROLLER | 2 | required | required | forbidden | forbidden | forbidden | forbidden |
| RECOVER | 3 | forbidden | required | required | forbidden | REPLACE only | forbidden |
| DEACTIVATE | 4 | required | forbidden | forbidden | forbidden | forbidden | forbidden |
| SET_ASSERTION_POLICY | 5 | required | forbidden | forbidden | forbidden | if non-nil | forbidden |
| SET_AUTHENTICATION_POLICY | 6 | required | forbidden | forbidden | if non-nil | forbidden | forbidden |
| SET_DELEGATION_POLICY | 7 | required | forbidden | forbidden | forbidden | forbidden | if non-nil |
| RESET_AUTHENTICATION | 8 | required | forbidden | forbidden | forbidden | forbidden | forbidden |
| RESET_DELEGATIONS | 9 | required | forbidden | forbidden | forbidden | forbidden | forbidden |

CREATE is special: field 2 is authorization under the proposed ControllerPolicy and already proves controller possession. Redundant field-3 Controller PoP is forbidden.

## 4. Signing domains

Proof purpose is cryptographically separated by signing domain:

```text
ordinary operation authorization:
["OpenIdentity Operation", 1, OperationBytes]

replacement controller PoP:
["OpenIdentity Controller Proof", 1, OperationBytes, methodId]

recovery authorization:
["OpenIdentity Recovery", 1, OperationBytes, methodId]

authentication PoP:
["OpenIdentity Authentication Proof", 1, OperationBytes, methodId]

assertion PoP:
["OpenIdentity Assertion Proof", 1, OperationBytes, methodId]

delegation PoP:
["OpenIdentity Delegation Proof", 1, OperationBytes, methodId]
```

A signature valid in one purpose domain is not valid evidence for another. Every VerificationMethod newly installed in a policy supplies its own purpose-specific PoP; policy threshold does not reduce PoP coverage.

## 5. Derived-authority lifecycle

For AuthenticationAuthority and DelegationAuthority, let the current policy be A and generation be N.

| Transition | Disposition | Resulting policy | Resulting generation |
|---|---|---|---:|
| absent -> A | absent | A | N |
| A -> B | PRESERVE_EXISTING | B | N |
| A -> B | INVALIDATE_EXISTING | B | N + 1 |
| A -> absent | invalidate semantics | absent | N + 1 |
| RESET | n/a | unchanged | N + 1 |

A -> identical A and absent -> absent are invalid no-ops. Generation never decreases, jumps, or wraps. An operation requiring increment when generation is 2^64-1 fails.

PRESERVE_EXISTING preserves generation-bound downstream trust; it does **not** let rotated-out policy A authorize new proofs.

## 6. Upgrade rules

```text
IdentityState v1 --successful PV2 operation--> IdentityState v3
IdentityState v2 --successful PV2 operation--> IdentityState v3
IdentityState v3 --successful PV2 operation--> IdentityState v3

IdentityState v3 --PV1 operation--> REJECT
IdentityState v3 --> v1/v2 downgrade --> REJECT
```

For eligible ordinary v1/v2 -> v3 upgrades, absent AuthenticationAuthority and DelegationAuthority initialize at generation 0. RESET_AUTHENTICATION and RESET_DELEGATIONS are not eligible upgrade operations: both require an IdentityState v3 predecessor because a reset invalidates an already-existing v3 security generation.

For RECOVER upgrading v1/v2 -> v3, both initialize at generation 1 because recovery is a security reset.

Historical v1/v2 StateBytes and StateHashes remain exactly authoritative for their historical states.

## 7. Recovery model

RECOVER is deliberately a stronger trust-boundary transition.

It is authorized **only** by the RecoveryPolicy committed by the predecessor state. Ordinary ControllerPolicy authorization is forbidden.

Successful RECOVER:

1. verifies the predecessor and sequence;
2. reveals and validates the committed RecoveryPolicy;
3. verifies RecoveryPolicy authorization;
4. verifies complete PoP for the replacement ControllerPolicy;
5. installs the replacement ControllerPolicy;
6. rotates recoveryCommitment;
7. sets status ACTIVE;
8. applies explicit AssertionPolicy disposition;
9. removes AuthenticationPolicy and increments authentication generation;
10. removes DelegationPolicy and increments delegation generation.

Assertion disposition is mandatory:

| Value | Meaning | Existing AssertionPolicy required? | Replacement policy permitted? | Assertion PoP |
|---:|---|---:|---:|---:|
| 1 | PRESERVE | no | no | forbidden |
| 2 | REMOVE | yes | no | forbidden |
| 3 | REPLACE | yes | yes/required | required |

If AssertionPolicy is absent, RECOVER cannot introduce one; only PRESERVE is valid.

## 8. Deactivation

DEACTIVATE preserves the authority structures and generations in StateBytes but changes status to DEACTIVATED.

While deactivated, RECOVER is the only permitted state-changing operation. ROTATE_CONTROLLER, DEACTIVATE, SET_ASSERTION_POLICY, SET_AUTHENTICATION_POLICY, SET_DELEGATION_POLICY, RESET_AUTHENTICATION, and RESET_DELEGATIONS are rejected. New authentication, delegation registration, and credential issuance are also invalid. Existing delegation grants are unusable. Historical credential verification remains possible against the historical authoritative state.

RECOVER returns the identity to ACTIVE and increments both derived-authority generations, preventing dormant derived authority from becoming usable again.

## 9. Delegation boundary

DelegationPolicy authorizes **registration** of constrained DelegationGrants; it does not make an offline grant authoritative by itself.

The v3 core state machine defines the generation behavior required to preserve or invalidate registered grants. The exact DelegationGrant and registration wire formats, backdating defenses, status model, and network representation are deferred to OI-014 / the network profile.

Do not invent an offline-grant validity rule from the v3 IdentityState schema.

## 10. Recommended validation order

A state processor should conceptually validate in this order:

```text
1. deterministic CBOR / structural schema
2. supported protocolVersion and operation type
3. identity / status applicability
4. exact next sequence
5. exact previousStateHash
6. operation-specific payload semantics
7. current authorization policy
8. purpose-specific proof collections and domains
9. generation/disposition invariants
10. construct resulting canonical StateBytes
11. compute StateHash
12. atomically establish at most one successor
```

Implementations may reorder internal checks only when externally observable conformance and security behavior remains equivalent.

## 10.1 Sequence exhaustion

Sequence is a uint64 state-history counter. At predecessor sequence `2^64 - 1`, the identity cannot accept another state-changing operation because the required exact-next sequence would be `2^64`. Implementations must reject rather than wrap, reuse an earlier value, or special-case RECOVER.

## 10A. Unrelated-state preservation

A state-changing operation owns only the fields its transition semantics explicitly modify. Every unrelated predecessor field must survive unchanged in the successor. For example, SET_AUTHENTICATION_POLICY must not alter ControllerPolicy, recoveryCommitment, AssertionPolicy, DelegationAuthority, or status; DEACTIVATE changes status and sequence but preserves all authority structures and generations. RECOVER is the deliberate exception because its specification explicitly replaces/resets several authority fields.

## 11. Canonical serialization rules that matter most

Protocol v2 continues the RFC 8949 deterministic-CBOR rules defined by OI-009.

In particular:

- optional absent fields are omitted;
- explicit nil is used only where the schema assigns nil meaning;
- VerificationMethods and proof collections use canonical method-ID ordering;
- duplicate method IDs are rejected;
- duplicate effective cryptographic keys inside one VerificationPolicy are rejected even under different method IDs;
- unknown OpenIdentity labels are rejected;
- OperationBytes never contain proof collections;
- StateHash is over exact StateBytes, never a decoded/re-encoded approximation.

## 12. Conformance and implementation evidence

The byte-frozen candidate contains:

```text
V301-V324    successful state-transition vectors
VI301-VI337  invalid/security vectors
```

The candidate is independently verified by Python and Java. Java reconstructs the positive state machine independently from deterministic seeds and checks the negative suite. Frozen v0.1 regression suites also pass.

Candidate integrity:

```text
test-vectors/generated/protocol-v2-identity-state-v3.json
125506 bytes
SHA-256 3a5cf175f0b3fb72c7f6b363d169739fffa8102e61f8a37fba2992c3f3803b3c
```

The tracked checksum is:

```text
checksums/protocol-v2-identity-state-v3.json.sha256
```

## 13. Where to read next

For the candidate itself:

```text
spec/protocol-v2-identity-state-v3.md       normative semantic draft
spec/cddl/openidentity-operation-v3.cddl    normative structural draft
spec/protocol-v2-v3-conformance-plan.md     vector/security coverage
```

For inherited foundations from the released line:

```text
docs/identity-id.md
docs/cryptographic-agility.md
docs/credential.md
spec/sequence-and-replay.md
spec/canonical-serialization.md
spec/signature-envelope.md
spec/state-hash.md
```

The operation-specific v0.1 documents remain authoritative for the released ProtocolVersion 1 line. Where ProtocolVersion 2 deliberately changes behavior—especially CREATE derived-policy PoPs, SET_ASSERTION_POLICY proof field, derived authorities, RECOVER disposition/reset semantics, and v3 upgrade rules—the Protocol v2 / IdentityState v3 candidate specification and v3 CDDL define the candidate behavior.

## 14. Source-of-truth order for this candidate

For Protocol v2 / IdentityState v3 candidate questions, use:

1. `spec/protocol-v2-identity-state-v3.md` for semantic requirements;
2. `spec/cddl/openidentity-operation-v3.cddl` for structural wire validity;
3. the byte-frozen V301-V324 / VI301-VI337 bundle and checksum for exact conformance bytes;
4. independent Python/Java verification behavior;
5. this guide and other explanatory documentation.

A disagreement among items 1-3 is a release blocker and must not be silently resolved by implementation code.
