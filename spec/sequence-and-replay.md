# OpenIdentity Sequence and Replay Rules

**Document:** `sequence-and-replay.md`  
**Story:** OI-008 — Define sequence and replay rules  
**Status:** Complete v0.1  
**Protocol:** OpenIdentity  
**Depends on:** OI-004, OI-005, OI-007

## 1. Purpose

This document defines OpenIdentity sequence, predecessor, replay, ordering, and conflict rules.

Sequence numbers establish a strict per-identity ordering of authoritative state transitions. Sequence validation is combined with exact predecessor StateHash binding so stale, replayed, skipped, and conflicting operations cannot be applied to a later authoritative state merely because their signatures remain cryptographically valid.

Sequence is scoped to one permanent OpenIdentity Identity ID. It is not a global registry sequence, timestamp, ledger height, transaction number, or ordering mechanism between different identities.

## 2. Sequence representation

Protocol v0.1 represents sequence as an unsigned 64-bit integer in the range:

```text
1 .. 18,446,744,073,709,551,615
```

Sequence `0` is invalid. Sequence numbers MUST NOT decrease, reset, skip, or wrap.

The `2^64 - 1` bound is the representational limit of protocol v0.1. A future protocol version MAY extend the representable range, but MUST preserve the existing sequence history and monotonic ordering and MUST NOT reset an identity's sequence.

## 3. Starting sequence

CREATE establishes the first authoritative IdentityState and MUST use:

```text
sequence = 1
previousStateHash = nil
```

The resulting initial IdentityState MUST also have sequence 1. No other operation may establish sequence 1.

A CREATE with another sequence MUST be rejected with `INVALID_SEQUENCE`.

## 4. Valid next sequence

For every state-changing operation after CREATE:

```text
operation.sequence = currentState.sequence + 1
```

The resulting authoritative IdentityState MUST have the accepted operation's sequence.

An operation whose sequence is not exactly `currentState.sequence + 1` MUST be rejected with `INVALID_SEQUENCE`.

There is no protocol concept of consuming, reserving, or pre-allocating a sequence number.

## 5. Predecessor StateHash binding

Sequence validation alone does not identify the exact authoritative predecessor.

Every state-changing operation after CREATE MUST also contain:

```text
previousStateHash = StateHash(current authoritative IdentityState)
```

A processor MUST independently derive the current StateHash from canonical StateBytes and require exact equality. A mismatch MUST be rejected with `INVALID_PREVIOUS_STATE_HASH`.

Every accepted transition is therefore bound by both sequence and previousStateHash.

## 6. Duplicate and replayed operations

An operation valid against an earlier authoritative state MUST NOT be accepted again after the identity advances.

For example, if an operation with sequence 5 and predecessor H4 is accepted, the next state requires sequence 6 and predecessor H5. Replaying the old operation is stale even if its signatures remain cryptographically valid.

A replay MUST fail the current sequence and/or predecessor StateHash requirements. OI-008 does not require a separate `REPLAYED_OPERATION` error; `INVALID_SEQUENCE` and `INVALID_PREVIOUS_STATE_HASH` are sufficient.

## 7. Out-of-order operations

OpenIdentity does not permit skipped sequence values. If current sequence is 5, the only valid next sequence is 6.

Past, duplicate, skipped, or future sequence values are not currently applicable and MUST be rejected with `INVALID_SEQUENCE`.

An implementation MAY retain future operations for transport or operational purposes, but MUST NOT treat them as accepted authoritative state transitions before their exact predecessor is authoritative.

## 8. Conflicting successor operations

Two or more operations may be independently valid against the same current state:

```text
                 State N / HN
                   /       \
                  v         v
           Operation A   Operation B
           seq = N+1     seq = N+1
           prev = HN     prev = HN
```

Both may have valid encoding, signatures, authorization, sequence, and predecessor binding when evaluated against State N.

Sequence does not select a winner. OpenIdentity v0.1 defines no cryptographic tie-breaker between competing operations referencing the same authoritative predecessor.

The authoritative registry, consensus mechanism, or serialization layer MUST establish at most one authoritative successor for a particular authoritative state.

Once one successor becomes authoritative, every competing operation against the old predecessor becomes stale and MUST NOT subsequently be applied.

## 9. Registry and consensus boundary

OI-008 defines state-transition validity, not registry consensus.

OpenIdentity does not require rules such as lowest operation hash, highest fee, earliest timestamp, lexicographically smallest operation, or first network arrival.

A registry MAY use a blockchain, database transaction, replicated log, consensus protocol, compare-and-swap operation, or another serialization mechanism. Whatever mechanism is used, it MUST preserve the invariant that at most one authoritative successor is established from a particular authoritative state.

## 10. Atomic transition requirement

A stateful implementation MUST validate applicability against the same authoritative predecessor it uses to establish the successor.

The effective sequence:

```text
load current state
validate sequence
validate previousStateHash
validate operation
establish successor
```

must be protected from races sufficiently to prevent two conflicting operations from both becoming authoritative successors of the same state.

A non-atomic check-then-write implementation that permits two authoritative successors violates OI-008.

## 11. Application to operation types

The sequence rule applies uniformly to every authoritative state-changing operation after CREATE, including:

```text
ROTATE_CONTROLLER
RECOVER
DEACTIVATE
SET_ASSERTION_POLICY
```

Future state-changing operations MUST follow this model unless a future protocol version explicitly defines otherwise.

Operations that do not create a new authoritative IdentityState do not consume an identity sequence number. Credential issuance, credential verification, resolution, and historical-state verification therefore do not inherently increment sequence.

## 12. Deactivation and recovery

DEACTIVATE consumes the next sequence because it creates a new authoritative state.

Recovery continues the same history and MUST NOT reset sequence:

```text
ACTIVE sequence 8
    |
    | DEACTIVATE sequence 9
    v
DEACTIVATED sequence 9
    |
    | RECOVER sequence 10
    v
ACTIVE sequence 10
```

RECOVER uses the same `current + 1` sequence and exact predecessor StateHash rules as every other subsequent operation. Recovery authority does not bypass replay protection.

## 13. Protocol evolution

Sequence belongs to the continuing history of the permanent OpenIdentity, not to a controller key, assertion key, recovery key, registry, or cryptographic algorithm.

Changing those MUST NOT reset sequence.

A future protocol version that expands sequence representation MUST preserve the existing value, strict monotonicity, next-state ordering, and historical predecessor relationships.

## 14. Validation algorithm

For CREATE, a conforming processor SHALL require sequence 1, require `previousStateHash = nil`, and derive resulting IdentityState sequence 1.

For every subsequent state-changing operation, a conforming processor SHALL:

1. load the current authoritative IdentityState;
2. require the operation identity to match that state;
3. require `operation.sequence = currentState.sequence + 1`;
4. derive StateHash from canonical current StateBytes;
5. require exact equality with `operation.previousStateHash`;
6. perform operation-specific structural, authorization, proof, and transition validation;
7. establish at most one authoritative successor from that predecessor; and
8. assign the accepted operation sequence to the resulting authoritative IdentityState.

An implementation MAY order internal validation differently only when observable conformance behavior and security invariants remain equivalent.

## 15. Error semantics

OI-008 reuses:

```text
INVALID_SEQUENCE
INVALID_PREVIOUS_STATE_HASH
```

`INVALID_SEQUENCE` means the submitted sequence is not the exact next sequence required by the current authoritative state.

`INVALID_PREVIOUS_STATE_HASH` means the operation does not reference the exact current authoritative predecessor StateHash.

OI-008 introduces no new stable error.

## 16. Existing conformance coverage

Sequence and replay behavior are already exercised across existing OpenIdentity conformance suites, including CREATE sequence 1, invalid CREATE and subsequent sequences, predecessor StateHash validation, controller rotation chaining, assertion-authority chaining, R01 recovery chaining, and R02 DEACTIVATED-to-ACTIVE sequence continuation.

OI-008 does not modify frozen OI-002, OI-003, or OI-007 normative vector bytes.

Future state-processor conformance SHOULD additionally exercise competing valid successors of the same predecessor and prove at most one becomes authoritative.

## 17. Stateful conflict conformance scenario

```text
SC01 — Competing successors

Precondition:
    authoritative state:
        sequence = N
        StateHash = HN

Inputs:
    Operation A:
        sequence = N + 1
        previousStateHash = HN

    Operation B:
        sequence = N + 1
        previousStateHash = HN

    both otherwise valid

Expected:
    exactly one MAY become authoritative

After winner:
    authoritative sequence = N + 1

Loser:
    MUST NOT later be applied against the new state
```

The registry mechanism selecting the winner is outside OI-008.

## 18. Security considerations

Sequence MUST never substitute for predecessor StateHash binding.

Accepting skipped or stale sequence numbers can enable replay or state-history ambiguity. Accepting a correct sequence with an incorrect predecessor hash can permit an operation from a conflicting branch to be misapplied.

Sequence MUST NOT wrap. Reusing earlier sequence values would undermine replay and ordering assumptions.

Registry implementations MUST protect the authoritative transition boundary against concurrency races.

Wall-clock timestamps MUST NOT replace sequence plus predecessor StateHash as the core OpenIdentity ordering mechanism.

## 19. OI-008 acceptance criteria

```text
Starting sequence is defined                 Section 3
Valid next sequence is defined               Section 4
Duplicate/replayed sequence is rejected      Section 6
Out-of-order operations are rejected         Section 7
Conflict behavior is documented              Sections 8-10
```

## 20. Normative references

OI-008 depends on OI-004 CREATE, OI-005 ROTATE_CONTROLLER, OI-006 DEACTIVATE, OI-007 RECOVER, `spec/cddl/openidentity-operation-v2.cddl`, deterministic IdentityState encoding, and OpenIdentity StateHash rules.

The current operation CDDL remains the normative structural definition of wire-level sequence ranges. OI-008 defines their state-machine semantics.
