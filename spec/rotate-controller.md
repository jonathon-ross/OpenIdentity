# OpenIdentity ROTATE_CONTROLLER Operation

**Document:** `rotate-controller.md`\
**Story:** OI-005 --- Define ROTATE_CONTROLLER\
**Status:** Complete v0.1\
**Protocol:** OpenIdentity\
**Operation:** ROTATE_CONTROLLER (`operationType = 2`)\
**Depends on:** OI-001, OI-002, OI-003, OI-004

## 1. Purpose

This document defines the OpenIdentity `ROTATE_CONTROLLER` operation. It
replaces the authoritative ControllerPolicy of an existing OpenIdentity
without changing its permanent OI-001 Identity ID.

The normative structural schema remains
`spec/cddl/openidentity-operation-v2.cddl`. OI-005 consolidates existing
rotation semantics and does not introduce a competing wire encoding.

## 2. Operation and payload

ROTATE_CONTROLLER uses `operationType = 2`.

``` text
{
  1: protocolVersion,
  2: 2,
  3: identity,
  4: sequence,
  5: previousStateHash,
  6: { 1: replacementControllerPolicy }
}
```

For v0.1, `protocolVersion = 1`, `sequence = currentState.sequence + 1`,
and `previousStateHash = StateHash(currentState)`.

The operation identity MUST equal the identity in the current
authoritative IdentityState.

The replacement ControllerPolicy is complete and atomic, not a patch or
implicit merge. It MUST satisfy OI-002 policy, VerificationMethod,
ordering, uniqueness, COSE key, and SINGLE/THRESHOLD requirements.

## 3. Current-controller authorization

The **current authoritative ControllerPolicy** authorizes
ROTATE_CONTROLLER.

Authorization proofs sign:

``` text
[
  "OpenIdentity Operation",
  1,
  OperationBytes
]
```

The proposed replacement ControllerPolicy MUST NOT authorize its own
installation.

The rotation MUST NOT be accepted unless the current ControllerPolicy
threshold is satisfied by distinct, authorized, valid proofs.

## 4. Proposed-controller proof of possession

Every VerificationMethod in the proposed replacement ControllerPolicy
MUST provide exactly one valid proof of possession in SignedOperation
field 3.

Each signs:

``` text
[
  "OpenIdentity Controller Proof",
  1,
  OperationBytes,
  verificationMethodId
]
```

Authorization and possession proofs are separate signing domains and
MUST NOT substitute for one another.

Missing, duplicate, wrong-domain, wrong-method-bound, malformed, or
cryptographically invalid required proof of possession MUST cause
rejection under the applicable OI-002 stable error semantics.

## 5. Controller replacement and retirement

A successful ROTATE_CONTROLLER atomically replaces the current
ControllerPolicy with the proposed replacement ControllerPolicy.

After the transition, authorization of subsequent controller operations
is determined solely by the resulting ControllerPolicy.

A VerificationMethod from the previous ControllerPolicy that is omitted
from the replacement policy immediately ceases to have controller
authority.

A previous VerificationMethod retains controller authority only when
that exact method is explicitly present in the resulting replacement
ControllerPolicy.

``` text
State N                       State N+1
ControllerPolicy = A   --->   ControllerPolicy = B
```

For subsequent operations, policy B is authoritative. Policy A has no
residual or implicit authority.

Historical IdentityStates remain historical facts. Retirement from
current controller authority does not rewrite earlier states.

## 6. Identity preservation

ROTATE_CONTROLLER MUST NOT change the permanent OI-001 Identity ID.

The operation identity MUST match the current state identity, and the
resulting state identity MUST be byte-identical.

Changing controller keys, algorithms, policy type, threshold, or
membership does not create a new OpenIdentity.

## 7. Sequence, predecessor, and replay

A valid rotation MUST use:

``` text
sequence = currentState.sequence + 1
previousStateHash = StateHash(currentState)
```

The current StateHash MUST be recomputed from canonical StateBytes.

Wrong sequence fails with `INVALID_SEQUENCE`. Incorrect predecessor hash
fails with `INVALID_PREVIOUS_STATE_HASH`.

After a successful rotation, replaying that operation against the new
state is invalid: the expected next sequence and predecessor StateHash
have changed.

A stale operation MUST NOT be accepted merely because its historical
signatures remain cryptographically valid.

## 8. Resulting IdentityState

A successful rotation produces a new authoritative state with:

``` text
identity             = unchanged
sequence             = current sequence + 1
controllerPolicy     = replacement ControllerPolicy
recoveryCommitment   = preserved when present
```

For an ACTIVE source state, the resulting state remains ACTIVE.

State schema version is preserved:

``` text
IdentityState v1 -> IdentityState v1
IdentityState v2 -> IdentityState v2
```

For IdentityState v2, `AssertionPolicy` MUST be preserved unchanged.
ROTATE_CONTROLLER MUST NOT silently remove, replace, or infer assertion
authority.

The resulting state MUST be deterministically encoded as StateBytes and
hashed according to the OpenIdentity StateHash rules.

## 9. State-transition algorithm

A conforming processor SHALL:

1.  load the current authoritative IdentityState;
2.  validate deterministic operation/envelope encoding;
3.  require supported protocol version and operation type 2;
4.  require operation identity to match current state;
5.  require `sequence = currentState.sequence + 1`;
6.  recompute current StateHash and require it as `previousStateHash`;
7.  validate the replacement ControllerPolicy;
8.  validate authorization proofs against the current ControllerPolicy;
9.  require the current ControllerPolicy threshold;
10. validate exactly one proof of possession for every proposed
    VerificationMethod;
11. atomically replace ControllerPolicy;
12. preserve identity, applicable state version, recovery commitment,
    and AssertionPolicy;
13. increment sequence; and
14. derive canonical resulting StateBytes and StateHash.

No partial policy replacement is permitted.

## 10. Invalid signatures

Invalid current-controller authorization signatures MUST cause
rejection.

Invalid proposed-controller possession signatures MUST cause rejection.

Threshold satisfaction MUST NOT cause invalid, duplicate, or
unauthorized extra proofs to be ignored.

OI-005 introduces no new signature error; it reuses applicable OI-002
stable errors.

## 11. Conformance

OI-005 reuses the frozen OI-002 cryptographic-agility suite.

The primary positive vector is:

``` text
V04 — ROTATE_CONTROLLER + proof of possession
```

V04 establishes predecessor StateHash linkage, current-controller
authorization, proposed-controller proof of possession, deterministic
resulting IdentityState, and resulting StateHash.

The frozen invalid suite supplies applicable negative coverage for
sequence, predecessor StateHash, controller threshold,
duplicate/unauthorized proofs, invalid signatures, missing/invalid proof
of possession, wrong signing domains, method binding, and unsupported
algorithms.

OI-005 MUST NOT modify the frozen OI-002 v0.1 vectors merely to restate
rotation semantics.

A future stateful implementation SHOULD additionally exercise:

``` text
RCR01 — Retired controller cannot authorize later operation

Precondition:
    State N ControllerPolicy contains A

Transition:
    valid ROTATE_CONTROLLER installs B and omits A

Postcondition:
    State N+1 ControllerPolicy contains B and not A

Follow-up:
    operation at the next valid sequence is signed only by A

Expected:
    reject as unauthorized / controller threshold not satisfied
```

## 12. Security considerations

Implementations MUST NOT union old and new ControllerPolicies; that
would silently retain retired authority.

The proposed controller proves possession but does not authorize its own
installation.

Historical rotation signatures do not bypass sequence or
predecessor-StateHash checks.

Controller rotation MUST NOT accidentally change AssertionPolicy.
ControllerPolicy and AssertionPolicy remain separate authorization
purposes.

## 13. OI-005 acceptance criteria

``` text
Current controller can authorize rotation       Sections 3 and 9
New controller becomes authoritative             Sections 5 and 8
Previous controller cannot authorize later ops   Section 5
Identity ID remains unchanged                    Section 6
Sequence increments                              Sections 7 and 8
Invalid signatures and replay are rejected       Sections 7 and 10
```

## 14. Deferred implementation work

OI-005 defines protocol behavior rather than a particular registry/state
processor. Future executable state-machine conformance tests can
exercise RCR01 against an authoritative store. This does not make
controller-retirement semantics optional.

## 15. Normative references

OI-005 depends on OI-001, OI-002, OI-003, OI-004,
`spec/cddl/openidentity-operation-v2.cddl`, and the frozen OI-002
cryptographic-agility conformance vectors.
