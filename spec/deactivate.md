# OpenIdentity DEACTIVATE Operation

**Document:** `deactivate.md`\
**Story:** OI-006 --- Define DEACTIVATE\
**Status:** Complete v0.1\
**Protocol:** OpenIdentity\
**Operation:** DEACTIVATE (`operationType = 4`)\
**Depends on:** OI-001, OI-002, OI-003, OI-004, OI-005

## 1. Purpose

This document defines the OpenIdentity `DEACTIVATE` operation.

DEACTIVATE changes an existing authoritative OpenIdentity from ACTIVE to
DEACTIVATED without deleting its identity or historical state.

Deactivation is final for ordinary controller authority. A normal
controller operation MUST NOT reactivate a deactivated identity. OI-007 RECOVER may reactivate a DEACTIVATED identity using independent RecoveryPolicy authority.

## 2. Normative foundation

The normative structural schema remains:

``` text
spec/cddl/openidentity-operation-v2.cddl
```

OI-006 reuses OI-002 deterministic CBOR, authorization, sequence,
StateHash, ControllerPolicy, proof, and stable-error rules.

OI-003 state-version and historical-state rules also apply.

## 3. Operation type and payload

DEACTIVATE uses:

``` text
operationType = 4
```

Conceptually:

``` text
{
  1: protocolVersion,
  2: 4,
  3: identity,
  4: sequence,
  5: previousStateHash,
  6: {}
}
```

The DEACTIVATE payload is the empty map:

``` text
{}
```

A DEACTIVATE payload MUST NOT carry a reason string, timestamp,
replacement key, recovery instruction, personal information, or other
application data.

## 4. Preconditions

A valid DEACTIVATE MUST target an existing ACTIVE authoritative
IdentityState.

The operation MUST use:

``` text
protocolVersion = 1
identity = currentState.identity
sequence = currentState.sequence + 1
previousStateHash = StateHash(currentState)
```

The current StateHash MUST be recomputed from canonical StateBytes.

Wrong sequence fails with `INVALID_SEQUENCE`.

Incorrect predecessor StateHash fails with
`INVALID_PREVIOUS_STATE_HASH`.

## 5. Authorization

The current authoritative ControllerPolicy authorizes DEACTIVATE.

Authorization proofs sign:

``` text
[
  "OpenIdentity Operation",
  1,
  OperationBytes
]
```

The current ControllerPolicy threshold MUST be satisfied by distinct,
authorized, cryptographically valid proofs.

DEACTIVATE installs no new VerificationMethod and therefore requires no
controller proof-of-possession collection.

## 6. Resulting state

A successful DEACTIVATE preserves the permanent identity and produces a
new authoritative IdentityState whose status is DEACTIVATED.

The transition preserves all state except sequence and status:

``` text
identity             = unchanged
sequence             = current sequence + 1
status               = DEACTIVATED
controllerPolicy     = unchanged
recoveryCommitment   = unchanged when present
```

State schema version is preserved:

``` text
IdentityState v1 -> IdentityState v1
IdentityState v2 -> IdentityState v2
```

For IdentityState v2:

``` text
AssertionPolicy = preserved unchanged
```

Preserving ControllerPolicy, recovery commitment, and AssertionPolicy
does not mean those policies remain usable for ordinary operations after
deactivation. They remain part of the canonical historical state and may
be relevant to historical verification or a future OI-007 recovery
protocol.

The resulting state MUST be deterministically encoded as StateBytes and
hashed using the applicable OpenIdentity StateHash rules.

## 7. Post-deactivation behavior

Once the current authoritative IdentityState is DEACTIVATED, ordinary
controller-authorized state-changing operations MUST NOT be applied.

At minimum:

``` text
ROTATE_CONTROLLER       -> IDENTITY_DEACTIVATED
SET_ASSERTION_POLICY    -> IDENTITY_DEACTIVATED
DEACTIVATE              -> IDENTITY_DEACTIVATED
```

A new CREATE for the same Identity ID remains duplicate creation and is
governed by OI-004:

``` text
CREATE                  -> IDENTITY_ALREADY_EXISTS
```

RECOVER is not an ordinary controller operation:

``` text
RECOVER                 -> governed exclusively by OI-007
```

OI-006 does not assert that RECOVER is permitted from DEACTIVATED state.
OI-007 must make that decision explicitly.

## 8. Reversibility decision

OI-006 v0.1 adopts the following rule:

> DEACTIVATION IS IRREVERSIBLE BY ORDINARY CONTROLLER AUTHORITY.

No operation authorized solely by the current ControllerPolicy may
change a DEACTIVATED identity back to ACTIVE.

Potential recovery from deactivation, if supported at all, requires the
independent recovery semantics defined by OI-007.

This preserves a meaningful distinction between normal controller
authority and recovery authority.

## 9. Resolver behavior

A deactivated identity continues to exist.

A resolver MUST distinguish:

``` text
identity never created
```

from:

``` text
identity exists and is DEACTIVATED
```

Resolution of the current authoritative state MUST expose deactivated
status rather than treating the identity as nonexistent.

Where historical resolution is supported, historical IdentityStates
remain available according to the applicable resolver/registry
specification.

Deactivation MUST NOT erase historical StateHashes or rewrite historical
authorization facts.

## 10. Historical verification

DEACTIVATE changes current state applicability. It does not
retroactively rewrite earlier IdentityStates.

Protocols that bind cryptographic assertions to an exact historical
StateHash, including OI-003 credentials, continue to evaluate historical
authorization against that exact historical state.

Deactivation alone MUST NOT be interpreted as retroactive revocation of
every historically issued credential or assertion. Credential
status/revocation is a separate protocol concern.

## 11. State-transition algorithm

A conforming state-transition processor SHALL:

1.  load the current authoritative IdentityState;
2.  reject ordinary DEACTIVATE processing if current status is already
    DEACTIVATED;
3.  validate deterministic operation/envelope encoding;
4.  require supported protocol version and operation type 4;
5.  require operation identity to equal current state identity;
6.  require `sequence = currentState.sequence + 1`;
7.  recompute current StateHash and require it as `previousStateHash`;
8.  require the empty DEACTIVATE payload;
9.  validate authorization proofs against the current ControllerPolicy;
10. require the current ControllerPolicy threshold;
11. preserve identity, ControllerPolicy, recovery commitment, state
    version, and AssertionPolicy when present;
12. increment sequence;
13. set status to DEACTIVATED; and
14. derive canonical resulting StateBytes and StateHash.

The transition MUST be atomic.

## 12. Stable error

OI-006 defines:

``` text
IDENTITY_DEACTIVATED
```

This is a state-transition applicability error.

It indicates that the current authoritative state is DEACTIVATED and the
requested ordinary operation is not permitted in that state.

It is not a structural CDDL error.

`CREATE` against a deactivated but existing identity continues to use
`IDENTITY_ALREADY_EXISTS`, because the identity already exists.

## 13. Conformance scenarios

The existing operation schema and OI-002 rules provide structural,
authorization, sequence, and StateHash foundations. Stateful
implementation tests SHOULD additionally exercise:

``` text
D01 — Valid deactivation

Precondition:
    current state ACTIVE

Input:
    correctly chained and authorized DEACTIVATE

Expected:
    new state status = DEACTIVATED
    sequence increments
    identity/policies/commitments preserved
```

``` text
DI01 — Repeated deactivation

Precondition:
    current state DEACTIVATED

Input:
    DEACTIVATE

Expected:
    IDENTITY_DEACTIVATED
    no state change
```

``` text
DI02 — Controller rotation after deactivation

Precondition:
    current state DEACTIVATED

Input:
    otherwise valid ROTATE_CONTROLLER

Expected:
    IDENTITY_DEACTIVATED
    no state change
```

``` text
DI03 — Assertion-policy update after deactivation

Precondition:
    current state DEACTIVATED

Input:
    otherwise valid SET_ASSERTION_POLICY

Expected:
    IDENTITY_DEACTIVATED
    no state change
```

These are state-machine scenarios and do not require modification of
frozen OI-002 cryptographic vectors.

## 14. Security considerations

A compromised controller can potentially authorize DEACTIVATE while the
identity is ACTIVE. For this reason, ordinary controller authority
cannot also provide an implicit reactivation mechanism.

OI-007 should consider independent recovery authority, delays, threshold
diversity, and compromise resistance before permitting any recovery from
a deactivated state.

Implementations MUST NOT erase controller, assertion, or recovery
information from the canonical deactivated state merely to make the
identity unusable; doing so would alter historical/state commitments.

## 15. OI-006 acceptance criteria

``` text
DEACTIVATE payload specified           Section 3
Authorization requirements specified   Section 5
Post-deactivation behavior specified   Section 7
Resolver exposes deactivated status    Section 9
Reversibility decision documented      Section 8
```

## 16. Deferred work

OI-006 intentionally does not define:

-   RECOVER payload or authorization;
-   whether OI-007 permits recovery from DEACTIVATED state;
-   recovery thresholds, delays, or UX;
-   credential revocation/status;
-   registry-specific consensus or persistence; or
-   application-specific consequences of deactivation.

Those omissions MUST NOT be interpreted as permitting ordinary
controller reactivation.

## 17. Normative references

OI-006 depends on OI-001, OI-002, OI-003, OI-004, OI-005,
`spec/cddl/openidentity-operation-v2.cddl`, and the applicable frozen
OpenIdentity conformance vectors.
