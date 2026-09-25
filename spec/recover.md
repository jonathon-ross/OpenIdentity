# OpenIdentity RECOVER Operation

**Document:** `recover.md`\
**Story:** OI-007 --- Define RECOVER operation\
**Status:** Complete v0.1\
**Protocol:** OpenIdentity\
**Operation:** RECOVER (`operationType = 3`)\
**Depends on:** OI-001 through OI-006

## 1. Purpose

This document defines the OpenIdentity `RECOVER` operation.

RECOVER allows an identity to replace its ControllerPolicy using
recovery authority that is cryptographically separate from ordinary
controller and assertion authority.

Recovery preserves the permanent OI-001 Identity ID. Recovery UX remains
pluggable: hardware recovery keys, guardians, MPC, secret sharing,
custodial services, inheritance workflows, and other mechanisms may
exist above the protocol, but core RECOVER validation depends only on
the canonical RecoveryPolicy, its commitment, and its proofs.

## 2. Authority separation

OpenIdentity defines three independent authorization purposes:

``` text
ControllerPolicy -> ordinary IdentityState changes
AssertionPolicy  -> assertions and credentials
RecoveryPolicy   -> RECOVER only
```

Membership in one policy MUST NOT imply membership in another.

ControllerPolicy MUST NOT authorize RECOVER merely because its methods
are cryptographically valid.

AssertionPolicy MUST NOT authorize RECOVER.

RecoveryPolicy MUST NOT authorize ordinary controller operations or
assertions.

The same underlying key material MAY appear explicitly in more than one
policy, but authority is granted independently by explicit membership in
each policy. Implementations SHOULD encourage operational and
cryptographic diversity between ordinary controller and recovery
authority.

## 3. Recovery commitment

IdentityState stores only a commitment to RecoveryPolicy, not the policy
itself.

For v0.1:

``` text
RecoveryPolicyBytes =
    deterministic CBOR encoding of RecoveryPolicy

digest =
    SHA-256(RecoveryPolicyBytes)

recoveryCommitment =
    0x12 || 0x20 || digest
```

The v0.1 recovery commitment is therefore a 34-byte SHA2-256 Multihash.

A verifier MUST recompute RecoveryPolicyBytes from the revealed policy
and require the resulting Multihash to equal the `recoveryCommitment` in
the current authoritative IdentityState.

A state with no `recoveryCommitment` has no protocol-level RECOVER
authority under OI-007 v0.1.

## 4. RecoveryPolicy

RecoveryPolicy is deterministic CBOR and has its own version.

### 4.1 SINGLE

``` text
{
  1: 1,              recoveryPolicyVersion
  2: 1,              SINGLE
  3: [ method ]      exactly one RecoveryMethod
}
```

### 4.2 THRESHOLD

``` text
{
  1: 1,              recoveryPolicyVersion
  2: 2,              THRESHOLD
  3: threshold,
  4: [ methods... ]
}
```

RecoveryMethod reuses the OpenIdentity VerificationMethod encoding:

``` text
{
  1: verificationMethodId,
  2: COSE_Key
}
```

Methods MUST be sorted by Verification Method ID using unsigned bytewise
lexicographic ordering. Duplicate method IDs MUST be rejected.

For THRESHOLD:

``` text
1 <= threshold <= number of methods
```

Only distinct qualifying recovery methods count toward threshold.

## 5. RECOVER operation

RECOVER uses:

``` text
operationType = 3
```

Conceptually:

``` text
{
  1: protocolVersion,
  2: 3,
  3: identity,
  4: sequence,
  5: previousStateHash,
  6: recoverPayload
}
```

The payload is:

``` text
{
  1: newControllerPolicy,
  2: currentRecoveryPolicy,
  3: newRecoveryCommitment
}
```

`currentRecoveryPolicy` is the revealed policy whose deterministic bytes
MUST match the current state's recovery commitment.

`newRecoveryCommitment` commits to the policy that will authorize the
next recovery. The next RecoveryPolicy itself remains hidden until
needed.

## 6. Sequence and predecessor state

RECOVER MUST use:

``` text
identity = currentState.identity
sequence = currentState.sequence + 1
previousStateHash = StateHash(currentState)
```

The current StateHash MUST be recomputed from canonical StateBytes.

Wrong sequence fails with `INVALID_SEQUENCE`.

Wrong predecessor StateHash fails with `INVALID_PREVIOUS_STATE_HASH`.

The permanent identity MUST NOT change.

## 7. Recovery authorization proofs

Recovery proofs are carried in SignedOperation field 4.

Each recovery proof is:

``` text
{
  1: recoveryMethodId,
  2: signature
}
```

Each signs deterministic CBOR encoding of:

``` text
[
  "OpenIdentity Recovery",
  1,
  OperationBytes,
  recoveryMethodId
]
```

Recovery proofs MUST resolve exclusively against the revealed current
RecoveryPolicy.

A recovery proof MUST NOT be accepted as ordinary controller
authorization, controller proof of possession, or assertion proof.

RECOVER MUST reject duplicate proof IDs, unauthorized method IDs,
malformed signatures, unsupported required algorithms, invalid
signatures, and insufficient distinct threshold coverage.

SignedOperation field 2, ordinary ControllerPolicy authorization proofs,
MUST be absent for RECOVER.

## 8. New-controller proof of possession

Recovery authority authorizes installation of a replacement controller,
but it does not prove possession of the replacement controller's private
keys.

Every VerificationMethod in `newControllerPolicy` MUST therefore provide
exactly one valid controller proof of possession in SignedOperation
field 3.

The existing controller PoP domain remains:

``` text
[
  "OpenIdentity Controller Proof",
  1,
  OperationBytes,
  verificationMethodId
]
```

The proposed new ControllerPolicy MUST NOT authorize its own
installation.

## 9. Recovery commitment rotation

Every successful RECOVER MUST install `newRecoveryCommitment`.

The current RecoveryPolicy authorizes the current recovery only. Its
commitment is replaced atomically with the new commitment.

For v0.1, `newRecoveryCommitment` MUST differ from the current
`recoveryCommitment`.

This requirement prevents accidental reuse of the same recovery
authority and forces recovery-authority rotation after use.

A future specification may define carefully constrained exceptions, but
v0.1 does not.

The new RecoveryPolicy corresponding to the new commitment need not be
revealed during the current recovery.

## 10. Recovery from ACTIVE and DEACTIVATED state

RECOVER MAY apply when the current authoritative state is ACTIVE or
DEACTIVATED.

Successful RECOVER always produces:

``` text
status = ACTIVE
```

Therefore:

``` text
ACTIVE       -> RECOVER -> ACTIVE
DEACTIVATED  -> RECOVER -> ACTIVE
```

This is the only OI-007 v0.1 mechanism capable of restoring a
DEACTIVATED identity to ACTIVE.

Ordinary ControllerPolicy authority cannot perform this transition.

## 11. Resulting IdentityState

Successful RECOVER produces:

``` text
identity              = unchanged
sequence              = current sequence + 1
status                = ACTIVE
controllerPolicy      = newControllerPolicy
recoveryCommitment    = newRecoveryCommitment
stateVersion          = preserved
```

For IdentityState v2:

``` text
AssertionPolicy = preserved unchanged
```

Recovery does not automatically rotate assertion authority. A recovered
controller may subsequently use `SET_ASSERTION_POLICY` if assertion
authority also needs replacement.

The resulting IdentityState MUST be deterministically encoded as
StateBytes and hashed according to the OpenIdentity StateHash rules.

## 12. Recovery when no commitment exists

If current authoritative IdentityState contains no `recoveryCommitment`,
RECOVER MUST fail with:

``` text
RECOVERY_NOT_CONFIGURED
```

A verifier MUST NOT fall back to ControllerPolicy, AssertionPolicy,
application accounts, email ownership, registry administrators, or other
authority.

Recovery authority exists only when committed by authoritative
IdentityState.

## 13. RecoveryPolicy commitment mismatch

If the revealed current RecoveryPolicy does not produce the exact
current `recoveryCommitment`, RECOVER MUST fail with:

``` text
INVALID_RECOVERY_POLICY
```

Recovery signatures MUST NOT be evaluated as authority under a policy
that fails this commitment check.

## 14. Recovery threshold

If the revealed policy is malformed or has an invalid threshold, RECOVER
MUST fail with:

``` text
INVALID_RECOVERY_THRESHOLD
```

If the policy is valid but supplied distinct valid proofs do not satisfy
its threshold, RECOVER MUST fail with:

``` text
RECOVERY_THRESHOLD_NOT_SATISFIED
```

## 15. Recovery proof failures

OI-007 defines:

``` text
DUPLICATE_RECOVERY_PROOF
UNAUTHORIZED_RECOVERY_METHOD
INVALID_RECOVERY_SIGNATURE
```

`DUPLICATE_RECOVERY_PROOF` means the same RecoveryMethod ID appears more
than once in the recovery-proof collection.

`UNAUTHORIZED_RECOVERY_METHOD` means a proof claims a method not present
in the committed RecoveryPolicy.

`INVALID_RECOVERY_SIGNATURE` means a claimed authorized recovery proof
fails cryptographic verification over the required recovery signing
domain.

Generic malformed encoding and unsupported-algorithm errors continue to
use the applicable OpenIdentity errors.

## 16. New recovery commitment validation

`newRecoveryCommitment` MUST be a semantically valid v0.1 recovery
Multihash.

Invalid format or unsupported commitment hash semantics MUST cause:

``` text
INVALID_RECOVERY_COMMITMENT
```

A new commitment equal to the current commitment MUST also fail with
`INVALID_RECOVERY_COMMITMENT` in v0.1.

## 17. Validation order

Conceptually, RECOVER validation proceeds as follows:

1.  validate deterministic CBOR and structural shape;
2.  require supported protocol version and operation type 3;
3.  load current authoritative IdentityState;
4.  validate identity equality;
5.  validate sequence;
6.  validate previousStateHash;
7.  require current recoveryCommitment;
8.  validate revealed RecoveryPolicy structure and canonical ordering;
9.  recompute RecoveryPolicy commitment and require equality;
10. validate recovery threshold;
11. validate recovery-proof structure and duplicate IDs;
12. reject unauthorized recovery method IDs;
13. require recovery threshold coverage;
14. verify recovery signatures over the recovery signing domain;
15. validate new ControllerPolicy;
16. validate new-controller proof-of-possession coverage;
17. verify new-controller PoP signatures;
18. validate new recovery commitment and require rotation;
19. apply the state transition; and
20. derive resulting StateBytes and StateHash.

Implementations MAY optimize internally only if observable conformance
behavior is equivalent.

## 18. Recovery UX remains pluggable

OI-007 does not define how a user obtains or coordinates recovery
proofs.

Examples of mechanisms that MAY exist above the protocol include:

-   offline hardware recovery keys;
-   multiple trusted guardians;
-   professional recovery providers;
-   threshold/MPC systems;
-   secret-sharing workflows;
-   inheritance systems; and
-   enterprise recovery processes.

Such mechanisms are conforming only insofar as the resulting canonical
RecoveryPolicy and recovery proofs satisfy OI-007.

Core IdentityState MUST NOT contain guardian names, email addresses,
service URLs, biometric templates, social graphs, or other recovery UX
metadata.

## 19. Delays

OI-007 v0.1 defines no protocol-level recovery delay.

Registries and applications MUST NOT invent a delay and treat it as part
of core RECOVER validity.

A future version may define cryptographically and operationally precise
delayed recovery semantics.

## 20. Stateful concurrency

RECOVER is a state-changing operation and is subject to the same
authoritative serialization requirement as other transitions.

Two competing RECOVER operations referencing the same predecessor cannot
both become sequentially authoritative without one becoming stale.

After one recovery is accepted, the other operation's sequence and/or
`previousStateHash` no longer match current authoritative state and MUST
be rejected.

## 21. Security considerations

Recovery authority is highly privileged and SHOULD be operationally
separated from frequently used controller authority.

Revealing RecoveryPolicy during recovery exposes its public recovery
configuration. Mandatory recovery-commitment rotation prevents that
revealed policy from remaining the committed authority after successful
recovery.

RecoveryPolicy commitment does not hide information against brute-force
guessing when policy entropy is low. Recovery policies SHOULD include
cryptographically strong public-key material and SHOULD NOT encode
predictable human secrets directly.

Recovery MUST NOT erase or rewrite historical IdentityStates.

Recovery from DEACTIVATED state is intentionally stronger than ordinary
controller authority and therefore requires independent RecoveryPolicy
authorization.

## 22. Conformance plan

OI-007 requires new conformance vectors because RECOVER introduces new
wire structures and signing semantics.

The planned positive vector is:

``` text
R01 — valid threshold recovery
```

The planned invalid/security suite should include at least:

``` text
RI01  recovery not configured
RI02  revealed RecoveryPolicy commitment mismatch
RI03  invalid recovery threshold
RI04  insufficient recovery threshold
RI05  duplicate recovery proof
RI06  unauthorized recovery method
RI07  invalid recovery signature
RI08  missing new-controller proof of possession
RI09  new recovery commitment equals old commitment
RI10  wrong recovery signing domain / cross-domain substitution
```

A positive recovery-from-DEACTIVATED vector SHOULD also be included
before OI-007 is frozen.

## 23. OI-007 acceptance criteria

The original OI-007 acceptance criteria are addressed as follows:

``` text
Recovery operation shape specified          Sections 5-8
Recovery authorization evidence represented Sections 3-7
Sequence/state rules defined                Sections 6, 10-11, 20
Identity ID does not change                 Sections 6 and 11
Recovery UX remains pluggable               Section 18
```

## 24. Completion gate

OI-007 MUST NOT be marked complete until:

-   this specification and `openidentity-operation-v2.cddl` agree;
-   RecoveryPolicy and commitment encodings are frozen;
-   RECOVER proof domains and proof-set semantics are frozen;
-   recovery from ACTIVE and DEACTIVATED state is covered;
-   R01 and RI01-RI10 are generated;
-   the vectors are independently verified; and
-   the normative recovery vector bundle and checksum verify.

## 25. Normative references

OI-007 depends on OI-001 through OI-006,
`spec/cddl/openidentity-operation-v2.cddl`, deterministic CBOR and
StateHash rules, and the existing OpenIdentity
ControllerPolicy/VerificationMethod/COSE encodings.
