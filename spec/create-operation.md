# OpenIdentity CREATE Operation

**Document:** `create-operation.md`\
**Story:** OI-004 --- Define CREATE operation\
**Status:** Complete v0.1\
**Protocol:** OpenIdentity\
**Operation:** CREATE (`operationType = 1`)\
**Depends on:** OI-001, OI-002, OI-003

## 1. Purpose

This document defines the OpenIdentity CREATE operation. CREATE
establishes the first authoritative `IdentityState` for an OI-001
Identity ID. It defines the operation payload, initial sequence and
predecessor rules, authorization requirements, duplicate-creation
behavior, and deterministic resulting state.

This document does not define registry storage, consensus, transport, or
persistence APIs. Those systems enforce the state-machine preconditions
defined here.

## 2. Normative foundation

OI-004 reuses the canonical operation, cryptographic, ControllerPolicy,
deterministic-CBOR, and StateHash rules defined by OI-002 and the
applicable OpenIdentity operation CDDL.

`spec/cddl/openidentity-operation-v2.cddl` remains the normative
structural schema. OI-004 does not introduce a competing CREATE
encoding.

## 3. CREATE operation

CREATE uses `operationType = 1`.

A conforming CREATE SHALL have:

``` text
protocolVersion   = 1
operationType     = 1
identity          = 32-byte OI-001 Identity ID
sequence          = 1
previousStateHash = nil
payload           = CreatePayload
```

Conceptually:

``` text
{
  1: 1,
  2: 1,
  3: identity,
  4: 1,
  5: nil,
  6: createPayload
}
```

## 4. CREATE payload

``` text
{
  1: controllerPolicy,
  ? 2: recoveryCommitment
}
```

`controllerPolicy` is REQUIRED. `recoveryCommitment` is OPTIONAL.

The ControllerPolicy MUST be structurally and semantically valid under
OI-002, including Verification Method uniqueness, canonical ordering,
supported key encoding, and valid SINGLE or THRESHOLD policy semantics.

## 5. Initial sequence and predecessor

CREATE is the only operation that establishes sequence 1.

A valid CREATE MUST use `sequence = 1` and `previousStateHash = nil`.

A CREATE with another sequence MUST fail with `INVALID_SEQUENCE`.

A CREATE with non-nil `previousStateHash` MUST fail with
`INVALID_PREVIOUS_STATE_HASH`.

## 6. Authorization

CREATE has no prior ControllerPolicy because no authoritative
IdentityState yet exists for the Identity ID. Therefore the
ControllerPolicy being established by CREATE authorizes CREATE.

Authorization proofs are carried in the SignedOperation
authorization-proof collection and sign:

``` text
[
  "OpenIdentity Operation",
  1,
  OperationBytes
]
```

`OperationBytes` are deterministic CBOR encoding of the CREATE operation
only. Proof collections are excluded.

Every supplied authorization proof MUST satisfy OI-002 proof rules,
including method authorization, uniqueness, key/algorithm validation,
signature verification, and threshold evaluation.

CREATE MUST NOT be accepted unless the proposed ControllerPolicy
authorization threshold is satisfied.

CREATE normally omits the controller proof-of-possession collection
because its controller methods authorize CREATE directly through
authorization proofs.

## 7. Duplicate creation

CREATE is valid only when no authoritative OpenIdentity state already
exists for the supplied Identity ID.

Before applying an otherwise valid CREATE, the authoritative
state-transition processor or registry MUST determine whether the
Identity ID already has authoritative state.

If authoritative state already exists, CREATE MUST fail with:

``` text
IDENTITY_ALREADY_EXISTS
```

This applies even when the submitted CREATE is byte-identical to the
original, proposes a different ControllerPolicy, has otherwise valid
signatures, or the existing identity has advanced beyond sequence 1.

CREATE is not an update, reset, recovery, or replacement mechanism. A
repeated CREATE MUST NOT overwrite, reset, fork, or replace an existing
authoritative IdentityState.

### 7.1 Validation-layer boundary

Duplicate creation is a state-machine precondition and cannot be
determined from CREATE CBOR bytes in isolation. It therefore is not
structurally expressible by CDDL.

CDDL answers whether the bytes are structurally a CREATE operation. The
state-transition layer answers whether that CREATE may be applied to
authoritative state.

A stateless parser or cryptographic verifier MUST NOT claim to have
established non-existence of an identity merely by validating CREATE
bytes.

## 8. Deterministic resulting IdentityState

An accepted CREATE produces the first authoritative IdentityState:

``` text
{
  1: 1,
  2: identity,
  3: 1,
  4: 1,
  5: controllerPolicy,
  ? 6: recoveryCommitment
}
```

The resulting identity MUST equal the CREATE identity. Sequence MUST be
`1`. Status MUST be ACTIVE. ControllerPolicy MUST equal the canonically
encoded policy authorized by CREATE. An optional recovery commitment
MUST be preserved according to the canonical state schema.

The deterministic CBOR encoding is `StateBytes`. Given the same valid
logical CREATE inputs, conforming implementations MUST derive
byte-identical StateBytes and the corresponding StateHash.

## 9. State-transition algorithm

A conforming state-transition processor SHALL:

1.  decode and validate deterministic CBOR;
2.  require the supported protocol version and CREATE operation type;
3.  validate the OI-001 Identity ID;
4.  require sequence 1;
5.  require nil previousStateHash;
6.  validate the proposed ControllerPolicy;
7.  validate authorization proofs and require its threshold;
8.  require that no authoritative IdentityState already exists for the
    Identity ID;
9.  derive canonical initial ACTIVE IdentityState; and
10. derive StateBytes and StateHash.

If the existence check fails, processing MUST return
`IDENTITY_ALREADY_EXISTS` and MUST NOT change authoritative state.

## 10. Concurrent CREATE attempts

A registry MAY receive competing valid CREATE operations for the same
previously unknown Identity ID.

At most one may establish authoritative initial state. The registry's
transaction or consensus mechanism MUST ensure this uniqueness. Once
authoritative state exists, competing CREATE operations are duplicate
creation and MUST fail with `IDENTITY_ALREADY_EXISTS`.

The serialization/consensus mechanism is registry-specific and is not
defined by OI-004.

## 11. Conformance

### 11.1 Existing byte-level and cryptographic coverage

OI-004 reuses the frozen OI-002 cryptographic-agility vectors:

``` text
V01  SINGLE Ed25519 CREATE
V02  Hybrid Ed25519 + ML-DSA-65 2-of-2 CREATE
V03  canonical ordering equivalence
```

The frozen OI-002 invalid suite already covers CREATE sequence,
predecessor, controller threshold, duplicate Verification Method,
proof/signature, algorithm, and related cryptographic/structural
failures.

OI-004 MUST NOT modify frozen OI-002 v0.1 vector bytes merely to add
stateful registry behavior.

### 11.2 Stateful duplicate-CREATE scenario

``` text
CRI01 — Duplicate CREATE

Precondition:
    authoritative state exists for Identity ID X

Input:
    otherwise structurally and cryptographically valid CREATE
    for Identity ID X

Expected result:
    reject

Expected error:
    IDENTITY_ALREADY_EXISTS

State effect:
    none
```

CRI01 is a state-transition conformance scenario, not a claim that
duplicate existence can be inferred from CBOR.

A future executable registry/state-processor conformance harness SHALL
establish the precondition in its authoritative store, submit CREATE,
require `IDENTITY_ALREADY_EXISTS`, and verify that existing
authoritative state is unchanged.

## 12. Security considerations

Accepting a second CREATE could permit ControllerPolicy replacement or
operation-history reset. Conforming registries MUST reject it.

A non-atomic check-then-write implementation can permit racing CREATE
operations. Registry implementations MUST enforce uniqueness at the
authoritative state-transition boundary.

A cryptographically valid CREATE does not authorize replacement of an
existing identity. Cryptographic validity and state-machine
applicability are separate checks.

## 13. Registry independence

OI-004 does not require a blockchain, database product, consensus
algorithm, or persistence technology.

An implementation conforms when it preserves the protocol semantics,
including unique initial creation and deterministic resulting state,
regardless of registry mechanism.

## 14. OI-004 acceptance criteria

``` text
CREATE payload specified              Section 4
Initial sequence rules defined        Section 5
Signature requirements defined        Section 6
Duplicate creation rejected           Sections 7 and 10
Resulting state deterministic         Section 8
```

## 15. Deferred implementation work

OI-004 defines protocol behavior, not a production registry
implementation.

Executable enforcement of `IDENTITY_ALREADY_EXISTS` belongs to the
authoritative state-transition/registry implementation and its
conformance tests.

This does not make duplicate CREATE behavior optional. The rejection
rule is normative.

## 16. Normative references

OI-004 depends on OI-001, OI-002, OI-003,
`spec/cddl/openidentity-operation-v2.cddl`, and the frozen OI-002
cryptographic-agility conformance vectors.
