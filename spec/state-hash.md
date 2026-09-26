# OpenIdentity StateHash

**Document:** `state-hash.md`  
**Story:** OI-011 — Define StateHash  
**Status:** Draft v0.1  
**Protocol:** OpenIdentity  
**Depends on:** OI-003, OI-008, OI-009

## 1. Purpose

This document defines StateHash, the cryptographic identifier of one exact canonical authoritative OpenIdentity IdentityState.

StateHash binds transitions to their exact predecessor and provides a stable historical-state identifier independent of storage, registry, transport, projection, or programming-language representation.

## 2. StateBytes

OI-009 defines `StateBytes` as the complete deterministic RFC 8949 CBOR encoding of exactly one valid IdentityState under its applicable schema version.

StateHash MUST be computed over those exact StateBytes:

```text
IdentityState
    -> schema/semantic validation
    -> canonical collection ordering
    -> deterministic CBOR
    -> StateBytes
    -> StateHash
```

StateHash MUST NOT be computed directly from a noncanonical object or human-readable representation.

## 3. v0.1 algorithm and representation

OpenIdentity v0.1 uses SHA-256:

```text
digest = SHA-256(StateBytes)
```

The raw 32-byte digest alone is not StateHash.

StateHash is the binary SHA2-256 Multihash:

```text
StateHash = 0x12 || 0x20 || SHA-256(StateBytes)
```

where `0x12` is the Multihash SHA2-256 code and `0x20` is the 32-byte digest length.

A v0.1 StateHash is therefore exactly 34 bytes.

## 4. Structural algorithm agility

The operation schema permits `previousStateHash` as a byte string wider than the current 34-byte profile to permit future supported Multihash algorithms without redesigning the operation envelope.

That structural capacity does not make arbitrary hashes valid in v0.1. A v0.1 verifier MUST require:

```text
code          = 0x12
digest length = 0x20
digest bytes  = 32
total length  = 34
```

## 5. Complete state commitment

StateHash commits to the complete canonical IdentityState.

IdentityState v1 includes:

```text
stateVersion
identity
sequence
status
ControllerPolicy
recoveryCommitment, when present
```

IdentityState v2 additionally includes:

```text
AssertionPolicy, when present
```

Optional fields contribute exactly when present according to canonical schema semantics.

Changing any canonical state field changes StateBytes and is expected to change StateHash.

## 6. State schema version binding

The IdentityState schema version is part of StateBytes. StateHash therefore commits to both state content and the schema version under which that state is interpreted.

A verifier MUST reconstruct historical StateBytes under the schema version encoded in the historical state.

## 7. Identity, sequence, and status binding

Identity, sequence, and status are all part of StateBytes.

Changing the permanent Identity ID changes StateBytes.

Changing sequence changes StateBytes and binds StateHash to a specific position in identity history.

Changing ACTIVE to DEACTIVATED changes StateBytes even if authority fields are otherwise preserved.

## 8. ControllerPolicy binding

The complete canonical ControllerPolicy is part of StateBytes.

Changes to policy type, threshold, Verification Method IDs, algorithms, or public keys change StateBytes.

Set-like VerificationMethod collections MUST first be canonically ordered according to OI-009. Equivalent logical input ordering that canonicalizes to identical policy bytes MUST produce identical StateBytes and StateHash.

## 9. Recovery commitment binding

When present, `recoveryCommitment` is part of StateBytes. Changing or rotating it changes StateBytes and StateHash.

StateHash does not directly hash RecoveryPolicyBytes as a separate input:

```text
RecoveryPolicyBytes
    -> recoveryCommitment
    -> IdentityState
    -> StateBytes
    -> StateHash
```

Recovery commitment and state-history commitment remain distinct protocol concepts.

## 10. AssertionPolicy binding

When present in IdentityState v2, the complete canonical AssertionPolicy is part of StateBytes.

Installing, replacing, or removing AssertionPolicy changes canonical state and is expected to change StateHash.

This permits OI-003 credentials to bind issuance authority to an exact historical state.

## 11. Canonicalization invariance

StateHash is a hash of canonical StateBytes, not construction order.

For logically equivalent set-like policy input:

```text
input A,B
input B,A
    -> same canonical policy
    -> same StateBytes
    -> same StateHash
```

Every conforming implementation MUST derive identical StateBytes and StateHash for the same valid logical IdentityState.

## 12. Non-authoritative representations

StateHash MUST NOT be calculated over JSON, YAML, W3C projections, database rows, ledger account layouts, blockchain transactions, HTTP/message envelopes, SignedOperation, OperationBytes, partial state, hexadecimal text, Base58 text, or another display/storage representation.

Those representations may carry state information but are not StateBytes.

## 13. State-transition chaining

Every state-changing operation after CREATE MUST contain:

```text
previousStateHash = StateHash(current authoritative IdentityState)
```

A verifier MUST independently reconstruct the current StateBytes and StateHash and require exact binary equality.

A mismatch MUST be rejected with:

```text
INVALID_PREVIOUS_STATE_HASH
```

Sequence and StateHash chaining are both required.

## 14. CREATE

CREATE uses `previousStateHash = nil`.

After successful CREATE, the resulting initial IdentityState is canonically encoded and hashed. That StateHash becomes the predecessor identifier for the next authoritative transition.

## 15. Subsequent operations

ROTATE_CONTROLLER, DEACTIVATE, RECOVER, and SET_ASSERTION_POLICY all chain from the exact StateHash of their current authoritative predecessor.

Each successful transition produces a new canonical IdentityState and therefore a new StateHash over the complete resulting state.

RECOVER may chain from ACTIVE or DEACTIVATED state and hashes the resulting ACTIVE state, including replacement ControllerPolicy, rotated recoveryCommitment, preserved schema version, and preserved AssertionPolicy when applicable.

## 16. Historical credential binding

OI-003 credentials use `issuanceStateHash` to identify the exact historical authoritative IdentityState under which assertion authority is evaluated.

A verifier MUST NOT replace the issuance state with current state merely because the permanent Identity ID is unchanged.

A DID Resolution `versionId` may expose StateHash as a historical identifier, but the DID projection itself is not StateBytes.

## 17. Related hash values

These values have distinct semantics:

```text
StateHash
    Multihash of canonical IdentityState StateBytes.

previousStateHash
    Operation field carrying the predecessor StateHash.

recoveryCommitment
    Multihash commitment to deterministic RecoveryPolicyBytes.

issuanceStateHash
    Credential field carrying the historical StateHash at issuance.
```

They MUST NOT be substituted merely because they use the same SHA2-256 Multihash profile.

## 18. Hash comparison

StateHash comparison is exact binary comparison of the complete Multihash.

Implementations MUST NOT compare only the trailing digest while ignoring the algorithm code or digest-length prefix.

Malformed or unsupported Multihashes MUST NOT be normalized into an accepted representation.

## 19. Collision resistance and evolution

StateHash security depends on collision and second-preimage resistance of the selected algorithm. Protocol v0.1 uses SHA-256.

A future supported StateHash algorithm MUST use an explicitly defined Multihash representation and MUST NOT silently reinterpret historical v0.1 StateHashes.

## 20. Validation algorithm

To derive a v0.1 StateHash, a conforming implementation SHALL:

1. validate the complete IdentityState under its encoded schema version;
2. apply protocol-defined canonical collection ordering;
3. deterministically CBOR encode the complete state according to OI-009;
4. call those bytes `StateBytes`;
5. calculate `SHA-256(StateBytes)`;
6. construct `0x12 || 0x20 || digest`; and
7. return the resulting 34-byte StateHash.

To validate a supplied v0.1 StateHash, it SHALL require code `0x12`, digest length `0x20`, exactly 32 digest bytes, exactly 34 total bytes, independently reconstruct StateBytes, independently calculate the expected StateHash, and require exact binary equality.

## 21. Stable error semantics

OI-011 reuses `INVALID_PREVIOUS_STATE_HASH` for a state-changing operation whose predecessor does not exactly equal the StateHash of the current authoritative state.

OI-011 introduces no raw-digest alternative and no second StateHash representation.

## 22. Existing conformance coverage

Existing OpenIdentity vectors already exercise initial state hashing, controller rotation, predecessor chaining, AssertionPolicy transitions, credential historical-state binding, DEACTIVATE, recovery from ACTIVE and DEACTIVATED states, recoveryCommitment rotation, and independent Java/Python StateHash reconstruction.

OI-011 consolidates those rules into one specification.

## 23. Dedicated OI-011 conformance suite

OI-011 SHOULD publish SH01-SH10:

```text
SH01 IdentityState v1 produces expected StateHash
SH02 IdentityState v2 produces expected StateHash
SH03 sequence mutation changes StateHash
SH04 status mutation changes StateHash
SH05 ControllerPolicy mutation changes StateHash
SH06 recoveryCommitment mutation changes StateHash
SH07 AssertionPolicy mutation changes StateHash
SH08 canonical VerificationMethod input-order variation produces identical StateBytes and StateHash
SH09 raw SHA-256 digest alone is not StateHash
SH10 hash of a non-StateBytes representation is not authoritative StateHash
```

The suite SHOULD reuse existing deterministic keys, policies, and state fixtures and MUST be independently reconstructed and verified.

## 24. Security considerations

StateHash MUST be derived only from canonical StateBytes.

Hashing noncanonical serialization can create different identifiers for the same intended state. Hashing only a subset of state can fail to bind security-critical status, recovery authority, or AssertionPolicy.

Registries MUST NOT derive StateHash from storage representation. Historical verification MUST use the correct IdentityState schema version and complete historical state.

## 25. OI-011 acceptance criteria

OI-011 defines:

```text
StateHash input is canonical StateBytes
v0.1 hash algorithm is SHA-256
v0.1 representation is SHA2-256 Multihash
v0.1 StateHash is exactly 34 bytes
complete IdentityState is committed
previousStateHash chaining is explicit
historical-state use is explicit
StateHash is serialization/ledger independent
cross-language deterministic verification is possible
```

## 26. Normative references

OI-011 depends on OI-003 IdentityState and historical credential authority, OI-008 sequence/replay semantics, OI-009 canonical serialization, `spec/cddl/openidentity-operation-v2.cddl`, the OpenIdentity cryptographic-agility profile, and existing normative OpenIdentity conformance vectors.
