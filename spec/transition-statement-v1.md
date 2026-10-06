# OI-TS-001 — TransitionStatement v1

Status: BYTE-FREEZE CANDIDATE; NOT YET NORMATIVE.

TransitionStatement v1 is the public statement emitted by a conforming
OpenIdentity transition proof. It reveals commitments required to advance an
external registry without revealing predecessor StateBytes, SignedOperationBytes,
policies, keys, signatures, or successor StateBytes.

## Deterministic CBOR

The statement MUST be encoded as the deterministic CBOR map:

```text
{
  1 => 1,                         ; statement version
  2 => bstr .size 32,             ; IdentityId
  3 => bstr .size 34 / null,      ; previous StateHash; null only for CREATE
  4 => bstr .size 32,             ; SHA-256(OperationBytes)
  5 => uint,                      ; resulting state sequence
  6 => bstr .size 34              ; successor StateHash
}
```

Map labels MUST appear in deterministic integer-key order. Unknown, duplicate,
missing, or reordered labels are invalid. No trailing bytes are permitted.

## Semantics

- version MUST equal 1.
- identity MUST equal the permanent IdentityId accepted by the transition verifier.
- previousStateHash MUST be null exactly for CREATE; otherwise it MUST equal the
  predecessor StateHash verified by the transition.
- operationHash MUST equal SHA-256(OperationBytes), without a multihash prefix.
- sequence MUST equal the sequence of the derived successor state.
- successorStateHash MUST equal the canonical StateHash of the derived successor
  StateBytes (0x12 || 0x20 || SHA-256(StateBytes) in the current profile).

A proof system MUST derive this statement from the result of the normative
transition verifier. A caller MUST NOT supply individual statement fields as
trusted verifier inputs.

## Privacy boundary

TransitionStatement v1 intentionally does not expose StateBytes,
SignedOperationBytes, VerificationMethods, policies, signatures, RecoveryPolicy,
or application/personal data.

## Registry use

A registry MAY bind additional external context (chain ID, registry/object ID,
approved program verification key, replay/nullifier state) outside this
statement. Those bindings are registry-specific and are not part of
TransitionStatement v1.
