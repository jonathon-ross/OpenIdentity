# OpenIdentity Signature Envelope

**Document:** `signature-envelope.md`  
**Story:** OI-010 — Define signature envelope  
**Status:** Complete v0.1  
**Protocol:** OpenIdentity  
**Depends on:** OI-002, OI-005, OI-007, OI-009  
**Normative Keywords:** MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, MAY

## 1. Purpose

This document defines how OpenIdentity v0.1 binds cryptographic proofs to the
exact operation and protocol context they authorize.

The signature envelope separates:

1. the canonical operation being authorized;
2. the purpose-specific signing structure;
3. the cryptographic proof; and
4. the outer SignedOperation that transports proof collections.

This separation prevents circular signing dependencies and cross-purpose proof
substitution.

## 2. Operation

An OpenIdentity Operation contains:

```text
{
  1: protocolVersion,
  2: operationType,
  3: identity,
  4: sequence,
  5: previousStateHash,
  6: payload
}
```

The applicable operation CDDL defines the exact payload shape for each
operation type.

## 3. OperationBytes

OI-009 defines `OperationBytes` as the complete deterministic RFC 8949 CBOR
encoding of exactly one valid Operation.

OperationBytes therefore cover:

```text
protocolVersion
operationType
identity
sequence
previousStateHash
payload
```

Changing any covered field changes OperationBytes.

Proof collections, transport metadata, registry metadata, timestamps added by a
transport, database fields, and ledger-specific wrappers are not part of
OperationBytes.

## 4. SigningInput

A signature is never calculated directly over arbitrary JSON, API objects, or
transport serialization.

The signer constructs the purpose-specific signing structure and
deterministically CBOR encodes that structure. The resulting bytes are the
`SigningInput`.

Conceptually:

```text
Operation
    |
    v
OperationBytes
    |
    v
purpose-specific signing structure
    |
    v
deterministic CBOR
    |
    v
SigningInput
    |
    v
cryptographic signature
```

## 5. Signing-structure version

OpenIdentity v0.1 uses:

```text
signingStructureVersion = 1
```

The signing-structure version is distinct from `protocolVersion`.

`protocolVersion` is encoded inside OperationBytes and identifies operation
wire/protocol semantics.

`signingStructureVersion` identifies the format and semantics of a
purpose-specific signing structure.

A future protocol version MAY continue using signing-structure version 1 if its
signing semantics remain compatible. A future signing-envelope change MAY
require a new signing-structure version independently of operation protocol
versioning.

Implementations MUST NOT substitute one version field for the other.

## 6. Ordinary controller authorization

Ordinary ControllerPolicy authorization signs the deterministic CBOR encoding
of:

```text
[
  "OpenIdentity Operation",
  1,
  OperationBytes
]
```

The exact UTF-8 text string:

```text
OpenIdentity Operation
```

is the domain separator.

All VerificationMethods satisfying the same ControllerPolicy sign the exact
same ordinary authorization SigningInput.

This common SigningInput is intentional for SINGLE and THRESHOLD policies.

## 7. Ordinary authorization proof

An ordinary authorization proof is:

```text
{
  1: verificationMethodId,
  2: signature
}
```

The Verification Method ID identifies which method in the applicable
ControllerPolicy must verify the signature.

The cryptographic algorithm is obtained from that VerificationMethod's
COSE_Key.

The Verification Method ID is not added to the ordinary authorization
SigningInput. All methods participating in one ControllerPolicy authorize the
same operation intent.

The proof's method ID determines which authorized public key verifies that
common signature input.

## 8. Controller proof of possession

A proposed controller VerificationMethod proves possession using the
deterministic CBOR encoding of:

```text
[
  "OpenIdentity Controller Proof",
  1,
  OperationBytes,
  verificationMethodId
]
```

The exact UTF-8 domain separator is:

```text
OpenIdentity Controller Proof
```

Binding `verificationMethodId` into this SigningInput prevents a possession
proof from being detached from the proposed method it is intended to prove.

Controller proof of possession is cryptographically separate from ordinary
ControllerPolicy authorization.

## 9. Recovery authorization

OI-007 recovery authorization signs the deterministic CBOR encoding of:

```text
[
  "OpenIdentity Recovery",
  1,
  OperationBytes,
  recoveryMethodId
]
```

The exact UTF-8 domain separator is:

```text
OpenIdentity Recovery
```

The recovery method ID binds each recovery proof to the RecoveryPolicy method
whose authority it satisfies.

Recovery proofs MUST NOT be interpreted as ordinary controller authorization or
controller proof of possession.

## 10. SignedOperation

The current OpenIdentity operation schema carries proofs in an outer
SignedOperation:

```text
{
  1: Operation,
  2?: authorizationProofs,
  3?: controllerProofs,
  4?: recoveryProofs
}
```

The exact required or prohibited proof collections depend on operation type.

For the current v2 schema:

```text
CREATE:
    ordinary authorization proofs required

ROTATE_CONTROLLER:
    ordinary authorization proofs required
    controller proof-of-possession proofs required

DEACTIVATE:
    ordinary authorization proofs required

SET_ASSERTION_POLICY:
    ordinary authorization proofs required
    controller proofs required when installing non-nil assertion authority

RECOVER:
    ordinary authorization proofs absent
    replacement-controller proof-of-possession proofs required
    recovery authorization proofs required
```

The outer SignedOperation is a transport of cryptographic evidence. It is not
recursively included in OperationBytes.

## 11. No circular signing dependency

Proofs sign OperationBytes.

Proofs are not themselves included in OperationBytes.

Therefore:

```text
Operation
    |
    v
OperationBytes
    |
    +----> authorization proof
    +----> controller PoP proof
    +----> recovery proof

Operation + proofs
    |
    v
SignedOperation
```

An implementation MUST NOT calculate OperationBytes from SignedOperation.

Doing so would make signatures depend on a structure containing the signatures
themselves.

## 12. Signed-field coverage

Because the complete canonical Operation is encoded into OperationBytes,
ordinary authorization, controller PoP, and recovery authorization are all
transitively bound to:

```text
protocolVersion
operationType
identity
sequence
previousStateHash
payload
```

For CREATE, `previousStateHash` is the explicit semantic value `nil`.

For subsequent operations, `previousStateHash` is the exact predecessor
StateHash required by the state-transition rules.

A verifier MUST reconstruct OperationBytes from the exact submitted Operation
before constructing any SigningInput.

## 13. Mutation resistance

After a proof is created, changing any covered Operation field changes
OperationBytes and therefore changes every purpose-specific SigningInput derived
from it.

A proof created for one operation MUST fail if an attacker changes, without
valid re-signing:

- protocolVersion;
- operationType;
- identity;
- sequence;
- previousStateHash; or
- payload.

Canonical serialization rules from OI-009 apply before signature verification.

## 14. Domain separation

A verifier MUST construct the signing structure required for the proof's
protocol purpose.

A valid signature over one domain MUST NOT be accepted in another domain.

In particular:

```text
OpenIdentity Operation
    !=
OpenIdentity Controller Proof
    !=
OpenIdentity Recovery
```

A signature valid for ordinary controller authorization MUST NOT be accepted as
controller proof of possession.

A controller proof-of-possession signature MUST NOT be accepted as ordinary
controller authorization.

A recovery signature MUST NOT be accepted as ordinary controller authorization
or controller proof of possession.

Domain comparison is exact and case-sensitive.

## 15. Cross-protocol replay

OpenIdentity domain separators are part of the bytes being signed.

A verifier MUST NOT verify a proof over raw OperationBytes alone when the
protocol requires a domain-separated signing structure.

A signature originating in another protocol, application, credential system, or
purpose is not an OpenIdentity operation proof unless it verifies against the
exact OpenIdentity SigningInput required for that proof purpose.

The protocol name/domain and signing-structure version therefore provide
explicit context separation in addition to the operation's own protocolVersion.

## 16. Cross-operation replay

`operationType` is inside OperationBytes.

A signature authorizing one operation type cannot be transplanted to another
operation type without changing OperationBytes.

For example, a signature over ROTATE_CONTROLLER OperationBytes cannot authorize
DEACTIVATE or RECOVER OperationBytes.

Likewise, changing a payload while retaining operation type invalidates the
original proof.

## 17. Identity and history binding

`identity`, `sequence`, and `previousStateHash` are inside OperationBytes.

Therefore a proof is bound to:

- one permanent Identity ID;
- one exact sequence position; and
- one exact authoritative predecessor, except CREATE where predecessor is
  explicitly nil.

A valid proof for one identity MUST NOT authorize another identity.

A historical proof MUST NOT authorize a later sequence or a competing branch
with a different predecessor StateHash.

## 18. Proof ordering

Proof collection ordering is defined by OI-009 and the applicable policy
specification.

Authorization proofs, controller proofs, and recovery proofs use canonical
Verification Method ID ordering where their collections are set-like.

Proof ordering does not alter SigningInput because proof collections are
outside OperationBytes.

Canonical proof ordering nevertheless ensures byte-deterministic
SignedOperation serialization.

## 19. Duplicate proofs

A Verification Method ID MUST count at most once toward a threshold.

Duplicate proof entries MUST be rejected according to the applicable ordinary
controller, assertion, or recovery policy rules.

Canonical ordering MUST NOT be used to hide or silently deduplicate malformed
duplicate proof input.

## 20. Algorithm independence

Signature-envelope construction is independent of the signature algorithm.

Ed25519, ML-DSA-65, and future supported algorithms sign the exact canonical
SigningInput required by the applicable proof purpose.

Algorithm-specific signature encoding and verification occur after the common
SigningInput has been constructed.

The envelope MUST NOT silently change based on algorithm choice.

## 21. Credential signatures

OI-003 defines native credential signing and verification.

Credential signing domains are separate from the operation signature envelope
defined here.

A credential signature MUST NOT be accepted as an operation authorization,
controller proof of possession, or recovery proof merely because the same key
or algorithm is used.

OI-010 does not replace OI-003 credential-signature semantics.

## 22. Verification algorithm

For each proof, a conforming verifier SHALL:

1. validate the Operation against its applicable schema;
2. reconstruct canonical OperationBytes according to OI-009;
3. determine the proof purpose from the operation and proof collection;
4. construct the exact purpose-specific signing structure;
5. deterministically CBOR encode it to obtain SigningInput;
6. resolve the claimed Verification Method ID under the applicable policy;
7. validate the referenced COSE_Key and algorithm;
8. validate signature representation and length;
9. cryptographically verify the signature over the exact SigningInput;
10. reject cross-domain or cross-purpose substitution; and
11. evaluate the distinct valid proof set against the applicable policy.

An implementation MAY internally reorder checks only when doing so does not
weaken validation or alter required externally observable conformance behavior.

## 23. Stable error semantics

OI-010 reuses existing stable errors, including:

```text
INVALID_SIGNATURE
INVALID_SIGNATURE_FORMAT
DUPLICATE_PROOF
UNAUTHORIZED_VERIFICATION_METHOD
CONTROLLER_THRESHOLD_NOT_SATISFIED
MISSING_PROOF_OF_POSSESSION
INVALID_PROOF_OF_POSSESSION
DUPLICATE_RECOVERY_PROOF
UNAUTHORIZED_RECOVERY_METHOD
INVALID_RECOVERY_SIGNATURE
RECOVERY_THRESHOLD_NOT_SATISFIED
```

A cross-domain substitution is rejected under the error semantics of the proof
purpose being evaluated.

OI-010 does not require a new generic `INVALID_SIGNATURE_DOMAIN` error for
protocol v0.1.

## 24. Existing conformance coverage

Existing OpenIdentity vector suites already cover substantial OI-010 behavior,
including:

- deterministic OperationBytes;
- ordinary authorization SigningInput;
- hybrid signatures over a common SigningInput;
- controller proof-of-possession SigningInput;
- proof-method binding;
- mutation-sensitive operation bytes;
- recovery SigningInput;
- recovery method binding; and
- cross-domain recovery substitution rejection.

OI-010 consolidates those rules into one signature-envelope specification.

## 25. Normative OI-010 conformance suite

OI-010 publishes the normative SE01-SE10 envelope/domain-separation
conformance suite in:

```text
test-vectors/signature-envelope-v0.1.json
```

The suite contains:

```text
SE01 valid ordinary controller authorization
SE02 identity mutation invalidates authorization
SE03 sequence mutation invalidates authorization
SE04 previousStateHash mutation invalidates authorization
SE05 payload mutation invalidates authorization
SE06 ordinary authorization substituted as controller PoP is rejected
SE07 controller PoP substituted as ordinary authorization is rejected
SE08 recovery authorization substituted as ordinary authorization is rejected
SE09 signingStructureVersion mutation invalidates proof
SE10 operationType mutation invalidates authorization
```

The suite reuses deterministic OpenIdentity test keys and operation fixtures.
SE01-SE10 were independently reconstructed and verified by the Python
conformance verifier.

The normative bundle checksum is published in:

```text
test-vectors/signature-envelope-v0.1.json.sha256
```

The frozen SHA-256 of `signature-envelope-v0.1.json` is:

```text
ac1f4867402e3d5d12b5b68ef27fb52c3442332e2a6432fb445e0616658469da
```

## 26. Security considerations

Implementations MUST NOT sign raw JSON or arbitrary transport bytes where an
OpenIdentity signing structure is defined.

Implementations MUST NOT omit the domain separator or
signingStructureVersion.

Implementations MUST NOT accept a signature solely because it verifies under a
known public key; the signature must verify over the exact SigningInput for its
claimed protocol purpose.

Proof collections MUST remain outside OperationBytes.

Verification Method IDs in purpose-specific signing structures MUST use raw
protocol bytes, not display encodings.

Historical signatures remain cryptographically verifiable but are applicable to
state transitions only when all current sequence, predecessor, authority, and
state-transition rules are also satisfied.

## 27. OI-010 acceptance criteria

The original OI-010 acceptance criteria are satisfied as follows:

```text
Signed fields specified
    Sections 2-3 and 12

Protocol/version domain separation included
    Sections 5-9 and 14-15

Identity, sequence, previousStateHash and payload covered
    Sections 3, 12-13 and 17

Cross-protocol replay addressed
    Sections 14-16
```

## 28. Normative references

OI-010 depends on:

- OI-002 cryptographic agility and controller authorization;
- OI-003 credential authority separation;
- OI-005 controller proof of possession;
- OI-007 recovery authorization;
- OI-008 sequence and replay semantics;
- OI-009 canonical serialization;
- `spec/cddl/openidentity-operation-v2.cddl`; and
- existing normative OpenIdentity cryptographic and recovery vectors.

The v2 CDDL remains the normative structural definition of SignedOperation and
its proof collections. This document defines their signature-envelope and
domain-separation semantics.
