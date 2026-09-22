# OpenIdentity Cryptographic Agility Specification

**Document:** `cryptographic-agility.md`\
**Story:** OI-002 --- Define Cryptographic Agility Model\
**Status:** Draft v0.1 --- conformance candidate\
**Protocol:** OpenIdentity\
**Wire Format:** OpenIdentity Operation v1

## 1. Purpose

This specification defines cryptographic authority for an OpenIdentity
root identity while preserving the permanent root DID across key
rotation, algorithm migration, post-quantum migration, provider changes,
and registry changes. It also defines the canonical operation, proof,
identity-state, state-hash, and conformance model proven by OI-002.

The keywords MUST, MUST NOT, SHALL, SHALL NOT, SHOULD, SHOULD NOT, and
MAY are normative.

## 2. Core invariants

The root identity is independent of controller keys and algorithms.
Changing a controller key, controller policy, cryptographic algorithm,
device, registry, or provider MUST NOT change the root DID.

Operations describe requested state transitions. Proofs provide
cryptographic evidence. `IdentityState` describes the authoritative
result of accepted transitions.

Root-controller keys MUST NOT normally be used directly as website or
application login keys.

## 3. v0.1 cryptographic profile

OpenIdentity v0.1 SHALL support Ed25519 and ML-DSA-65.

The default root controller SHALL be THRESHOLD 2-of-2 containing exactly
one Ed25519 VerificationMethod and one ML-DSA-65 VerificationMethod.
Hybrid authorization uses independent proofs; v0.1 does not define a
proprietary composite signature.

Ed25519 uses COSE `kty=1`, `alg=-8`, `crv=6`, a 32-byte public key, and
a 64-byte signature.

ML-DSA-65 uses COSE `kty=7`, `alg=-49`, a 1952-byte raw public key, and
a 3309-byte signature.

Structurally valid unsupported algorithms MUST produce
`UNSUPPORTED_ALGORITHM`. Unsupported algorithms MUST NOT cause threshold
downgrade.

## 4. Controller policies and VerificationMethods

v0.1 defines SINGLE (`type=1`) and THRESHOLD (`type=2`).

SINGLE contains exactly one VerificationMethod. THRESHOLD MUST satisfy
`1 <= threshold <= methodCount`.

A VerificationMethod is:

``` text
{
  1: verificationMethodId,   ; exactly 16 bytes
  2: COSE_Key
}
```

Verification Method IDs MUST be unique. VerificationMethods and proof
collections MUST be sorted by Verification Method ID using unsigned
bytewise lexicographic ordering. Duplicate IDs MUST be rejected.

## 5. Deterministic CBOR

Cryptographically authoritative structures SHALL use RFC 8949
deterministic CBOR. Arbitrary JSON serialization MUST NOT be signed or
hashed.

v0.1 requires definite lengths, preferred integer serialization,
deterministic map-key ordering, and rejection of duplicate map keys,
unknown signed OpenIdentity map labels, floating point, NaN, Infinity,
undefined, arbitrary tags, and unassigned simple values.

## 6. Operation model

An Operation is:

``` text
{
  1: protocolVersion,
  2: operationType,
  3: identity,
  4: sequence,
  5: previousStateHash,
  6: payload
}
```

`protocolVersion=1`. The identity is exactly the raw 32 bytes defined by
OI-001; the textual `did:open:z...` form MUST NOT be embedded.

Operation codes are CREATE=1, ROTATE_CONTROLLER=2, RECOVER=3, and
DEACTIVATE=4. Codes 5..23 are reserved. RECOVER is allocated but
unsupported in v0.1 and MUST produce `UNSUPPORTED_OPERATION`.

`OperationBytes` are the deterministic CBOR encoding of exactly one
Operation. They contain no authorization proofs and no controller
proof-of-possession proofs.

## 7. SignedOperation envelope

The signed envelope is:

``` text
{
  1: operation,
  2: [+ authorizationProof],
  ? 3: [+ controllerProof]
}
```

CREATE normally omits field 3. ROTATE_CONTROLLER requires field 3
semantically. Keeping both proof collections outside OperationBytes
prevents circular signing dependencies.

## 8. Authorization

Authorization signs deterministic CBOR encoding of:

``` text
[
  "OpenIdentity Operation",
  1,
  operationBytes
]
```

An authorization proof is:

``` text
{
  1: verificationMethodId,
  2: signature
}
```

A verifier MUST resolve the proof against the applicable controller
policy, reject duplicate or unauthorized IDs, validate the COSE key and
algorithm, verify the exact canonical SigningInput, count each method at
most once, and require the threshold to be satisfied.

A 2-of-2 policy remains 2-of-2 even when one algorithm is unavailable.

## 9. CREATE

CREATE SHALL have `protocolVersion=1`, `operationType=1`, `sequence=1`,
`previousStateHash=nil`, a 32-byte identity, and a valid controller
policy.

Its payload is:

``` text
{
  1: controllerPolicy,
  ? 2: recoveryCommitment
}
```

CREATE has no prior controller. The policy being created authorizes
creation. Default-profile CREATE therefore requires valid Ed25519 and
ML-DSA-65 authorization proofs.

## 10. Canonical IdentityState

Every accepted state-changing operation produces canonical authoritative
state:

``` text
{
  1: stateVersion,
  2: identity,
  3: sequence,
  4: status,
  5: controllerPolicy,
  ? 6: recoveryCommitment
}
```

`stateVersion=1`. Status `1` is ACTIVE and status `2` is DEACTIVATED.

IdentityState contains no signatures, proofs, transport metadata, or
registry-specific metadata. Its deterministic CBOR encoding is
`StateBytes`.

A normal CREATE produces ACTIVE state at sequence 1 containing the newly
established controller policy.

## 11. StateHash and chaining

v0.1 calculates:

``` text
digest    = SHA-256(StateBytes)
StateHash = 0x12 || 0x20 || digest
```

`0x12` is the SHA2-256 Multihash code and `0x20` is the 32-byte digest
length. The resulting StateHash is exactly 34 bytes.

For subsequent operations:

``` text
sequence = currentState.sequence + 1
previousStateHash = StateHash(currentState)
```

A verifier MUST recompute the predecessor hash from canonical
StateBytes.

## 12. ROTATE_CONTROLLER

ROTATE_CONTROLLER uses operation type 2. Its payload contains only:

``` text
{
  1: newControllerPolicy
}
```

The current authoritative controller policy authorizes the operation.
The proposed controller MUST NOT authorize its own installation.

After successful authorization and proof of possession, the resulting
ACTIVE IdentityState increments sequence and replaces the current
controller policy with the proposed policy without changing the root
identity.

## 13. Controller proof of possession

Every VerificationMethod installed by ROTATE_CONTROLLER MUST provide
exactly one valid proof of possession in SignedOperation field 3.

Each proposed method signs:

``` text
[
  "OpenIdentity Controller Proof",
  1,
  operationBytes,
  verificationMethodId
]
```

The method ID is part of the signed domain. Authorization proofs MUST
NOT be accepted as controller proofs and controller proofs MUST NOT be
accepted as authorization proofs.

A verifier MUST reject missing proofs, duplicate proofs, signatures made
over the authorization domain, signatures bound to another method ID, or
signatures that fail under the proposed public key.

## 14. RECOVER and DEACTIVATE

RECOVER (`operationType=3`) is reserved but invalid in v0.1. Recovery
payload, authorization, thresholds, timing, and state-transition
semantics are deferred.

DEACTIVATE (`operationType=4`) is structurally allocated. A valid
deactivation chains from the current StateHash and produces DEACTIVATED
IdentityState. Final permanence, delay, recoverability, and additional
policy requirements require further specification before production use.

## 15. Stable conformance errors

OI-002 v0.1 defines these conformance errors:

``` text
INVALID_SEQUENCE
INVALID_PREVIOUS_STATE_HASH
INVALID_CONTROLLER_THRESHOLD
DUPLICATE_VERIFICATION_METHOD
CONTROLLER_THRESHOLD_NOT_SATISFIED
DUPLICATE_PROOF
INVALID_SIGNATURE
UNAUTHORIZED_VERIFICATION_METHOD
MISSING_PROOF_OF_POSSESSION
INVALID_PROOF_OF_POSSESSION
UNSUPPORTED_ALGORITHM
UNSUPPORTED_PROTOCOL_FEATURE
UNSUPPORTED_OPERATION
```

Implementations MAY expose additional typed errors for malformed
encoding, identity, COSE keys, or signature representation.
Human-readable messages MAY vary.

## 16. Validation precedence

Normative negative vectors require deterministic rejection semantics.
Validation conceptually proceeds in this order:

1.  decode CBOR and enforce deterministic encoding;
2.  validate allowed labels and structural shape;
3.  validate protocol version and operation type;
4.  validate identity representation;
5.  validate operation-specific sequence;
6.  validate previousStateHash requirements;
7.  validate controller-policy structure and threshold;
8.  reject duplicate Verification Method IDs;
9.  validate supported COSE algorithms and keys;
10. validate proof collections and reject duplicate proof IDs;
11. reject unauthorized proof IDs;
12. evaluate threshold coverage;
13. verify authorization signatures;
14. validate proof-of-possession coverage;
15. verify proof-of-possession signatures and domain binding; and
16. apply the state transition.

Implementations MAY optimize internally only when externally observable
conformance behavior remains equivalent.

## 17. Normative conformance vectors

The normative artifact is:

``` text
test-vectors/cryptographic-agility-v0.1.json
```

It contains:

``` text
V01  SINGLE Ed25519 CREATE
V02  Hybrid Ed25519 + ML-DSA-65 2-of-2 CREATE
V03  Canonical ordering equivalence
V04  ROTATE_CONTROLLER with authorization and proof of possession
I01-I20 negative conformance vectors
```

The vectors cover deterministic CBOR, OperationBytes, both signing
domains, Ed25519 and ML-DSA-65 interoperability, canonical ordering,
IdentityState, StateHash chaining, rotation, threshold behavior,
proof-of-possession, duplicate rejection, unsupported
algorithms/operations, and stable negative validation.

Expected bytes MUST be independently verified before publication. The
normative JSON SHALL be accompanied by
`cryptographic-agility-v0.1.sha256` after final independent
verification.

## 18. Proven implementation behavior

The OI-002 conformance work has established cross-implementation
agreement between the Java reference generator and independent Python
verification for the positive vectors, including deterministic CBOR and
Ed25519/ML-DSA-65 verification.

V03 proves reversed input ordering produces byte-identical canonical
ControllerPolicy, OperationBytes, SigningInput, and SignedOperation.

V04 proves predecessor StateHash linkage, current-controller
authorization, new-controller proof of possession, signing-domain
separation, resulting IdentityState, and resulting StateHash.

The normative negative suite I01-I20 defines required rejection
behavior.

## 19. Relationship to OI-001

OI-001 defines the permanent root identifier. OI-002 does not alter that
format. Controller keys, algorithms, COSE identifiers, sequence, and
registry information remain absent from the root DID.

## 20. Deferred work

OI-002 intentionally defers complete recovery-policy design,
device/passkey authorization, pairwise application identifiers,
credential presentation, registry-specific verification mechanics,
ledger implementation details, hardware key storage, and final
production deactivation policy.

## 21. OI-002 completion gate

OI-002 is complete when:

-   this document and `openidentity-operation-v1.cddl` agree;
-   Ed25519 and ML-DSA-65 profiles are fixed;
-   default hybrid policy is fixed;
-   deterministic CBOR and canonical ordering are fixed;
-   authorization and proof-of-possession signing domains are fixed;
-   IdentityState and StateHash are fixed;
-   CREATE and ROTATE_CONTROLLER semantics are fixed;
-   stable error semantics and validation precedence are documented;
-   V01-V04 and I01-I20 are present in the normative JSON;
-   `verify_cryptographic_agility.py` independently passes the normative
    JSON; and
-   `cryptographic-agility-v0.1.sha256` verifies the exact published
    normative artifact.

Once the checksum is published, changing any normative byte, field,
algorithm identifier, state rule, signing domain, or conformance
expectation requires a new specification/vector version.
