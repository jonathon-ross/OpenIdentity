# OpenIdentity Canonical Serialization

**Document:** `canonical-serialization.md`  
**Story:** OI-009 — Define canonical serialization  
**Status:** Complete v0.1  
**Protocol:** OpenIdentity  
**Depends on:** OI-003, OI-008  
**Normative Keywords:** MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, MAY

## 1. Purpose

This document defines the canonical serialization rules for OpenIdentity v0.1.

Every compliant implementation MUST produce identical authoritative bytes for
the same valid logical OpenIdentity object.

Canonical serialization is independent of programming language, API format,
database, transport, registry, consensus system, and ledger.

## 2. Canonical format

OpenIdentity v0.1 uses RFC 8949 CBOR under the Core Deterministic Encoding
Requirements for all cryptographically authoritative protocol structures.

Human-readable representations MAY use JSON, YAML, diagnostic notation, or
other formats, but those representations are not authoritative bytes and MUST
NOT be signed or hashed directly where an OpenIdentity specification requires
canonical protocol bytes.

The canonicalization pipeline is:

```text
logical OpenIdentity object
        |
        v
schema and semantic validation
        |
        v
protocol-defined collection ordering
        |
        v
RFC 8949 deterministic CBOR
        |
        v
authoritative bytes
```

## 3. Authoritative byte sequences

Depending on context, deterministic serialization produces authoritative byte
sequences including:

```text
OperationBytes
StateBytes
RecoveryPolicyBytes
CredentialBytes
SecuredCredential
authorization SigningInput
controller proof-of-possession SigningInput
recovery SigningInput
```

Each byte sequence is defined by the schema and protocol specification that
owns the corresponding logical structure.

Serialization does not transfer authorization semantics between structures.

## 4. Permitted CBOR types

Where permitted by the applicable CDDL/schema, OpenIdentity may use:

- unsigned integers;
- negative integers;
- byte strings;
- text strings;
- arrays;
- maps; and
- nil.

Negative integers are permitted where required by standardized structures such
as COSE identifiers.

OpenIdentity v0.1 prohibits, unless a future specification explicitly changes
the rule:

- floating-point values;
- NaN;
- Infinity;
- undefined;
- arbitrary or unassigned simple values;
- indefinite-length byte strings;
- indefinite-length text strings;
- indefinite-length arrays;
- indefinite-length maps;
- arbitrary CBOR tags;
- duplicate map keys; and
- unknown OpenIdentity-defined map labels.

## 5. Definite lengths and preferred serialization

All strings, arrays, and maps MUST use definite lengths.

Integers and lengths MUST use RFC 8949 preferred serialization: the shortest
valid deterministic encoding for the value.

An implementation MUST NOT emit a wider integer or length representation when a
shorter preferred representation exists.

For example, the integer `1` is encoded using its preferred one-byte CBOR
representation, not a wider uint8, uint16, uint32, or uint64 representation.

## 6. Map key ordering

CBOR map keys MUST follow RFC 8949 deterministic map-key ordering.

OpenIdentity map labels are generally small integers, but implementations MUST
NOT replace the RFC 8949 rule with an assumption that all maps can simply be
sorted numerically.

This distinction matters for embedded standardized structures such as COSE
maps, which may contain negative integer labels.

Duplicate map keys MUST be rejected rather than normalized or silently
overwritten.

## 7. Protocol-defined collection ordering

Some arrays represent logically unordered sets. Those collections require an
OpenIdentity-defined order before deterministic CBOR encoding.

VerificationMethods in ControllerPolicy, AssertionPolicy, and RecoveryPolicy
MUST be sorted by Verification Method ID using unsigned bytewise
lexicographic ordering.

Authorization proofs, controller proof-of-possession proofs, and recovery
proofs MUST use the same Verification Method ID ordering.

Duplicate Verification Method IDs or duplicate proof IDs MUST be rejected
according to the applicable protocol rules.

Arrays whose order has protocol meaning MUST preserve that semantic order and
MUST NOT be arbitrarily sorted merely for serialization.

## 8. Optional fields

An optional map field that is logically absent MUST be omitted from the
canonical CBOR map.

An implementation MUST NOT encode an absent optional field as `nil`, an empty
byte string, an empty text string, zero, an empty array, or an empty map unless
the applicable schema explicitly defines that value as the logical value.

Therefore:

```text
field absent
```

and:

```text
field present with nil
```

are not interchangeable.

When a schema explicitly assigns semantic meaning to `nil`, `nil` MUST be
encoded.

Examples include CREATE's required `previousStateHash = nil` and
SET_ASSERTION_POLICY's explicit `nil` value when removing assertion authority.

## 9. Whitespace

Canonical CBOR contains no JSON-style insignificant whitespace.

Whitespace in JSON, YAML, source code, configuration files, logs, diagnostic
notation, or documentation has no effect on authoritative OpenIdentity bytes
because those textual representations are not signed or hashed directly.

Implementations MUST parse or construct the logical protocol object first and
then produce deterministic CBOR.

## 10. Text strings

Where a schema permits text, the value is encoded as a CBOR text string using
UTF-8 as required by CBOR.

A protocol specification that permits free-form text SHOULD define any
additional Unicode normalization requirements if logically equivalent Unicode
spellings must collapse to one value.

OpenIdentity v0.1 MUST NOT silently apply unspecified text normalization during
canonical serialization.

Protocol-fixed domain-separation strings such as:

```text
OpenIdentity Operation
OpenIdentity Controller Proof
OpenIdentity Recovery
OpenIdentity Credential
```

MUST be encoded exactly as specified by their owning protocol definitions.

## 11. Byte strings

Binary protocol values such as Identity IDs, Verification Method IDs, public
key material, signatures, StateHashes, recovery commitments, OperationBytes,
and CredentialBytes are encoded as CBOR byte strings where specified.

Hexadecimal, Base64, Base58, Multibase, JSON strings, or other display
representations MUST NOT be substituted for the raw bytes inside canonical CBOR
unless a specific schema explicitly defines a textual representation.

## 12. OperationBytes

`OperationBytes` are the complete deterministic CBOR encoding of exactly one
valid OpenIdentity Operation.

They include the operation's protocol version, operation type, identity,
sequence, previousStateHash, and operation payload.

They exclude SignedOperation proof collections and transport or registry
metadata.

Proofs therefore sign stable operation bytes without creating circular
serialization dependencies.

## 13. StateBytes

`StateBytes` are the complete deterministic CBOR encoding of exactly one valid
IdentityState under its applicable state schema version.

StateHash is derived from StateBytes as defined by the OpenIdentity StateHash
rules.

Two implementations given the same logical valid IdentityState MUST produce
byte-identical StateBytes.

## 14. RecoveryPolicyBytes

`RecoveryPolicyBytes` are the deterministic CBOR encoding of the complete
RecoveryPolicy.

The OI-007 recovery commitment is calculated over these exact bytes.

Canonical VerificationMethod ordering is therefore part of recovery commitment
calculation.

## 15. Credential serialization

OI-003 CredentialBytes and SecuredCredential are serialized using the same
deterministic CBOR profile.

Human-readable W3C credential projections are projections of native
OpenIdentity credentials and are not replacements for the authoritative native
SecuredCredential bytes.

## 16. Signing structures

Every OpenIdentity signing structure is itself deterministically CBOR encoded.

Examples include:

```text
[
  "OpenIdentity Operation",
  1,
  OperationBytes
]
```

```text
[
  "OpenIdentity Controller Proof",
  1,
  OperationBytes,
  verificationMethodId
]
```

```text
[
  "OpenIdentity Recovery",
  1,
  OperationBytes,
  verificationMethodId
]
```

Serialization rules apply identically regardless of the signing algorithm.

## 17. Validation before canonicalization

Canonical serialization does not make an invalid object valid.

An implementation MUST validate applicable structural and semantic constraints,
including prohibited unknown labels and duplicate identifiers, rather than
attempting to canonicalize malformed input into a different valid object.

Where input is received as CBOR, a verifier MUST reject encodings that violate
the required deterministic profile even if they decode to a logical object that
could have been encoded canonically.

## 18. Cross-language determinism

Canonical serialization is language-independent.

Java, Python, JavaScript, Rust, Go, or any other implementation given the same
valid logical object MUST produce identical authoritative bytes.

OpenIdentity's existing conformance work demonstrates this property through
Java-generated vectors independently reconstructed and verified in Python,
including canonical policy/proof ordering, StateBytes, OperationBytes,
CredentialBytes, RecoveryPolicyBytes, and signing structures.

OI-009 does not require implementations to use the same CBOR library.

## 19. Ledger and storage independence

Canonical OpenIdentity serialization MUST NOT depend on:

- blockchain transaction encoding;
- ledger account layout;
- database row layout;
- SQL column ordering;
- JSON property ordering;
- HTTP headers;
- message-broker envelopes;
- filesystem representation;
- programming-language object layout; or
- vendor-specific serialization.

A registry stores, transports, or anchors OpenIdentity data. It does not define
the canonical OpenIdentity bytes.

## 20. Canonical examples

### 20.1 Optional field omitted

If an optional `recoveryCommitment` is absent from IdentityState, its map label
is omitted entirely.

It is not encoded as:

```text
6: nil
```

unless a future schema explicitly defines that value.

### 20.2 Explicit nil

CREATE requires:

```text
previousStateHash = nil
```

That field is present because nil is the required semantic value.

### 20.3 Canonical VerificationMethod order

Given method IDs:

```text
B
A
```

as logical input to a set-like policy collection, canonical serialization
orders them:

```text
A
B
```

according to unsigned bytewise lexicographic comparison of the raw method-ID
bytes.

### 20.4 Proof ordering

Proof input order does not determine canonical proof order. Proof collections
are ordered by raw Verification Method ID under the same rule as their
corresponding methods.

## 21. Existing conformance coverage

OI-009 reuses existing OpenIdentity conformance vectors rather than introducing
a competing serialization suite.

Existing coverage includes deterministic operation encoding, canonical
VerificationMethod ordering, canonical proof ordering, deterministic
IdentityState encoding, StateHash reconstruction, assertion-policy encoding,
credential encoding, W3C projection source preservation, RecoveryPolicy
encoding, recovery proof ordering, and cross-language Java/Python
reconstruction.

In particular, canonical-ordering vectors demonstrate that differing logical
input order for set-like collections produces the same canonical result.

OI-009 does not modify frozen OI-002, OI-003, or OI-007 normative vector bytes.

## 22. Security considerations

Non-deterministic serialization can cause different implementations to sign or
hash different bytes for the same intended logical object.

Signing JSON text directly is prohibited because property ordering, whitespace,
number representation, and implementation behavior can differ.

Duplicate map keys are prohibited because parsers can disagree about which
value is authoritative.

Unknown labels are rejected to prevent unsigned or ambiguously interpreted
extension data from silently entering authoritative structures.

Optional-field omission rules prevent multiple byte encodings for the same
logical absence.

Canonical collection ordering prevents input-order differences from changing
policy commitments, StateHashes, signatures, or credential bytes.

## 23. OI-009 acceptance criteria

The original OI-009 acceptance criteria are satisfied as follows:

```text
Canonical format specified                  Sections 2-5
Field ordering and encoding explicit        Sections 5-7, 10-16
Whitespace/optional-field behavior explicit Sections 8-9
Cross-language test vectors possible        Sections 18 and 21
Serialization ledger-independent            Section 19
```

## 24. Normative references

OI-009 depends on:

- OI-003 IdentityState and credential serialization;
- OI-008 sequence and replay semantics;
- RFC 8949 CBOR Core Deterministic Encoding Requirements;
- `spec/cddl/openidentity-operation-v2.cddl`;
- OI-002 cryptographic-agility serialization rules;
- OI-007 RecoveryPolicy serialization rules; and
- the existing normative OpenIdentity conformance vectors.
