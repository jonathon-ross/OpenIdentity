# OpenIdentity W3C Identity Projection

**Status:** Frozen v0.1\
**Depends on:** OI-001, OI-002

Canonical OpenIdentity `IdentityState` is authoritative. DID /
Controlled Identifier documents are deterministic interoperability
projections and MUST NOT become alternate state stores.

## Namespace and context

OpenIdentity-specific projection terms use:

``` text
Vocabulary: https://openidentity.foundation/ns#
Context v1: https://openidentity.foundation/ns/v1
Vocabulary document: https://openidentity.foundation/ns
```

The published `/ns/v1` context is immutable for version 1. Breaking
semantic changes require a new versioned context URI.

The repository source is:

``` text
contexts/openidentity-v1.jsonld
```

and its integrity file is:

``` text
contexts/openidentity-v1.sha256
```

Standard W3C terms MUST NOT be redefined in the OpenIdentity context.

`openIdentityVerificationPolicy` is an embedded policy object. Its
JSON-LD term definition MUST NOT coerce the value with `@type: @id`.

## Authority and projection boundary

The canonical OI-001/OI-002 state and canonical CBOR/COSE encodings
remain authoritative.

The W3C projection:

-   is derived deterministically from authoritative OpenIdentity state;
-   does not create a second identity state;
-   does not change OpenIdentity authorization semantics;
-   does not replace canonical `COSE_Key` material;
-   does not make JSON object member ordering, whitespace, or
    pretty-printing cryptographically authoritative; and
-   MUST NOT be accepted as an unsigned OpenIdentity state transition.

Two implementations that hold the same canonical OpenIdentity state MUST
produce the same semantic projection.

## Root identifier

The OI-001 32-byte identity is projected as the subject identifier:

``` text
did:open:<multibase-base58btc(identity)>
```

For the current v0.1 projection, the Multibase prefix is `z` and the
payload is the raw 32-byte OI-001 identity encoded with base58btc.

Controller rotation MUST NOT change this root DID. Rotation changes
controller authority, not identity.

## Verification Method identifiers

Each OI-002 16-byte `verificationMethodId` projects to the fragment:

``` text
vm-u<base64url-no-pad(verificationMethodId)>
```

and the complete Verification Method DID URL is:

``` text
did:open:<root>#vm-u<base64url-no-pad(verificationMethodId)>
```

The `u` identifies the base64url Multibase encoding used for the
method-local identifier bytes. OpenIdentity does not allocate a private
Multicodec value for the Verification Method ID.

Verification Method IDs are distinct from public-key fingerprints and
COSE Key Thumbprints.

## Verification material

Canonical key material remains the OI-002 `COSE_Key`. W3C `Multikey`
values are derived interoperability representations.

### Ed25519

An Ed25519 public key projects as:

``` text
publicKeyMultibase =
    "z" + base58btc(
        unsigned-varint(ed25519-pub multicodec) ||
        raw-ed25519-public-key
    )
```

For v0.1:

``` text
ed25519-pub multicodec = 0xed
unsigned varint         = ed 01
raw public key length   = 32 bytes
```

The projected Verification Method uses:

``` json
{
  "id": "did:open:<root>#vm-u<method-id>",
  "type": "Multikey",
  "controller": "did:open:<root>",
  "publicKeyMultibase": "z..."
}
```

### ML-DSA-65

ML-DSA-65 MUST use the externally registered `mldsa-65-pub` Multicodec
identifier. OpenIdentity MUST NOT allocate a private codec for
ML-DSA-65.

The v0.1 projection uses:

``` text
mldsa-65-pub multicodec = 0x1211
unsigned varint          = 91 24
raw public key length    = 1952 bytes
```

The projected key is:

``` text
publicKeyMultibase =
    "u" + base64url-no-pad(
        0x91 0x24 ||
        raw-ML-DSA-65-public-key
    )
```

Canonical OI-002 COSE key material remains authoritative.

The ML-DSA Multikey ecosystem is still less mature than Ed25519.
OpenIdentity therefore treats the external ML-DSA Multicodec/Multikey
representation as an interoperability dependency, not as an
OpenIdentity-created cryptographic encoding. If the applicable external
draft/registry representation changes before it becomes stable, a future
OpenIdentity projection version MUST explicitly version that change
rather than silently changing v0.1 semantics.

RFC 9679 COSE Key Thumbprints SHOULD be used when exact COSE key
identity/fingerprinting is needed. A COSE Key Thumbprint is distinct
from an OpenIdentity Verification Method ID.

## ControllerPolicy projection

Active root-controller methods project to the W3C `capabilityInvocation`
verification relationship.

They MUST NOT automatically project to:

-   `authentication`;
-   `assertionMethod`;
-   `keyAgreement`; or
-   `capabilityDelegation`.

`capabilityInvocation` identifies methods eligible for controller
capability invocation, but it does not itself encode OpenIdentity m-of-n
authorization semantics. It MUST NOT be used alone to authorize
OpenIdentity state transitions.

The authoritative combination rule remains
`IdentityState.ControllerPolicy`.

## `openIdentityVerificationPolicy`

The deterministic projection of the OpenIdentity controller combination
rule uses `openIdentityVerificationPolicy`, mapped by the OpenIdentity
v1 JSON-LD context to:

``` text
https://openidentity.foundation/ns#verificationPolicy
```

The value is an embedded policy object.

### SINGLE

A SINGLE controller projects as:

``` json
{
  "openIdentityVerificationPolicy": {
    "id": "did:open:<root>#controller-policy",
    "type": "Single",
    "appliesTo": "capabilityInvocation",
    "verificationMethod": [
      "did:open:<root>#vm-u<method-id>"
    ]
  }
}
```

### Threshold

An m-of-n controller projects as:

``` json
{
  "openIdentityVerificationPolicy": {
    "id": "did:open:<root>#controller-policy",
    "type": "Threshold",
    "appliesTo": "capabilityInvocation",
    "threshold": 2,
    "verificationMethod": [
      "did:open:<root>#vm-u<method-a>",
      "did:open:<root>#vm-u<method-b>"
    ]
  }
}
```

The extension is informational and deterministic. It exposes the
authoritative OI-002 combination rule to W3C-oriented consumers but
never supersedes canonical OpenIdentity state or OI-002 authorization
evaluation.

## Canonical ordering

Whenever multiple active Verification Methods are projected, they MUST
be ordered by unsigned lexicographic comparison of the canonical 16-byte
OI-002 `verificationMethodId`.

The same canonical order MUST be used for:

-   the projected `verificationMethod` array;
-   `capabilityInvocation`;
-   `openIdentityVerificationPolicy.verificationMethod`; and
-   conformance-vector method metadata.

Construction order, parser order, map order, proof order, or source JSON
order MUST NOT alter the semantic projection.

P03 proves this invariant by starting from V03's deliberately reversed
method/proof construction order and producing the same semantic
projection as P02.

## Controller rotation

A successful OI-002 `ROTATE_CONTROLLER` operation changes active
controller authority while preserving the OI-001 identity.

For the W3C projection:

1.  the root DID MUST remain unchanged;
2.  retired controller Verification Methods MUST be absent from the
    resulting active `verificationMethod` set;
3.  retired methods MUST be absent from `capabilityInvocation`;
4.  retired methods MUST be absent from
    `openIdentityVerificationPolicy.verificationMethod`;
5.  newly active controller methods MUST be projected from the resulting
    OI-002 controller state;
6.  new methods MUST use the same identifier, Multikey, and
    canonical-ordering rules defined by this document; and
7.  the projected threshold MUST equal the resulting authoritative
    OI-002 `ControllerPolicy`.

A historical implementation MAY retain prior states outside the active
DID document for audit/history purposes, but historical methods MUST NOT
thereby regain active verification relationships.

P04 proves identity continuity and authority replacement: the P02 root
DID remains stable, P02 controller methods are removed, V04's new
controller methods become the only active `capabilityInvocation`
methods, and Threshold 2-of-2 semantics are preserved.

## JSON-LD processing

The projected DID document uses:

``` json
[
  "https://www.w3.org/ns/did/v1",
  "https://w3id.org/security/multikey/v1",
  "https://openidentity.foundation/ns/v1"
]
```

Applications MUST understand every context they use.

OpenIdentity contexts use explicit protected term mappings and do not
use `@vocab` to manufacture undefined production terms.

Remote contexts used in security-sensitive processing SHOULD be cached
or bundled and integrity checked. The repository publishes the SHA-256
of `openidentity-v1.jsonld`.

The OpenIdentity v1 context has been independently exercised for context
loading, Threshold expansion, SINGLE expansion, semantic round-trip
behavior, protected-term redefinition rejection, and prevention of
accidental vocabulary leakage.

JSON-LD expansion/compaction semantics are authoritative for the JSON-LD
projection meaning; pretty-printed JSON byte layout is not a protocol
signing or hashing format.

## DID document shape

A projected hybrid controller has the following semantic shape:

``` json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/multikey/v1",
    "https://openidentity.foundation/ns/v1"
  ],
  "id": "did:open:<root>",
  "verificationMethod": [
    {
      "id": "did:open:<root>#vm-u<method-a>",
      "type": "Multikey",
      "controller": "did:open:<root>",
      "publicKeyMultibase": "..."
    },
    {
      "id": "did:open:<root>#vm-u<method-b>",
      "type": "Multikey",
      "controller": "did:open:<root>",
      "publicKeyMultibase": "..."
    }
  ],
  "capabilityInvocation": [
    "did:open:<root>#vm-u<method-a>",
    "did:open:<root>#vm-u<method-b>"
  ],
  "openIdentityVerificationPolicy": {
    "id": "did:open:<root>#controller-policy",
    "type": "Threshold",
    "appliesTo": "capabilityInvocation",
    "threshold": 2,
    "verificationMethod": [
      "did:open:<root>#vm-u<method-a>",
      "did:open:<root>#vm-u<method-b>"
    ]
  }
}
```

This shape is a projection. It is not a replacement serialization for
canonical `IdentityState`.

## DID resolution and dereferencing

Resolution begins with authoritative OpenIdentity state and
deterministically constructs the current projection.

DID URL fragment dereferencing returns the corresponding projected
Verification Method.

Relationship-aware dereferencing MUST enforce the requested verification
relationship. A method authorized only for `capabilityInvocation` MUST
NOT be treated as `authentication`, `assertionMethod`, `keyAgreement`,
or another relationship merely because the Verification Method exists in
the DID document.

Resolution MUST NOT infer active authority from historical or retired
methods.

## Security requirements

Projection implementations MUST NOT:

-   downgrade controller thresholds;
-   omit active controller methods for convenience;
-   retain retired methods as active authority after rotation;
-   alter key-to-method bindings;
-   expose private or secret key material;
-   reuse retired method IDs for different key material;
-   interpret `capabilityInvocation` alone as the OI-002 threshold rule;
-   silently change the external encoding associated with a frozen
    projection version;
-   treat JSON property ordering or whitespace as cryptographically
    meaningful; or
-   accept a projected DID document as an unsigned OpenIdentity state
    update.

Implementations MUST derive the projection from validated authoritative
state.

## External and draft dependencies

OpenIdentity intentionally reuses external standards and registries
where suitable rather than creating equivalent private formats.

The v0.1 projection depends on external specifications/registries for
concepts including:

-   W3C DID / Controlled Identifier document semantics;
-   W3C verification relationships such as `capabilityInvocation`;
-   W3C Multikey;
-   Multibase;
-   Multicodec;
-   Ed25519 public-key Multicodec representation;
-   ML-DSA-65 public-key Multicodec representation; and
-   COSE / COSE Key Thumbprints.

Maturity is not identical across all dependencies. In particular,
Ed25519 Multikey representation is mature, while ML-DSA-related Multikey
integration is newer and may depend on draft or registry material.

A dependency's draft status MUST NOT be disguised as an OpenIdentity
standard. Conversely, OpenIdentity MUST NOT create a competing private
representation merely because an appropriate external representation is
still progressing through standardization.

Any incompatible change required by an external dependency MUST be
introduced through an explicitly versioned OpenIdentity projection
update.

## Conformance vectors

The v0.1 projection suite is:

  -----------------------------------------------------------------------
Vector                  Source                  Purpose
  ----------------------- ----------------------- -----------------------
P01                     OI-002 V01              SINGLE Ed25519
projection

P02                     OI-002 V02              Hybrid Ed25519 +
ML-DSA-65 Threshold
2-of-2 projection

P03                     OI-002 V03              Canonical-ordering
invariance under
reversed
construction/proof
order

P04                     OI-002 V04              Controller rotation,
stable identity,
retired-authority
removal, and
new-authority
projection
  -----------------------------------------------------------------------

The normative vector artifact is:

``` text
test-vectors/w3c-projection-v0.1.json
```

The Java derivation implementation is:

``` text
tools/test-vectors-java/src/main/java/org/openidentity/vectors/W3cProjectionVectors.java
```

The independent Python verifier is:

``` text
tools/test-vectors/verify_w3c_projection.py
```

P01 through P04 have been independently verified.

The independent verifier derives expected projection values from the
normative OI-002 vectors rather than accepting Java-generated
convenience fields as authoritative. It verifies, as applicable:

-   source-vector linkage;
-   identity and method-ID lengths;
-   root DID derivation;
-   Verification Method DID URL derivation;
-   Ed25519 Multicodec and Multikey construction;
-   ML-DSA-65 Multicodec, Multibase, raw-key length, and Multikey
    construction;
-   canonical Verification Method ordering;
-   `capabilityInvocation`;
-   SINGLE and Threshold policy semantics;
-   absence of unintended verification relationships;
-   P03 canonical invariance;
-   P04 stable identity across rotation;
-   removal of old controller authority;
-   derivation of new controller authority; and
-   complete projected DID document structure.

A projection implementation claiming v0.1 conformance SHOULD reproduce
P01-P04 from the corresponding normative OI-002 vectors and pass
equivalent independent semantic checks.

## Future delegation and additional relationships

ZCAP or other standards-based capability mechanisms may later be used
for delegated or attenuated authority. Such mechanisms do not replace
OI-002 `ControllerPolicy` threshold evaluation.

Additional verification relationships, including `authentication`, MUST
be specified explicitly by a future OpenIdentity profile or operation.
Root controller authority MUST NOT automatically acquire those
relationships.

A future relationship-aware dereferencing vector may be added when
OpenIdentity defines such additional relationship semantics. It is not
part of the frozen P01-P04 v0.1 projection suite.

## v0.1 freeze criteria

The W3C Identity Projection v0.1 is ready to freeze when all of the
following are true:

1.  the published `/ns/v1` context and its checksum are fixed;
2.  the JSON-LD context verification suite passes;
3.  an independent JSON-LD implementation confirms the context behavior;
4.  P01-P04 are generated from frozen OI-002 normative vectors;
5.  P01-P04 pass independent verification;
6.  this document matches the tested implementation; and
7.  checksums are recorded for the frozen projection artifacts.

At freeze, later incompatible changes require a new projection version
rather than silent modification of v0.1.
