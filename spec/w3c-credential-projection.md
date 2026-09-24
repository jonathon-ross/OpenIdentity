# OpenIdentity W3C Credential Projection

**Document:** `w3c-credential-projection.md`\
**Protocol:** OpenIdentity\
**Status:** Draft v0.1\
**Depends on:** OI-001, OI-002, OI-003, OpenIdentity W3C Identity
Projection\
**Projection Target:** W3C Verifiable Credentials Data Model 2.x

## 1. Purpose and authority

This document defines the deterministic projection of a canonical OI-003
`SecuredCredential` into a W3C Verifiable Credentials Data Model
representation.

Canonical OI-003 CBOR remains authoritative.

``` text
SecuredCredential
        |
        | validate native OI-003
        v
canonical OpenIdentity credential
        |
        | deterministic projection
        v
W3C VC Data Model representation
```

The projection is an interoperability representation. It MUST NOT become
an independent OpenIdentity credential store, assertion-authority store,
or cryptographic source of truth.

A projected document MUST NOT be edited and converted back into
authoritative OI-003 CredentialBytes as though the edited W3C document
had been signed by the issuer.

## 2. Standards adopted

The projection uses applicable semantics from W3C Verifiable Credentials
Data Model 2.x, W3C Controlled Identifiers, W3C DID/DID Resolution
semantics used by `did:open`, JSON-LD 1.1, Multibase, and the
OpenIdentity W3C Identity Projection.

OpenIdentity MUST use standard W3C terms when those terms faithfully
represent the native semantic.

OpenIdentity-specific extension terms MUST be used when dropping the
native semantic would make verification ambiguous or weaker.

## 3. Projection boundary

The native OI-003 signature secures the deterministic CBOR encoding of:

``` text
[
  "OpenIdentity Credential",
  1,
  CredentialBytes
]
```

It does not sign the JSON-LD graph or JSON serialization of the W3C
projection.

Therefore an OI-003 native `CredentialProof` MUST NOT be represented as
a W3C `DataIntegrityProof` unless a separate OpenIdentity Data Integrity
cryptosuite specification defines the required transformation, hashing,
proof creation, and proof verification algorithms.

This specification does not define such a cryptosuite.

The v0.1 W3C projection instead carries the canonical native
`SecuredCredential` as explicit OpenIdentity security metadata.

## 4. Projection input

Projection input MUST be a structurally valid OI-003 v1
`SecuredCredential`.

Before projecting, an implementation MUST be able to recover canonical
CredentialBytes, credential version, credential ID, issuer identity,
issuance StateHash, validity interval, credential profile, credential
subject, claims, and the complete native proof set.

Projection alone does not establish cryptographic validity. When a
caller requests a verified projection, native OI-003 verification MUST
succeed before the projection is treated as verified.

## 5. W3C base context

The projected document SHALL use the applicable W3C VC 2.x base context
first:

``` json
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://openidentity.foundation/ns/v2"
  ]
}
```

The OpenIdentity credential projection uses the cumulative version 2
context.

The v1 context remains immutable and MUST NOT be modified to add OI-003
credential terms. The v2 context retains the v1 mappings and adds the
credential-projection terms required by this specification.

The repository artifacts are:

``` text
contexts/openidentity-v2.jsonld
contexts/openidentity-v2.sha256
```

The SHA-256 of the frozen v2 context is:

``` text
b3ad060c4a1841a3c4a7f7c9f96c11e62e8da54542e68eb1c383897eb19fda88
```

Once published, `/ns/v2` is immutable. Future incompatible
context-processing changes require a new versioned context.

Standard W3C terms MUST NOT be redefined incompatibly.


## 6. Credential identifier projection

The 32-byte native `credentialId` projects to:

``` text
urn:openidentity:credential:<multibase-base64url-credential-id>
```

where:

``` text
multibase-base64url-credential-id =
    "u" + base64url-no-pad(credentialId)
```

The transformation MUST be deterministic and reversible to the exact 32
bytes.

The credential ID URI is not a StateHash, key fingerprint, or issuer
identifier.

## 7. Issuer projection

The native 32-byte `issuerIdentity` projects to the canonical OI-001
root DID.

The W3C `issuer` value SHALL be that root DID unless a future Credential
Profile normatively requires the object form for additional issuer
metadata.

Controller or assertion-key rotation MUST NOT change the projected
issuer DID.

## 8. Validity-period projection

Native `validFrom` and optional `validUntil` are unsigned Unix-epoch
seconds and SHALL project to UTC `dateTimeStamp` strings while
preserving the exact instant.

Example:

``` text
1787590800 -> 2026-08-24T17:00:00Z
```

`validFrom` SHALL project to W3C `validFrom`. When present, `validUntil`
SHALL project to W3C `validUntil`.

The projection MUST NOT invent `validUntil` when the native credential
omits it.

## 9. Credential Profile projection

The native `credentialProfile` URI MUST be preserved using:

``` text
openIdentityCredentialProfile
```

The Credential Profile additionally defines profile-specific W3C
credential types, additional contexts, credential-subject mapping,
claim-term mappings, and projection constraints.

The generic projection MUST NOT guess semantic W3C claim terms for an
unknown Credential Profile.

If the profile is unknown, generic OpenIdentity security metadata MAY
still be projected, but profile-specific subject/claim projection is
INDETERMINATE.

## 10. Credential type projection

Every projected credential SHALL include:

``` json
"type": [
  "VerifiableCredential",
  "OpenIdentityCredential"
]
```

A supported Credential Profile MAY append profile-defined types.

`OpenIdentityCredential` MUST have a stable OpenIdentity vocabulary
definition before normative JSON-LD publication.

Type ordering SHALL be deterministic: `VerifiableCredential`, then
`OpenIdentityCredential`, then profile-defined types in profile-defined
order.

## 11. Credential subject projection

Native `credentialSubject` is opaque bytes interpreted by the Credential
Profile.

The generic projection MUST NOT assume those bytes are a DID, URI, human
identifier, or UTF-8 string.

A supported Credential Profile SHALL define how the bytes map into W3C
`credentialSubject`.

If the profile defines a subject identifier satisfying W3C identifier
requirements, it SHOULD project to `credentialSubject.id`. Otherwise the
projection MUST NOT invent one.

## 12. Claims projection

The Credential Profile SHALL define the W3C term and value mapping for
every permitted native claim.

The generic projection MUST NOT manufacture semantic URLs for unknown
claim keys.

A supported profile MUST define sufficient JSON-LD vocabulary mappings
for its projected claims.

Native values that cannot be represented losslessly under the profile
mapping MUST cause projection failure rather than silent coercion or
loss.

## 13. Historical issuance-state binding

Native `issuanceStateHash` MUST be preserved using:

``` text
openIdentityIssuanceStateHash
```

For v0.1 the binary Multihash SHALL be represented with Multibase
base58btc:

``` text
"z" + base58btc(issuanceStateHash)
```

The value is the exact Multihash bytes from CredentialBytes. It MUST NOT
be recomputed from the W3C projection.

This is a cryptographic authorization-state identifier, not merely an
integrity digest for an auxiliary resource.

## 14. Native secured credential preservation

The complete canonical native `SecuredCredential` bytes MUST be
preserved using:

``` text
openIdentitySecuredCredential
```

The bytes SHALL use Multibase base64url without padding:

``` text
"u" + base64url-no-pad(SecuredCredentialBytes)
```

A verifier MUST be able to decode this value to the exact native bytes.

Native verification MUST operate on those canonical bytes, not on a
credential reconstructed from arbitrary projected fields.

## 15. Native proof metadata

OI-003 native credential proofs MUST NOT be emitted as W3C
`DataIntegrityProof` values by this specification.

A future projection MAY expose informational native-proof metadata, but
it MUST NOT be necessary for verification because the complete native
proof set is already carried in `openIdentitySecuredCredential`.

## 16. Historical assertionMethod relationship

The OpenIdentity W3C Identity Projection maps `AssertionPolicy` methods
to W3C `assertionMethod`.

For credential verification, the relevant relationship is projected from
the exact historical IdentityState identified by `issuanceStateHash`.

``` text
projected credential
       |
       +-- issuer DID
       +-- openIdentityIssuanceStateHash
                    |
                    v
       historical did:open resolution
                    |
                    v
       historical IdentityState
                    |
                    v
       historical AssertionPolicy
                    |
                    v
       historical assertionMethod
```

A verifier MUST NOT substitute the current DID document's
`assertionMethod` for the historical assertion authority required by
OI-003.

## 17. Verification Method identifiers

Native 16-byte `verificationMethodId` values project using the
OpenIdentity W3C Identity Projection:

``` text
did:open:<root>#vm-u<base64url-no-pad(verificationMethodId)>
```

The identifier is deterministic and reversible.

It MUST NOT replace the native method ID inside CredentialProof.

## 18. Verification algorithm for a projected credential

A verifier evaluating native OpenIdentity security SHALL:

1.  require the OpenIdentity projection context and required extension
    terms;
2.  decode `openIdentitySecuredCredential` to exact native bytes;
3.  parse the native OI-003 `SecuredCredential`;
4.  perform complete native OI-003 verification;
5.  derive the native issuer DID and require equality with projected
    `issuer`;
6.  derive the credential identifier URI and require equality with
    projected `id`;
7.  derive the Multibase issuance StateHash and require equality with
    `openIdentityIssuanceStateHash`;
8.  derive validity values and require equality with projected
    `validFrom` and optional `validUntil`;
9.  require `openIdentityCredentialProfile` to equal the signed native
    profile URI; and
10. when the profile is supported, validate profile-specific type,
    context, subject, and claim projection.

Any mismatch between signed native data and projected W3C data MUST
cause projection verification to fail.

A verifier MUST NOT repair mismatched projected values and continue as
though the W3C document were authentic.

## 19. Projection verification result

Processing SHOULD distinguish:

``` text
nativeCryptographicVerification:
    VALID / INVALID

projectionConsistency:
    VALID / INVALID

credentialProfileValidation:
    VALID / INVALID / INDETERMINATE

applicationAcceptance:
    ACCEPT / REJECT
```

A valid native credential with modified projected semantic fields has
valid native cryptography but INVALID projection consistency.

Applications consuming the projection SHOULD require projection
consistency before trusting projected semantic fields.

## 20. JSON-LD processing

Applications MUST understand every context they use.

OpenIdentity contexts MUST use stable protected term definitions for
security-relevant extension terms.

Remote contexts used in security-sensitive processing SHOULD be bundled
or cached and integrity checked.

Projection implementations MUST NOT use an unconstrained `@vocab` rule
to manufacture meanings for unknown native claim keys.

Unknown terms MUST NOT be silently dropped during security-sensitive
projection validation.

## 21. OpenIdentity extension vocabulary

The projection requires:

``` text
OpenIdentityCredential
openIdentityCredentialProfile
openIdentityIssuanceStateHash
openIdentitySecuredCredential
```

They SHALL use:

``` text
https://openidentity.foundation/ns#
```

Before normative publication, each term MUST have a stable vocabulary
definition and immutable versioned context mapping.

Semantic intent:

-   `OpenIdentityCredential`: W3C-facing type for a deterministic
    projection of a native OI-003 credential.
-   `openIdentityCredentialProfile`: URI identifying the immutable
    OI-003 Credential Profile.
-   `openIdentityIssuanceStateHash`: Multibase representation of the
    exact native issuance StateHash.
-   `openIdentitySecuredCredential`: Multibase representation of the
    exact canonical native SecuredCredential bytes.

## 22. Example projection shape

This example is illustrative; profile-specific terms remain subject to
the applicable Credential Profile.

``` json
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://openidentity.foundation/ns/v2",
    "https://openidentity.foundation/test/credentials/basic/v1/context"
  ],
  "id": "urn:openidentity:credential:u...",
  "type": [
    "VerifiableCredential",
    "OpenIdentityCredential",
    "OpenIdentityBasicCredential"
  ],
  "issuer": "did:open:z...",
  "validFrom": "2026-08-24T17:00:00Z",
  "validUntil": "2027-08-24T17:00:00Z",
  "credentialSubject": {
    "id": "https://example.test/subjects/alice",
    "name": "Alice Example",
    "role": "member",
    "active": true
  },
  "openIdentityCredentialProfile":
    "https://openidentity.foundation/test/credentials/basic/v1",
  "openIdentityIssuanceStateHash": "z...",
  "openIdentitySecuredCredential": "u..."
}
```

This example intentionally contains no W3C `proof` property. Native
OI-003 proof material is inside `openIdentitySecuredCredential`.

## 23. Data Integrity boundary

W3C Data Integrity proof objects have their own cryptosuite,
transformation, hashing, proof-generation, and verification semantics.

This specification MUST NOT label native OI-003 CBOR signatures as
`DataIntegrityProof`.

A future OpenIdentity Data Integrity cryptosuite MAY secure an
OpenIdentity W3C credential directly, but it MUST define its own
normative algorithms and relationship to native OI-003.

Until then:

``` text
native OI-003 proof != W3C DataIntegrityProof
```

## 24. Determinism

Given the same canonical OI-003 credential, Credential Profile version,
and projection version, conforming implementations MUST produce the same
semantic W3C projection.

JSON object member ordering and insignificant whitespace are not
authoritative.

Determinism applies to identifier derivation, context/type ordering,
issuer derivation, time conversion, StateHash encoding, native
secured-credential encoding, profile-defined subject/claim mappings, and
projected Verification Method identifiers.

## 25. One-way authority

The authority direction is:

``` text
canonical OI-003 -> W3C projection
```

not:

``` text
W3C projection -X-> canonical OI-003 credential
```

A processor MAY decode the embedded exact native secured credential and
verify it.

It MUST NOT synthesize new authoritative CredentialBytes from edited W3C
fields and treat them as issuer-signed.

## 26. Security requirements

A conforming implementation MUST NOT:

-   substitute current assertion authority for historical assertion
    authority;
-   drop `issuanceStateHash`;
-   drop or alter the native secured credential;
-   represent native proofs as a standardized W3C proof type they do not
    satisfy;
-   silently weaken a native SINGLE/THRESHOLD policy;
-   reinterpret a controller-only method as an assertion method;
-   change the issuer root identity;
-   alter claim meaning during profile projection;
-   invent semantic mappings for unknown claim keys;
-   treat projection metadata as an unsigned state update; or
-   accept a mismatch between native signed data and projected semantic
    fields.

## 27. Privacy

Projection does not imply that every relying party should receive the
root DID or full native credential.

The issuer DID, credential ID, issuance StateHash, native secured
credential, subject identifier, and claims can all be correlatable.

Credential Profiles SHOULD minimize projected information and SHOULD use
pairwise or pseudonymous subject identifiers where appropriate.

Applications SHOULD avoid logging native secured credentials or root
identifiers unnecessarily.

## 28. Unknown Credential Profiles

If a verifier understands the generic projection but not the
credential's profile:

-   native OI-003 cryptographic verification MAY still succeed;
-   generic consistency for issuer, ID, time, StateHash, profile URI,
    and native bytes MAY still be checked;
-   profile-specific subject and claim validation is INDETERMINATE; and
-   the verifier MUST NOT invent a profile interpretation.

The reason SHOULD be `UNSUPPORTED_CREDENTIAL_PROFILE`.

## 29. Failure semantics

Projection implementations SHOULD expose stable failures including:

-   `INVALID_NATIVE_SECURED_CREDENTIAL`
-   `INVALID_PROJECTED_CREDENTIAL_ID`
-   `INVALID_PROJECTED_ISSUER`
-   `INVALID_PROJECTED_VALIDITY`
-   `INVALID_PROJECTED_CREDENTIAL_PROFILE`
-   `INVALID_PROJECTED_ISSUANCE_STATE_HASH`
-   `INVALID_PROJECTED_SUBJECT`
-   `INVALID_PROJECTED_CLAIMS`
-   `UNSUPPORTED_CREDENTIAL_PROFILE`
-   `UNSUPPORTED_PROJECTION_CONTEXT`
-   `MISLEADING_W3C_PROOF`
-   `HISTORICAL_ASSERTION_AUTHORITY_REQUIRED`

These are projection-layer failures and do not replace native OI-003
cryptographic errors.

## 30. Credential status

This projection does not define W3C `credentialStatus` mapping because
OI-003 v0.1 has not yet defined a native credential-status mechanism.

A future status specification MAY define deterministic projection into
W3C `credentialStatus`.

Implementations MUST NOT invent status semantics from assertion-key
rotation or removal.

## 31. Conformance requirements

A conforming v0.1 implementation MUST demonstrate:

1.  deterministic credential-ID URI construction;
2.  deterministic issuer DID projection;
3.  exact Unix-time to W3C time projection;
4.  exact Multibase issuance-StateHash projection;
5.  exact round-trip preservation of native SecuredCredential bytes;
6.  deterministic context and type ordering;
7.  profile-defined subject and claim projection;
8.  no generic interpretation of unknown profiles;
9.  historical rather than current assertion-authority verification;
10. exact projection-consistency checking against signed native data;
11. no representation of native proofs as Data Integrity proofs; and
12. one-way native-authority-to-W3C-projection behavior.

## 32. Projection test vectors

Projection vectors SHOULD derive from frozen OI-003 credential vectors.

Initial positive vectors SHALL include:

``` text
WP01 <- C01 SINGLE Ed25519
WP02 <- C02 THRESHOLD Ed25519 + ML-DSA-65
```

WP01 SHALL verify deterministic projection of the SINGLE credential and
historical A01 StateHash.

WP02 SHALL verify deterministic projection of the hybrid threshold
credential and historical A04 StateHash.

Projection vectors SHOULD include exact expected:

-   credential ID URI;
-   issuer DID;
-   contexts;
-   types;
-   validity timestamps;
-   credential profile URI;
-   issuance StateHash Multibase value;
-   native SecuredCredential Multibase value;
-   profile-defined credentialSubject;
-   projected claims; and
-   complete semantic W3C projection.

An independent verifier MUST derive expected projection values from the
frozen native vectors rather than trusting generator convenience fields.

## 33. Invalid projection vectors

The normative invalid/security suite is WPI01 through WPI10:

-   WPI01 --- altered projected issuer:
    `INVALID_PROJECTED_ISSUER`.
-   WPI02 --- altered projected credential ID:
    `INVALID_PROJECTED_CREDENTIAL_ID`.
-   WPI03 --- altered projected validity:
    `INVALID_PROJECTED_VALIDITY`.
-   WPI04 --- altered projected issuance StateHash:
    `INVALID_PROJECTED_ISSUANCE_STATE_HASH`.
-   WPI05 --- corrupted embedded native `SecuredCredential`:
    `INVALID_NATIVE_SECURED_CREDENTIAL`.
-   WPI06 --- projected subject inconsistent with Basic v1 derivation:
    `INVALID_PROJECTED_SUBJECT`.
-   WPI07 --- projected claims inconsistent with signed native claims:
    `INVALID_PROJECTED_CLAIMS`.
-   WPI08 --- unsupported projection context:
    `UNSUPPORTED_PROJECTION_CONTEXT`.
-   WPI09 --- misleading W3C `DataIntegrityProof` representation of
    native OI-003 proof material: `MISLEADING_W3C_PROOF`.
-   WPI10 --- substitution of current assertion authority for the exact
    historical assertion authority bound by `issuanceStateHash`:
    `HISTORICAL_ASSERTION_AUTHORITY_REQUIRED`.

The normative projection bundle is:

``` text
test-vectors/w3c-credential-projection-v0.1.json
test-vectors/w3c-credential-projection-v0.1.json.sha256
```

A conforming implementation MUST reproduce the positive projection
semantics and MUST reject the invalid vectors for the represented
projection-security conditions.

## 34. Relationship to OpenIdentity W3C Identity Projection

This specification reuses the root DID, Verification Method DID URL,
Multikey, historical-state resolution, and `assertionMethod` projection
rules from `w3c-identity-projection.md`.

Credential projection MUST NOT define a conflicting Verification Method
identifier algorithm.

Historical credential verification MUST use the historical identity
projection corresponding to the native `issuanceStateHash`.

## 35. Deferred work

This v0.1 projection intentionally defers:

-   an OpenIdentity W3C Data Integrity cryptosuite;
-   W3C `credentialStatus` mapping;
-   presentation and holder-binding projection;
-   selective-disclosure projection;
-   production Credential Profiles and their W3C vocabularies;
-   registry-specific historical resolution transport; and
-   additional W3C securing mechanisms.

Deferred work MUST NOT be inferred by weakening the native OI-003
security model.

## 36. Completion criteria

This projection is complete for v0.1 when:

-   required OpenIdentity vocabulary terms are defined;
-   the immutable `/ns/v2` JSON-LD context containing those terms is
    published and its SHA-256 integrity value is frozen;
-   a test Credential Profile defines deterministic subject/claim
    projection;
-   WP01 and WP02 are generated;
-   WP01 and WP02 are independently verified;
-   WPI01 through WPI10 are independently verified; and
-   `w3c-credential-projection-v0.1.json` and its SHA-256 checksum are
    published.

## 37. References

This specification depends on OI-001, OI-002, OI-003, the OpenIdentity
W3C Identity Projection, W3C Verifiable Credentials Data Model 2.x, W3C
Controlled Identifiers, JSON-LD 1.1, and applicable Multibase/Multicodec
specifications.

Canonical OI-003 remains authoritative whenever a projection
representation cannot faithfully express a native semantic.
