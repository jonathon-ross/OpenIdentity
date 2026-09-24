# OpenIdentity Basic Credential Profile v1

**Document:** `credential-profiles/basic-v1.md`\
**Protocol:** OpenIdentity\
**Profile:** OpenIdentity Basic Credential Profile\
**Status:** Test Profile v1\
**Profile URI:**
`https://openidentity.foundation/test/credentials/basic/v1`\
**Depends on:** OI-003, OpenIdentity W3C Credential Projection

## 1. Purpose

This document defines the deterministic semantics and W3C projection
rules for the Basic Credential Profile used by the OI-003 v0.1
conformance vectors.

This is a test/conformance profile. It exists to freeze interoperable
behavior for C01, C02, WP01, and WP02. It MUST NOT be interpreted as a
general-purpose production identity credential.

## 2. Profile identity and immutability

The immutable profile identifier is:

``` text
https://openidentity.foundation/test/credentials/basic/v1
```

A credential claiming this profile MUST use that exact URI in the native
OI-003 `credentialProfile` field.

Incompatible changes to the profile require a new profile URI/version.
Published v1 semantics MUST NOT be silently changed.

## 3. Native credential subject

For this profile, native `credentialSubject` is a UTF-8 encoded
email-style test identifier.

The conformance subject is:

``` text
alice@example.test
```

with exact UTF-8 bytes corresponding to that ASCII string.

The `.test` domain is intentional and reserved for testing.

The subject value is profile data. It is not an OpenIdentity root
identity, DID, controller identifier, or assertion Verification Method
ID.

## 4. W3C subject identifier

The Basic v1 profile projects the native subject into a deterministic
URN:

``` text
urn:openidentity:test-subject:<multibase-base64url-subject-bytes>
```

where:

``` text
multibase-base64url-subject-bytes =
    "u" + base64url-no-pad(credentialSubject)
```

This mapping is deterministic and reversible to the exact native subject
bytes.

The projected value SHALL be used as:

``` text
credentialSubject.id
```

The raw email-style test identifier MUST NOT be used directly as a URI
merely because it happens to contain an `@` character.

## 5. Claims schema

Basic v1 permits exactly these three claims:

``` text
name
role
active
```

All three claims are REQUIRED.

Unknown claims MUST cause Basic v1 profile validation to fail.

### 5.1 name

`name` MUST be a non-empty text string.

For C01 and C02:

``` text
name = "Alice Example"
```

The W3C projection property is `name`.

The profile context maps this term to:

``` text
https://schema.org/name
```

### 5.2 role

`role` MUST be a non-empty text string.

The frozen native vectors use:

``` text
C01: role = "member"
C02: role = "hybrid-member"
```

The W3C projection property is `role`.

The profile context maps this term to:

``` text
https://openidentity.foundation/test/credentials/basic/v1#role
```

The profile does not assign broader authorization semantics to these
test values. Applications MUST NOT interpret `"member"` or
`"hybrid-member"` as OpenIdentity controller or assertion authority.

### 5.3 active

`active` MUST be a CBOR boolean.

For C01 and C02:

``` text
active = true
```

The W3C projection property is `active`.

The profile context maps this term to:

``` text
https://openidentity.foundation/test/credentials/basic/v1#active
```

## 6. Native claims map

A valid Basic v1 native claims map therefore has the logical form:

``` text
{
  "name": text,
  "role": text,
  "active": bool
}
```

Native canonical ordering remains governed by OI-003 deterministic CBOR,
not the presentation order shown above.

## 7. W3C context

The Basic v1 W3C projection SHALL add this profile context after the W3C
VC base context and OpenIdentity `/ns/v2` context:

``` text
https://openidentity.foundation/test/credentials/basic/v1/context
```

The complete context order is:

``` json
[
  "https://www.w3.org/ns/credentials/v2",
  "https://openidentity.foundation/ns/v2",
  "https://openidentity.foundation/test/credentials/basic/v1/context"
]
```

The profile context is immutable once published.

## 8. W3C credential type

Basic v1 adds:

``` text
OpenIdentityBasicCredential
```

to the generic types.

The deterministic type array is:

``` json
[
  "VerifiableCredential",
  "OpenIdentityCredential",
  "OpenIdentityBasicCredential"
]
```

The profile context maps `OpenIdentityBasicCredential` to:

``` text
https://openidentity.foundation/test/credentials/basic/v1#OpenIdentityBasicCredential
```

## 9. W3C credentialSubject

The deterministic Basic v1 W3C subject shape is:

``` json
{
  "id": "urn:openidentity:test-subject:u...",
  "name": "Alice Example",
  "role": "member",
  "active": true
}
```

For C02, only the role value changes:

``` text
role = "hybrid-member"
```

Property order in ordinary JSON serialization is not cryptographically
authoritative. The semantic mapping is authoritative for projection
consistency.

## 10. Projection algorithm

Given a cryptographically valid native OI-003 credential using this
profile, a projector SHALL:

1.  require the exact Basic v1 profile URI;
2.  decode `credentialSubject` as UTF-8 and reject invalid UTF-8;
3.  require the subject to be non-empty;
4.  require exactly the claims `name`, `role`, and `active`;
5.  require `name` and `role` to be non-empty text strings;
6.  require `active` to be boolean;
7.  derive `credentialSubject.id` from the exact native subject bytes
    using the URN algorithm in Section 4;
8.  copy `name`, `role`, and `active` losslessly to their
    profile-defined W3C properties;
9.  append the Basic v1 profile context after the W3C and OpenIdentity
    contexts; and
10. append `OpenIdentityBasicCredential` after the two generic
    credential types.

The projector MUST NOT normalize, lowercase, trim, or otherwise alter
the native subject, `name`, or `role` values.

## 11. Projection validation

A verifier validating a Basic v1 W3C projection SHALL derive the
expected subject identifier and claim values from the signed native
credential.

It MUST require exact semantic equality with the projected
`credentialSubject`.

A modified projected `name`, `role`, `active`, or subject identifier
MUST produce projection-consistency failure even when the embedded
native credential remains cryptographically valid.

## 12. Unknown and extra claims

Because this profile intentionally freezes a minimal conformance schema,
unknown or additional native claims are not valid Basic v1 claims.

A future profile that needs additional claims MUST use a different
immutable profile version/URI.

This restriction is profile-specific. It does not restrict the generic
OI-003 claims model.

## 13. Security considerations

This profile is designed for conformance testing.

The email-style native subject is test data and MUST NOT be interpreted
as proof that the holder controls an email address.

The `role` claim is test data and MUST NOT grant OpenIdentity
controller, assertion, recovery, or application authorization merely
because the credential is valid.

The `active` claim is an ordinary signed claim. It is not the OI-003
credential-status or revocation mechanism.

## 14. Privacy considerations

The profile deliberately uses stable test data to make vectors
reproducible.

Production profiles SHOULD NOT copy this choice blindly. Stable subject
identifiers can enable correlation across relying parties.

## 15. Conformance vectors

The initial W3C projection vectors are:

``` text
WP01 <- C01
WP02 <- C02
```

For WP01, expected claims are:

``` text
name   = "Alice Example"
role   = "member"
active = true
```

For WP02:

``` text
name   = "Alice Example"
role   = "hybrid-member"
active = true
```

Both use native subject bytes for:

``` text
alice@example.test
```

The vectors MUST independently derive the subject URN rather than trust
a generator-supplied convenience field.

## 16. Public artifacts

Before WP01/WP02 become normative, the repository SHALL publish the
immutable Basic v1 JSON-LD context corresponding to this profile and its
SHA-256 integrity file.

Recommended repository paths:

``` text
public/test/credentials/basic/v1/context
public/test/credentials/basic/v1/context.sha256
```

The HTTP deployment MAY map these repository artifacts to the profile
context URI defined in Section 7.

## 17. Completion criteria

Basic Credential Profile v1 is complete for the OI-003 conformance suite
when:

-   this specification is frozen;
-   the profile context and checksum are published;
-   C01 and C02 satisfy the profile;
-   WP01 and WP02 deterministically project the profile;
-   an independent verifier validates both projections; and
-   invalid projection tests demonstrate subject/claim mismatch
    rejection.
