# OpenIdentity Credential Specification

**Document:** `credential.md`\
**Story:** OI-003 --- Define OpenIdentity Credentials\
**Status:** Complete v0.1\
**Protocol:** OpenIdentity\
**Credential Wire Format:** OpenIdentity Credential v1\
**Identity State:** OpenIdentity IdentityState v2\
**Normative Keywords:** MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT,
SHOULD, SHOULD NOT, MAY

## 1. Purpose

This document defines the canonical OpenIdentity credential model,
credential signing and proof semantics, historical assertion-authority
binding, deterministic encoding, credential verification, and Credential
Profile processing.

An OpenIdentity credential is a signed assertion made on behalf of an
OpenIdentity issuer identity.

The issuer's permanent root identifier is defined by OI-001.
Cryptographic controller primitives and algorithms are defined by
OI-002. OI-003 adds a distinct assertion authority and binds each
credential to the exact historical OpenIdentity state that authorized
its assertion proof or proofs.

The canonical OI-003 credential is deterministic CBOR. A W3C Verifiable
Credential representation MAY be defined as a deterministic projection,
but that projection is not the cryptographic source of truth for native
OI-003 signatures.

## 2. Core separation

OpenIdentity MUST keep the following concepts distinct:

``` text
Root Identity
    |
    +-- ControllerPolicy
    |      +-- authorizes IdentityState changes
    |
    +-- AssertionPolicy
    |      +-- authorizes cryptographic assertions
    |
    +-- Credential
           +-- binds to one historical StateHash
           +-- is signed by methods authorized by
               that historical AssertionPolicy
```

Membership in `ControllerPolicy` MUST NOT imply assertion authority.
Membership in `AssertionPolicy` MUST NOT imply controller authority.

An absent `AssertionPolicy` means the state has no assertion authority.
A verifier MUST NOT fall back to `ControllerPolicy`.

## 3. Relationship to OI-001 and OI-002

OI-001 defines a permanent 32-byte root identity and its canonical
`did:open:` representation. OI-003 MUST NOT change that identifier when
assertion keys, algorithms, policies, or credentials change.

OI-002 defines VerificationMethods, `COSE_Key`, deterministic CBOR
requirements, Ed25519, ML-DSA-65, SINGLE/THRESHOLD policy semantics, and
StateHash construction. OI-003 reuses those cryptographic primitives
without transferring authorization purpose between controller and
assertion policies.

The canonical credential SHALL contain the issuer as the raw 32-byte
OpenIdentity identifier. The textual DID form MUST NOT be embedded in
canonical CredentialBytes.

## 4. Assertion authority

### 4.1 IdentityState v2

OI-003 uses explicit state-version evolution. IdentityState v1 contains
no `AssertionPolicy`. IdentityState v2 MAY contain an `AssertionPolicy`.

A transition that installs an `AssertionPolicy` into a v1 state produces
a v2 state. A v2 state MUST NOT be silently interpreted as v1, and a
v2-to-v1 state downgrade is forbidden.

Unsupported future IdentityState versions MUST be rejected rather than
interpreted while ignoring unknown fields.

### 4.2 AssertionPolicy

`AssertionPolicy` reuses the SINGLE and THRESHOLD policy structures
defined by OI-002.

For SINGLE, exactly one VerificationMethod is authoritative.

For THRESHOLD, `1 <= threshold <= numberOfVerificationMethods`.

Verification Method IDs MUST be unique. VerificationMethods MUST be
canonically ordered by Verification Method ID using unsigned bytewise
lexicographic ordering.

### 4.3 SET_ASSERTION_POLICY

OI-003 uses operation type `5`, `SET_ASSERTION_POLICY`.

The operation MUST identify the current root identity, use
`sequence = currentSequence + 1`, use the current StateHash as
`previousStateHash`, and be authorized by the current
`ControllerPolicy`.

`AssertionPolicy` MUST NOT authorize its own installation, replacement,
or removal.

The payload contains either a complete replacement `AssertionPolicy` or
`nil` to remove assertion authority.

A non-nil proposed policy MUST include valid proof of possession for
every proposed VerificationMethod using the OI-002 controller-proof
signing domain.

Replacement is atomic. New assertion methods do not accumulate with
retired methods unless explicitly included in the replacement policy.

### 4.4 Removal and historical authority

Setting the policy to `nil` removes current assertion authority. No
assertion-key proof of possession is required because no new assertion
key is installed. Removal MUST NOT cause controller keys to become
assertion keys.

Replacing or removing `AssertionPolicy` changes current authority but
does not rewrite historical IdentityStates. A credential issued against
an earlier state is evaluated against the `AssertionPolicy` in that
exact historical state.

## 5. Canonical credential data model

The canonical OpenIdentity credential is:

``` text
{
  1: credentialVersion,
  2: credentialId,
  3: issuerIdentity,
  4: issuanceStateHash,
  5: validFrom,
  ? 6: validUntil,
  7: credentialProfile,
  8: credentialSubject,
  9: claims
}
```

The complete deterministic CBOR encoding of this map is
`CredentialBytes`.

### 5.1 credentialVersion

OpenIdentity Credential Wire Format v1 SHALL use
`credentialVersion = 1`.

### 5.2 credentialId

`credentialId` SHALL be exactly 32 bytes and unique within the issuer's
credential namespace. Producers MUST generate credential identifiers
with sufficient cryptographic randomness to make collision impractical.

### 5.3 issuerIdentity

`issuerIdentity` SHALL contain exactly the raw 32 identifier bytes
defined by OI-001. The textual `did:open:` representation MUST NOT
appear in canonical CredentialBytes.

### 5.4 issuanceStateHash

`issuanceStateHash` identifies the exact historical authoritative
IdentityState whose `AssertionPolicy` authorized the credential.

OpenIdentity v0.1 producers SHALL use:

``` text
0x12 || 0x20 || SHA-256(StateBytes)
```

The v0.1 SHA2-256 Multihash is exactly 34 bytes. The structural field
permits 1 through 128 bytes for future supported Multihashes.

A verifier MUST validate the Multihash, recompute the hash of the
resolved historical IdentityState, and require equality with
`issuanceStateHash`. The verifier MUST NOT substitute the current
IdentityState.

### 5.5 validFrom and validUntil

`validFrom` and `validUntil` are unsigned integer seconds from the Unix
epoch. `validFrom` is REQUIRED and `validUntil` is OPTIONAL.

When present, `validUntil` MUST be greater than `validFrom`.

Validity-period evaluation is distinct from cryptographic verification,
historical assertion authorization, Credential Profile validation, and
credential status.

### 5.6 credentialProfile

`credentialProfile` SHALL be a non-empty absolute URI identifying one
immutable version of an OpenIdentity Credential Profile.

A Credential Profile defines application semantics including permitted
and required claims, claim constraints, subject syntax, semantic
meaning, privacy/security requirements, and interoperability projection
rules.

An incompatible profile change MUST use a new profile URI/version.

The URI is an identifier, not an instruction to perform network access.
Cryptographic verification MUST NOT require dereferencing it.

If cryptographic verification succeeds but the verifier does not support
the profile, Credential Profile validation SHALL be:

``` text
INDETERMINATE
reason = UNSUPPORTED_CREDENTIAL_PROFILE
```

An unknown profile MUST NOT by itself make an otherwise valid credential
cryptographically INVALID.

### 5.7 credentialSubject

`credentialSubject` SHALL be a non-empty byte string interpreted by the
Credential Profile.

It is intentionally not restricted to an OpenIdentity identity. A
profile MAY describe a person, organization, device, resource, document,
pairwise identifier, or another subject type.

### 5.8 claims

A credential MUST contain at least one claim.

Claim-map keys MUST be non-empty UTF-8 text strings.

Permitted claim values are signed integers, text strings, byte strings,
booleans, `nil`, arrays of permitted values, and text-keyed maps of
permitted values.

The generic OI-003 schema MUST NOT use unrestricted CBOR `any`.

The v1 claim model excludes floating-point values, NaN, Infinity,
`undefined`, arbitrary CBOR tags, unassigned simple values,
indefinite-length encodings, and duplicate map keys.

The Credential Profile defines the exact permitted and required claims,
nesting, types, and semantics.

## 6. Deterministic CBOR

Every cryptographically authoritative OI-003 structure MUST use RFC 8949
Core Deterministic Encoding Requirements.

OI-003 v1 additionally requires definite lengths, preferred integer
serialization, deterministic map-key ordering, rejection of duplicate
map keys, rejection of unknown OpenIdentity-defined core labels, and the
restricted claim-value model in Section 5.8.

For text-keyed claim maps, ordering SHALL be determined from the
deterministic CBOR encoding of each key according to RFC 8949
deterministic map ordering, not ordinary implementation-language string
ordering.

Two conforming implementations given the same logical credential MUST
produce identical CredentialBytes.

## 7. Credential signing

### 7.1 CredentialSigningInput

Every credential proof signs the deterministic CBOR encoding of:

``` text
[
  "OpenIdentity Credential",
  1,
  CredentialBytes
]
```

Every algorithm contributing to the same credential proof set MUST sign
this exact same CredentialSigningInput.

### 7.2 Domain separation

A signature over another OpenIdentity signing structure MUST NOT be
accepted as a credential signature.

In particular, signatures from `"OpenIdentity Operation"` or
`"OpenIdentity Controller Proof"` MUST NOT be accepted as credential
proofs.

Changing the signing-domain string, signing-structure version, or
CredentialBytes changes the signing input.

### 7.3 CredentialProof

A credential proof is:

``` text
{
  1: verificationMethodId,
  2: signature
}
```

`verificationMethodId` SHALL be exactly 16 bytes.

The proof MUST NOT carry an independent algorithm identifier. The
authoritative algorithm and public key come from the VerificationMethod
in the historical `AssertionPolicy`.

For v0.1, Ed25519 signatures MUST be 64 bytes and ML-DSA-65 signatures
MUST be 3309 bytes.

### 7.4 SecuredCredential

A secured credential is:

``` text
{
  1: OpenIdentityCredential,
  2: [ CredentialProof, ... ]
}
```

At least one proof is structurally required.

## 8. Proof collection requirements

OI-003 v1 uses strict proof-set validation. Threshold satisfaction MUST
NOT cause a verifier to ignore additional supplied proofs.

Credential proofs MUST be sorted by Verification Method ID using
unsigned bytewise lexicographic ordering.

Every supplied proof MUST use a distinct Verification Method ID.
Duplicates MUST fail with `DUPLICATE_CREDENTIAL_PROOF`.

Every supplied proof MUST identify a VerificationMethod explicitly
present in the `AssertionPolicy` of the exact historical state
identified by `issuanceStateHash`.

Any proof from another method, including a controller-only method, MUST
fail with `UNAUTHORIZED_CREDENTIAL_PROOF`. Unauthorized proofs MUST NOT
be silently ignored.

Every supplied proof MUST cryptographically verify using the algorithm
and public key in its historical VerificationMethod. Any supplied
authorized proof whose signature fails verification MUST fail with
`INVALID_CREDENTIAL_SIGNATURE`.

## 9. SINGLE policy verification

For a historical SINGLE `AssertionPolicy`:

1.  exactly one credential proof MUST be supplied;
2.  its Verification Method ID MUST equal the SINGLE policy method;
3.  the method and key MUST be valid and supported; and
4.  its signature MUST verify over the exact CredentialSigningInput.

A mathematically valid signature from another method is still
unauthorized.

## 10. THRESHOLD policy verification

For a historical THRESHOLD `AssertionPolicy`:

1.  every supplied proof MUST have a distinct Verification Method ID;
2.  every supplied method MUST be authorized by the historical policy;
3.  every supplied signature MUST verify;
4.  supplied proof count MUST NOT exceed policy method count; and
5.  distinct authorized valid proof count MUST be at least `threshold`.

Threshold evaluation counts distinct authorized Verification Method IDs,
never raw signature count.

If the threshold is not satisfied, verification MUST fail with
`ASSERTION_THRESHOLD_NOT_SATISFIED`.

A 2-of-2 policy remains 2-of-2 if an algorithm is unavailable,
unsupported, deprecated, or expensive. The threshold MUST NOT be
silently reduced.

## 11. Historical authorization verification algorithm

Given a `SecuredCredential`, a verifier SHALL:

1.  Parse and deterministically validate the secured credential.
2.  Reconstruct canonical CredentialBytes.
3.  Read `issuerIdentity` and `issuanceStateHash` from CredentialBytes.
4.  Resolve or load the exact historical authoritative IdentityState
    identified by those values.
5.  Recompute StateHash and require equality with `issuanceStateHash`;
    otherwise fail with `INVALID_ISSUANCE_STATE_HASH`.
6.  Require the historical state's identity to equal `issuerIdentity`.
7.  Require a supported historical state containing `AssertionPolicy`;
    if absent, fail with `NO_ASSERTION_AUTHORITY`.
8.  Construct the exact CredentialSigningInput.
9.  Validate the complete proof set, rejecting duplicate, unauthorized,
    malformed, unsupported-required, or cryptographically invalid
    supplied proofs.
10. Evaluate the complete valid proof set against the historical
    SINGLE/THRESHOLD policy.
11. Return cryptographic VALID only if all required checks succeed.

The current IdentityState MUST NOT replace the bound historical state.

Cryptographic VALID does not by itself establish profile validity, time
validity, credential status, or application acceptance.

## 12. Historical authority semantics

A credential's issuance authority is fixed by the historical state
identified by its signed `issuanceStateHash`.

``` text
A01: AssertionPolicy = SINGLE(B)
     credential issued by B

A02: AssertionPolicy = SINGLE(C)
     B retired for new assertions
     C authorized for new assertions
```

A credential correctly bound to A01 is evaluated against A01 for
historical issuance authorization. A verifier MUST NOT reject it merely
because B is absent from A02.

Later removal of all assertion authority likewise does not rewrite
earlier historical states.

Historical authorization does not override separate credential-status,
revocation, algorithm-security, validity-period, or application
policies.

## 13. Credential Profile processing

Credential processing has distinct layers:

``` text
1. Cryptographic verification
      VALID / INVALID

2. Credential Profile validation
      VALID / INVALID / INDETERMINATE

3. Application acceptance
      ACCEPT / REJECT
```

These layers MUST NOT be silently collapsed.

A verifier SHOULD use locally installed or explicitly trusted Credential
Profile handlers. Automatic network retrieval of arbitrary profile URIs
MUST NOT be required for cryptographic verification.

An unknown profile produces profile-validation `INDETERMINATE`, not
cryptographic `INVALID`, when the underlying credential is otherwise
cryptographically valid.

## 14. Validity-period processing

Validity-period evaluation is separate from historical cryptographic
verification.

Before `validFrom`, a credential is outside its issuer-declared validity
interval.

When `validUntil` is present, an implementation SHALL apply its defined
expiration-boundary semantics consistently.

Clock source, clock skew, archival validation time, and
application-specific time policy are verifier concerns unless a
Credential Profile defines stricter requirements.

## 15. Credential status and revocation

Credential status, suspension, and revocation are separate from
historical assertion authorization.

A historically valid signature proves that an authorized assertion key
signed the credential under the bound historical state. It does not
prove that the credential remains currently acceptable.

The concrete credential-status mechanism is deferred from OI-003 v0.1.

Implementations MUST NOT reinterpret assertion-key removal as implicit
revocation of every credential historically signed by that key.

## 16. Algorithm processing

Algorithm selection MUST come from the historical VerificationMethod's
`COSE_Key`. A credential proof MUST NOT override that algorithm.

OI-003 v0.1 SHALL support Ed25519 and ML-DSA-65 credential verification
consistently with OI-002.

A structurally valid but unsupported required algorithm MUST NOT cause
threshold downgrade.

Historical protocol validity and current algorithm-security
acceptability are distinct. A verifier MAY establish historical validity
while application or security policy rejects that algorithm for current
use.

## 17. Failure semantics

Implementations SHOULD expose stable typed failures including:

-   `INVALID_ISSUANCE_STATE_HASH`
-   `NO_ASSERTION_AUTHORITY`
-   `DUPLICATE_CREDENTIAL_PROOF`
-   `UNAUTHORIZED_CREDENTIAL_PROOF`
-   `INVALID_CREDENTIAL_SIGNATURE`
-   `ASSERTION_THRESHOLD_NOT_SATISFIED`
-   `UNSUPPORTED_CREDENTIAL_PROFILE`
-   `UNSUPPORTED_ALGORITHM`
-   `INVALID_COSE_KEY`
-   `INVALID_SIGNATURE_FORMAT`

Human-readable messages MAY vary.

Structural CBOR/schema failures MAY use implementation-specific typed
errors provided they preserve the underlying failure distinction.

## 18. Security considerations

### 18.1 Historical-state substitution

A verifier MUST NOT verify a credential against current assertion
authority when the credential binds to a different historical state.

### 18.2 Controller/assertion confusion

A controller signature MUST NOT satisfy credential assertion authority
unless that exact VerificationMethod is also explicitly present in the
historical `AssertionPolicy`.

### 18.3 Proof-set smuggling

A verifier MUST validate every supplied proof before accepting threshold
satisfaction. Unauthorized, duplicate, malformed, or invalid extra
proofs MUST NOT be ignored.

### 18.4 Method rebinding

A signature produced by one key MUST NOT become authorized merely by
changing the proof's Verification Method ID.

### 18.5 Signing-domain confusion

Credential signatures MUST verify only over the OI-003
CredentialSigningInput. A valid signature over another domain is not a
valid credential signature.

### 18.6 Credential mutation

Issuer identity, historical StateHash, profile, subject, validity
interval, and claims are all inside CredentialBytes. Changing any of
them after signing MUST invalidate the credential signature.

## 19. Privacy considerations

The OI-001 root DID is privacy-sensitive and potentially correlatable.

Credential Profiles SHOULD avoid unnecessary disclosure of the root
identity to relying parties and SHOULD support pairwise or pseudonymous
subject identifiers where appropriate.

Claims SHOULD follow data-minimization principles. Credential
identifiers, profile identifiers, subjects, and claims can themselves
become correlators.

## 20. W3C interoperability

A Credential Profile MAY define a deterministic projection of a
canonical OpenIdentity credential into a W3C Verifiable Credential
representation.

At minimum, such a projection is expected to map:

-   `issuerIdentity` to the appropriate `did:open:` issuer identifier;
-   `credentialSubject` and claims to W3C credential-subject semantics;
-   `validFrom` and `validUntil` to the W3C validity period;
-   `credentialProfile` to profile-defined type/context semantics; and
-   historical `AssertionPolicy` methods to the applicable W3C
    `assertionMethod` relationship.

Native OI-003 `CredentialProof` values are not W3C `DataIntegrityProof`
values. The deterministic W3C projection preserves the exact native
`SecuredCredential` and is defined by
`spec/w3c-credential-projection.md`.

A W3C projection MUST NOT become an independent source of cryptographic
truth and MUST NOT alter the issuer identity, historical StateHash
binding, VerificationMethod identity, key material, assertion threshold,
or signed claim semantics.

The exact W3C credential projection is specified separately.

## 21. Separation of verification questions

Implementations MUST distinguish:

``` text
Historical assertion authorization:
    Was this method authorized at the exact bound state?

Signature verification:
    Did that authorized key sign these exact CredentialBytes?

Credential Profile validation:
    Do subject and claims conform to the identified profile?

Validity evaluation:
    Is the credential within its declared time window?

Credential status:
    Has the credential been revoked, suspended, or otherwise changed?

Application policy:
    Should this verifier accept the credential for this purpose?
```

These questions MUST NOT be silently collapsed into one result.

## 22. Normative CDDL

The normative credential wire schema is:

``` text
spec/cddl/openidentity-credential-v1.cddl
```

The assertion-authority state and operation schema is:

``` text
spec/cddl/openidentity-operation-v2.cddl
```

The Markdown specification and CDDL MUST agree. Where a constraint is
intentionally semantic because CDDL cannot express it, this document
defines that semantic requirement.

## 23. Conformance vectors

OI-003 v0.1 publishes assertion-authority and credential conformance
vectors.

### 23.1 Assertion-authority vectors

Positive vectors:

-   A01 --- v1 to v2 installation of SINGLE Ed25519 assertion authority.
-   A02 --- replacement of the SINGLE assertion method.
-   A03 --- removal of `AssertionPolicy`.
-   A04 --- installation of THRESHOLD 2-of-2 Ed25519 + ML-DSA-65
    assertion authority.

Invalid/security vectors AI01 through AI10 cover assertion-key
self-authorization, missing/invalid proof of possession, incorrect
historical state binding, invalid sequence, insufficient controller
authorization, duplicate methods, invalid assertion threshold, and
forbidden state-version downgrade.

The normative bundle is:

``` text
test-vectors/assertion-authority-v0.1.json
test-vectors/assertion-authority-v0.1.json.sha256
```

### 23.2 Credential vectors

Positive vectors:

-   C01 --- SINGLE Ed25519 credential bound to historical A01.
-   C02 --- THRESHOLD 2-of-2 Ed25519 + ML-DSA-65 credential bound to
    historical A04, including canonical proof ordering from reversed
    generator input.

Invalid/security vectors:

-   CI01 --- insufficient assertion threshold.
-   CI02 --- duplicate credential proof.
-   CI03 --- unauthorized extra proof.
-   CI04 --- invalid Ed25519 signature.
-   CI05 --- invalid ML-DSA-65 signature.
-   CI06 --- incorrect `issuanceStateHash`.
-   CI07 --- wrong credential signing domain.
-   CI08 --- Verification Method rebinding to an unauthorized method.
-   CI09 --- claims modified after signing.
-   CI10 --- exact historical state contains no `AssertionPolicy`.

The normative bundle is:

``` text
test-vectors/credential-v0.1.json
test-vectors/credential-v0.1.json.sha256
```

### 23.3 W3C credential projection vectors

The deterministic W3C credential projection is defined separately by:

``` text
spec/w3c-credential-projection.md
```

Positive vectors:

-   WP01 --- deterministic projection of C01.
-   WP02 --- deterministic projection of C02.

Invalid/security vectors WPI01 through WPI10 cover altered issuer,
credential ID, validity, issuance StateHash, embedded native credential,
subject, claims, context, misleading W3C proof representation, and
current-state substitution for historical assertion authority.

The normative bundle is:

``` text
test-vectors/w3c-credential-projection-v0.1.json
test-vectors/w3c-credential-projection-v0.1.json.sha256
```

WP01-WP02 and WPI01-WPI10 are independently verified.

A conforming implementation MUST reproduce the byte-exact positive
vector encodings and MUST reject the invalid vectors for the represented
security conditions.

## 24. OI-003 protocol invariants

OI-003 establishes the following invariants:

1.  Controller authority and assertion authority are distinct.
2.  Assertion authority is explicit in IdentityState v2.
3.  AssertionPolicy cannot authorize its own installation or
    replacement.
4.  Removing AssertionPolicy creates zero assertion authority; there is
    no ControllerPolicy fallback.
5.  CredentialBytes cryptographically commit to issuer identity,
    historical StateHash, validity interval, profile, subject, and
    claims.
6.  Credential verification uses the exact historical state identified
    by the signed `issuanceStateHash`.
7.  Current assertion authority MUST NOT replace historical assertion
    authority during credential verification.
8.  All proofs sign the same domain-separated CredentialSigningInput.
9.  Algorithm selection comes from the historical VerificationMethod's
    `COSE_Key`.
10. Duplicate, unauthorized, or invalid supplied proofs are fatal; they
    are not ignored after threshold satisfaction.
11. Thresholds MUST NOT be silently weakened.
12. Unknown Credential Profiles do not by themselves make a
    cryptographically valid credential cryptographically invalid.
13. Credential status/revocation is separate from historical issuance
    authorization.
14. W3C representations are projections and do not replace canonical
    OpenIdentity credential semantics.

## 25. Deferred work

OI-003 v0.1 intentionally defers:

-   a general Credential Profile document format and registry;
-   production Credential Profiles;
-   credential status, suspension, and revocation mechanisms;
-   selective disclosure and zero-knowledge presentation formats;
-   holder-binding and presentation-proof protocols;
-   pairwise subject-identifier derivation;
-   an OpenIdentity W3C Data Integrity cryptosuite;
-   registry-specific historical-state retrieval mechanics; and
-   additional assertion algorithms beyond those inherited from the v0.1
    cryptographic profile.

Deferred features MUST NOT be inferred by weakening or silently
extending the v0.1 wire format.

## 26. Completion criteria

OI-003 v0.1 is complete when:

-   `credential.md`, `openidentity-operation-v2.cddl`, and
    `openidentity-credential-v1.cddl` agree;
-   IdentityState v2 and `AssertionPolicy` semantics are fixed;
-   `SET_ASSERTION_POLICY` installation, replacement, removal, and
    proof-of-possession semantics are fixed;
-   historical `issuanceStateHash` binding is fixed;
-   CredentialBytes and CredentialSigningInput are fixed;
-   strict proof-set semantics are fixed;
-   Credential Profile unknown-schema behavior is fixed;
-   A01-A04 and AI01-AI10 are independently verified;
-   C01-C02 and CI01-CI10 are independently verified;
-   `spec/w3c-credential-projection.md` defines the deterministic W3C
    projection;
-   WP01-WP02 and WPI01-WPI10 are independently verified; and
-   normative assertion-authority, credential, and W3C credential
    projection vector bundles have published checksums.

## 27. Normative references

OI-003 depends on:

-   OI-001 --- OpenIdentity Identity Identifier Specification;
-   OI-002 --- OpenIdentity Cryptographic Agility Specification;
-   `spec/cddl/openidentity-operation-v2.cddl`;
-   `spec/cddl/openidentity-credential-v1.cddl`;
-   `spec/w3c-credential-projection.md`;
-   RFC 8949 --- Concise Binary Object Representation (CBOR);
-   the COSE specifications and IANA COSE registries used by OI-002; and
-   NIST FIPS 204 for ML-DSA.

The permanent OpenIdentity identifier remains independent of
credentials, cryptographic algorithms, registries, and infrastructure
providers.
