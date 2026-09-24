# OpenIdentity Vocabulary

**Vocabulary namespace:** `https://openidentity.foundation/ns#`\
**Vocabulary document:** `https://openidentity.foundation/ns`\
**JSON-LD context v1:** `https://openidentity.foundation/ns/v1`

## Stability

The semantic vocabulary namespace is unversioned. The v1 context is
immutable once published. Future incompatible context processing changes
require a new versioned context such as `/ns/v2`.

The v1 context SHA-256 is:

``` text
2125613959be8c288fd31a0aa2258d652cd9812ab21a0b5c6bc10a4081e8c6f4
```

OI-003 credential projection terms are additions to the unversioned
vocabulary. They MUST NOT be added retroactively to the immutable v1
context. A cumulative v2 context SHALL carry the existing v1 mappings
plus the OI-003 credential projection mappings.

Implementations SHOULD bundle or integrity-pin the context rather than
require live retrieval during security-sensitive processing. W3C
guidance recommends published contexts, explicit term definitions,
protected terms, and integrity/caching mechanisms for remote contexts.

## Terms

### verificationPolicy

URI: `https://openidentity.foundation/ns#verificationPolicy`

JSON term: `openIdentityVerificationPolicy`

A deterministic projection of the authoritative OpenIdentity
`ControllerPolicy`. It describes how eligible verification methods
combine for the relationship identified by `appliesTo`.

It is informational in a projected DID document. OpenIdentity
state-transition authorization remains governed by canonical
`IdentityState.ControllerPolicy`.

### appliesTo

URI: `https://openidentity.foundation/ns#appliesTo`

Identifies the W3C verification relationship to which the projected
policy applies. OI-002 root-controller policy projects to
`capabilityInvocation`.

### threshold

URI: `https://openidentity.foundation/ns#threshold`

Integer number of distinct qualifying verification methods required by a
`Threshold` policy.

### Single

URI: `https://openidentity.foundation/ns#Single`

Policy type representing one required VerificationMethod.

### Threshold

URI: `https://openidentity.foundation/ns#Threshold`

Policy type representing an m-of-n verification policy.


### OpenIdentityCredential

URI: `https://openidentity.foundation/ns#OpenIdentityCredential`

JSON-LD term: `OpenIdentityCredential`

W3C-facing type identifying a deterministic projection of a canonical
OI-003 OpenIdentity credential.

The projected representation is an interoperability view. The canonical
OI-003 `SecuredCredential` remains the cryptographic source of truth.

### credentialProfile

URI: `https://openidentity.foundation/ns#credentialProfile`

JSON-LD term: `openIdentityCredentialProfile`

Identifies the immutable OI-003 Credential Profile governing the
credential's subject syntax, claims, semantics, and interoperability
projection rules.

The value is an absolute URI. It is an identifier and MUST NOT be
interpreted as a requirement to dereference the URI during cryptographic
verification.

### issuanceStateHash

URI: `https://openidentity.foundation/ns#issuanceStateHash`

JSON-LD term: `openIdentityIssuanceStateHash`

Identifies the exact historical authoritative OpenIdentity
`IdentityState` whose `AssertionPolicy` authorized issuance of the
credential.

In the W3C credential projection, the value is the Multibase
representation of the exact native OI-003 `issuanceStateHash`. It MUST
NOT be recomputed from the projected W3C credential.

The current IdentityState MUST NOT be substituted for the historical
state identified by this value.

### securedCredential

URI: `https://openidentity.foundation/ns#securedCredential`

JSON-LD term: `openIdentitySecuredCredential`

Carries the Multibase representation of the exact canonical native
OI-003 `SecuredCredential` bytes in an OpenIdentity W3C credential
projection.

Native OI-003 verification operates on the decoded canonical bytes.
This term does not define a W3C Data Integrity proof and MUST NOT cause
native OI-003 credential proofs to be interpreted as
`DataIntegrityProof`.

## Reused W3C terms

OpenIdentity does not redefine standard terms such as `id`, `type`,
`controller`, `verificationMethod`, `capabilityInvocation`, `Multikey`,
or `publicKeyMultibase`. Their definitions come from the applicable W3C
contexts/vocabularies.

## Context usage

A JSON-LD projection should load the applicable DID/Controlled
Identifier and Multikey contexts before the OpenIdentity context. The
exact base DID context version used by a frozen projection profile MUST
be recorded in that profile.

Example policy:

``` json
{
  "id": "did:open:<root>#controller-policy",
  "type": "Threshold",
  "appliesTo": "capabilityInvocation",
  "threshold": 2,
  "verificationMethod": [
    "did:open:<root>#vm-A",
    "did:open:<root>#vm-B"
  ]
}
```

The containing DID document associates this node through
`openIdentityVerificationPolicy`.
