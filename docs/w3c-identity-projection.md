# OpenIdentity W3C Identity Projection

**Status:** Draft v0.1\
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

Once published, `/ns/v1` is immutable.

The repository source is:

``` text
contexts/openidentity-v1.jsonld
```

and its integrity file is:

``` text
contexts/openidentity-v1.sha256
```

Standard W3C terms MUST NOT be redefined in the OpenIdentity context.

## Root and method identifiers

The OI-001 root DID is the projected subject identifier.

Each OI-002 16-byte `verificationMethodId` projects to:

``` text
did:open:<root>#vm-<multibase-base64url-method-id>
```

The method bytes are Multibase base64url without padding (`u`). No
private Multicodec assignment is created for the method-local
identifier.

## Verification material

Canonical key material remains `COSE_Key`.

Ed25519 projects to standardized Multikey using the registered Ed25519
public-key Multicodec and the applicable W3C Multikey encoding.

ML-DSA-65 projection MUST use the registered `ml-dsa-65-pub` Multicodec
and the standards-defined Multikey construction. OpenIdentity MUST NOT
allocate a private codec. Canonical COSE remains authoritative even if
external cryptosuite maturity differs.

RFC 9679 COSE Key Thumbprints SHOULD be used when exact COSE key
identity/fingerprinting is needed; they are distinct from Verification
Method IDs.

## ControllerPolicy

Active root-controller methods project to `capabilityInvocation`.

They MUST NOT automatically project to `authentication`,
`assertionMethod`, `keyAgreement`, or `capabilityDelegation`.

`capabilityInvocation` identifies eligible methods but does not encode
OpenIdentity m-of-n semantics. Therefore it MUST NOT be used alone to
authorize OpenIdentity state transitions.

The authoritative combination rule remains
`IdentityState.ControllerPolicy`.

## Policy extension

The projected combination rule uses `openIdentityVerificationPolicy`,
mapped by the OpenIdentity v1 context to
`https://openidentity.foundation/ns#verificationPolicy`.

Example:

``` json
{
  "openIdentityVerificationPolicy": {
    "id": "did:open:<root>#controller-policy",
    "type": "Threshold",
    "appliesTo": "capabilityInvocation",
    "threshold": 2,
    "verificationMethod": [
      "did:open:<root>#vm-A",
      "did:open:<root>#vm-B"
    ]
  }
}
```

The extension is a deterministic informational projection. It never
supersedes canonical state.

## JSON-LD processing

Applications MUST understand every context they use. OpenIdentity
contexts use explicit protected term mappings and do not use `@vocab` to
manufacture undefined production terms.

Remote contexts used in security-sensitive processing SHOULD be
cached/bundled and integrity checked. The repository publishes the
SHA-256 of `openidentity-v1.jsonld`.

## DID Resolution

Resolution begins with authoritative OpenIdentity state. DID URL
fragment dereferencing returns the corresponding projected
VerificationMethod.

Relationship-aware dereferencing MUST enforce the requested verification
relationship. A method authorized only for `capabilityInvocation` MUST
NOT be treated as `authentication`.

## Security

Projection MUST NOT downgrade thresholds, omit active methods for
convenience, alter key bindings, expose private keys, reuse retired
method IDs, or accept a projected document as an unsigned state update.

## Future delegation

ZCAP may later be used for delegated/attenuated authority. It does not
replace OI-002 `ControllerPolicy` threshold evaluation.

## Projection vectors

Future vectors should include P01 SINGLE Ed25519, P02 hybrid 2-of-2, P03
canonical ordering, P04 rotation, and P05 relationship-aware
dereferencing. They should be independently verified before becoming
normative.
