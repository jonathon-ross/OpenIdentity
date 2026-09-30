# OpenIdentity OAuth 2.0 Delegated Agent Profile v1 — Pre-Freeze Conformance Review

**Status:** DRAFT — pre-freeze review  
**Profile:** `https://openidentity.org/oauth/profile/delegated-agent-v1`  
**Specification:** `spec/oauth-delegated-agent-profile-v1.md`

## 1. Release boundary

This profile defines interoperability and authorization-server processing semantics for composing frozen OpenIdentity artifacts with OAuth 2.0 Token Exchange.

It does not redefine the wire bytes of OI-014, OI-015, OI-016, or OAuthTokenExchangeContextV1.

It also does not replace the generic conformance suites of RFC 8693, RFC 8707, RFC 9068, RFC 9449, RFC 8414, or RFC 9700.

## 2. Current evidence

The draft profile conformance bundle contains:

- positive vectors PX01-PX03;
- adversarial vectors PXI01-PXI37;
- deterministic Python generation;
- independent Python verification;
- independent Java verification;
- no profile checksum/byte-freeze yet.

Both Python and Java suites are green through PX01-PX03 + PXI01-PXI37.

## 3. Positive coverage

- PX01 — successful delegated-agent authorization decision, target/scope mapping, root subject/current actor projection, DPoP confirmation, delegation-clipped expiration, and no refresh token.
- PX02 — profile discovery behavior: DPoP required, refresh unsupported, 300-second advertised maximum.
- PX03 — safe public invalid_request projection while retaining a detailed internal OpenIdentity diagnostic.

## 4. Adversarial coverage

### Admission / transport

- PXI01 wrong subject_token_type.
- PXI02 wrong actor_token_type.
- PXI03 padded subject-token base64url.
- PXI04 invalid actor-token base64url character.
- PXI05 missing mandatory DPoP.
- PXI06 validated DPoP key differs from frozen context binding.
- PXI07 issued token DPoP key differs from context/validated proof.
- PXI08 refresh-token issuance attempt.
- PXI28 wrong grant_type.
- PXI29 required OAuth client authentication missing.

### Authorization mapping

- PXI09 requested scope not explicitly authorized.
- PXI10 requested target not explicitly authorized.
- PXI11 one Cartesian target/scope pair fails; atomic exchange fails.
- PXI12 required pinned Capability Profile OAuth mapping unavailable.
- PXI13 target resolution ambiguous.

### Current OpenIdentity state / cross-binding

- PXI14 authoritative state resolves to currently unusable delegation.
- PXI15 required authoritative state unavailable.
- PXI16 OI-015 identity differs from OI-016 terminalDelegate.
- PXI17 OI-016 actorAssertionId / OI-015 context binding fails.
- PXI30 OI-015 purpose mismatch.
- PXI31 OI-015 authorization-server verifier/audience mismatch.
- PXI32 already-consumed AssertionId replay.

### Issuance/output invariants

- PXI18 access token outlives earliest delegation expiration.
- PXI19 access token exceeds deployment maximum.
- PXI20 JWT subject does not project rootGrantor.
- PXI21 JWT current actor does not project terminalDelegate.
- PXI22 output scope amplification.
- PXI23 output audience amplification.
- PXI24 missing DPoP confirmation.
- PXI25 wrong output cnf.jkt.
- PXI26 response contains refresh token.
- PXI33 unsupported requested output token type.

### Public errors / discovery

- PXI27 public error_description leaks internal delegation state.
- PXI34 target failure does not project invalid_target.
- PXI35 discovery claims DPoP is not required.
- PXI36 discovery claims refresh tokens are supported.
- PXI37 advertised lifetime exceeds enforced maximum.

## 5. Profile invariants

A successful delegated-agent-v1 exchange requires all of:

    exact RFC 8693 grant_type
    exact OpenIdentity subject/actor token types
    valid OAuth client processing
    valid mandatory RFC 9449 DPoP proof
    complete current OI-014/OI-016 verification
    exact frozen OAuthTokenExchangeContextV1 reconstruction
    complete current OI-015 verification
    OI016.actorAssertionId == OI015.AssertionId
    OI015.identity == OI016.terminalDelegate
    OI015.contextHash == reconstructed contextHash
    every requested target/scope pair explicitly authorized
    no output authority amplification
    output DPoP key == context/proof DPoP key
    exp bounded by delegation and deployment policy
    no refresh token
    one-time assertion/exchange replay policy

## 6. Standards delegated to underlying implementations

The profile requires complete conformance to its referenced OAuth standards but does not duplicate all generic test cases.

Examples intentionally delegated to the RFC 9449 implementation include:

- DPoP JWT signature verification;
- typ, alg, public JWK rules;
- htm / htu;
- iat freshness;
- jti replay cache mechanics;
- authorization-server DPoP nonce behavior;
- protected-resource ath processing.

Examples intentionally delegated to RFC 9068/JWT implementation include generic:

- iss/aud/exp parsing and validation;
- JWT signature validation;
- algorithm policy;
- generic claim syntax.

The profile vectors test the OpenIdentity-specific composition/binding/projection rules around those standards.

## 7. Frozen dependencies

This profile consumes and MUST NOT modify:

- Protocol v2 / IdentityState v3;
- OI-014 DelegationGrant v1;
- OI-015 Authentication Assertion v1;
- OI-016 Delegated Subject Token v1;
- OAuthTokenExchangeContextV1.

## 8. Requirements before profile byte freeze

1. run the unified delegated-agent profile pre-freeze gate;
2. require Python PX01-PX03 + PXI01-PXI37 PASS;
3. require Java PX01-PX03 + PXI01-PXI37 PASS;
4. confirm all previously frozen OpenIdentity/context commitments remain unchanged;
5. review specification/vector terminology and stable profile errors;
6. confirm clean worktree after deterministic regeneration;
7. only then create a profile conformance-bundle checksum candidate.

## 9. Freeze status

**NOT BYTE-FROZEN. NOT NORMATIVE.**

Passing this review/gate establishes readiness to create a profile conformance-bundle freeze candidate. It does not alter any frozen dependency.
