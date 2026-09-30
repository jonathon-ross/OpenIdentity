# OpenIdentity OAuth 2.0 Delegated Agent Profile v1

**Status:** Design draft; non-normative  
**Profile identifier:** `https://openidentity.org/oauth/profile/delegated-agent-v1`

## 1. Purpose

This interoperability profile composes frozen OpenIdentity authority/authentication artifacts with standard OAuth 2.0 Token Exchange.

It is not a new core OpenIdentity primitive and therefore is not assigned an OI-### number.

Dependencies:

- OI-014 DelegationGrant v1 — FROZEN-NORMATIVE;
- OI-015 Authentication Assertion v1 — FROZEN-NORMATIVE;
- OI-016 Delegated Subject Token v1 — FROZEN-NORMATIVE;
- OAuthTokenExchangeContextV1 — FROZEN-NORMATIVE;
- RFC 8693 Token Exchange;
- RFC 8707 Resource Indicators;
- RFC 9068 when JWT access tokens are issued;
- RFC 9449 DPoP;
- RFC 8414 Authorization Server Metadata;
- RFC 9700 OAuth Security BCP.

## 2. Required request profile

The token endpoint request uses:

    grant_type =
      urn:ietf:params:oauth:grant-type:token-exchange

    subject_token_type =
      https://openidentity.org/oauth/token-type/delegated-subject-v1

    subject_token =
      base64url-no-pad(exact OI-016 DelegatedSubjectToken bytes)

    actor_token_type =
      https://openidentity.org/oauth/token-type/authentication-assertion-v1

    actor_token =
      base64url-no-pad(exact OI-015 SecuredAuthenticationAssertion bytes)

A valid RFC 9449 DPoP proof is mandatory.

resource, audience, scope, and requested_token_type follow their respective OAuth/RFC rules and the frozen OAuthTokenExchangeContextV1 canonicalization profile.

## 3. Authorization-server processing algorithm

The authorization server processes a delegated-agent-v1 exchange in the following security stages.

### Stage 1 — OAuth request and client processing

1. Require POST to the configured token endpoint using the authorization server's supported OAuth token-endpoint request encoding.
2. Parse the OAuth request and reject malformed/duplicate parameters according to OAuth and local policy.
3. Require grant_type = RFC 8693 token exchange.
4. Perform normal OAuth client identification/authentication as required for the client type and deployment.
5. Establish the trusted authorization-server identifier and authenticated/resolved clientId used by OAuthTokenExchangeContextV1.
6. Validate subject_token_type and actor_token_type exactly against this profile.
7. Parse/validate requested_token_type, resource, audience, and scope syntax.
8. Resolve resource/audience identifiers to authorization-server target identities. Failure to support a requested target is fail closed.

Client authentication is not replaced by OpenIdentity or DPoP.

### Stage 2 — DPoP validation

9. Require exactly one DPoP proof header.
10. Perform complete RFC 9449 token-endpoint proof validation, including typ, asymmetric alg policy, public JWK, signature, htm, htu, iat freshness, jti/replay policy, and DPoP nonce when required.
11. Derive the RFC 7638 SHA-256 JWK thumbprint representation (dpopJkt) from the validated proof public JWK.

The server MUST NOT trust a client-supplied thumbprint that was not derived from the validated proof.

DPoP proof validation may internally occur in an implementation-optimized order, but no OpenIdentity authorization decision or token issuance proceeds until it succeeds. RFC 9449 itself permits its proof checks to be performed in any order.

### Stage 3 — Decode input OpenIdentity tokens

12. Decode subject_token from base64url-no-pad to exact OI-016 bytes.
13. Deterministically parse OI-016 and perform its structural/immutable-evidence checks.
14. Decode actor_token from base64url-no-pad to exact OI-015 secured assertion bytes.
15. Deterministically parse OI-015.

Malformed or unacceptable input security tokens fail closed.

### Stage 4 — OI-016 / OI-014 verification

16. Recompute every OI-014 GrantId from exact embedded GrantBytes.
17. Validate the selected root-to-terminal OI-014 path, parent links, issuer/delegate relationships, rootGrantor consistency, profile commitments, attenuation, and path limits.
18. Resolve and verify authoritative current RegisteredGrantState and all other current OI-014 material required by frozen OI-014.
19. Require the complete path to be currently usable.
20. Derive:
    
        subjectIdentity = rootGrantor
        actorIdentity   = terminalDelegate
        delegationEvidenceId = normative OI-016 DelegationEvidenceId

Historical embedded evidence never substitutes for authoritative current state.

### Stage 5 — Reconstruct frozen OAuth context

21. Canonicalize validated OAuth scope/resource/audience inputs according to frozen OAuthTokenExchangeContextV1.
22. Construct exact OAuthTokenExchangeContextV1 using:
    
        trusted authorizationServer
        resolved/authenticated clientId
        requestedTokenType presence/value
        canonical resources
        canonical audiences
        canonical scopes
        exact delegationEvidenceId
        validated DPoP dpopJkt

23. Deterministically encode contextBytes.
24. Derive the normative SHA2-256 Multihash contextHash.

### Stage 6 — OI-015 verification and cross-binding

25. Perform complete frozen OI-015 verification against current IdentityState, AuthenticationAuthority generation, AuthenticationPolicy, audience, purpose, time, nonce, and proofs.
26. Require:

        purpose =
          "openidentity.oauth.token-exchange"

27. Require the OI-015 verifier/audience semantics to identify this authorization server according to the integration profile.
28. Require:

        OI015.contextHash
            ==
        reconstructed OAuth contextHash

29. Derive the normative OI-015 AssertionId.
30. Require:

        OI016.actorAssertionId
            ==
        OI015.AssertionId

31. Require:

        OI015.identity
            ==
        OI016.terminalDelegate

Failure of any binding rejects the exchange.

### Stage 7 — Authorization mapping

32. Compute the effective attenuated OI-014 authority of the verified path.
33. For each resolved target and each requested/default OAuth scope, invoke the applicable pinned OI-014 Capability Profile mapping.
34. Require every target/scope pair to be explicitly authorized.
35. Reject unknown/unavailable mapping profiles or ambiguous target resolution.
36. Apply authorization-server/client/deployment policy in addition to OpenIdentity authority.

v1 uses atomic fulfillment: an unauthorized requested target/scope pair rejects the exchange rather than silently narrowing it.

### Stage 8 — Recheck issuance-critical state

37. Immediately before issuance, ensure no cached verification result has exceeded deployment freshness/finality policy.
38. Reconfirm any mutable authoritative state that deployment policy requires to prevent a check-to-issue race.
39. Consume/record OI-015 nonce/AssertionId replay state according to the authorization-server's one-time token-exchange policy.

Implementations SHOULD minimize the interval between authoritative-state verification and issuance.

### Stage 9 — Issue sender-constrained token

40. Determine output token type under requested_token_type and authorization-server policy.
41. Set the authorization subject from verified rootGrantor.
42. Set current actor from verified terminalDelegate.
43. Bind the access token to the validated DPoP key.
44. Limit issued scopes/audiences to the fully authorized request.
45. Bound exp by the earliest applicable OI-014 expiration and deployment maximum.
46. Do not issue a refresh token in delegated-agent-v1.
47. Return the normal RFC 8693/OAuth token response.

For RFC 9068 JWT access tokens, the projection includes conceptually:

    sub = projected rootGrantor
    act = { sub = projected terminalDelegate }
    cnf = { jkt = validated dpopJkt }

plus all RFC 9068 required/applicable claims.

## 4. Processing-order security rules

The numbered stages define dependency order, not a mandate that every low-level parser/check execute serially.

Implementations MAY perform cheap independent syntax checks earlier or in parallel when doing so does not:

- authorize before prerequisites are satisfied;
- skip required verification;
- change stable semantics;
- expose sensitive OpenIdentity state through distinguishable public errors.

In particular, implementations SHOULD perform cheap OAuth/token-type/size/DPoP syntax checks before expensive registry resolution.

## 5. Failure behavior

No failure before Stage 9 issues an access token.

Detailed OI-014/OI-015/OI-016/context failures remain internal by default.

Consistent with RFC 8693:

- invalid/unacceptable subject_token or actor_token -> invalid_request;
- unsupported/unissuable resource/audience target -> invalid_target when applicable;
- standard OAuth client-authentication/request errors remain standard OAuth errors;
- RFC 9449 DPoP nonce challenges use RFC 9449 behavior.

Public error_description values remain generic and MUST NOT reveal private delegation state.

## 6. DPoP policy

DPoP is mandatory in delegated-agent-v1.

The DPoP key is not required to equal an OI-015 AuthenticationPolicy key. Separate keys are recommended.

The validated proof's jkt is bound into frozen OAuthTokenExchangeContextV1 and into the issued token's RFC 9449 confirmation data.

Therefore:

    context.dpopJkt
        ==
    jkt(validated token-endpoint DPoP proof)
        ==
    jkt(bound to issued access token)

DPoP key substitution after OI-015 authentication fails contextHash verification.

## 7. Access-token lifetime and renewal

The default recommended maximum delegated access-token lifetime is 300 seconds.

The issued token MUST NOT outlive the earliest expiration of the OI-014 authority path that justified issuance.

OI-015 freshness proves recent authentication for issuance; it does not itself require the output token to expire at OI-015 expiresAt.

delegated-agent-v1 MUST NOT issue refresh tokens.

Renewal is a fresh RFC 8693 exchange with newly verified OI-016/OI-015 evidence and current OpenIdentity state.

## 8. Discovery

RFC 8414 metadata advertises normal OAuth capabilities including RFC 8693 grant support and RFC 9449 DPoP algorithms.

Profile-specific metadata includes:

    openidentity_token_exchange_profiles_supported
    openidentity_subject_token_types_supported
    openidentity_actor_token_types_supported
    openidentity_dpop_required
    openidentity_refresh_tokens_supported
    openidentity_max_access_token_lifetime_seconds

The profile identifier is:

    https://openidentity.org/oauth/profile/delegated-agent-v1

## 9. Privacy and logging

Implementations SHOULD avoid logging full OI-014 GrantBytes, OI-016 tokens, OI-015 assertions, DPoP proofs, or bearer access tokens.

Nested RFC 8693 act history is not required. The default JWT projection exposes only root subject and current actor.

## 10. Conformance boundary

The profile conformance suite currently covers PX01-PX03 + PXI01-PXI37 in independent Python and Java implementations.

It pins the OpenIdentity-specific interoperability surface across:

- profile admission and exact token/grant types;
- strict OpenIdentity token transport;
- mandatory DPoP composition and three-way jkt binding;
- current OI-014/OI-016 authority;
- frozen OAuthTokenExchangeContextV1 reconstruction;
- current OI-015 purpose/audience/identity/assertion/context binding;
- Capability Profile target/scope mapping and atomic fulfillment;
- assertion replay handling;
- output subject/actor/audience/scope projection;
- access-token expiration clipping;
- no-refresh behavior;
- discovery metadata;
- safe public OAuth error projection.

Generic RFC 9449 cryptographic proof conformance and generic RFC 9068/JWT validation remain delegated to conforming implementations of those standards rather than duplicated here.

The profile remains non-normative until its conformance bundle is byte-frozen and the final release gate passes.
