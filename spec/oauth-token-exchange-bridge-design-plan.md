# OpenIdentity OAuth 2.0 Token Exchange Bridge — Design Plan

**Status:** Design draft; non-normative  
**Purpose:** map frozen OpenIdentity authentication and delegation evidence into standard OAuth 2.0 token exchange without redefining OAuth authorization semantics  
**Depends on:** OI-014 DelegationGrant v1 (FROZEN-NORMATIVE), OI-015 Authentication Assertion v1 (FROZEN-NORMATIVE), RFC 8693, RFC 8707, RFC 9068 where JWT access tokens are used, RFC 9449 where DPoP sender constraint is used

## 1. Design rule

OpenIdentity is an authority/evidence source. OAuth remains the application-facing token protocol.

The bridge MUST NOT invent OpenIdentity replacements for OAuth scope, resource, audience, access tokens, refresh tokens, DPoP, or OIDC ID Tokens.

## 2. Roles

### 2.1 Non-delegated authentication

When an OpenIdentity identity acts for itself, an OI-015 Authentication Assertion is sufficient authentication evidence. An integration profile MAY use it as a token-exchange subject token if the authenticated identity is also the authorization subject.

### 2.2 Delegated authentication

When OI-014 delegation exists:

- the **subject** is the rootGrantor / party whose authority is being exercised;
- the **actor** is the currently authenticated delegate;
- OI-015 authenticates the actor;
- OI-014 proves the constrained authorization path from subject to actor.

Therefore the bridge SHOULD model:

    subject_token  = subject/root authority identity evidence
    actor_token    = OI-015 assertion for current delegate
    delegation evidence = OI-014 chain

OI-015 MUST NOT be interpreted as delegated authorization.

OI-014 MUST NOT be interpreted as proof that the current presenter controls the delegate identity; OI-015 provides that proof.

## 3. RFC 8693 token types

The bridge needs explicit token-type identifiers so an authorization server can dispatch validation correctly.

Candidate identifiers:

    urn:ietf:params:oauth:token-type:openidentity-authentication-assertion
    urn:ietf:params:oauth:token-type:openidentity-delegation-evidence

These are design identifiers only until registration/namespace strategy is resolved.

The first identifies exact canonical SecuredAuthenticationAssertion bytes.

The second identifies a bridge-defined canonical delegation-evidence envelope containing OI-014 material. It does not create new delegation semantics.

## 4. Subject token architecture — DECISION

Raw OI-014 delegation evidence MUST NOT be used directly as the RFC 8693 subject_token.

RFC 8693 requires subject_token to be a security token representing the identity of the party on whose behalf the request is made. OI-014 is authorization/delegation evidence: it names rootGrantor and proves an attenuated authority path, but it is not itself an authentication assertion for rootGrantor.

The bridge therefore defines a new **OpenIdentity Delegated Subject Token** concept.

Conceptually:

    OpenIdentityDelegatedSubjectToken {
        version
        subjectIdentity
        delegationEvidence
        terminalDelegate
        issuedFor
        contextCommitment
    }

The exact structure is not frozen.

Its semantics are:

- subjectIdentity MUST equal the verified OI-014 rootGrantor;
- terminalDelegate MUST equal the terminal delegate of the verified OI-014 chain;
- delegationEvidence MUST contain or cryptographically commit to the exact OI-014 material needed by the authorization server;
- the token represents the subject identity specifically in the context of the attached delegated authority;
- it MUST NOT imply that rootGrantor is online or freshly authenticated;
- it MUST NOT grant authority beyond the verified OI-014 chain.

This is a composite security token/profile for RFC 8693 purposes, not a replacement for OI-014.

Candidate token type identifier:

    urn:ietf:params:oauth:token-type:openidentity-delegated-subject

This identifier remains provisional until namespace/registration strategy is resolved.

No extra `openidentity_delegation` OAuth request parameter is needed in the preferred design.

## 5. Exchange binding

The OI-015 assertion used as actor_token MUST use:

    purpose = "openidentity.oauth.token-exchange"

Its audience MUST identify the authorization server according to the bridge profile.

Its contextHash MUST bind the exact exchange context.

Candidate context includes at least:

    authorization-server identifier
    OAuth client identifier
    requested resource value(s)
    requested audience value(s), if used
    requested scope
    requested_token_type
    subject-token commitment
    delegation-evidence commitment
    DPoP public-key thumbprint when the exchange requests DPoP binding

This prevents a valid OI-015 assertion prepared for one token exchange from being replayed with broader/different OAuth parameters.

The exact deterministic context encoding is not yet frozen.

## 6. subject_token — RESOLVED DIRECTION

For delegated exchange:

    subject_token_type =
      <OpenIdentity Delegated Subject Token type>

    subject_token =
      base64url-no-pad(OpenIdentityDelegatedSubjectTokenBytes)

The subject token is self-contained enough for the authorization server to identify the root subject and validate the OI-014 authorization path without requiring a fresh rootGrantor signature.

This preserves offline delegation:

    rootGrantor
        |
        | creates/registers OI-014 authority
        v
    delegate can later exchange
    without rootGrantor being online

The authorization server MUST validate the delegated subject token according to its OpenIdentity token-type profile and MUST perform complete OI-014 verification.

The token's subjectIdentity becomes the OAuth authorization subject only after that verification succeeds.

A non-delegated self exchange may instead use OI-015 as subject_token under a separate profile because the live actor and subject are the same party.

## 7. actor_token

For delegated exchange:

    actor_token_type =
      urn:ietf:params:oauth:token-type:openidentity-authentication-assertion

    actor_token =
      base64url-no-pad(SecuredAuthenticationAssertionBytes)

The authorization server:

1. decodes exact OI-015 bytes;
2. performs full current-state OI-015 verification;
3. obtains the authenticated actor identity;
4. verifies OI-014 delegation evidence;
5. requires the terminal delegate identity to equal the OI-015 actor identity.

A mismatch MUST reject the exchange.

## 8. OI-014 delegation verification

The bridge MUST perform complete OI-014 verification, including:

- rootGrantor identity;
- current registration/status requirements;
- ancestor chain integrity;
- delegation generation validity;
- capability attenuation;
- resource attenuation;
- time validity;
- depth/cycle rules;
- revocation/relinquishment status;
- terminal delegate identity.

OAuth token issuance MUST NOT increase authority beyond the verified OI-014 chain.

## 9. OAuth resource and audience

OAuth resource targeting remains governed by RFC 8707.

OpenIdentity resource constraints are authorization limits, not replacements for the OAuth resource parameter.

The bridge must define a deterministic mapping:

    requested OAuth resource
        MUST be permitted by
    OI-014 resource constraints

The bridge MUST reject widening.

For RFC 9068 JWT access tokens, the authorization server should follow the RFC 9068/RFC 8707 audience mapping rather than invent an OpenIdentity audience claim.

## 10. OAuth scope

OAuth scope remains an authorization-server/application vocabulary.

OI-014 capabilities do not automatically equal OAuth scope strings.

An integration profile defines:

    OI-014 capability -> allowed OAuth scope set

The requested scope MUST be a subset of the scopes permitted by the verified capability mapping.

Unknown/unmapped capabilities MUST NOT silently grant OAuth scopes.

## 11. JWT access-token projection

Where RFC 9068 JWT access tokens are issued:

- `sub` identifies the authorization subject/root authority according to deployment policy;
- `act` identifies the current actor;
- nested `act` MAY represent delegation history when appropriate;
- `aud` follows OAuth/RFC 8707/RFC 9068 rules;
- `scope` contains only OAuth scopes actually granted.

The access token is a projection of the authorization decision, not a replacement for canonical OI-014 evidence.

The bridge should avoid embedding the complete OI-014 chain in every access token unless a deployment specifically requires independently verifiable provenance at the resource server.

## 12. DPoP

DPoP is complementary.

OI-015 answers:

    who authenticated for this exchange?

OI-014 answers:

    what delegated authority does that actor possess?

DPoP answers:

    is the presenter of the OAuth token the holder of the key to which the token was bound?

If DPoP is required, the OI-015 contextHash SHOULD bind the DPoP JWK thumbprint used at the token endpoint so an attacker cannot reuse the OpenIdentity exchange evidence while substituting another DPoP key.

The authorization server still performs normal RFC 9449 validation and emits the standard confirmation binding.

## 13. OIDC

OIDC remains the login/session identity layer.

OI-015 may be used by an OpenID Provider as an authentication mechanism, but this bridge MUST NOT redefine ID Token semantics.

Delegation should normally affect OAuth authorization/access tokens, not rewrite the human identity semantics of an OIDC ID Token.

## 14. Authorization decision

Conceptually:

    authenticatedActor = verify(OI-015)
    delegation = verify(OI-014)

    require delegation.terminalDelegate == authenticatedActor

    allowedCapabilities = delegation.effectiveCapabilities
    allowedResources = delegation.effectiveResources

    requestedScopes = OAuth request.scope
    requestedResources = OAuth request.resource/audience

    require requestedScopes <= mapCapabilities(allowedCapabilities)
    require requestedResources <= mapResources(allowedResources)

    issue standard OAuth token

The bridge is an attenuation boundary. It MUST NOT manufacture authority.

## 15. AI-agent use

An AI agent can be a normal OpenIdentity identity with AuthenticationAuthority.

A human, company, workload, or another authorized principal can delegate constrained authority to the agent using OI-014.

The agent proves current control using OI-015.

The bridge converts that verified combination into short-lived standard OAuth tokens accepted by existing APIs.

No downstream API needs native OI-014/OI-015 support in the initial deployment model.

## 16. Initial threat model

The bridge must reject at least:

- actor_token identity differs from terminal OI-014 delegate;
- OI-015 prepared for another authorization server;
- OI-015 prepared for another token-exchange context;
- altered scope after OI-015 signing;
- altered resource/audience after OI-015 signing;
- substituted subject token;
- substituted OI-014 delegation chain;
- capability-to-scope widening;
- resource widening;
- expired/revoked/relinquished delegation;
- stale authentication generation;
- stale delegation generation;
- DPoP-key substitution when DPoP binding is requested;
- reuse of exchange evidence contrary to nonce/replay policy.

## 17. Resolved RFC 8693 interpretation

The bridge uses RFC 8693 delegation semantics rather than impersonation semantics.

For delegated exchange:

    subject_token = OpenIdentity Delegated Subject Token
                    (root subject + OI-014 authority evidence)

    actor_token   = OI-015 SecuredAuthenticationAssertion
                    (live terminal delegate authentication)

The authorization server MUST require:

    delegatedSubject.subjectIdentity
        == verified OI-014 rootGrantor

    delegatedSubject.terminalDelegate
        == verified OI-014 terminal delegate

    OI-015 identity
        == delegatedSubject.terminalDelegate

The issued token may project:

    sub = root subject
    act = current delegate

Nested act history is informational for prior actors; authorization decisions remain based on the top-level token claims/current actor as required by RFC 8693.

## 18. Remaining questions before assigning a new OI number

1. What exact fields belong in OpenIdentityDelegatedSubjectToken, and which are derived rather than serialized?
2. Does the subject token embed exact OI-014 chain bytes, a deterministic chain envelope, or references plus committed hashes?
3. What exact deterministic exchange-context structure is hashed by OI-015?
4. How should OpenIdentity token-type URIs be named before/after any IANA registration effort?
5. How are OI-014 capabilities mapped to OAuth scopes without a global capability/scope registry?
6. How are OI-014 resource constraints mapped to RFC 8707 absolute resource URIs?
7. What minimal JWT act projection preserves useful provenance without leaking unnecessary delegation history?
8. Is DPoP mandatory for agent/workload profiles or strongly recommended?
9. What authorization-server metadata advertises OpenIdentity token-exchange support?
10. What error mapping exposes OpenIdentity failures without leaking sensitive authorization details?
11. What maximum lifetime may an issued OAuth token have relative to OI-014 grant/ancestor expiration and OI-015 freshness?
12. Are refresh tokens ever permitted for delegated OpenIdentity exchanges?

No bridge wire format is frozen until these questions are resolved.
