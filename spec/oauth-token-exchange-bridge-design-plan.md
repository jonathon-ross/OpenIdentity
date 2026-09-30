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

## 3. RFC 8693 token types — DECISION

RFC 8693 token type identifiers are URIs and permits token types beyond those registered by RFC 8693.

OpenIdentity v1 uses OpenIdentity-controlled HTTPS identifiers rather than unregistered values in the IETF URN namespace:

    subject_token_type =
      https://openidentity.org/oauth/token-type/delegated-subject-v1

    actor_token_type =
      https://openidentity.org/oauth/token-type/authentication-assertion-v1

The identifiers describe the exact frozen OpenIdentity token semantics, not merely a serialization format.

Binary OpenIdentity token bytes are transported in RFC 8693 form parameters using base64url without padding.

A future IETF/IANA-assigned identifier is an explicit profile revision/migration; implementations MUST NOT silently treat it as an alias unless that profile defines the equivalence.

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

## 18. Delegated subject evidence representation — DECISION

The OpenIdentity Delegated Subject Token uses a **hybrid exact-evidence envelope**.

It MUST carry enough exact canonical OI-014 material for the authorization server to independently reconstruct the delegation chain's immutable cryptographic commitments, while authoritative current-status data remains externally resolved.

### 18.1 Embedded immutable evidence — REFINED

The frozen OI-014 use-time algorithm determines the minimum authoritative evidence.

For every grant in the selected root-to-terminal chain, the delegated subject evidence MUST embed:

- exact canonical GrantBytes;
- GrantId.

The verifier MUST recompute GrantId from GrantBytes and require exact equality.

GrantBytes already commit to the immutable grant semantics required for ancestry and attenuation, including rootGrantor, issuer, delegate, capabilities/resources, time bounds, nonce, and parentGrantId where present.

The subject token MUST NOT require embedding direct-registration requests, child-registration requests, registration signatures, DelegationPolicy proofs, delegate proofs used during registration, revocation proofs, or relinquishment proofs merely to establish use-time authority. Those proofs authorize registry transitions; they are not part of the frozen OI-014 relying-party use-time evidence once authoritative registration state has been established.

Likewise, a historical RegisteredGrantState RecordBytes/RecordHash snapshot is NOT required as authoritative embedded evidence.

A profile MAY carry a record snapshot or RecordHash as a non-authoritative retrieval/cache hint, but the verifier MUST NOT treat that snapshot as current status.

### 18.2 Externally resolved current facts

The embedded evidence MUST NOT be treated as proof of current usability.

Before issuing OAuth authority, the authorization server MUST resolve and verify all current OI-014 facts required by the frozen OI-014 specification, including as applicable:

- current grant record revision/status;
- revocation;
- relinquishment;
- current root DelegationAuthority generation;
- ancestor usability;
- current root identity status;
- expiration/time validity;
- any registry-specific authoritative state required by OI-014.

A token containing a historically valid chain that is now revoked, relinquished, invalidated by generation change, or otherwise unusable MUST be rejected.

### 18.3 Why not GrantId references only

A GrantId-only token would require retrieval of the private/full GrantBytes before the authorization server could reconstruct grant semantics, parent links, capability/resource attenuation, or subject/actor identities.

Frozen OI-014 explicitly states that GrantId provides integrity, not availability, and that a verifier evaluating a grant must obtain enough material to reconstruct exact GrantBytes.

Embedding exact GrantBytes therefore removes that availability dependency for immutable authority content while preserving authoritative registry lookups for mutable status.

### 18.4 Why not embed registration proofs

Registration authorization proves that a registry transition was valid when established. The authoritative RegisteredGrantState is the resulting state commitment.

Re-verifying historical registration request signatures at every OAuth exchange would:

- substantially increase token size;
- duplicate work already represented by authoritative registration state;
- require retaining proof material that frozen OI-014 does not require relying parties to possess at use time;
- risk confusing historical registration authorization with current grant usability.

The OAuth bridge follows OI-014's frozen relying-party algorithm instead.

### 18.5 Why not snapshot-only

A self-contained historical snapshot cannot safely establish current delegated authority.

OI-014 deliberately supports later revocation, relinquishment, generation invalidation, deactivation, and ancestor invalidation. Treating embedded historical records as current would turn the subject token into a bearer delegation credential and would violate the current-state model.

Therefore:

    embedded bytes = immutable evidence
    authoritative lookup = current usability

Both are required.

### 18.6 Chain selection

The token carries one explicit root-to-terminal authorization path for the requested exchange.

It SHOULD NOT carry unrelated grants or alternate paths.

This minimizes disclosure and makes attenuation verification deterministic.

If multiple valid paths could authorize the same actor/capability, the client/bridge selects one path and the authorization server verifies that exact path. Path selection MUST NOT combine capabilities/resources from independent paths unless a future profile explicitly defines such composition.

## 19. Candidate logical object — REFINED

Conceptually:

    DelegationEvidence {
        version
        registryDomain
        grants[]
    }

    GrantEvidence {
        grantBytes
        grantId
    }

    OpenIdentityDelegatedSubjectToken {
        version
        delegationEvidence
        actorAssertionId
    }

For every GrantEvidence:

    recompute GrantId(grantBytes)
        == grantId

For each child:

    child.parentGrantId
        == parent.grantId

rootGrantor and terminalDelegate are derived from the verified GrantBytes chain and are not duplicated.

registryDomain appears once at DelegationEvidence level because the selected OI-014 path MUST remain within one authoritative registryDomain. The verifier MUST use that domain for every current RegisteredGrantState lookup.

At exchange time, for every embedded grant the authorization server retrieves the authoritative current record at:

    (registryDomain, grantId)

and performs the complete frozen OI-014 use-time algorithm.

Optional cached RecordBytes/RecordHash material is outside the normative DelegationEvidence v1 candidate shape unless later review finds a concrete interoperability need.

## 20. Exchange binding — DECISION

A direct two-way hash between the final Delegated Subject Token ID and OI-015 AssertionId would be circular:

    subjectTokenId -> AssertionId -> contextHash -> subjectTokenId

OI-016 MUST NOT rely on recursive/fixed-point hashing.

The bridge instead separates immutable delegation evidence identity from the final exchange-bound subject token.

### 20.1 DelegationEvidenceBytes

Define a deterministic pre-exchange evidence object containing exactly the selected OI-014 root-to-terminal chain material required by Section 18.

Conceptually:

    DelegationEvidence {
        version
        registryDomain
        chainEvidence[]
    }

    DelegationEvidenceBytes =
        deterministicCBOR(DelegationEvidence)

    DelegationEvidenceId =
        SHA2-256-Multihash(DelegationEvidenceBytes)

DelegationEvidenceId is stable for those exact submitted immutable chain bytes. It does not assert current usability.

### 20.2 OI-015 exchange context

The OI-015 actor assertion for token exchange uses:

    purpose = "openidentity.oauth.token-exchange"

Its profile-defined contextBytes MUST commit to:

    bridge context version
    authorization-server identifier
    OAuth client identifier
    requested_token_type
    requested resource value(s)
    requested audience value(s), when present
    requested scope representation
    DelegationEvidenceId
    DPoP JWK thumbprint, when DPoP is requested/required
    other profile-defined security-critical exchange parameters

Then:

    OI-015.contextHash =
        SHA2-256-Multihash(contextBytes)

This prevents delegation-evidence swapping and OAuth-request widening after actor authentication.

### 20.3 Final delegated subject token

After the OI-015 assertion exists, construct:

    OpenIdentityDelegatedSubjectToken {
        version
        delegationEvidence
        actorAssertionId
    }

where:

    actorAssertionId = OI-015 AssertionId

The final token therefore binds the exact delegation evidence to the exact actor authentication ceremony.

A verifier MUST require:

    subjectToken.actorAssertionId
        == derived AssertionId(actor_token)

and:

    actor_token.contextHash
        == hash(reconstructed exchange context containing
                DelegationEvidenceId(subjectToken.delegationEvidence))

This is bidirectional transaction binding without a circular hash.

### 20.4 Attack analysis

**Delegation swapping**

An attacker pairs a valid OI-015 actor assertion with different OI-014 evidence.

Result:

    DelegationEvidenceId changes
        -> reconstructed OI-015 contextHash changes
        -> actor assertion no longer matches

Reject.

**Authentication swapping**

An attacker pairs a valid delegated subject token with a different valid OI-015 assertion from the same actor.

Result:

    AssertionId changes
        -> subjectToken.actorAssertionId mismatch

Reject.

**OAuth request swapping**

An attacker changes requested scope, resource, audience, requested_token_type, client, authorization server, or bound DPoP key.

Result:

    reconstructed contextBytes changes
        -> contextHash mismatch

Reject.

**Evidence byte substitution with same semantic story**

Changing exact embedded grant/record bytes changes DelegationEvidenceBytes and therefore DelegationEvidenceId. Additionally OI-014 GrantId/RecordHash reconstruction must still succeed.

Reject.

### 20.5 What is deliberately not bound twice

The final subject token does not need to serialize rootGrantor or terminalDelegate merely for exchange binding. They remain derived from verified delegation evidence.

OAuth scope/resource strings are not copied into the subject token. They are committed through OI-015 contextHash and remain OAuth request semantics.

The DPoP proof itself is not embedded. The context commits to the expected DPoP public-key thumbprint, while normal RFC 9449 processing validates the actual DPoP proof.

### 20.6 Replay consequence

This construction binds evidence pieces together but does not by itself make an exchange single-use.

OI-015 nonce issuance/consumption and authorization-server replay policy remain required. The authorization server SHOULD reject replay of an already-consumed OI-015 AssertionId for token-exchange profiles.

The final OAuth token lifetime and refresh-token policy remain separate authorization-server decisions constrained by Section 22 questions.

## 21. Candidate logical layering

    OI-014 exact chain evidence
            |
            v
    DelegationEvidenceBytes
            |
            v
    DelegationEvidenceId
            |
            +-----------------------------+
            |                             |
            v                             |
    OI-015 contextBytes                   |
    + OAuth request parameters            |
    + optional DPoP thumbprint            |
            |                             |
            v                             |
    OI-015 AuthenticationAssertion        |
            |                             |
            v                             |
       AssertionId                        |
            |                             |
            +----------+                  |
                       v                  |
          DelegatedSubjectToken           |
          { evidence, AssertionId } <------+
                       |
                       v
             RFC 8693 subject_token

    OI-015 SecuredAuthenticationAssertion
                       |
                       v
             RFC 8693 actor_token

## 22. OI-014 evidence requirements — RESOLVED

The delegated subject token needs:

    exact GrantBytes + GrantId for every selected path element
    one registryDomain for the whole path

It does NOT need, as normative embedded authority evidence:

    registration request bytes
    registration signatures/proofs
    child-registration delegate proofs
    revocation/relinquishment proofs
    historical RecordBytes/RecordHash snapshots

Current RegisteredGrantState is retrieved authoritatively at exchange time for every GrantId.

This directly follows frozen OI-014's distinction:

    GrantId / GrantBytes = immutable authority intent
    RecordHash / RegisteredGrantState = current authoritative registration/status state

## 23. Remaining questions before assigning a new OI number

1. What exact deterministic CBOR schema/labels define DelegationEvidence, GrantEvidence, and DelegatedSubjectToken?
2. What exact canonical representation/order is used for OAuth scope, resource, and audience collections inside OI-015 contextBytes?
3. How should OpenIdentity token-type URIs be named before/after any IANA registration effort?
4. How are OI-014 capabilities mapped to OAuth scopes without a global capability/scope registry?
5. How are OI-014 resource constraints mapped to RFC 8707 absolute resource URIs?
6. What minimal JWT act projection preserves useful provenance without leaking unnecessary delegation history?
7. Is DPoP mandatory for agent/workload profiles or strongly recommended?
8. What authorization-server metadata advertises OpenIdentity token-exchange support?
9. What error mapping exposes OpenIdentity failures without leaking sensitive authorization details?
10. What maximum lifetime may an issued OAuth token have relative to OI-014 grant/ancestor expiration and OI-015 freshness?
11. Are refresh tokens ever permitted for delegated OpenIdentity exchanges?

No bridge/delegated-subject wire format is frozen until these questions are resolved.
