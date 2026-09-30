# OI-015 Authentication Assertion — Design Plan

**Status:** Design draft; non-normative  
**Target:** protocol-neutral proof of current OpenIdentity authentication and verifier-bound intent  
**Depends on:** ProtocolVersion 2 / IdentityState v3 (FROZEN-NORMATIVE), OI-009 deterministic serialization, OI-010 signature-domain principles, OI-011 StateHash  
**Explicitly does not replace:** OAuth 2.0/OIDC, DPoP, WebAuthn, SPIFFE, access tokens, credentials, or OI-014 delegation

## 1. Problem

OpenIdentity has a frozen current AuthenticationAuthority but no portable core object that lets an identity prove to an external verifier:

> I am OpenIdentity identity X, and I can satisfy X's exact current AuthenticationAuthority for this verifier, this purpose, this challenge, this context, and this short time window.

OI-014 answers a different question: what authority has been delegated to an actor. OI-015 MUST remain authentication-only.

## 2. Core separation

    OI-015 = who is acting / current authentication / intent
    OI-014 = what authority the actor has / delegation provenance
    OAuth  = application-facing authorization token transport
    DPoP   = possession/presentation binding for OAuth tokens

An OI-015 assertion MUST NOT itself grant application capability, role, scope, resource access, or delegation.

## 3. Proposed logical model

    AuthenticationAssertion {
        version
        identity
        stateHash
        authenticationGeneration
        audience
        purpose
        issuedAt
        expiresAt
        nonce
        contextHash
    }

    SecuredAuthenticationAssertion {
        assertion
        proofs[]
    }

Proofs are evaluated against the AuthenticationPolicy committed by the exact current IdentityState identified by stateHash.

## 4. Candidate field decisions

### 4.1 version

Initial version is 1.

The assertion version identifies the OI-015 assertion schema, not the OpenIdentity protocolVersion or IdentityState version.

### 4.2 identity

Exactly 32 bytes using the frozen OpenIdentity identity identifier representation.

The asserted identity MUST equal the identity in the authoritative IdentityState used during verification.

### 4.3 stateHash

An OI-011 SHA2-256 Multihash of exact deterministic StateBytes.

The verifier MUST require this to equal the exact current authoritative StateHash. Historical-state authentication is invalid even when a historical key can still produce a valid signature.

### 4.4 authenticationGeneration

uint64 equal to current AuthenticationAuthority.generation.

This gives explicit security-reset semantics and a stable rejection reason distinct from StateHash mismatch.

### 4.5 audience

Bounded opaque bytes.

Candidate bounds:

    audience = bstr .size (1..2048)

Core performs exact byte equality only.

An integration profile defines how its verifier identifier is converted to these bytes. Examples may include a UTF-8 authorization-server identifier, SPIFFE trust-domain/verifier identifier, or a deployment-local service identifier.

Core MUST NOT normalize URI, DNS, tenant, application, or platform identifiers.

### 4.6 purpose

Bounded UTF-8 text used for domain separation between authentication uses.

Candidate bound:

    purpose = tstr .size (1..255)

Examples:

    openidentity.authentication
    openidentity.oauth.token-exchange
    openidentity.workload-federation

Purpose is not authorization. It identifies why the verifier requested authentication.

Purpose comparison is exact Unicode/UTF-8 value equality after canonical CBOR decoding. Profiles SHOULD use stable lowercase ASCII domain-style identifiers.

### 4.7 issuedAt / expiresAt

Unsigned Unix seconds.

Core rules:

    issuedAt < expiresAt
    expiresAt - issuedAt <= 300 seconds

A profile MAY impose a smaller maximum.

The verifier MAY allow a small explicitly configured clock-skew tolerance when comparing current time, but skew MUST NOT increase the signed assertion lifetime itself.

Assertions are short-lived authentication ceremonies, not credentials.

### 4.8 nonce

Opaque verifier challenge:

    nonce = bstr .size (16..128)

For challenge-response use, the verifier generates the nonce using a cryptographically secure random source and MUST require exact equality.

The nonce is deliberately not fixed at 32 bytes so integration profiles can bind existing challenge formats without lossy reinterpretation.

Profiles supporting noninteractive federation MUST define equivalent replay prevention and nonce issuance/acceptance semantics. They MUST NOT silently treat nonce as claimant-selected uniqueness.

### 4.9 contextHash

OI-011 SHA2-256 Multihash over exact profile-defined context bytes.

Core does not interpret the context bytes.

Profiles MUST define deterministic context construction. Examples:

    OAuth token exchange:
        authorization server + client + exchange parameters

    workload federation:
        trust domain + workload target + federation transaction

    HTTP ceremony:
        method + target + request/body commitment

The verifier reconstructs the expected context bytes, hashes them, and requires exact contextHash equality.

Using a hash rather than embedding arbitrary context keeps the core assertion bounded and avoids importing external protocol structures into the OI-015 schema.

## 5. Assertion identity

Candidate:

    AssertionBytes = deterministicCBOR(AuthenticationAssertion)

    AssertionId =
        0x12 || 0x20 || SHA-256(AssertionBytes)

AssertionId is content identity, not replay authorization. A verifier still enforces nonce/time/current-state requirements.

## 6. Authentication signing domain

Each AuthenticationPolicy proof signs deterministic CBOR of:

    [
      "OpenIdentity Authentication Assertion",
      1,
      AssertionBytes,
      verificationMethodId
    ]

Every proof signs the same AssertionBytes.

The verificationMethodId suffix binds each signature to its intended AuthenticationPolicy method and follows existing OpenIdentity purpose-specific proof conventions.

Proof ordering MUST be canonical by verificationMethodId.

Duplicate method IDs are invalid.

All supplied proofs MUST be authorized methods and cryptographically valid. Threshold satisfaction alone MUST NOT excuse unauthorized, duplicate, or invalid extra proofs.

## 7. Verification algorithm

Given SecuredAuthenticationAssertion S and verifier expectations E:

1. deterministically parse and validate the secured assertion;
2. require assertion version 1;
3. validate identity, audience, purpose, nonce, time, and contextHash shapes;
4. resolve the exact current authoritative IdentityState for assertion.identity;
5. require current status ACTIVE;
6. compute current StateHash and require equality with assertion.stateHash;
7. require current AuthenticationAuthority.generation == assertion.authenticationGeneration;
8. require current AuthenticationPolicy present;
9. require assertion.audience == E.audience exactly;
10. require assertion.purpose == E.purpose exactly;
11. require assertion.nonce == E.nonce exactly;
12. require issuedAt < expiresAt and signed lifetime <= 300 seconds;
13. require current time to be within the accepted signed interval, subject only to configured clock skew;
14. reconstruct E.contextBytes according to the integration profile;
15. compute its SHA2-256 Multihash and require equality with assertion.contextHash;
16. reconstruct AssertionBytes exactly;
17. verify canonical proof ordering and uniqueness;
18. require every supplied proof method to belong to current AuthenticationPolicy;
19. verify every supplied signature over the OI-015 signing domain;
20. require current AuthenticationPolicy satisfaction.

Any failure rejects authentication.

## 8. Current-state rule

OI-015 is not a bearer credential and is not independently valid from historical state.

A previously signed assertion becomes unusable if, before verification:

- IdentityState becomes DEACTIVATED;
- RESET_AUTHENTICATION changes authenticationGeneration;
- RECOVER resets AuthenticationAuthority;
- a security-invalidating AuthenticationPolicy transition changes generation;
- current StateHash otherwise differs from the assertion's StateHash.

A generation-preserving planned AuthenticationPolicy rotation still changes StateHash. Therefore a proof prepared under the old exact state is stale for a new verification ceremony.

## 9. Replay model

Audience, purpose, nonce, time, contextHash, and current-state binding are independent defenses.

Nonce reuse policy is verifier/profile responsibility, but challenge-response profiles MUST consume or otherwise prevent replay of accepted nonce ceremonies.

AssertionId MUST NOT be treated as sufficient replay prevention.

An assertion valid for one audience or purpose MUST NOT be accepted for another.

## 10. Privacy and correlation

The assertion necessarily exposes a stable root identity identifier and exact StateHash to its verifier.

Therefore:

- assertions SHOULD be disclosed only to intended verifiers;
- assertions SHOULD NOT be logged unnecessarily;
- context bytes SHOULD remain outside the core assertion when disclosure is unnecessary;
- profiles SHOULD avoid embedding unrelated personal information in audience, purpose, nonce, or context;
- OI-015 v1 does not claim unlinkability or selective disclosure.

Future privacy-preserving authentication MUST use explicit protocol evolution/profile work rather than weakening these bindings.

## 11. Relationship to existing standards

### OAuth / JWT assertions

OAuth JWT assertion profiles already use audience and expiration and may use unique identifiers for replay handling. OI-015 reuses those security concepts but remains deterministic-CBOR/OpenIdentity-native and binds current StateHash + AuthenticationAuthority generation.

An OAuth bridge may translate a verified OI-015 result into standards-compliant OAuth client/token-exchange behavior. OAuth claims are projections/integration data, not OI-015 authority.

### DPoP

DPoP proves possession of a client-selected key for OAuth request/token sender constraint. DPoP is not itself identity authentication or access control.

OI-015 MUST NOT replace DPoP. An OAuth integration may require both:

    OI-015 -> authenticate current OpenIdentity actor
    OI-014 -> establish delegated authority
    DPoP   -> bind resulting OAuth token to presenter key

### OpenID Connect

OIDC ID Tokens remain application-facing assertions from an OpenID Provider. OI-015 may be one authentication mechanism used by an OP; it is not a replacement ID Token.

### WebAuthn/passkeys

WebAuthn may eventually be represented through an AuthenticationPolicy method/profile or gateway. OI-015 does not redefine WebAuthn ceremonies.

### SPIFFE/workload identity

SPIFFE identities may integrate through profile/gateway mechanisms. OI-015 does not replace SVIDs or SPIFFE trust domains.

### Microsoft Entra / enterprise federation

An OpenIdentity federation service may verify OI-015 and then participate in Entra-supported federation/token mechanisms. Tenant/client/application identifiers belong to the integration profile/context, not core OI-015 fields.

## 12. OI-014 composition

Typical delegated OAuth flow:

    Actor
      |
      | OI-015
      v
    current actor authentication
      |
      | OI-014
      v
    delegated authority + provenance
      |
      v
    OAuth bridge
      |
      v
    standard short-lived access token

OI-015 MUST NOT embed an OI-014 GrantId or delegation chain in core v1. Integration profiles may bind a delegation transaction through contextHash.

This keeps authentication reusable for non-delegated scenarios.

## 13. Initial stable error taxonomy

Candidate semantic errors:

    INVALID_AUTHENTICATION_ASSERTION
    INVALID_ASSERTION_VERSION
    IDENTITY_MISMATCH
    IDENTITY_NOT_ACTIVE
    INVALID_STATE_HASH
    INVALID_AUTHENTICATION_GENERATION
    AUTHENTICATION_POLICY_ABSENT
    AUDIENCE_MISMATCH
    PURPOSE_MISMATCH
    NONCE_MISMATCH
    INVALID_TIME_RANGE
    ASSERTION_LIFETIME_EXCEEDED
    ASSERTION_NOT_YET_VALID
    ASSERTION_EXPIRED
    CONTEXT_HASH_MISMATCH
    INVALID_PROOF_SET
    DUPLICATE_AUTHENTICATION_PROOF
    UNAUTHORIZED_AUTHENTICATION_PROOF
    INVALID_AUTHENTICATION_SIGNATURE
    AUTHENTICATION_POLICY_NOT_SATISFIED

Parser/structural errors may be separated from semantic errors during CDDL work.

## 14. Positive vector plan

Initial candidates:

- AA01 SINGLE AuthenticationPolicy assertion;
- AA02 THRESHOLD AuthenticationPolicy assertion with canonical proof ordering;
- AA03 exact 300-second lifetime boundary;
- AA04 integration-specific opaque audience bytes;
- AA05 generation-preserving current-state assertion after planned AuthenticationPolicy rotation;
- AA06 contextHash-bound OAuth-style exchange fixture.

## 15. Adversarial vector plan

High-priority invalids:

- AAI01 historical StateHash / valid historical signature;
- AAI02 stale authentication generation;
- AAI03 DEACTIVATED identity;
- AAI04 AuthenticationPolicy absent;
- AAI05 wrong audience;
- AAI06 wrong purpose;
- AAI07 wrong nonce;
- AAI08 context substitution;
- AAI09 expiresAt <= issuedAt;
- AAI10 lifetime > 300 seconds;
- AAI11 expired assertion;
- AAI12 assertion not yet valid;
- AAI13 proof from ControllerPolicy instead of AuthenticationPolicy;
- AAI14 duplicate proof method;
- AAI15 unauthorized extra proof despite threshold satisfaction;
- AAI16 invalid signature;
- AAI17 insufficient threshold;
- AAI18 cross-purpose replay;
- AAI19 cross-audience replay;
- AAI20 recovery/reset invalidates previously prepared assertion.

## 16. Questions to resolve before CDDL

1. Should the accepted time rule be exactly `issuedAt <= now < expiresAt`, with clock skew applied only as verifier policy, or should skew semantics be normative?
2. Should assertion lifetime maximum 300 seconds be core normative or profile-controlled with a core upper ceiling?
3. Should purpose be constrained to ASCII rather than arbitrary UTF-8 to remove Unicode-equivalence hazards?
4. Should audience remain arbitrary opaque bytes or receive an optional typed envelope in v1?
5. Should contextHash permit only SHA2-256 Multihash in v1, matching current StateHash discipline?
6. Should AssertionId be normative even though verification does not require it?
7. Do we need a separate verifier-challenge object, or is out-of-band nonce issuance intentionally sufficient for v1?

No OI-015 wire labels are frozen until these questions are resolved adversarially.

## 17. Freeze discipline

OI-015 development MUST NOT modify frozen Protocol v2 / IdentityState v3 or OI-014 v1 bytes.

Any discovered need to alter those frozen components requires explicit protocol/version evolution.

OI-015 begins as draft/non-normative and receives its own deterministic vectors, independent implementation verification, checksum, and release gate before normative promotion.
