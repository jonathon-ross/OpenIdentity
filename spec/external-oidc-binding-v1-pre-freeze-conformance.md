# OpenIdentity External OIDC Identity Binding v1

**Status:** FROZEN-NORMATIVE v1
**Profile identifier:** https://openidentity.org/interop/external-oidc-binding-v1

## 1. Scope

This profile binds an already-validated OpenID Connect federated identifier to an OpenIdentity identity. It is interoperability registry state, not canonical OpenIdentity IdentityState and not a core operation.

The external identity key is the exact OIDC issuer and subject pair. clientId is mandatory RP/provenance context but is not part of the identity key.

## 2. Deterministic encoding and identifiers

All normative CBOR uses RFC 8949 Core Deterministic Encoding Requirements plus OpenIdentity cryptographic-agility restrictions.

BindingBytes is deterministic CBOR of ExternalOidcBindingV1:

    {
      1: 1,
      2: identity bytes (32),
      3: exact issuer text,
      4: exact subject text,
      5: clientId text,
      6: createdAt uint64,
      7: expiresAt uint64 or nil,
      8: authenticationGeneration uint64
    }

Text fields are non-empty valid UTF-8. This profile performs no Unicode normalization, case folding, URL rewriting, trailing-slash rewriting, tenant aliasing, or provider-specific canonicalization.

BindingId is the SHA2-256 Multihash of deterministic CBOR of the array containing the domain string "OpenIdentity External OIDC Binding", version 1, and exact BindingBytes.

The multihash representation is 0x12, 0x20, then the 32-byte digest.

Registry uniqueness is over the exact issuer and subject tuple.

## 3. Authoritative registry state

Conceptually RegisteredExternalOidcBindingState contains BindingId, exact BindingBytes, status, registeredAt, and optional revokedAt.

Status is ACTIVE or REVOKED. REVOKED is terminal for that BindingId.

The registry retains enough immutable evidence to recompute BindingId and atomically enforces at most one OpenIdentity identity for an exact active issuer+subject key.

## 4. Binding authorization context

ExternalOidcBindingContextV1 is defined by spec/cddl/openidentity-external-oidc-binding-context-v1.cddl.

BIND uses action 1 and OI-015 purpose openidentity.external-oidc.bind. REVOKE uses action 2, requires the exact BindingId, and uses purpose openidentity.external-oidc.revoke.

OI-015 contextHash is the SHA2-256 Multihash of exact deterministic ContextBytes.

## 5. BIND algorithm

1. Establish trusted OIDC provider configuration and expected issuer.
2. Complete normal OIDC authentication and obtain an already-validated principal.
3. Require exact non-empty issuer and subject.
4. Require clientId/RP context allowed by deployment policy.
5. Establish a fresh single-ceremony registryChallenge and fix proposed createdAt before authorization.
6. Construct exact BIND context including proposed createdAt and expiresAt.
7. Verify OI-015 completely against current OpenIdentity state, policy, audience, purpose, time, nonce, generation and contextHash.
8. Require assertion identity equal proposed identity.
9. Apply requested-expiration policy without changing the signed createdAt/expiresAt values.
10. Construct exact BindingBytes from the values already committed by the BIND context and derive BindingId.
11. Atomically enforce external-subject uniqueness.
12. Consume challenge and replay state.
13. Store immutable evidence and ACTIVE state.

No ACTIVE binding exists until all checks succeed.

## 6. REVOKE algorithm

Resolve BindingId; require ACTIVE; recompute its ID; require the bound identity currently ACTIVE; construct exact REVOKE context with fresh challenge/current generation/exact BindingId; completely verify OI-015 with revoke purpose; atomically transition ACTIVE to REVOKED; consume challenge/replay state.

A revoked BindingId never returns to ACTIVE.

## 7. RESOLVE algorithm

After normal OIDC validation yields a current trusted principal: require provider trusted; look up exact issuer+subject; require one ACTIVE binding; recompute BindingId; require OpenIdentity identity ACTIVE; require stored authenticationGeneration equals current generation; enforce expiresAt when present; require clientId context allowed; apply current authentication freshness/assurance policy; return ResolvedExternalOidcAuthentication.

Resolution never grants controller, recovery, assertion, or delegation authority.

## 8. Resolved authentication result

Conceptually contains identity, BindingId, issuer, subject, clientId, optional authenticatedAt, optional acr, amr values, and providerAssurance. Assurance is transient request/session evidence.

## 9. Failure behavior and stable labels

Public surfaces should not reveal binding ownership or detailed OpenIdentity state. Normative internal conformance labels are:

OIDC_PROVIDER_UNTRUSTED; OIDC_PRINCIPAL_INVALID; OIDC_CLIENT_NOT_ALLOWED; BINDING_CHALLENGE_INVALID; BINDING_AUTHORIZATION_INVALID; BINDING_CONTEXT_MISMATCH; BINDING_GENERATION_STALE; BINDING_EXPIRED; BINDING_CONFLICT; BINDING_NOT_FOUND; BINDING_REVOKED; BINDING_ID_MISMATCH; IDENTITY_INACTIVE; ASSURANCE_INSUFFICIENT; BINDING_REPLAY.

## 10. Candidate conformance vectors

Successful-operation vectors: B01 valid bind and exact BindingId; B02 exact resolution; B03 revoke; B05 multiple distinct external subjects may bind one identity; B06 permitted alternate client context resolves without another identity binding.

Expected-rejection lifecycle vector: B04 generation reset invalidates the old binding with BINDING_GENERATION_STALE.

Invalid: BI01 different issuer; BI02 different subject; BI03 disallowed client context; BI04 email-only match; BI05 invalid OI-015; BI06 issuer context mismatch; BI07 subject mismatch; BI08 client context mismatch; BI09 duplicate active external subject owned by another identity; BI10 revoked; BI11 stale generation; BI12 inactive identity; BI13 untrusted issuer; BI14 administrator-only attempted binding; BI15 BindingId mismatch; BI16 expired; BI17 stale/replayed registry challenge; BI18 bind authorization replay; BI19 bind-purpose assertion used for revoke; BI20 revoke-purpose assertion used for bind; BI21 revoke names another BindingId; BI22 insufficient use-time assurance; BI23 malformed/non-deterministic BindingBytes.

## 11. Frozen v1 conformance gate

Frozen v1 was gated on CDDL/prose agreement; independent Python and Java reproduction of BindingBytes, BindingId, ContextBytes and ContextHash; executable semantic rejection vectors with stable labels; independently verified checksum manifests; and a green Java SDK reactor. Frozen artifacts MUST NOT be regenerated or modified in place. Any normative wire or semantic change requires a new explicitly versioned profile.
