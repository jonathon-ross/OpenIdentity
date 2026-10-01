# OpenIdentity External OIDC Identity Binding — Design Plan

**Status:** DESIGN-DRAFT; not frozen normative
**Purpose:** bind a verified external OpenID Connect account to an OpenIdentity identity without making the external provider an OpenIdentity authority or trust root.

## 1. Core decisions

- External OIDC proves authentication of an external account; OpenIdentity proves authority over an OpenIdentity identity.
- A valid external ID Token alone MUST NOT create, rotate, recover, control, or delegate an OpenIdentity identity.
- This is interoperability registry state, not canonical IdentityState and not a new core operation.
- The stable external account identifier is the exact validated tuple `(issuer, subject, clientId)` for v1. Email, UPN, username, phone, and display name MUST NOT be binding keys.

## 2. Who may create a binding

Creation requires BOTH:

1. verified control of the external OIDC subject through a normal validated OIDC login ceremony; and
2. current OpenIdentity authorization by the identity being bound.

An enterprise/deployment administrator MAY configure trusted issuers, tenants, clients, assurance requirements, or suspend an issuer, but MUST NOT unilaterally bind an external account to an OpenIdentity identity.

## 3. Binding record

Conceptually:

    ExternalOidcBinding {
        version
        bindingId
        identity
        issuer
        subject
        oidcClientId
        createdAt
        expiresAt?
        authenticationGeneration
        state
    }

`bindingId` is a domain-separated SHA2-256 Multihash commitment over deterministic canonical binding bytes. State is ACTIVE or REVOKED. A revoked BindingId never becomes active again.

`authenticationGeneration` binds the record to the AuthenticationAuthority generation current at creation. RESET_AUTHENTICATION therefore invalidates older bindings.

## 4. Creation ceremony

The RP first performs normal OIDC Authorization Code authentication and validates provider/issuer, signature/JWKS, iss, sub, aud/azp where applicable, exp, nonce, and PKCE/mix-up protections.

The OpenIdentity identity then authorizes the exact proposed binding under dedicated purpose `openidentity.external-oidc.bind`. The signed context commits to identity, exact issuer, exact subject, OIDC clientId, a binding nonce/challenge, current authentication generation, and requested expiration if present.

A generic login or token-exchange assertion MUST NOT be accepted as binding authorization.

The registry creates ACTIVE state only after both sides succeed. One active external tuple MUST NOT silently identify multiple OpenIdentity identities in the same deployment trust domain.

## 5. Authentication use

A later validated OIDC login may resolve `(iss, sub, clientId)` through an ACTIVE binding to an OpenIdentity identity. This proves only that the external account is an approved authentication bridge.

It MUST NOT imply controller, recovery, assertion, or delegation authority, and MUST NOT authorize mutation of OpenIdentity state or creation of delegation grants.

## 6. Revocation, reset, recovery

The OpenIdentity identity may revoke a binding under dedicated purpose `openidentity.external-oidc.revoke`.

A deployment administrator MAY disable an issuer or suspend use as local policy, but cannot transfer ownership or rewrite the binding to another identity.

RESET_AUTHENTICATION invalidates bindings from older authentication generations. Identity deactivation invalidates all bindings immediately.

External OIDC is NOT a protocol-level recovery authority in v1. Possession of an enterprise account, including an administrator-controlled account, is insufficient to recover or rotate an OpenIdentity controller.

## 7. Enterprise policy

Deployments may additionally require exact issuers/tenants/client IDs, approved signing algorithms, acr/amr values, authentication age, MFA, managed-device, or conditional-access signals.

Group, role, email-domain, and directory claims MUST NOT automatically create OpenIdentity delegation or authority. Enterprise authorization mapping is a separate explicit profile.

## 8. Federation

Static issuer pinning is sufficient for v1. OpenID Federation may later establish provider trust and metadata policy, but federation trust does not establish the user-to-OpenIdentity binding.

## 9. Initial Java boundaries

    ExternalOidcPrincipalVerifier -> VerifiedExternalOidcPrincipal
    ExternalOidcBindingRegistry  -> register / resolve / revoke
    ExternalOidcBindingAuthorizer -> verify bind/revoke OpenIdentity authorization

Spring Security integration SHOULD consume an already validated OIDC principal where possible rather than reimplement OIDC/JWT verification.

Microsoft Entra ID, Okta, Auth0, Keycloak, and other providers remain configuration/adapters around this generic OIDC boundary.

## 10. First conformance gates

Positive: B01 valid two-sided bind; B02 exact tuple resolves; B03 revoke blocks resolution; B04 authentication reset invalidates old binding.

Negative: BI01 same sub/different issuer; BI02 same issuer/different sub; BI03 different clientId; BI04 email-only match; BI05 invalid/stale OpenIdentity authorization; BI06 tuple mismatch; BI07 duplicate active tuple; BI08 revoked; BI09 stale authentication generation; BI10 deactivated identity; BI11 untrusted issuer; BI12 administrator-only attempted binding.

## 11. OI-015 authorization — DECISION

v1 reuses frozen OI-015 rather than defining another signature object.

BIND requires purpose `openidentity.external-oidc.bind`; REVOKE requires `openidentity.external-oidc.revoke`.

The OI-015 contextHash is the SHA2-256 Multihash of deterministic `ExternalOidcBindingContextV1` bytes defined in `spec/cddl/openidentity-external-oidc-binding-context-v1.cddl`.

The context domain-separates BIND from REVOKE and commits to the exact OpenIdentity identity, validated issuer, subject, OIDC clientId, registry ceremony challenge, expected AuthenticationAuthority generation, requested expiration, and BindingId for revocation.

The registry challenge is deliberately distinct from the OI-015 verifier nonce: the challenge identifies this binding transaction, while the OI-015 nonce retains its frozen verifier freshness/replay role.

This lets the profile inherit OI-015's current-state, AuthenticationPolicy, generation, threshold-signature, expiry, nonce, and replay semantics without creating a second authentication primitive.

## 12. Open questions before freeze

1. Keep clientId always in the v1 key, or distinguish public vs pairwise subjects from trusted metadata?
2. Mandatory binding lifetime, or permit non-expiring generation-bound bindings?
3. Registry uniqueness global per deployment or scoped to an issuer trust domain?
4. Which OIDC assurance claims, if any, belong in the resolved authentication result?