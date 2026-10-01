# Microsoft Entra ID External OIDC Profile

Status: reference integration / development profile.

## Trust model

Microsoft Entra ID authenticates an external OIDC principal. It does not become an OpenIdentity controller, recovery authority, assertion authority, authentication authority, or delegation authority.

The frozen external identity lookup key remains the exact OIDC pair:

    (issuer, subject)

The Entra profile is single-tenant. The configured tenant-specific v2 issuer and approved client ID are required. Provider claims such as tid, oid, preferred_username, name, roles, groups, sid, idp, ver, and xms_cc are assurance/context inputs only and do not replace (issuer, subject).

## Binding ceremony

An unbound Entra principal cannot create an OpenIdentity binding by OIDC authentication alone.

Binding requires:

1. successful Entra OIDC authentication;
2. a selected existing OpenIdentity identity;
3. a fresh ExternalOidcBindingContext and challenge;
4. a fresh OI-015 audience and nonce;
5. an OI-015 assertion for purpose openidentity.external-oidc.bind;
6. verification against the identity's current canonical StateHash and AuthenticationAuthority;
7. matching authentication generation;
8. successful persistence of the resulting ExternalOidcBindingV1.

Private OpenIdentity authentication keys remain on the authenticator side and are never stored in the canonical public state or external OIDC binding store.

## Resolution

A subsequent Entra login resolves only when the stored binding passes integrity validation and all current policy checks: provider trust, exact issuer/subject lookup, approved client, active OpenIdentity identity, current authentication generation, expiry, and provider assurance.

Changing AuthenticationAuthority generation invalidates bindings created under an older generation.

## Persistence and replay

The development file-backed binding registry persists ACTIVE/REVOKED binding records and consumed binding challenges atomically. Consumed challenges survive process restart.

The development canonical state repository contains public state only. Development private controller/authentication seed files are separate and gitignored.

## Threat cases covered by automated tests

The Java suites cover successful binding plus fail-closed behavior for cross-account context substitution, wrong identity, wrong purpose, audience mutation, nonce mutation, context mutation, expired assertions, authentication-generation changes, completed challenge replay, reused challenges, conflicting bindings, exact issuer/subject mismatch, untrusted provider, disallowed client, inactive identity, insufficient assurance, binding expiry, revocation, persisted replay state, and binding-ID integrity.

## Reference sample

samples/spring-entra-oidc is a development reference, not a production account-management UI. It intentionally exposes only the resolved OpenIdentity identity, provider label, authentication mode, and binding status after successful resolution. It does not expose ID tokens, access tokens, Entra subject identifiers, session identifiers, or private OpenIdentity key material.
