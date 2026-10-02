# Spring Active Directory integration

`openidentity-spring-active-directory` integrates Microsoft Active Directory authentication with OpenIdentity through Spring Boot and Spring Security.

## Public application-facing API

Applications should treat these types as the supported integration surface:

- `OpenIdentityActiveDirectoryProperties` — Boot configuration under `openidentity.active-directory`.
- `OpenIdentityActiveDirectoryAuthentication` — immutable authentication result, including AD verification and OpenIdentity binding state.
- `OpenIdentityAdAuthenticationToken` — Spring Security authentication stored in the `SecurityContext`.
- `OpenIdentityActiveDirectoryService` — non-HTTP resolution API for callers that already possess a cryptographically established Kerberos principal.
- `OpenIdentityActiveDirectorySecurityConfigurer` — explicit integration point for applications that supply their own `SecurityFilterChain`.
- `ActiveDirectoryCredentialProvider` — optional application-provided LDAP secret source.

The default credential provider reads `OPENIDENTITY_LDAP_BIND_PASSWORD`. Applications may instead expose their own `ActiveDirectoryCredentialProvider` bean backed by a secret manager or platform credential facility.

## Binding semantics

An AD-authenticated principal that has not yet completed OpenIdentity linking is authenticated with `ROLE_AD_AUTHENTICATED` only. Its Spring principal is the Kerberos principal.

An ACTIVE binding receives both `ROLE_AD_AUTHENTICATED` and `ROLE_OPENIDENTITY`. Its Spring principal is the 64-hex OpenIdentity identity.

Applications MUST NOT treat `ROLE_AD_AUTHENTICATED` alone as proof of an OpenIdentity binding.

## Failure semantics

Malformed HTTP Negotiate input fails before directory resolution. GSS rejection results in a Negotiate authentication challenge. Directory, binding-integrity, policy, and state-repository failures are not converted into Kerberos challenges; they propagate as service failures so operational faults do not become credential loops.

## Security chain ownership

The SPNEGO filter is installed inside Spring Security only. Standalone servlet registration is disabled to prevent a second invocation outside `SecurityContextHolderFilter`.

When the module supplies the default `SecurityFilterChain`, unauthenticated access is challenged with `401 WWW-Authenticate: Negotiate`. Applications that define their own chain should apply `OpenIdentityActiveDirectorySecurityConfigurer` and provide compatible authorization and authentication-entry-point behavior.
