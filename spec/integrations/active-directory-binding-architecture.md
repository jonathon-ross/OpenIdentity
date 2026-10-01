# External Authentication Binding Architecture

Status: design investigation. This document does not modify or supersede ExternalOidcBindingV1.

## Decision

OpenIdentity external authentication integrations SHALL share a provider-neutral orchestration layer, but each authentication protocol SHALL retain a protocol-specific binding object and verifier.

ExternalOidcBindingV1 remains frozen and unchanged.

Active Directory SHALL NOT be encoded as a synthetic OIDC issuer/subject pair.

## Common orchestration

All external authentication profiles share these invariants:

1. external authentication proves control of an external account; it does not grant OpenIdentity authority by itself;
2. an existing OpenIdentity AuthenticationAuthority authorizes creation/revocation of the external binding through OI-015;
3. binding context commits to the exact provider-specific identity key and policy-relevant fields;
4. current OpenIdentity identity status and AuthenticationAuthority generation are checked at resolution time;
5. provider trust, account usability, client/service policy, expiry, revocation, and assurance are re-evaluated at resolution;
6. private OpenIdentity authentication keys never enter the provider adapter or binding store.

A provider-neutral service may expose begin/complete/revoke/resolve operations, but MUST delegate canonical binding bytes, identity-key equality, provider proof validation, and provider-specific policy to the selected profile.

## Microsoft Active Directory profile

### Stable external identity key

The AD profile uses a tuple:

    (directoryId, objectGUID)

where:

- directoryId is an OpenIdentity configuration identifier for one explicitly trusted AD forest/directory security boundary;
- objectGUID is the exact 128-bit AD objectGUID value returned by the trusted directory.

DN, CN, sAMAccountName, displayName, mail, and userPrincipalName MUST NOT be the binding identity key.

objectSID MAY be captured as policy/audit context, but is not the primary binding key in v1.

### Why directoryId exists

objectGUID identifies an object inside an AD directory but does not by itself name the trusted directory/forest from which it came. OpenIdentity therefore scopes objectGUID with an explicit configured directoryId rather than relying on DNS names or user-controlled naming attributes as an implicit trust boundary.

directoryId is local OpenIdentity policy/configuration, not an AD user attribute.

### Authentication proof

LDAP search alone is not authentication.

An AD adapter must first establish an authenticated security context accepted by the configured AD profile. Initial implementations may support:

- Kerberos/SPNEGO authenticated context; or
- LDAP authentication over a protected channel under an explicit deployment policy.

The adapter then resolves the authenticated account to objectGUID from a trusted domain controller.

The binding context commits to directoryId, objectGUID, service/client identifier, authentication mechanism, creation/expiry times, current OpenIdentity AuthenticationAuthority generation, and a fresh challenge.

### Transport requirements

Production profiles MUST reject anonymous/unsigned cleartext authentication flows.

LDAP deployments must use a transport/authentication configuration providing integrity and appropriate peer authentication, such as LDAP signing with SASL/Kerberos or TLS/LDAPS according to deployment policy. Certificate validation must include the expected domain-controller name when TLS is used.

### Resolution

A subsequent AD authentication resolves a binding only after:

1. authenticated AD security context succeeds;
2. trusted directory profile is selected;
3. exact objectGUID is obtained from the trusted directory;
4. an ACTIVE binding for (directoryId, objectGUID) exists and passes integrity checks;
5. OpenIdentity identity remains ACTIVE;
6. AuthenticationAuthority generation equals the binding generation;
7. service/client policy permits the relying application;
8. AD account/provider assurance policy remains sufficient.

### Account lifecycle

Rename/move does not change the binding because DN is not the key.

If an AD account is deleted and a different account is later created with the same human-readable name, it must not inherit the binding because it has a different objectGUID.

Disabled/locked/expired account handling is profile policy and must fail closed when configured as unusable.

## Proposed AD v1 binding

Conceptual fields:

    version
    identity[32]
    directoryId
    objectGuid[16]
    serviceId
    createdAt
    expiresAt?
    authenticationGeneration

The exact CDDL, canonical CBOR integer labels, context schema, error taxonomy, and test vectors must be designed and frozen separately before implementation.

## Non-goals

This design does not:

- synchronize AD passwords into OpenIdentity;
- store Kerberos tickets or NTLM secrets in OpenIdentity bindings;
- make a domain controller an OpenIdentity authority;
- infer OpenIdentity identity from UPN/email/DN;
- alter ExternalOidcBindingV1;
- define cross-forest trust semantics implicitly.

Cross-forest and multi-domain behavior requires explicit directory-profile policy.
