# OpenIdentity Spring Active Directory Integration Guide

This guide describes the supported v0.1 integration surface for authenticating Microsoft Active Directory users with Kerberos/SPNEGO, resolving the authenticated directory object over validated LDAPS, and resolving an existing OpenIdentity external-directory binding.

## What the module does

`openidentity-spring-active-directory` composes these boundaries:

```text
Windows domain user
  -> HTTP Negotiate / Kerberos
  -> Java GSS ticket verification
  -> authenticated Kerberos principal
  -> validated LDAPS lookup
  -> exact AD objectGUID octets
  -> External AD Binding v1 lookup
  -> Spring Security Authentication
```

The module does not treat a username supplied by an HTTP client as authentication evidence. The AD principal enters the OpenIdentity flow only after GSS establishes the Kerberos security context.

## Dependency

Add the OpenIdentity Spring Active Directory module using the same OpenIdentity version as the rest of the SDK:

```xml
<dependency>
  <groupId>org.openidentity</groupId>
  <artifactId>openidentity-spring-active-directory</artifactId>
  <version>0.1.0-SNAPSHOT</version>
</dependency>
```

## Active Directory prerequisites

The deployment needs:

- a Microsoft AD domain and reachable KDC;
- an HTTP service principal such as `HTTP/app.example.com@EXAMPLE.COM`;
- a service keytab containing the corresponding Kerberos service key;
- an LDAPS endpoint whose certificate chain and hostname are trusted by the JVM;
- an LDAP lookup account with only the directory permissions required by the resolver;
- a stable OpenIdentity directory identifier configured as `directory-id-hex`.

Use AES-capable Kerberos service credentials. Do not enable obsolete Kerberos encryption merely to accommodate an old service-account configuration.

The keytab, LDAP password, CA private key, and OpenIdentity authentication private keys are secrets and MUST NOT be committed to the application repository.

## Spring Boot configuration

```yaml
openidentity:
  active-directory:
    enabled: true
    kerberos:
      service-principal: HTTP/app.example.com@EXAMPLE.COM
      keytab: /run/secrets/openidentity-http.keytab
    ldap:
      profile-id: microsoft-ad
      host: dc01.example.com
      port: 636
      base-dn: DC=example,DC=com
      bind-principal: openidentity-ldap@example.com
      directory-id-hex: 000102030405060708090a0b0c0d0e0f
    bindings:
      state-directory: /var/lib/openidentity/state
      store: /var/lib/openidentity/ad-bindings.store
```

The default LDAP credential source is the environment variable:

```text
OPENIDENTITY_LDAP_BIND_PASSWORD
```

For a secret manager, expose an application bean instead:

```java
@Bean
ActiveDirectoryCredentialProvider activeDirectoryCredentials(MySecretManager secrets) {
    return () -> secrets.read("openidentity/ad/ldap-password");
}
```

## Default Spring Security behavior

If the application does not provide a `SecurityFilterChain`, the module supplies one that requires authentication for every request and uses:

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Negotiate
```

for the initial Kerberos challenge.

The SPNEGO filter is registered inside Spring Security only. Do not register it separately as a servlet filter.

## Custom SecurityFilterChain

Applications that define their own security chain should apply the supported configurer:

```java
@Bean
SecurityFilterChain security(
        HttpSecurity http,
        OpenIdentityActiveDirectorySecurityConfigurer openIdentityAd)
        throws Exception {

    http.with(openIdentityAd, config -> {});

    http.exceptionHandling(exceptions -> exceptions
        .authenticationEntryPoint((request, response, failure) -> {
            response.setHeader("WWW-Authenticate", "Negotiate");
            response.setStatus(401);
        }));

    http.authorizeHttpRequests(auth -> auth
        .requestMatchers("/openidentity/link/**").hasRole("AD_AUTHENTICATED")
        .requestMatchers("/api/**").hasRole("OPENIDENTITY")
        .anyRequest().authenticated());

    return http.build();
}
```

A custom chain owns its authorization policy and authentication entry point. It must preserve the HTTP Negotiate challenge semantics required by the browser/client.

## Authentication states

The module deliberately distinguishes two states.

### AD authenticated, OpenIdentity unbound

The Kerberos ticket and AD object have been verified, but no active OpenIdentity binding exists.

```text
principal: alice@EXAMPLE.COM
authority: ROLE_AD_AUTHENTICATED
binding:   UNBOUND
```

This state may access an application's linking workflow, but MUST NOT be treated as an OpenIdentity identity.

### Active OpenIdentity binding

The external AD principal resolves through an ACTIVE binding.

```text
principal: <64-hex OpenIdentity identity>
authorities:
  ROLE_AD_AUTHENTICATED
  ROLE_OPENIDENTITY
binding: ACTIVE
```

## Accessing the result

```java
@GetMapping("/whoami")
Map<String, Object> whoami(Authentication authentication) {
    OpenIdentityAdAuthenticationToken token =
        (OpenIdentityAdAuthenticationToken) authentication;

    OpenIdentityActiveDirectoryAuthentication result = token.result();

    return Map.of(
        "kerberosPrincipal", result.kerberosPrincipal(),
        "bound", result.bound(),
        "bindingStatus", result.bindingStatus().name()
    );
}
```

When `result.bound()` is true, `result.openIdentityId()` contains the 32-byte OpenIdentity identity.

## Non-HTTP use

Applications that already possess a cryptographically established Kerberos principal may use:

```java
OpenIdentityActiveDirectoryAuthentication result =
    activeDirectoryService.resolveEstablishedKerberosPrincipal(
        "alice@EXAMPLE.COM");
```

The caller is responsible for ensuring the supplied principal actually came from an established Kerberos security context. Do not pass arbitrary request usernames to this API.

## OI-015 linking

An UNBOUND AD principal requires an explicit OpenIdentity linking ceremony before it receives `ROLE_OPENIDENTITY`.

The application workflow should:

1. authenticate the AD principal;
2. resolve the exact directory `objectGUID`;
3. construct the External AD Binding v1 context;
4. obtain OI-015 authorization from the target OpenIdentity identity;
5. persist the resulting binding;
6. resolve subsequent authentications through that persistent binding.

The Microsoft reference sample demonstrates this workflow. The Spring AD module intentionally does not silently auto-link an AD account to an OpenIdentity identity.

## Failure behavior

- Missing credentials enter the normal HTTP Negotiate challenge.
- Malformed Negotiate input fails before AD resolution.
- GSS rejection causes another authentication challenge.
- LDAPS outages, binding-integrity failures, policy failures, and state-repository failures are service failures, not credential failures.
- An unavailable directory MUST NOT be converted into a repeated browser login prompt.

## Production deployment

Run the application under a dedicated low-privilege service identity. Grant it only the filesystem permissions required to read its keytab and runtime state.

Keep the keytab outside the application artifact and repository. Rotate Kerberos service credentials according to organizational policy.

Use JVM-trusted LDAPS with hostname verification. Do not disable TLS certificate validation.

Use an external/HA binding repository when moving beyond a single-node deployment; the current file-backed registry is suitable for the reference implementation and interoperability work but is not itself a distributed persistence design.

Protect OI-015 private authentication keys separately from the AD service host.

## Microsoft interoperability status

The v0.1 integration has been exercised end-to-end against Windows Server 2025 AD and a domain-joined Windows client, including AES-256 Kerberos, Edge HTTP Negotiate, Java GSS verification, validated LDAPS, exact binary `objectGUID` resolution, persistent External AD Binding v1 resolution, application restart, and resolution of the same OpenIdentity identity without repeating the OI-015 ceremony.

See `microsoft-ad-end-to-end-interoperability.md` for the recorded interoperability boundary and lab observations.
