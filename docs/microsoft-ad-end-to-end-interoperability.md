# Microsoft Active Directory end-to-end interoperability

Status: **verified interoperability milestone; not a normative protocol artifact**

## Verified environment

The interoperability lab used Windows Server 2025 Active Directory Domain Services with domain `oi-test.internal`, a domain-joined Windows 11 Pro client, Java 21, and the OpenIdentity Java SDK.

The verified authentication and resolution path was:

1. A domain user authenticated to Windows and received a Kerberos TGT from Microsoft AD.
2. Edge performed HTTP Negotiate for `HTTP/openidentity.oi-test.internal`.
3. Microsoft AD issued an AES-256 Kerberos service ticket.
4. OpenIdentity's Java GSS acceptor verified the SPNEGO token using a protected service keytab.
5. GSS established the authenticated principal `alice@OI-TEST.INTERNAL`.
6. That authenticated principal became `AdAuthenticationEvidence`; no HTTP-supplied username was trusted independently.
7. `LdapAdPrincipalResolver` connected to Microsoft AD over LDAPS with JVM CA-chain and hostname validation.
8. LDAP returned the exact binary `objectGUID` octets.
9. Those octets became the external principal key used by frozen External AD Binding v1.
10. OI-015 authorized the initial binding to an OpenIdentity identity.
11. The binding was persisted.
12. After application restart, a new Kerberos authentication plus LDAPS lookup resolved the same persistent OpenIdentity identity without another OI-015 ceremony.

## objectGUID interoperability observation

For the lab account, Microsoft displayed the GUID as:

`0eb3e20a-ec9d-42df-b5d5-2e854a81ec20`

The exact LDAP `objectGUID` octets were:

`0ae2b30e9decdf42b5d52e854a81ec20`

Java retrieved the same exact 16 LDAP octets. This empirically validates the frozen protocol rule that the external AD principal identifier uses the LDAP attribute octets rather than bytes inferred from textual GUID formatting.

## Security properties exercised

- Kerberos/SPNEGO was cryptographically accepted by Java GSS.
- The HTTP service ticket used AES-256; RC4 was not enabled in Java as a workaround.
- The HTTP SPN had a single AD owner.
- Service credentials were supplied at runtime and were not committed.
- LDAPS used JVM trust-chain validation and hostname verification.
- The Microsoft LDAP signing requirement remained enabled.
- The keytab was kept outside the repository.
- The OpenIdentity authentication private key remained outside the AD application host.
- Initial external binding required OI-015 authorization.
- Persistent binding resolution rechecked OpenIdentity identity activity and AuthenticationAuthority generation through the binding policy.

## Trust boundaries

The keytab authenticates the HTTP service to Kerberos; it is not an OpenIdentity identity key.

The LDAP service credential authorizes directory lookup; it does not establish the end user's identity. The end-user principal is accepted only after GSS establishes the Kerberos security context.

The AD `objectGUID` identifies the external directory object. It does not replace the OpenIdentity identity. External AD Binding v1 maps that stable external principal to the OpenIdentity identity under OI-015 authorization.

## Non-portable lab material

The following are environment-specific and MUST NOT become normative vectors or repository secrets:

- service-account passwords;
- keytabs;
- CA private keys;
- private OpenIdentity authentication keys;
- persisted runtime binding stores;
- machine-specific truststores;
- Alice's generated AD `objectGUID`.

The observed GUID may appear in interoperability documentation as a non-secret test observation, but implementations MUST NOT depend on it.

## Remaining productization work

This milestone proves interoperability and the reusable Spring integration. Remaining productization work includes enterprise deployment automation, HA/state-store strategy, keytab rotation, multi-domain/forest discovery, managed service identities, and operational telemetry. Those concerns remain above the frozen protocol layer.

## Reusable Spring integration hardening

The proven Microsoft path has been extracted into `openidentity-spring-active-directory`. The reusable module owns SPNEGO exchange lifecycle, Spring Security authentication, validated LDAP principal resolution, persistent binding lookup, and Boot auto-configuration. The `spring-ad-microsoft` sample consumes that module rather than reimplementing those mechanics.

Local tests verify that missing or malformed HTTP Negotiate input does not invoke GSS/AD, multi-round SPNEGO continuation is preserved, GSS rejection produces a Negotiate challenge, UNBOUND principals receive AD-only authority, ACTIVE bindings expose the OpenIdentity identity and authority, downstream directory failures propagate rather than becoming authentication loops, disabled auto-configuration contributes no integration beans, and enabled incomplete configuration fails closed.

The final live acceptance pass used the extracted Spring module through `spring-ad-microsoft` and resolved the existing persistent binding as `AUTHENTICATED` / `ACTIVE` without repeating OI-015. Success of the older sample-owned integration alone is not sufficient for this milestone.
