# Microsoft Active Directory → OpenIdentity → OAuth2/OIDC E2E Gate

Status: **LIVE ACCEPTANCE PASS — 2026-10-02**

## Proven chain

```text
Alice Windows logon
  → Kerberos TGT
  → HTTP/openidentity.oi-test.internal service ticket (AES-256)
  → SPNEGO on APP01
  → alice@OI-TEST.INTERNAL
  → LDAPS principal resolution on DC01
  → existing ACTIVE external-AD binding
  → OpenIdentityPrincipal
  → Spring Authorization Server
  → OAuth 2.0 Authorization Code + S256 PKCE
  → OpenID Connect ID token
  → ordinary Spring OIDC client
```

Expected and observed OIDC subject:

```text
99e2da9324adadb2f18350e1b95d9e491a502f4a91e12857cd7c092c0b0e62f3
```

Observed issuer:

```text
http://openidentity.oi-test.internal:9000
```

Observed audience:

```text
openidentity-reference-client
```

## Lab topology

- DC01: Microsoft Active Directory / KDC / LDAPS
- APP01: `192.168.77.20`
- OpenIdentity Authorization Server: APP01 port 9000
- OIDC reference client: port 8081
- Kerberos SPN: `HTTP/openidentity.oi-test.internal`
- Binding store: `C:\OpenIdentity-Data\microsoft-ad-bindings.store`
- Keytab: `C:\OpenIdentity-Secrets\openidentity-http.keytab`
- Canonical state directory: `C:\OpenIdentity-State`

## Required Authorization Server environment

```powershell
$env:SPRING_PROFILES_ACTIVE = "microsoft-ad"
$env:OPENIDENTITY_KERBEROS_SERVICE_PRINCIPAL = "HTTP/openidentity.oi-test.internal"
$env:OPENIDENTITY_KERBEROS_KEYTAB = "C:\OpenIdentity-Secrets\openidentity-http.keytab"
$env:OPENIDENTITY_AD_HOST = "DC01.oi-test.internal"
$env:OPENIDENTITY_AD_BASE_DN = "DC=oi-test,DC=internal"
$env:OPENIDENTITY_AD_BIND_DN = "oi-ldap@oi-test.internal"
$env:OPENIDENTITY_AD_DIRECTORY_ID = "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
$env:OPENIDENTITY_STATE_DIR = "C:\OpenIdentity-State"
$env:OPENIDENTITY_AD_BINDING_STORE = "C:\OpenIdentity-Data\microsoft-ad-bindings.store"
$env:OPENIDENTITY_AUTHORIZATION_SERVER_ISSUER = "http://openidentity.oi-test.internal:9000"
# OPENIDENTITY_LDAP_BIND_PASSWORD must be supplied securely to the process.
```

## Browser/IWA requirement

The successful Edge configuration used:

```text
AuthServerAllowlist = openidentity.oi-test.internal
AuthSchemes         = negotiate
```

Do **not** enable `EnableAuthNegotiatePort` with the current portless SPN. Enabling it caused Edge not to send the working `HTTP/openidentity.oi-test.internal` Kerberos credential for the `:9000` origin. `AuthNegotiateDelegateAllowlist` is not required for this authentication-only flow.

Server-side proof of successful browser negotiation must include:

```text
SPNEGO filter: Negotiate token present
SPNEGO filter: GSS established principal=alice@OI-TEST.INTERNAL
```

Independent Windows proof:

```powershell
klist get HTTP/openidentity.oi-test.internal
```

must retrieve the service ticket.

## PASS criteria

1. Browser reaches `/oauth2/authorize`.
2. APP01 challenges with `WWW-Authenticate: Negotiate`.
3. Browser sends a Negotiate token.
4. GSS establishes `alice@OI-TEST.INTERNAL`.
5. AD/LDAPS resolves the principal and the existing binding is ACTIVE.
6. Authorization Code flow uses PKCE S256.
7. OIDC client completes login.
8. ID-token `iss` is `http://openidentity.oi-test.internal:9000`.
9. ID-token `aud` contains `openidentity-reference-client`.
10. ID-token `sub` is exactly `99e2da9324adadb2f18350e1b95d9e491a502f4a91e12857cd7c092c0b0e62f3`.

A failure at any step is a gate failure.

## Deterministic CI companion

Run:

```bash
python scripts/verify-oauth2-oidc-reference.py
```

The deterministic gate builds the SDK and both reference applications and checks that the production AD composition, SPNEGO challenge, configurable issuer, PKCE requirement, subject projection, and distinct localhost session cookies remain wired. It deliberately does not pretend to replace the live Kerberos/AD acceptance gate.
