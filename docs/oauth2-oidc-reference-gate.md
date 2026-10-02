# OAuth2 / OpenID Connect Reference Gate

This gate locks down the standards-facing bridge from an authenticated `OpenIdentityPrincipal` to Spring Authorization Server and a conventional OIDC client.

It verifies that the Java SDK and both reference applications build, that the authorization server registers a public Authorization Code client with PKCE required, that OIDC is requested, that the deterministic development principal carries the expected OpenIdentity identity, that JWT projection maps that identity to `sub`, and that the two localhost applications use distinct session-cookie names.

Run from the repository root:

```bash
python scripts/verify-oauth2-oidc-reference.py
```

On Windows with an explicit Maven installation:

```bash
python scripts/verify-oauth2-oidc-reference.py "C:/Users/jonat/apache-maven-3.9.16/bin/mvn.cmd"
```

The gate is intentionally deterministic and does not require DC01, APP01, a browser, or a live Active Directory environment. The separately performed browser acceptance test proved Authorization Code + S256 PKCE + OIDC issuance with `sub=99e2da9324adadb2f18350e1b95d9e491a502f4a91e12857cd7c092c0b0e62f3`.

The production Microsoft AD interoperability layer has now also passed live acceptance. See `docs/microsoft-ad-oauth2-oidc-e2e.md`. The deterministic gate checks that the production AD composition, SPNEGO challenge, configurable issuer, and OAuth/OIDC wiring remain present; the live gate remains authoritative for real Kerberos, LDAPS, binding resolution, browser IWA, and end-to-end token issuance.
