# Native OI-015 → OAuth2/OIDC End-to-End Gate

Status: **BROWSER-OWNED LIVE ACCEPTANCE PASS — 2026-10-03**

## Proven chain

```text
External Ed25519 authentication key
  → server-issued OI-015 challenge
  → audience + purpose + nonce + context binding
  → canonical OI-015 assertion and proof
  → Oi015Codec
  → Oi015Verifier against current canonical identity state
  → VerifiedAuthentication
  → OpenIdentityNativeAuthenticationToken
  → OpenIdentityPrincipal
  → Spring Security authenticated session
  → OAuth 2.0 Authorization Code + S256 PKCE
  → OpenID Connect ID token
  → ordinary Spring OIDC client
```

Observed native identity / OIDC subject:

```text
be3d2604cf501d1c9a6a00d253390620a0e56cb909d2cb29997939c29d305708
```

Observed issuer:

```text
http://127.0.0.1:9000
```

Observed audience:

```text
openidentity-reference-client
```

## Security properties exercised

The live flow used a server-generated single-use challenge with purpose `openidentity.oauth.authenticate`, a 32-byte nonce, Authorization Server audience binding, deterministic context binding, short expiration, current state hash, current authentication generation, a current Ed25519 authentication method, and a real Ed25519 proof.

The verifier output was converted to the generic `OpenIdentityPrincipal` contract before OAuth processing. The OIDC client therefore had no native OI-015 knowledge.

## Test scaffolding note

The first live acceptance test transferred the already-authenticated Authorization Server session from curl's cookie jar into the browser cookie jar so the real browser-based Authorization Code + PKCE flow could continue. This was test scaffolding only; it did not replace OI-015 verification. The authenticated session had already been created by successful cryptographic OI-015 verification.

The product/reference flow must replace that manual transfer with a native browser continuation/handoff while keeping the private authentication key outside the Authorization Server.

## PASS criteria

1. Native challenge is issued.
2. External signer constructs canonical OI-015 bytes.
3. Current canonical state resolves.
4. Ed25519 proof verifies.
5. Challenge cannot replay.
6. Spring session contains an authenticated `OpenIdentityPrincipal`.
7. `/oauth2/authorize` accepts that principal and reaches consent.
8. Authorization Code flow uses PKCE S256.
9. OIDC client completes login.
10. ID-token `sub` equals the native OpenIdentity identity exactly.

Result: **OPENIDENTITY NATIVE OI-015 → OAUTH2/OIDC END-TO-END: PASS**


## Browser-owned continuation acceptance

A second live acceptance run removed the manual session-cookie transfer. The ordinary OIDC client initiated authorization, the Authorization Server redirected the unauthenticated browser to the native OI-015 login handoff, the browser created the challenge in its own Authorization Server session, an external signer produced the OI-015 assertion, the browser submitted that assertion, and successful verification established the same browser session before automatically resuming the original authorization request.

Observed final OIDC subject remained:

```text
be3d2604cf501d1c9a6a00d253390620a0e56cb909d2cb29997939c29d305708
```

Result: **OPENIDENTITY NATIVE OI-015 → BROWSER HANDOFF → OAUTH2/OIDC END-TO-END: PASS**

The reference UI currently uses copy/paste only as a transport between the external authenticator and browser. It is not the intended production authenticator transport.
