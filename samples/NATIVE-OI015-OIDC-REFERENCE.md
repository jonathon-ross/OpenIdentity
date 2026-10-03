# Native OI-015 to OAuth2/OIDC reference gate

This sample pair demonstrates identity continuity from native OpenIdentity authentication into a conventional OAuth2/OIDC authorization-code flow.

Use these samples together:

- `spring-authorization-server-reference`: the full reference authorization server. With profile `native-oi015`, it exposes the OI-015 challenge/verification login path and resumes OAuth authorization after authentication.
- `spring-oidc-client-reference`: the conventional OIDC relying-party/client on port 8081.
- `native-oi015-signer`: deterministic development fixture generation plus an end-to-end gate harness.

The older `spring-authorization-server` sample is focused on delegated-agent token exchange and protected-resource behavior. It is not the native OI-015 browser/OIDC reference server.

## Gate

Generate development state:

```bash
cd samples/native-oi015-signer
mkdir -p ../../tmp/native-oi015-state
mvn exec:java -Dexec.mainClass=org.openidentity.samples.nativeauth.NativeOi015FixtureGenerator -Dexec.args="../../tmp/native-oi015-state"
```

Start the reference authorization server with `OPENIDENTITY_STATE_DIR` pointing at that directory and profile `native-oi015`.

Then run `NativeOi015Flow` in its five-argument reference mode. The harness performs:

```text
OI-015 challenge
-> signed OI-015 assertion
-> verification
-> Spring Security session
-> OAuth authorization
-> consent
-> authorization code
-> PKCE token exchange
-> OIDC ID token
-> sub == authenticated OpenIdentity identity
```

Reference mode is a hard gate. It exits with an exception if any required stage fails. A complete successful run ends with:

```text
NATIVE OI-015 -> OAUTH2/OIDC END-TO-END: PASS
```

The authentication continuation implementation separately enforces local `/oauth2/authorize` continuations and single-use continuation consumption in the `openidentity-spring-authentication` tests.
