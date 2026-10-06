# OpenIdentity Java

Production Java SDK for the OpenIdentity Protocol.

This repository implements the frozen OpenIdentity Protocol **v0.1.1** as an independent consumer of the protocol specification and normative conformance artifacts.

## Scope

This repository contains production Java implementation code. It does **not** define or modify the OpenIdentity protocol.

The canonical protocol is maintained separately in `jonathon-ross/OpenIdentity`. Protocol v0.1.1 is the initial conformance target.

Product requirements must not silently redefine protocol semantics. If implementation work exposes a genuine protocol deficiency, that issue belongs in the protocol repository for explicit specification/version review.

## Initial target

The first SDK milestone is an end-to-end implementation of:

```text
Identity creation
    -> CREATE
    -> ROTATE_CONTROLLER
    -> SET_ASSERTION_POLICY
    -> credential issuance / verification
    -> DEACTIVATE
    -> RECOVER
```

The implementation will be continuously checked against the published OpenIdentity Protocol v0.1.1 normative vectors.

## Design principles

- Java 21 baseline.
- Deterministic RFC 8949 CBOR for authoritative protocol bytes.
- Protocol types are immutable.
- Explicit separation of controller, assertion, and recovery authority.
- Ed25519 and ML-DSA-65 support for the v0.1 conformance profile.
- No silent cryptographic threshold weakening.
- StateHash and signing-domain behavior must be byte-for-byte compatible with the normative protocol.
- Protocol validation errors are explicit; malformed or unsupported input is not silently normalized.
- No dependency on the protocol repository's Java vector-generator implementation.

## Modules

```text
openidentity-core          protocol-domain types and invariants
openidentity-cbor          deterministic encoding/decoding
openidentity-crypto        keys, signatures, signing domains, proof verification
openidentity-operations    operation construction and state transitions
openidentity-credentials   native credentials and W3C projection
openidentity-conformance   tests against Protocol v0.1.1 vectors
```

All modules above are implemented. Protocol semantics remain governed by the released specification.

## Protocol baseline

Target:

```text
OpenIdentity Protocol v0.1.1
```

Current operation schema in that release:

```text
spec/cddl/openidentity-operation-v2.cddl
```

The schema revision name `v2` is distinct from the signed operation envelope's `protocolVersion = 1`.

## Verification API

Credential verification exposes both a compatibility boolean API and a structured result API:

```java
VerificationResult result = CredentialVerifier.verifyResult(
        credentialBytes, issuer, issuanceStateHash, historicalState, proofs);

if (!result.valid()) {
    OpenIdentityError error = result.error();
    // Handle stable machine-readable failure code.
}
```

State-transition failures use `OpenIdentityException`, whose `error()` method returns the corresponding `OpenIdentityError` code.

## API documentation

Detailed usage documentation is available in [`docs/API_GUIDE.md`](docs/API_GUIDE.md). The build also produces Javadoc JARs for published modules. Public API Javadocs describe protocol semantics, parameters, return values, and protocol-aware failures.

## Source formatting

Java source formatting is enforced with Spotless and Google Java Format. To normalize the entire source tree before committing:

```bash
mvn spotless:apply
```

`mvn verify` runs `spotless:check`, so incorrectly formatted Java cannot pass the release gate.

## Build

The project uses Maven and Java 21.

```bash
mvn clean verify
```

## License

Licensed under the Apache License, Version 2.0.

OpenIdentity branding and official protocol status are governed separately by the OpenIdentity protocol project's published trademark guidance.


## Release verification

The SDK targets the frozen OpenIdentity Protocol v0.1.1 release.

Before tagging an SDK release, run:

```bash
./tools/release-gate.sh
```

On Windows with Git Bash, the same command is supported. The release gate automatically discovers common Maven installations under the Windows user profile when `mvn` is not already on `PATH`.

The Maven conformance suite independently verifies the SHA-256 manifests for every pinned normative v0.1.1 resource and exercises the protocol, cryptographic, operation, credential, recovery, and W3C projection vectors.
