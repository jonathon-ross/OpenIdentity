# OpenIdentity Java SDK API Guide

This guide describes the public API of `openidentity-java` targeting OpenIdentity Protocol v0.1.1.

## Adding the SDK to an application

During the 0.1.0 release, depend only on the modules your application uses. For example, credential verification typically needs the credentials artifact, whose transitive dependencies provide core, CBOR, and crypto support:

```xml
<dependency>
  <groupId>org.openidentity</groupId>
  <artifactId>openidentity-credentials</artifactId>
  <version>0.1.0</version>
</dependency>
```

State-transition applications can depend on `openidentity-operations`. Do not add `openidentity-conformance` as an application dependency; it exists to validate SDK releases against frozen protocol artifacts.

The coordinates above describe the intended 0.1.0 publication coordinates. Until 0.1.0 is published, build the reactor locally with `mvn clean install`.

## Modules

- **openidentity-core** — immutable protocol domain types: identities, state, policies, verification methods, StateHash, recovery commitments, and structured errors.
- **openidentity-cbor** — deterministic RFC 8949 encoding/decoding used by authoritative protocol structures.
- **openidentity-crypto** — Ed25519 and ML-DSA-65 verification, signing domains, proof collections, policy verification, and proof-of-possession.
- **openidentity-operations** — CREATE, ROTATE_CONTROLLER, SET_ASSERTION_POLICY, DEACTIVATE, and RECOVER construction and state transitions.
- **openidentity-credentials** — canonical OI-003 credentials, historical assertion-authority verification, multibase helpers, and deterministic W3C projection.
- **openidentity-conformance** — release tests against the frozen Protocol v0.1.1 vectors. It is not intended as an application dependency.

## Quick start: verify a credential

A verifier must resolve the exact historical state identified by the signed credential's issuance StateHash before calling the SDK. The SDK intentionally does not perform network resolution itself.

```java
VerificationResult result = CredentialVerifier.verifyResult(
        credentialBytes,
        issuerIdentity,
        issuanceStateHash,
        historicalState,
        proofs);

if (!result.valid()) {
    throw new IllegalStateException("Credential rejected: " + result.error());
}
```

Cryptographic validity is separate from profile validation, validity-period evaluation, credential status/revocation, and application acceptance policy.

## Core model

An OpenIdentity identity is represented by `IdentityId`. Verification methods combine a 16-byte `VerificationMethodId` with a supported COSE key. Policies are immutable and canonicalize verification methods by method ID.

`IdentityStateV1` contains controller authority and optional recovery commitment. `IdentityStateV2` explicitly adds assertion authority. A null v2 AssertionPolicy means **no assertion authority**; it never falls back to ControllerPolicy.

`StateHash.fromStateBytes(...)` computes the v0.1 SHA2-256 Multihash over canonical state bytes. Use `new StateHash(MultihashSha256.of(bytes))` only when loading an already-computed StateHash.

## Creating an identity

Construct a `CreateOperation` with the new identity, proposed controller policy, and optional recovery commitment. Every CREATE authorization proof signs `SigningInputs.operation(operation.encode())`.

Apply the transition with:

```java
IdentityStateV1 state = CreateTransition.apply(createOperation, authorizationProofs);
StateHash stateHash = CreateTransition.resultingStateHash(createOperation, authorizationProofs);
```

CREATE authorization is evaluated against the proposed ControllerPolicy.

## Rotating controllers

`RotateControllerOperation` binds the identity, exact next sequence, predecessor StateHash, and proposed ControllerPolicy.

```java
IdentityStateV1 next = RotateControllerTransition.apply(
        currentState,
        rotateOperation,
        currentControllerAuthorizationProofs,
        newControllerProofsOfPossession);
```

The current ControllerPolicy authorizes the operation. Every method in the proposed policy must separately prove possession using the controller-proof signing domain.

## Assertion authority

Use `SetAssertionPolicyOperation` to install, replace, or remove assertion authority. Applying it to v1 explicitly produces `IdentityStateV2`.

```java
IdentityStateV2 next = SetAssertionPolicyTransition.apply(
        currentState,
        operation,
        controllerAuthorizationProofs,
        proposedAssertionProofsOfPossession);
```

Passing a null AssertionPolicy removes assertion authority. It does not grant controller keys assertion authority.

## Deactivation

`DeactivateTransition.apply(...)` requires current-controller authorization and changes ACTIVE to DEACTIVATED while preserving controller, recovery, and v2 assertion-policy data.

## Recovery

RECOVER is intentionally independent of ordinary controller authorization. The caller reveals the committed `RecoveryPolicy`, supplies recovery-domain signatures satisfying that policy, proves possession of every new controller method, and rotates the recovery commitment.

```java
IdentityState recovered = RecoverTransition.apply(
        currentState,
        recoverOperation,
        recoveryProofs,
        newControllerProofsOfPossession);
```

Recovery can reactivate a DEACTIVATED identity. A v2 state's AssertionPolicy is preserved.

## Credential verification

A native credential binds to the exact historical state that authorized issuance through `issuanceStateHash`.

```java
VerificationResult result = CredentialVerifier.verifyResult(
        credentialBytes,
        issuerIdentity,
        issuanceStateHash,
        historicalIdentityState,
        credentialProofs);

if (!result.valid()) {
    OpenIdentityError error = result.error();
    String detail = result.detail();
}
```

The supplied historical state is canonicalized and hashed. Its StateHash must equal `issuanceStateHash`; it must be v2 and contain an AssertionPolicy. Credential proofs are evaluated only against that historical AssertionPolicy. Current assertion authority must never be substituted.

The older boolean `CredentialVerifier.verify(...)` delegates to the structured API.

## Structured transition errors

Protocol transition failures throw `OpenIdentityException`, which extends `IllegalArgumentException` for source compatibility and exposes a stable `OpenIdentityError`:

```java
try {
    RotateControllerTransition.apply(...);
} catch (OpenIdentityException e) {
    switch (e.error()) {
        case INVALID_SEQUENCE -> handleSequenceFailure();
        case INVALID_PREVIOUS_STATE_HASH -> reloadState();
        case CONTROLLER_THRESHOLD_NOT_SATISFIED -> rejectAuthorization();
        default -> handleProtocolFailure(e);
    }
}
```

Constructor and ordinary programming errors remain standard Java argument/null exceptions.

## W3C projection

`W3cCredentialProjection.basicV1(...)` creates the deterministic W3C representation for the Basic v1 profile. The projection contains the native secured credential in `openIdentitySecuredCredential` and intentionally contains no W3C `proof`.

`W3cProjectionValidator.validateBasicV1(...)` detects projection tampering by re-projecting from the canonical native credential. A valid projection is **not** a substitute for `CredentialVerifier`; native historical verification remains authoritative.

## Cryptography

The v0.1.1 SDK supports Ed25519 and ML-DSA-65 verification. Algorithm selection comes from the authoritative verification method key, never from an untrusted proof-side algorithm field.

Signing domains are separated:

- `OpenIdentity Operation`
- `OpenIdentity Controller Proof`
- `OpenIdentity Recovery`
- `OpenIdentity Credential`

Never reuse a signature from one domain in another.

## Building, formatting, and release verification

Requires Java 21.

```bash
mvn spotless:apply
mvn clean verify
./tools/release-gate.sh
```

`spotless:apply` formats Java sources. `verify` checks formatting and runs all tests. The release gate additionally requires a clean worktree and verifies all pinned Protocol v0.1.1 SHA-256 manifests.
