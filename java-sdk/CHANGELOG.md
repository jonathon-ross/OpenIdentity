# Changelog

All notable SDK changes are documented here.

## 0.1.2 — 2026-09-26

Patch release fixing controller rotation for IdentityState v2.

- `RotateControllerTransition.apply` now accepts the `IdentityState` abstraction.
- ROTATE_CONTROLLER preserves the predecessor state schema version.
- v2 rotation preserves the existing AssertionPolicy and RecoveryCommitment while replacing only ControllerPolicy.
- Added an end-to-end Ed25519 v2 rotation regression test covering current-controller authorization and proposed-controller proof of possession.
- No protocol wire format or normative artifact changed.
- Targets OpenIdentity Protocol v0.1.1.

## 0.1.1 — 2026-09-26

Patch release adding canonical operation decoding for resolver and service integrations.

- Added `OpenIdentityOperationDecoder.decode(byte[])`.
- Added module-neutral `DecodedOperation` CBOR representation to preserve module layering.
- Added canonical CBOR null decoding required by CREATE and assertion-policy removal.
- Decoder rejects unsupported versions/types, invalid envelope/payload shapes, trailing bytes, and non-canonical re-encodings.
- Added frozen-vector round-trip coverage for CREATE and ROTATE_CONTROLLER.
- No protocol semantics, normative bytes, or transition rules changed.
- Targets OpenIdentity Protocol v0.1.1.

## 0.1.0 — 2026-09-26

Initial production release of the OpenIdentity Java SDK, targeting the frozen **OpenIdentity Protocol v0.1.1**.

### Protocol and state

- Immutable IdentityState v1 and v2 domain models.
- Deterministic RFC 8949 CBOR encoding and state decoding.
- SHA2-256 Multihash StateHash support.
- Controller, assertion, and recovery authority policies with canonical method ordering and threshold validation.
- Ed25519 and ML-DSA-65 key models.

### Operations

- CREATE.
- ROTATE_CONTROLLER with current-controller authorization and proposed-controller proof of possession.
- SET_ASSERTION_POLICY with explicit v1-to-v2 state evolution and no controller fallback.
- DEACTIVATE.
- RECOVER with committed RecoveryPolicy verification, recovery-domain authorization, new-controller proof of possession, recovery-commitment rotation, and v2 assertion-policy preservation.

### Credentials

- Canonical native OpenIdentity credential encoding.
- Historical issuance-state binding through issuanceStateHash.
- AssertionPolicy-based credential verification.
- SINGLE Ed25519 and hybrid Ed25519 + ML-DSA-65 credential verification.
- Structured VerificationResult and OpenIdentityError failures.
- Deterministic W3C Credential projection with the native secured credential retained as the cryptographic source of truth.
- Projection tamper validation and prohibition on misleading W3C proof substitution.

### Conformance

- Protocol v0.1.1 StateHash vectors.
- Cryptographic-agility vectors.
- Signature-envelope SE01-SE10 coverage.
- Assertion-authority A01-A04 and AI01-AI10 coverage.
- Recovery R01-R02 and invalid recovery coverage.
- Credential C01-C02 and CI01-CI10 coverage.
- W3C projection WP01-WP02 and WPI01-WPI10 coverage.
- Independent SHA-256 verification of every pinned normative Protocol v0.1.1 artifact.

### Developer experience

- Java 21 baseline.
- Structured transition errors through OpenIdentityException and OpenIdentityError.
- Detailed API guide and package/public API Javadocs.
- Javadoc doclint enforced during release verification.
- Spotless + Google Java Format enforced by Maven.
- Source and Javadoc JAR generation.
- Cross-platform release gate with Git Bash Maven discovery on Windows.

### Compatibility

SDK version **0.1.0** implements OpenIdentity Protocol **v0.1.1**. The SDK version and protocol version are intentionally independent.
