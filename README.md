# OpenIdentity

OpenIdentity is a decentralized identity protocol designed to keep a permanent root identity independent of controller keys, cryptographic algorithms, devices, registries, infrastructure providers, applications, and underlying ledgers.

This repository contains the OpenIdentity Protocol v0.1 specifications, normative schemas, conformance vectors, independent verification tooling, and W3C interoperability projections.

> **Release status:** Protocol v0.1 release candidate. Normative work through OI-011 is complete. OI-012 is the publication/release gate. A repository license must still be selected before the v0.1 release is tagged.

## Current wire format

The current operation schema is `spec/cddl/openidentity-operation-v2.cddl`.

Despite the filename `v2`, the signed operation envelope uses `protocolVersion = 1`. The v2 filename denotes the current schema revision. The earlier `openidentity-operation-v1.cddl` is historical/frozen compatibility material and MUST NOT be used to infer current omissions or reserved operations.

The credential schema is `spec/cddl/openidentity-credential-v1.cddl`.

## Normative specifications

- `docs/identity-id.md` — OI-001 Identity ID
- `docs/cryptographic-agility.md` — OI-002 cryptographic agility
- `docs/credential.md` — OI-003 credentials/assertion authority
- `spec/create-operation.md` — OI-004 CREATE
- `spec/rotate-controller.md` — OI-005 ROTATE_CONTROLLER
- `spec/deactivate.md` — OI-006 DEACTIVATE
- `spec/recover.md` — OI-007 RECOVER
- `spec/sequence-and-replay.md` — OI-008 sequence/replay
- `spec/canonical-serialization.md` — OI-009 canonical serialization
- `spec/signature-envelope.md` — OI-010 signature envelope
- `spec/state-hash.md` — OI-011 StateHash

W3C interoperability material includes `docs/w3c-identity-projection.md`, `spec/w3c-credential-projection.md`, `spec/credential-profiles/basic-v1.md`, and `docs/openidentity-vocabulary.md`.

Canonical OpenIdentity CBOR remains authoritative. W3C representations are interoperability projections, not alternate cryptographic state.

## Core v0.1 model

The permanent root identifier is `did:open:z<base58btc-encoded-32-byte-identifier>`.

Authority is separated:

```text
ControllerPolicy -> IdentityState changes
AssertionPolicy  -> credentials/assertions
RecoveryPolicy   -> RECOVER
```

Current operation types are:

```text
1 CREATE
2 ROTATE_CONTROLLER
3 RECOVER
4 DEACTIVATE
5 SET_ASSERTION_POLICY
```

Canonical Operation fields are protocolVersion, operationType, identity, sequence, previousStateHash, and payload.

IdentityState supports schema versions 1 and 2. v2 adds optional AssertionPolicy and MUST NOT silently downgrade to v1.

State chaining is:

```text
StateBytes = deterministicCBOR(IdentityState)
digest     = SHA-256(StateBytes)
StateHash  = 0x12 || 0x20 || digest
```

StateHash is exactly 34 bytes in v0.1. Every transition after CREATE requires `sequence = current + 1` and `previousStateHash = StateHash(current)`.

## Cryptographic profile

v0.1 conformance includes Ed25519 and ML-DSA-65. The default hybrid controller vectors use 2-of-2 Ed25519 + ML-DSA-65. Thresholds MUST NOT be silently weakened because an algorithm is unavailable.

Operation signing domains include `OpenIdentity Operation`, `OpenIdentity Controller Proof`, and `OpenIdentity Recovery`. Credential signing has a separate domain. Cross-purpose signatures are not interchangeable.

## Normative conformance vectors

Frozen bundles under `test-vectors/` include:

```text
identity-id-v0.1.json
cryptographic-agility-v0.1.json
assertion-authority-v0.1.json
credential-v0.1.json
w3c-credential-projection-v0.1.json
recovery-v0.1.json
signature-envelope-v0.1.json
state-hash-v0.1.json
```

Published `.sha256` files freeze exact artifacts. `test-vectors/generated/` is development/reference output and is not more authoritative than frozen bundles.

## Verification

Install the applicable dependencies from `tools/test-vectors/requirements.txt` and `tools/test-vectors/requirements-crypto.txt`.

Important independent verification entry points:

```bash
python tools/test-vectors/verify_identity_vectors.py
python tools/test-vectors/verify_cryptographic_agility.py
python tools/test-vectors/verify_assertion_authority.py
python tools/test-vectors/verify_credential.py
python tools/test-vectors/verify_w3c_projection.py
python tools/test-vectors/verify_w3c_credential_projection.py
python tools/test-vectors/verify_recovery.py
python tools/test-vectors/verify_signature_envelope.py
python tools/test-vectors/verify_state_hash.py
```

Verify published checksum files with `sha256sum -c` or the platform equivalent.

## Java reference tooling

```bash
cd tools/test-vectors-java
mvn clean compile
mvn exec:java -Dexec.mainClass=org.openidentity.vectors.GenerateVectors
```

The Java generator is reference/conformance tooling, not protocol truth. Independent verification is required before generated output becomes normative.

## Authority order

When sources disagree:

1. normative specification documents;
2. current normative CDDL schemas;
3. normative conformance vectors and checksums;
4. independently verified reference behavior;
5. implementation/reference code;
6. comments, examples, generated artifacts, and assumptions.

A normative conflict is a release blocker.

## Public artifacts

`public/` contains publishable static resources, immutable JSON-LD contexts, and integrity files. See `public/README.md` for deployment details. Published versioned contexts are immutable.

## Repository layout

```text
docs/             protocol documentation
spec/             protocol/projection/profile specifications
spec/cddl/        normative structural schemas
test-vectors/     frozen conformance vectors and checksums
tools/            independent verification and JSON-LD tooling
tools/test-vectors-java/  Java reference generator
contexts/         source JSON-LD contexts
public/           publishable static interoperability resources
```

## Deferred scope

v0.1 intentionally leaves future work such as production credential status/revocation, holder-binding/presentation protocols, selective disclosure/ZK presentations, production Credential Profile registries, registry-specific consensus/historical retrieval, ledger-specific implementations, device/passkey authorization, and future algorithms/profiles.

Deferred functionality MUST NOT be inferred by weakening frozen v0.1 semantics.

## Contributing

Read `AGENTS.md` before protocol-sensitive changes. Changes to canonical bytes, map labels, operation codes, StateHash, signing domains, policy semantics, stable errors, normative vectors, or frozen contexts require explicit protocol review.

## License

A repository license has not yet been selected. Do not assume an open-source license until a `LICENSE` file is added. License selection is part of OI-012.

## Release

Tag Protocol v0.1 only after OI-012 is complete, all normative verifiers/checksums pass from a clean checkout, publication documentation is final, and a repository license is selected.
