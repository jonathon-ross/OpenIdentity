# OpenIdentity

OpenIdentity is a decentralized identity protocol for portable, cryptographically controlled digital identity.

A permanent OpenIdentity root identifier is independent of controller keys, cryptographic algorithms, devices, registries, infrastructure providers, applications, and underlying ledgers. Authority can evolve without replacing the identity itself.

This repository is the **OpenIdentity protocol repository**. It defines the protocol, normative schemas, conformance vectors, interoperability projections, and release-verification tooling.

> **Release status:** OpenIdentity Protocol v0.1.0 release candidate. The complete release gate passes from a clean checkout.

## Repository scope

This repository defines **what OpenIdentity is**.

It is intentionally not a production SDK, wallet, hosted identity service, registry implementation, application backend, user interface, or commercial platform.

After a protocol version is released, its normative specifications, schemas, vectors, and integrity artifacts are treated as frozen. Changes to this repository should be limited to:

- protocol evolution and future protocol versions;
- security corrections;
- interoperability corrections;
- specification errata and clarifications;
- normative conformance vectors;
- verification/conformance tooling;
- published protocol contexts and vocabulary resources; and
- release engineering for the protocol itself.

Product requirements MUST NOT silently redefine the protocol. SDKs, services, wallets, registries, applications, and commercial infrastructure should be developed in separate projects that consume a released OpenIdentity protocol version.

If implementation work exposes a genuine protocol deficiency, the issue should return here for explicit specification review, new or updated conformance vectors, independent verification, and an appropriately versioned protocol release.

## Protocol model

The permanent root identifier is:

```text
did:open:z<base58btc-encoded-32-byte-identifier>
```

Authority is separated by purpose:

```text
ControllerPolicy -> IdentityState changes
AssertionPolicy  -> credentials/assertions
RecoveryPolicy   -> RECOVER
```

Membership in one policy does not implicitly grant authority in another.

## Current wire format

The current OpenIdentity v0.1 operation schema is:

```text
spec/cddl/openidentity-operation-v2.cddl
```

Despite the filename `v2`, the signed operation envelope uses `protocolVersion = 1`. The filename denotes the current schema revision.

The earlier:

```text
spec/cddl/openidentity-operation-v1.cddl
```

is historical/frozen compatibility material. New implementations MUST use the v2 schema together with the current normative specifications.

The credential schema is:

```text
spec/cddl/openidentity-credential-v1.cddl
```

## Normative specifications

```text
docs/identity-id.md                    OI-001 Identity ID
docs/cryptographic-agility.md          OI-002 cryptographic agility
docs/credential.md                     OI-003 credentials/assertion authority

spec/create-operation.md               OI-004 CREATE
spec/rotate-controller.md              OI-005 ROTATE_CONTROLLER
spec/deactivate.md                     OI-006 DEACTIVATE
spec/recover.md                        OI-007 RECOVER
spec/sequence-and-replay.md            OI-008 sequence/replay
spec/canonical-serialization.md        OI-009 canonical serialization
spec/signature-envelope.md             OI-010 signature envelope
spec/state-hash.md                     OI-011 StateHash
```

W3C interoperability material includes:

```text
docs/w3c-identity-projection.md
spec/w3c-credential-projection.md
spec/credential-profiles/basic-v1.md
docs/openidentity-vocabulary.md
```

Canonical OpenIdentity CBOR remains authoritative. W3C DID and credential representations are deterministic interoperability projections, not alternate cryptographic state.

## Operations

Canonical Operation fields are:

```text
1 protocolVersion
2 operationType
3 identity
4 sequence
5 previousStateHash
6 payload
```

OpenIdentity v0.1 operations are:

```text
1 CREATE
2 ROTATE_CONTROLLER
3 RECOVER
4 DEACTIVATE
5 SET_ASSERTION_POLICY
```

IdentityState supports schema versions 1 and 2. Version 2 adds optional AssertionPolicy. A v2 state MUST NOT silently downgrade to v1.

## State chaining

Cryptographically authoritative OpenIdentity structures use deterministic RFC 8949 CBOR.

State chaining is:

```text
StateBytes = deterministicCBOR(IdentityState)
digest     = SHA-256(StateBytes)
StateHash  = 0x12 || 0x20 || digest
```

The v0.1 StateHash is a 34-byte SHA2-256 Multihash.

CREATE establishes sequence 1 with no predecessor. Every later state-changing operation requires both:

```text
sequence = currentState.sequence + 1
previousStateHash = StateHash(currentState)
```

## Cryptographic profile

OpenIdentity is cryptographically agile.

The v0.1 conformance profile includes Ed25519 and ML-DSA-65. The default hybrid controller profile exercised by normative vectors is 2-of-2 Ed25519 + ML-DSA-65.

Implementations MUST NOT silently weaken a threshold because an algorithm is unavailable.

Operation-related signing domains include:

```text
OpenIdentity Operation
OpenIdentity Controller Proof
OpenIdentity Recovery
```

Credential signing uses a separate OpenIdentity credential domain. Proofs from different purposes are not interchangeable.

## Normative conformance vectors

Frozen normative bundles live under `test-vectors/`:

```text
identity-id-v0.1.json
cryptographic-agility-v0.1.json
assertion-authority-v0.1.json
credential-v0.1.json
w3c-projection-v0.1.json
w3c-credential-projection-v0.1.json
recovery-v0.1.json
signature-envelope-v0.1.json
state-hash-v0.1.json
```

Published `.sha256` files and integrity manifests freeze the applicable release artifacts.

Generated development output under `test-vectors/generated/` is ignored and is not normative.

Do not change frozen expected bytes merely to make an implementation pass. A legitimate normative change requires explicit protocol/version review.

## Release verification

The complete v0.1 release gate is:

```bash
python tools/release/verify-v0.1.py
```

The gate verifies required release artifacts, normative/public SHA-256 integrity, release-text sanity, licensing, independent Python conformance, Java reference generation, post-generation frozen-artifact integrity, post-generation independent verification, and a clean Git worktree.

If Maven is not visible from the Python environment, an explicit launcher may be supplied:

```bash
python tools/release/verify-v0.1.py --maven /path/to/mvn
```

On Windows, for example:

```powershell
python tools/release/verify-v0.1.py --maven "C:\path\to\apache-maven\bin\mvn.cmd"
```

A protocol release MUST NOT be tagged unless the complete gate passes from a clean checkout.

## Independent verification

Python verification dependencies are listed in:

```text
tools/test-vectors/requirements.txt
tools/test-vectors/requirements-crypto.txt
```

Primary independent verifiers include:

```text
tools/test-vectors/verify_identity_vectors.py
tools/test-vectors/verify_cryptographic_agility.py
tools/test-vectors/verify_assertion_authority.py
tools/test-vectors/verify_credential.py
tools/test-vectors/verify_w3c_projection.py
tools/test-vectors/verify_w3c_credential_projection.py
tools/test-vectors/verify_recovery.py
tools/test-vectors/verify_signature_envelope.py
tools/test-vectors/verify_state_hash.py
```

## Java reference tooling

The Java reference/vector tooling is under:

```text
tools/test-vectors-java/
```

It exists to generate and cross-check conformance material. It is **not a production OpenIdentity SDK**.

From that directory:

```bash
mvn clean compile
mvn exec:java -Dexec.mainClass=org.openidentity.vectors.GenerateVectors
```

Independent verification is required before generated output becomes a frozen normative artifact.

## Authority order

When repository sources disagree:

1. normative specification documents;
2. current normative CDDL schemas;
3. normative conformance vectors and published checksums;
4. independently verified reference behavior;
5. reference/conformance implementation code;
6. comments, examples, generated artifacts, and assumptions.

A conflict between normative layers is a release blocker. It MUST NOT be silently resolved in favor of whichever interpretation makes code pass.

## Public interoperability artifacts

`public/` contains the static resources required to publish OpenIdentity interoperability material, including immutable JSON-LD contexts, vocabulary documentation, integrity files, and the minimal protocol landing page.

See:

```text
public/README.md
```

Published versioned contexts are immutable. Breaking context changes require a new versioned context URI.

## Repository layout

```text
docs/                     normative/supporting protocol documentation
spec/                     normative operation/serialization/projection specs
spec/cddl/                normative structural schemas
contexts/                 source JSON-LD protocol contexts
test-vectors/             frozen normative conformance artifacts
checksums/                multi-artifact integrity manifests
tools/test-vectors/       independent verification tooling
tools/test-vectors-java/  Java reference/vector tooling
tools/jsonld*/            JSON-LD verification tooling
tools/release/            protocol release verification
public/                   publishable protocol interoperability resources
```

## What belongs elsewhere

Production development should occur outside this repository.

Examples include:

```text
OpenIdentity SDKs
wallets
identity agents
registry/node implementations
hosted resolution services
credential platforms
recovery services
developer APIs
authentication products
enterprise administration
billing and analytics
commercial cloud infrastructure
end-user applications
```

Those projects should declare which released OpenIdentity protocol version they implement and use this repository's normative artifacts as their conformance contract.

## Deferred protocol scope

v0.1 intentionally leaves some functionality for future protocol work, including production credential status/revocation mechanisms, holder-binding and presentation protocols, selective disclosure/zero-knowledge presentation formats, production Credential Profile registries, registry-specific consensus and historical-state retrieval, ledger-specific integrations, device/passkey authorization, and future algorithms/profiles.

Deferred functionality MUST NOT be inferred by weakening or silently extending frozen v0.1 semantics.

## Protocol evolution

A released protocol version is immutable in its normative meaning.

Typical versioning intent:

```text
v0.1.0  initial protocol release
v0.1.x  non-breaking errata, clarification, and release/conformance tooling
v0.2.0  deliberate protocol evolution
v1.0.0  future mature/stable protocol milestone
```

Changes that alter frozen canonical bytes, state-transition semantics, cryptographic domains, operation codes, authority rules, or normative vector behavior require explicit version review.

## Contributing

Read `AGENTS.md` before protocol-sensitive changes.

Protocol changes should be deliberate and conformance-driven. Product-specific behavior belongs in implementation/product repositories unless it exposes a genuine interoperability or protocol requirement.

## License

OpenIdentity is licensed under the Apache License, Version 2.0.

See:

```text
LICENSE
NOTICE
LICENSING.md
TRADEMARKS.md
```

Apache-2.0 permits implementations and commercial use subject to its terms. OpenIdentity branding, official-status claims, and future certification branding are addressed separately in `TRADEMARKS.md`.

## Release

OpenIdentity Protocol v0.1.0 is released from an exact Git commit only after:

1. the complete release gate passes;
2. the Git worktree is clean;
3. normative integrity artifacts verify; and
4. the release/tag points to the inspected commit.

Product development proceeds independently from the frozen protocol release.
