# AGENTS.md — OpenIdentity Engineering Instructions

Repository-level instructions for coding agents working on OpenIdentity.

## Project goal

Preserve OpenIdentity interoperability, deterministic cryptographic behavior, cryptographic agility, authority separation, and independence of the permanent root identity from keys, algorithms, registries, providers, applications, and ledgers. Correctness and interoperability take priority over convenience.

## Release baseline

The repository is preparing Protocol v0.1 under OI-012. Normative work through OI-011 is complete.

The CURRENT operation schema is:

```text
spec/cddl/openidentity-operation-v2.cddl
```

`spec/cddl/openidentity-operation-v1.cddl` is historical/frozen compatibility material. Never use its omissions or reserved ranges to infer current behavior.

The current schema still uses `protocolVersion = 1`; schema revision and operation protocol version are distinct.

## Authority order

When sources disagree:

1. normative specification documents;
2. current normative CDDL schemas;
3. normative conformance vectors and checksums;
4. independently verified reference behavior;
5. implementation/reference code;
6. comments, examples, generated artifacts, and assumptions.

Do not silently resolve normative conflicts.

## Primary normative sources

Read the owning documents before protocol-sensitive work:

```text
docs/identity-id.md
docs/cryptographic-agility.md
docs/credential.md
spec/create-operation.md
spec/rotate-controller.md
spec/deactivate.md
spec/recover.md
spec/sequence-and-replay.md
spec/canonical-serialization.md
spec/signature-envelope.md
spec/state-hash.md
spec/w3c-credential-projection.md
spec/credential-profiles/basic-v1.md
spec/cddl/openidentity-operation-v2.cddl
spec/cddl/openidentity-credential-v1.cddl
```

## Frozen artifacts

Treat completed v0.1 specs, normative CDDL, vector bundles/checksums, and published immutable JSON-LD contexts as frozen unless a task explicitly authorizes a normative change.

Never change normative bytes, labels, operation codes, algorithm IDs, signing domains, StateHash construction, authority semantics, stable errors, canonical encoding, contexts, or expected vectors merely to make code pass.

`test-vectors/generated/` is development/reference output, not normative output.

## Root identity

The permanent Identity ID is exactly 32 random bytes. Canonical text is:

```text
did:open:z<base58btc-encoded-32-byte-identifier>
```

It is independent of keys, algorithms, providers, applications, registries, credentials, and ledgers.

## Authority separation

```text
ControllerPolicy -> IdentityState changes
AssertionPolicy  -> credentials/assertions
RecoveryPolicy   -> RECOVER
```

Authority never transfers implicitly. Absent AssertionPolicy means zero assertion authority, not ControllerPolicy fallback.

## Cryptography

v0.1 conformance includes:

```text
Ed25519:   COSE kty=1, alg=-8, curve=6, public=32 bytes, signature=64 bytes
ML-DSA-65: COSE kty=7, alg=-49, public=1952 bytes, signature=3309 bytes
```

Default hybrid controller vectors use 2-of-2 Ed25519 + ML-DSA-65. Never silently weaken thresholds. Do not implement cryptographic primitives manually.

## Canonical serialization

Cryptographically authoritative structures use RFC 8949 deterministic CBOR plus OpenIdentity canonicalization rules. Do not sign/hash arbitrary JSON where canonical bytes are required.

Reject prohibited/noncanonical encodings, duplicate map keys, unknown signed labels, and nondeterministic set-like ordering. VerificationMethods and proof collections use unsigned bytewise lexicographic ordering by raw Verification Method ID where specified.

## Operations

Canonical fields:

```text
1 protocolVersion
2 operationType
3 identity
4 sequence
5 previousStateHash
6 payload
```

Current operation types:

```text
1 CREATE
2 ROTATE_CONTROLLER
3 RECOVER
4 DEACTIVATE
5 SET_ASSERTION_POLICY
```

## OperationBytes and proofs

OperationBytes are deterministic CBOR of exactly the Operation and exclude proofs and transport/registry metadata.

SignedOperation conceptually carries:

```text
{1: operation, 2?: authorizationProofs, 3?: controllerProofs, 4?: recoveryProofs}
```

Keep proofs outside OperationBytes.

Signing domains are:

```text
["OpenIdentity Operation", 1, OperationBytes]
["OpenIdentity Controller Proof", 1, OperationBytes, verificationMethodId]
["OpenIdentity Recovery", 1, OperationBytes, recoveryMethodId]
```

Credential signing has a separate credential domain. Cross-domain proofs are not interchangeable.

## IdentityState and StateHash

v1 state contains version, identity, sequence, status, ControllerPolicy, and optional recoveryCommitment.

v2 adds optional AssertionPolicy. v2 MUST NOT silently downgrade to v1.

Status: `1=ACTIVE`, `2=DEACTIVATED`.

```text
StateBytes = deterministicCBOR(complete IdentityState)
digest     = SHA-256(StateBytes)
StateHash  = 0x12 || 0x20 || digest
```

StateHash is exactly 34 bytes in v0.1. The raw 32-byte digest is not StateHash.

CREATE requires `sequence=1`, `previousStateHash=nil`. Every later state change requires `sequence=current+1` and exact `previousStateHash=StateHash(current)`.

## Operation semantics

CREATE establishes the first state.

ROTATE_CONTROLLER uses current ControllerPolicy authorization and proposed-controller proof of possession.

DEACTIVATE creates DEACTIVATED state; ordinary controller authority cannot reactivate it.

RECOVER is authorized only by RecoveryPolicy and follows OI-007, including recovery from DEACTIVATED state.

SET_ASSERTION_POLICY is authorized by current ControllerPolicy; non-nil proposed assertion methods require PoP. It installs/replaces/removes AssertionPolicy and upgrades v1 to v2 when first used.

## Credentials

OI-003 credentials bind to exact historical `issuanceStateHash`. Verify against AssertionPolicy from that historical state, never substituted current authority.

Native canonical credential bytes are authoritative. W3C credentials are deterministic projections, not an alternate signed source of truth.

## Stable errors

Stable error names are protocol behavior. Do not casually rename, merge, or reinterpret them. Follow the owning specification and central vocabulary.

## Conformance

Normative bundles/checksums live under `test-vectors/`. Never edit frozen expected bytes/errors to accommodate implementation failure.

Before protocol-sensitive completion or release, run all applicable independent verifiers under `tools/test-vectors/`, verify all normative `.sha256` files, and verify immutable context checksums.

Important final gates include:

```bash
python tools/test-vectors/verify_signature_envelope.py
python tools/test-vectors/verify_state_hash.py
```

Run all other owning verifiers for affected areas.

## Java generator

`tools/test-vectors-java` is reference tooling, not protocol truth.

```bash
cd tools/test-vectors-java
mvn clean compile
mvn exec:java -Dexec.mainClass=org.openidentity.vectors.GenerateVectors
```

Independent verification is required before generated output becomes normative.

## Coding-agent workflow

For protocol-sensitive work:

1. read this file;
2. read the owning spec;
3. read current CDDL;
4. inspect normative vectors/checksums;
5. identify affected invariants;
6. make the smallest coherent change;
7. run relevant tests;
8. run independent conformance verification;
9. verify checksums;
10. report changes and unresolved questions.

## Security-sensitive changes

Treat identity derivation, canonical encoding, signing domains, hashes, COSE IDs, signatures, thresholds, authority separation, state transitions, sequence/replay, previousStateHash, PoP, recovery, deactivation, credentials, historical authority, stable errors, vectors, and contexts as protocol/security-sensitive.

Do not invent missing semantics.

## Test philosophy

Test acceptance and rejection. Prefer byte-exact reconstruction, independent cryptographic verification, mutation/negative tests, duplicate-ID/proof tests, wrong-domain/method/state tests, replay tests, and threshold failures.

A library verifying its own output is insufficient evidence for a normative vector when independent verification is practical.

## Repository hygiene

Do not commit IDE metadata, virtual environments, build output, dependency directories, Python caches, temporary keys, debug dumps, generated secrets, local absolute paths, or unrelated formatting churn.

Do not log production secrets. Deterministic public vector seeds are test fixtures only.

## Deferred scope

Do not implement deferred features from assumptions. Follow explicit deferred sections in the owning v0.1 specs. Deferred functionality MUST NOT be inferred by weakening frozen behavior.

## Definition of done

Before reporting protocol-sensitive work complete:

- code compiles;
- relevant tests pass;
- independent conformance verification passes;
- normative checksums verify;
- frozen artifacts did not change unexpectedly;
- no temporary/debug artifacts remain;
- changed files, tests, and unresolved questions are reported.

## When uncertain

If implementation requirements conflict with a frozen specification, stop and state the conflict precisely. Do not choose whichever interpretation makes tests easiest.
