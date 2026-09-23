# AGENTS.md --- OpenIdentity Engineering Instructions

Repository-level instructions for coding agents working on OpenIdentity.

## Project goal

OpenIdentity is a decentralized identity protocol. Preserve
interoperability, deterministic cryptographic behavior, cryptographic
agility, and independence of the permanent root identity from controller
keys, algorithms, registries, providers, and applications. Correctness
and interoperability take priority over convenience.

## Authority order

When sources disagree, use this order:

1.  Normative specification documents.
2.  Normative CDDL schemas.
3.  Normative conformance vectors and published checksums.
4.  Independently verified reference behavior.
5.  Implementation code.
6.  Comments, examples, generated development artifacts, and
    assumptions.

Do not silently resolve a conflict. Report it and stop before making a
normative protocol change.

## Frozen OI-001 / OI-002 baseline

Important artifacts include:

``` text
docs/cryptographic-agility.md
spec/cddl/openidentity-operation-v1.cddl
test-vectors/identity-id-v0.1.json
test-vectors/identity-id-v0.1.sha256
test-vectors/cryptographic-agility-v0.1.json
test-vectors/cryptographic-agility-v0.1.sha256
```

Do not alter normative behavior merely to make code or tests pass. A
change to normative bytes, map labels, algorithm identifiers, signing
domains, state rules, error expectations, or canonical encoding requires
explicit protocol-version/specification review. Never regenerate
expected vectors simply because implementation output changed.

## Root identity invariants

The permanent root identity is independent of controller keys and
cryptographic algorithms. Do not embed controller keys, COSE
identifiers, algorithms, registry identifiers, providers, applications,
or pairwise application identifiers into the root DID. Normal
applications should not receive the root DID when a pairwise identifier
is appropriate.

## OI-002 cryptographic profile

Default v0.1 control is hybrid 2-of-2: Ed25519 plus ML-DSA-65.

``` text
Ed25519:   COSE kty=1, alg=-8, curve=6, public key=32 bytes, signature=64 bytes
ML-DSA-65: COSE kty=7, alg=-49, public key=1952 bytes, signature=3309 bytes
```

Do not silently downgrade a threshold because an algorithm is
unavailable.

## Deterministic CBOR and ordering

Cryptographically authoritative structures use deterministic RFC 8949
CBOR according to the specification and CDDL. Do not sign arbitrary
JSON.

Do not introduce indefinite-length items, floating point, NaN/Infinity,
undefined, arbitrary tags, duplicate map labels, unknown signed
OpenIdentity map labels, or nondeterministic collection ordering.

VerificationMethods and proof collections are ordered by Verification
Method ID using unsigned bytewise lexicographic ordering.

## Operation model

Canonical Operation fields:

``` text
1 protocolVersion
2 operationType
3 identity
4 sequence
5 previousStateHash
6 payload
```

v1 operation codes:

``` text
1 CREATE
2 ROTATE_CONTROLLER
3 RECOVER — allocated but unsupported in v0.1
4 DEACTIVATE
```

RECOVER MUST NOT be implemented by inferring behavior from ordinary
controller rules.

## OperationBytes and SignedOperation

OperationBytes contain the deterministic CBOR encoding of the Operation
only. They contain no authorization proofs and no controller
proof-of-possession proofs.

SignedOperation is:

``` text
{
  1: operation,
  2: authorizationProofs,
  3: controllerProofs?
}
```

Do not move controller proof-of-possession evidence into the
ROTATE_CONTROLLER payload; that creates a circular signing dependency.

## Signing domains

Authorization signs:

``` text
[
  "OpenIdentity Operation",
  1,
  operationBytes
]
```

New ROTATE_CONTROLLER methods prove possession using:

``` text
[
  "OpenIdentity Controller Proof",
  1,
  operationBytes,
  verificationMethodId
]
```

Do not change domain strings, versions, order, or byte representation
without protocol review. Authorization proofs and controller proofs are
not interchangeable. The current controller authorizes rotation; the
proposed controller does not authorize its own installation.

## IdentityState and StateHash

Authoritative v1 state is:

``` text
{
  1: stateVersion,
  2: identity,
  3: sequence,
  4: status,
  5: controllerPolicy,
  6: recoveryCommitment?
}
```

`stateVersion=1`; status `1=ACTIVE`, `2=DEACTIVATED`. IdentityState
contains no signatures, proofs, transport metadata, or registry-specific
metadata. Its deterministic CBOR encoding is StateBytes.

v0.1 state chaining:

``` text
digest = SHA-256(StateBytes)
StateHash = 0x12 || 0x20 || digest
```

StateHash is exactly 34 bytes. Subsequent operations use
`sequence=currentState.sequence+1` and
`previousStateHash=StateHash(currentState)`. Recompute hashes from
canonical StateBytes when validating.

## CREATE and ROTATE_CONTROLLER

CREATE requires protocolVersion 1, operationType 1, sequence 1,
previousStateHash nil, and a valid controller policy. The CREATE policy
authorizes creation because no prior controller exists.

ROTATE_CONTROLLER requires operation type 2, sequence current+1, correct
previousStateHash, authorization by the current controller, a valid
proposed policy, and proof of possession for every required proposed
VerificationMethod. Successful rotation preserves root identity and
installs the new policy.

## Stable conformance errors

Do not casually rename or reinterpret:

``` text
INVALID_SEQUENCE
INVALID_PREVIOUS_STATE_HASH
INVALID_CONTROLLER_THRESHOLD
DUPLICATE_VERIFICATION_METHOD
CONTROLLER_THRESHOLD_NOT_SATISFIED
DUPLICATE_PROOF
INVALID_SIGNATURE
UNAUTHORIZED_VERIFICATION_METHOD
MISSING_PROOF_OF_POSSESSION
INVALID_PROOF_OF_POSSESSION
UNSUPPORTED_ALGORITHM
UNSUPPORTED_PROTOCOL_FEATURE
UNSUPPORTED_OPERATION
```

Follow validation precedence in `docs/cryptographic-agility.md`.

## Normative vectors and checksums

The OI-002 normative artifact is:

``` text
test-vectors/cryptographic-agility-v0.1.json
```

It contains V01-V04 and I01-I20. Do not edit expected bytes or errors to
accommodate implementation failure. Diagnose the first divergence
against the specification and CDDL.

Files under `test-vectors/generated/` are development/reference outputs,
not more authoritative than the normative vector.

Published `.sha256` files freeze exact normative artifacts. If a
legitimate normative change is required, determine whether a new
specification/vector version is needed.

## Required conformance gate

Primary OI-002 verification:

``` bash
python tools/test-vectors/verify_cryptographic_agility.py test-vectors/cryptographic-agility-v0.1.json
```

Then verify:

``` bash
cd test-vectors
sha256sum -c cryptographic-agility-v0.1.sha256
```

Use the equivalent SHA-256 verification command on platforms without
`sha256sum`.

The older V01-V04 verification tools may be used diagnostically; the
normative-file verifier is the final gate.

## Java vector generator

`tools/test-vectors-java` is reference/test tooling, not the source of
protocol truth. It may generate development artifacts under
`test-vectors/generated/` and consolidate the normative artifact
according to the frozen specification. Never modify normative
expectations solely to make Java output pass.

## Coding-agent workflow

Before a protocol-sensitive implementation:

1.  Read this file.
2.  Read the relevant specification.
3.  Read the relevant CDDL.
4.  Inspect normative vectors.
5.  Identify affected invariants.
6.  Implement the smallest coherent change.
7.  Run relevant tests.
8.  Run conformance verification.
9.  Report changed files and test results.

For ordinary application code that does not alter protocol behavior, use
normal engineering judgment without unnecessary protocol ceremony.

## Security-sensitive changes

Treat identity derivation, canonical encoding, signing inputs,
domain-separation strings, hash construction, COSE encoding, algorithm
identifiers, key/signature validation, thresholds, proof evaluation,
state transitions, sequence handling, previousStateHash,
proof-of-possession, recovery, deactivation, normative errors, and
normative vectors as protocol/security-sensitive.

Do not invent missing semantics. Surface unresolved design questions.

## Test philosophy

Test acceptance and rejection. Prefer byte-exact tests, canonical
encoding tests, independent cryptographic verification where practical,
mutation/negative tests, duplicate-ID tests, wrong-domain tests,
wrong-method binding tests, wrong-state-hash tests, sequence/replay
tests, and threshold-failure tests.

A library verifying its own generated signature is insufficient evidence
for a normative vector when an independent implementation is practical.

## Dependencies and cryptography

Do not implement cryptographic primitives manually. Prefer standardized
maintained implementations with interoperable formats. Do not introduce
a new cryptographic dependency merely for convenience.

Small deterministic encoders, protocol adapters, validation code, and
vector tooling may be implemented directly when covered by byte-exact
tests.

## Repository hygiene

Do not commit unnecessary IDE metadata such as `.iml`, virtual
environments, build output, temporary keys, debug dumps, generated
secrets, local absolute paths, or unrelated formatting churn.

Do not log private keys, seeds, credentials, or production secrets.
Public deterministic test-vector seeds are fixtures, but avoid dumping
large cryptographic blobs to normal console logs.

## Deferred scope

Do not implement deferred features from assumptions. Deferred areas
currently include complete recovery policy, device/passkey
authorization, pairwise application identifier protocol, credential
issuance/presentation, registry-specific consensus, ledger-specific
implementation details, hardware key-storage policy, and final
production deactivation policy.

A future story may define these explicitly.

## Definition of done

Before reporting a coding task complete:

-   code compiles;
-   relevant tests pass;
-   applicable normative conformance verification passes;
-   normative checksums still verify unless intentionally versioned;
-   no frozen protocol artifact changed unexpectedly;
-   no debug/temporary artifacts remain; and
-   report files changed, tests run, and unresolved protocol questions.

## When uncertain

If implementation requirements conflict with the frozen specification,
do not choose whichever makes tests easiest. State the conflict
precisely.

If a proposed change alters a frozen OI-001/OI-002 invariant, stop and
request protocol-level review before implementing the normative change.
