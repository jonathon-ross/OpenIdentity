# OI-003 Cross-Spec Consistency Review

Reviewed canonical targets:

- `spec/credential.md`
- `spec/cddl/openidentity-operation-v2.cddl`
- `spec/cddl/openidentity-credential-v1.cddl`

## Result

The strict-proof credential CDDL is the correct canonical credential schema.

The previously identified proof-set mismatch is resolved by replacing the older
`openidentity-credential-v1.cddl` with the strict-proof version.

## Confirmed alignment

- IdentityState v2 explicitly carries optional AssertionPolicy.
- SET_ASSERTION_POLICY is authorized only by the current ControllerPolicy.
- AssertionPolicy does not authorize its own mutation.
- nil AssertionPolicy means zero assertion authority.
- There is no fallback from absent AssertionPolicy to ControllerPolicy.
- StateHash binds the exact historical IdentityState.
- Credential verification uses the historical state, not current state.
- CredentialBytes include issuer, issuanceStateHash, validity, profile, subject, and claims.
- CredentialSigningInput is domain-separated as:
  `["OpenIdentity Credential", 1, CredentialBytes]`.
- Claims use a restricted deterministic CBOR value model; unrestricted `any` is not permitted.
- Credential Profile is an immutable absolute-URI identifier and is not required to be dereferenced for cryptographic verification.
- Unknown profile handling is profile-validation INDETERMINATE, not cryptographic INVALID.
- Credential proofs are canonically ordered by Verification Method ID.
- Duplicate supplied proofs are rejected.
- Unauthorized supplied proofs are rejected rather than ignored.
- Invalid supplied signatures are rejected.
- Threshold evaluation counts distinct authorized valid Verification Method IDs.
- Assertion-key replacement/removal does not rewrite historical authorization.
- Credential status/revocation remains separate from historical issuance authorization.
- W3C representations remain projections rather than the native cryptographic source of truth.

## Canonical invalid-proof errors

- `DUPLICATE_CREDENTIAL_PROOF`
- `UNAUTHORIZED_CREDENTIAL_PROOF`
- `INVALID_CREDENTIAL_SIGNATURE`
- `ASSERTION_THRESHOLD_NOT_SATISFIED`
- `INVALID_ISSUANCE_STATE_HASH`
- `NO_ASSERTION_AUTHORITY`

## Remaining intentionally deferred areas

No inconsistency was found that requires changing the frozen v0.1 credential
wire format. The following remain intentionally deferred:

- credential status/revocation mechanism;
- production Credential Profiles/profile registry;
- holder-binding and presentation proofs;
- selective disclosure / zero-knowledge presentations;
- pairwise subject derivation;
- W3C Verifiable Credential projection details;
- registry-specific historical-state retrieval.

## Repository action

Replace:

`spec/cddl/openidentity-credential-v1.cddl`

with the attached canonical strict-proof file.

No change to the frozen credential vectors or their checksum is required by
this documentation/CDDL cleanup because the strict proof semantics are the
semantics already exercised by CI01-CI10.
