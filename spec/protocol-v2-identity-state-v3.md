# OpenIdentity Protocol v2 / IdentityState v3 — Draft

**Status:** Draft; not frozen  
**Operation protocolVersion:** 2  
**Resulting IdentityState version:** 3  
**Normative wire draft:** `spec/cddl/openidentity-operation-v3.cddl`

**Implementation guide:** `docs/protocol-v2-identity-state-v3-guide.md` (supporting/non-normative explanation)

## 1. Upgrade boundary

ProtocolVersion 2 is the explicit state-v3 upgrade boundary.

- A successful protocolVersion 2 state-changing operation against IdentityState v1 or v2 MUST produce IdentityState v3.
- A successful protocolVersion 2 operation against IdentityState v3 MUST preserve stateVersion 3.
- A protocolVersion 1 operation MUST NOT be applied to IdentityState v3.
- Historical v1/v2 StateBytes and StateHashes are never reinterpreted or rewritten.
- No transition from IdentityState v3 to v1/v2 is valid.

When an eligible non-RECOVER protocolVersion 2 operation upgrades v1/v2 to v3, derived authorities absent from the legacy state initialize with generation 0. A protocolVersion 2 RECOVER upgrading v1/v2 initializes both derived-authority generations to 1 because recovery is a security reset. RESET_AUTHENTICATION and RESET_DELEGATIONS MUST NOT perform a v1/v2-to-v3 upgrade; they are valid only when the authoritative predecessor is already IdentityState v3. A reset represents invalidation of an existing v3 security generation and MUST NOT manufacture a reset generation for authority that did not exist in the predecessor schema.

## 2. IdentityState v3

IdentityState v3 extends the frozen v2 labels without reassigning them:

- 1 stateVersion = 3
- 2 identity
- 3 sequence
- 4 status
- 5 ControllerPolicy
- 6 recoveryCommitment (optional)
- 7 AssertionPolicy (optional)
- 8 AuthenticationAuthority
- 9 DelegationAuthority

AuthenticationAuthority and DelegationAuthority are always present in v3. Each contains a uint64 generation and an optional VerificationPolicy. Policy absence does not erase the generation.

## 3. Purpose separation

ControllerPolicy changes root identity state. RecoveryPolicy authorizes RECOVER only. AssertionPolicy issues credentials/assertions. AuthenticationAuthority authenticates the identity. DelegationAuthority authorizes registration of constrained delegation grants.

Authority for one purpose MUST NOT imply authority for another purpose. Explicit reuse of a VerificationMethod across different policies is permitted, but each purpose uses a distinct signing domain.

Within one VerificationPolicy, VerificationMethod IDs MUST be unique and duplicate effective cryptographic keys are forbidden. Two methods contain the same effective key when the deterministic-CBOR encodings of their fully validated COSE_Key values are byte-identical. The same exact cryptographic key under multiple method IDs MUST NOT count as independent threshold members. This rule does not claim to detect common organizational or hardware control of distinct keys.

## 4. Proof collections

SignedOperation v3 appends, without reassigning existing labels:

- 2 ordinary ControllerPolicy authorization proofs
- 3 ControllerPolicy proof-of-possession proofs
- 4 RecoveryPolicy authorization proofs
- 5 AuthenticationPolicy proof-of-possession proofs
- 6 AssertionPolicy proof-of-possession proofs
- 7 DelegationPolicy proof-of-possession proofs

New proof domains are:

- `OpenIdentity Authentication Proof`
- `OpenIdentity Assertion Proof`
- `OpenIdentity Delegation Proof`

Every VerificationMethod newly installed in a policy MUST provide exactly one purpose-specific PoP. Policy threshold does not reduce PoP coverage.

### CREATE exception

CREATE is authorized by the proposed ControllerPolicy through field 2. Those signatures already prove possession and intent for the proposed controller over the exact CREATE OperationBytes. ProtocolVersion 2 CREATE therefore MUST NOT require redundant field-3 Controller PoPs.

Derived policies installed by CREATE do not authorize CREATE and therefore MUST provide their purpose-specific PoPs.

## 5. Operation registry

ProtocolVersion 2 allocates:

1 CREATE  
2 ROTATE_CONTROLLER  
3 RECOVER  
4 DEACTIVATE  
5 SET_ASSERTION_POLICY  
6 SET_AUTHENTICATION_POLICY  
7 SET_DELEGATION_POLICY  
8 RESET_AUTHENTICATION  
9 RESET_DELEGATIONS  

10..23 remain reserved.

## 6. AuthenticationAuthority

`generation` is a uint64 security generation, not a blockchain/consensus epoch.

SET_AUTHENTICATION_POLICY rules:

- absent -> A: install A; generation unchanged; disposition MUST be absent.
- A -> B with PRESERVE_EXISTING: replace policy; generation unchanged.
- A -> B with INVALIDATE_EXISTING: replace policy; generation increments exactly once.
- A -> absent: policy removed; generation increments exactly once; PRESERVE is not permitted.
- A -> identical A: invalid no-op.
- absent -> absent: invalid no-op.

RESET_AUTHENTICATION increments generation exactly once and changes no policy.

PRESERVE_EXISTING means already-established downstream trust may remain acceptable. It does not make a rotated-out AuthenticationPolicy valid for new AuthenticationProofs. New AuthenticationProofs MUST satisfy the current AuthenticationPolicy.

## 7. DelegationAuthority

SET_DELEGATION_POLICY uses the analogous transitions:

- absent -> A: install A; generation unchanged.
- A -> B / PRESERVE_EXISTING: policy B; generation unchanged.
- A -> B / INVALIDATE_EXISTING: policy B; generation +1.
- A -> absent: remove policy; generation +1.
- A -> identical A and absent -> absent are invalid no-ops.

RESET_DELEGATIONS increments generation exactly once and changes no policy.

## 8. Authoritative delegation registration

A purely offline signed DelegationGrant is not authoritative.

Reason: after a planned A -> B DelegationPolicy rotation with generation preserved, a holder of old key A could otherwise create a new grant and backdate it by referencing the historical state in which A was authorized.

A usable DelegationGrant MUST therefore be registered through the authoritative OpenIdentity network while its issuing DelegationPolicy is current.

Registration:

- validates the grant against the current ACTIVE grantor IdentityState;
- validates the current DelegationPolicy;
- binds the registered grant to the current delegation generation;
- creates a separate authoritative grant object/record;
- MUST NOT increment the grantor identity sequence;
- MUST NOT alter the grantor StateHash merely because a grant is registered.

Existing registered grants survive a PRESERVE_EXISTING policy rotation. INVALIDATE_EXISTING, RESET_DELEGATIONS, policy removal, or RECOVER invalidates prior-generation grants.

Exact ledger representation, fee sponsorship, and blockchain transaction mapping are defined by the future OpenIdentity Network Profile, not core IdentityState serialization.

## 9. AssertionPolicy in protocolVersion 2

SET_ASSERTION_POLICY remains ControllerPolicy-authorized, but installation of a non-nil AssertionPolicy uses field 6 Assertion PoPs rather than overloading field 3 Controller PoPs.

This is a protocolVersion 2 semantic change. Frozen protocolVersion 1 behavior is unchanged.

## 10. RECOVER

RECOVER remains authorized exclusively by the committed RecoveryPolicy. Ordinary ControllerPolicy authorization is forbidden.

Successful v3 RECOVER:

- preserves identity;
- increments sequence;
- sets status ACTIVE;
- installs replacement ControllerPolicy;
- rotates recoveryCommitment;
- handles existing AssertionPolicy by explicit disposition;
- removes AuthenticationPolicy and increments authentication generation exactly once;
- removes DelegationPolicy and increments delegation generation exactly once.

Assertion disposition has no default:

1 PRESERVE  
2 REMOVE  
3 REPLACE

Rules:

- If AssertionPolicy is present, PRESERVE, REMOVE, or REPLACE are valid.
- REPLACE requires a replacement AssertionPolicy and complete Assertion PoP coverage.
- PRESERVE and REMOVE prohibit replacement AssertionPolicy/Assertion PoPs.
- If AssertionPolicy is absent, only PRESERVE is valid; RECOVER cannot introduce a new assertion-authority class.

RECOVER cannot preserve or replace AuthenticationPolicy or DelegationPolicy. Those authorities must be deliberately reinstalled afterward by the recovered ControllerPolicy.

## 11. DEACTIVATE

DEACTIVATE preserves authority structures and generations in canonical state but makes current derived authority dormant.

While DEACTIVATED, RECOVER is the only state-changing operation permitted. CREATE is inapplicable because the identity already exists, and ROTATE_CONTROLLER, DEACTIVATE, SET_ASSERTION_POLICY, SET_AUTHENTICATION_POLICY, SET_DELEGATION_POLICY, RESET_AUTHENTICATION, and RESET_DELEGATIONS MUST be rejected before authoritative state mutation.

While DEACTIVATED:

- new AuthenticationProofs are invalid;
- new delegation registration is invalid;
- existing DelegationGrants are unusable;
- new credential issuance is invalid.

Historical credential verification is not erased merely because the issuer later deactivates.

DEACTIVATE does not increment authentication/delegation generations. RECOVER increments both, preventing prior derived authority from becoming usable again after reactivation.

## 12. Generation invariants

For each authority generation:

- range is 0..2^64-1;
- it never decreases;
- an operation either preserves it or increments it by exactly one;
- arbitrary jumps are invalid;
- wrapping is forbidden;
- an operation requiring increment at 2^64-1 fails.

## 12A. State preservation invariant

Except for fields explicitly modified by an operation's normative transition semantics, every field of the authoritative predecessor IdentityState MUST be preserved exactly in the successor logical state and therefore in its canonical StateBytes representation. Implementations MUST NOT silently drop, reset, reconstruct with different values, or otherwise mutate unrelated recovery, assertion, authentication, delegation, controller, identity, or status state.

Sequence changes according to the normal state-transition rule. State version changes only at the explicit protocolVersion 2 upgrade boundary. RECOVER is the intentional broad exception defined in Section 10 because its normative semantics explicitly replace/reset multiple authority fields.

## 13. StateHash

StateHash remains the SHA2-256 Multihash of exact deterministic CBOR StateBytes. In v3 it commits to both AuthenticationAuthority and DelegationAuthority, including their generations and installed policies.

Historical v1/v2 StateHashes are unchanged.

## 14. Conformance priorities

Positive vectors MUST cover CREATE variants, v1/v2->v3 upgrade, planned/security rotations, removals, resets, RECOVER assertion dispositions, recovery from DEACTIVATED, and delegation-generation preservation/invalidation semantics. DelegationGrant registration and backdating vectors are deferred to OI-014.

Invalid vectors MUST cover cross-domain PoP substitution, missing/duplicate/unauthorized PoPs, invalid disposition combinations, generation decrease/jump/overflow, PV1-on-v3 downgrade attempts, duplicate effective keys inside one policy, RECOVER attempts to preserve authentication/delegation authority, structurally forbidden proof collections, and malformed RECOVER assertion-disposition shapes. Delegation backdating and registration vectors are deferred to OI-014.
