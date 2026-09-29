# Protocol v2 / IdentityState v3 Conformance Plan

**Status:** Draft

## Positive vectors

- V301 minimal CREATE v3 — generator implemented; draft fixture generated and independently reconstructed
- V302 CREATE with AuthenticationPolicy — generator implemented; controller authorization + AuthenticationPolicy PoP independently reconstructed
- V303 CREATE with all derived authorities — generator implemented; authentication/assertion/delegation purpose-specific PoPs independently reconstructed
- V304 protocolVersion 2 operation upgrades v2 to v3 — generator implemented; exact historical v2 StateHash is carried into previousStateHash
- V305 AuthenticationPolicy planned rotation / PRESERVE_EXISTING — generator + independent verifier implemented; generation preserved
- V306 AuthenticationPolicy security rotation / INVALIDATE_EXISTING — generator + independent verifier implemented; generation increments exactly once
- V307 remove AuthenticationPolicy — generator + independent verifier implemented; policy absent and generation +1
- V308 RESET_AUTHENTICATION — generator + independent verifier implemented; policy preserved byte-for-byte and generation +1
- V309 initial DelegationPolicy installation — generator + independent verifier implemented; generation remains 0
- V310 DelegationPolicy planned rotation / PRESERVE_EXISTING — generator + independent verifier implemented; generation preserved
- V311 DelegationPolicy security rotation / INVALIDATE_EXISTING — generator + independent verifier implemented; generation +1
- V312 remove DelegationPolicy — generator + independent verifier implemented; policy absent and generation +1
- V313 RESET_DELEGATIONS — generator + independent verifier implemented; policy preserved byte-for-byte and generation +1
- V314 RECOVER / PRESERVE AssertionPolicy — generator + independent verifier implemented; derived authorities removed and generations +1
- V315 RECOVER / REMOVE AssertionPolicy — generator + independent verifier implemented; derived authorities removed and generations +1
- V316 RECOVER / REPLACE AssertionPolicy with complete Assertion PoP — generator + independent verifier implemented
- V317 RECOVER from DEACTIVATED — generator + independent verifier implemented; resulting state ACTIVE
- V318 protocolVersion 2 RECOVER upgrades v2 to v3 with generations = 1 — generator + independent verifier implemented
- V319 DelegationPolicy PRESERVE_EXISTING leaves delegation generation unchanged — generator + independent verifier implemented at nonzero generation 42
- V320 RESET_DELEGATIONS increments delegation generation exactly once — generator + independent verifier implemented at generation 42 -> 43
- V321 protocolVersion 2 SET_DELEGATION_POLICY upgrades v2 to v3 — delegation policy installed at generation 0; authentication generation initializes 0
- V322 ordinary protocolVersion 2 ROTATE_CONTROLLER upgrades v2 to v3 — both absent derived authorities initialize at generation 0

## Invalid/security vectors

Coverage status: VI301-VI308 and VI325-VI327 contain concrete cryptographic proof/domain attack artifacts. VI328 contains concrete duplicate effective-key material. VI309-VI324 and VI329-VI332 now contain byte-complete predecessor/operation/proposed-state or malformed SignedOperation/payload artifacts as appropriate to the rejection class. The suite remains draft/non-normative until the full regression, checksum, and frozen-artifact release gates pass.

- VI301 missing Authentication PoP
- VI302 Authentication PoP signed under Controller domain
- VI303 duplicate Authentication PoP
- VI304 unauthorized Authentication method
- VI305 missing Delegation PoP
- VI306 Delegation PoP signed under Authentication domain — cryptographic Python + Java cross-domain rejection coverage
- VI307 duplicate Delegation PoP
- VI308 unauthorized Delegation method
- VI309 A->B rotation missing required disposition — byte-complete Python + Java rejection coverage
- VI310 initial policy installation supplies forbidden disposition — byte-complete Python + Java rejection coverage
- VI311 policy removal attempts PRESERVE_EXISTING — byte-complete Python + Java rejection coverage
- VI312 exact A->A replacement — byte-complete Python + Java rejection coverage
- VI313 generation jump greater than one — byte-complete Python + Java rejection coverage
- VI314 generation decrease
- VI315 generation overflow
- VI316 RECOVER attempts to preserve AuthenticationPolicy — byte-complete Python + Java rejection coverage
- VI317 RECOVER attempts to preserve DelegationPolicy — byte-complete Python + Java rejection coverage
- VI318 RECOVER missing assertion disposition — byte-complete Python + Java rejection coverage
- VI319 RECOVER REMOVE while AssertionPolicy absent — byte-complete Python + Java rejection coverage
- VI320 RECOVER REPLACE while AssertionPolicy absent — byte-complete Python + Java rejection coverage
- VI321 RECOVER REPLACE missing Assertion PoP — byte-complete Python + Java rejection coverage
- VI322 stateVersion 3 downgrade attempt
- VI323 protocolVersion 1 operation applied to stateVersion 3
- VI324 malformed protocolVersion 2 proof collection
- VI325 Assertion PoP substituted for Authentication PoP — cryptographic Python + Java cross-domain rejection coverage
- VI326 Delegation PoP substituted for Assertion PoP
- VI327 Authentication PoP substituted for Delegation PoP
- VI328 duplicate effective public key under different method IDs in one policy
- VI329 CREATE supplies structurally forbidden redundant Controller PoP
- VI330 RESET_AUTHENTICATION carries a forbidden purpose-specific PoP collection — byte-complete Python + Java structural rejection coverage
- VI331 RECOVER carries forbidden ordinary ControllerPolicy authorization — byte-complete Python + Java structural rejection coverage
- VI332 RECOVER payload disposition/AssertionPolicy shape mismatch — byte-complete Python + Java rejection coverage
- VI333 RESET_AUTHENTICATION against IdentityState v1/v2 — reject with RESET_REQUIRES_IDENTITY_STATE_V3
- VI334 RESET_DELEGATIONS against IdentityState v1/v2 — reject with RESET_REQUIRES_IDENTITY_STATE_V3

DelegationGrant registration, backdating, individual status, and generation-aware
grant-validity vectors are deferred to OI-014, where the canonical DelegationGrant
and registration wire formats will be defined.

## Required invariants

Every implementation must independently reproduce identical StateBytes and StateHash for every successful state transition. Invalid vectors must fail structurally or semantically before any authoritative state mutation.

## Superseded byte-frozen candidate

The previous byte-frozen candidate (125506 bytes, SHA-256 `5fc4613f4e51d449c3cc2fce4b0d4f3d6aebf2edce3f0729e0ca194ae4f40d92`) was intentionally invalidated by the final adversarial review after discovering ambiguity around RESET_AUTHENTICATION / RESET_DELEGATIONS as v1/v2-to-v3 upgrade operations.

A new candidate checksum MUST NOT be established until V301-V322 / VI301-VI334 pass the Python and Java gates and all frozen v0.1 regressions remain green.
