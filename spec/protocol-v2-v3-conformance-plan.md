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
- V319 DelegationPolicy PRESERVE_EXISTING leaves delegation generation unchanged
- V320 RESET_DELEGATIONS increments delegation generation exactly once

## Invalid/security vectors

- VI301 missing Authentication PoP
- VI302 Authentication PoP signed under Controller domain
- VI303 duplicate Authentication PoP
- VI304 unauthorized Authentication method
- VI305 missing Delegation PoP
- VI306 Delegation PoP signed under Authentication domain — cryptographic cross-domain rejection implemented
- VI307 duplicate Delegation PoP
- VI308 unauthorized Delegation method
- VI309 A->B rotation missing required disposition — initial independent rejection check implemented
- VI310 initial policy installation supplies forbidden disposition — initial independent rejection check implemented
- VI311 policy removal attempts PRESERVE_EXISTING — independent rejection check implemented
- VI312 exact A->A replacement — initial independent rejection check implemented
- VI313 generation jump greater than one — initial independent rejection check implemented
- VI314 generation decrease
- VI315 generation overflow
- VI316 RECOVER attempts to preserve AuthenticationPolicy — independent rejection check implemented
- VI317 RECOVER attempts to preserve DelegationPolicy — independent rejection check implemented
- VI318 RECOVER missing assertion disposition — independent rejection check implemented
- VI319 RECOVER REMOVE while AssertionPolicy absent — independent rejection check implemented
- VI320 RECOVER REPLACE while AssertionPolicy absent — independent rejection check implemented
- VI321 RECOVER REPLACE missing Assertion PoP — independent rejection check implemented
- VI322 stateVersion 3 downgrade attempt
- VI323 protocolVersion 1 operation applied to stateVersion 3
- VI324 malformed protocolVersion 2 proof collection
- VI325 Assertion PoP substituted for Authentication PoP — cryptographic cross-domain rejection implemented
- VI326 Delegation PoP substituted for Assertion PoP
- VI327 Authentication PoP substituted for Delegation PoP
- VI328 duplicate effective public key under different method IDs in one policy
- VI329 CREATE supplies structurally forbidden redundant Controller PoP
- VI330 RESET_AUTHENTICATION carries a forbidden purpose-specific PoP collection — independent structural rejection check implemented
- VI331 RECOVER carries forbidden ordinary ControllerPolicy authorization — structural rejection check implemented
- VI332 RECOVER payload disposition/AssertionPolicy shape mismatch — independent rejection check implemented

DelegationGrant registration, backdating, individual status, and generation-aware
grant-validity vectors are deferred to OI-014, where the canonical DelegationGrant
and registration wire formats will be defined.

## Required invariants

Every implementation must independently reproduce identical StateBytes and StateHash for every successful state transition. Invalid vectors must fail structurally or semantically before any authoritative state mutation.
