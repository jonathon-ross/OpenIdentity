# Protocol v2 / IdentityState v3 Conformance Plan

**Status:** Draft

## Positive vectors

- V301 minimal CREATE v3
- V302 CREATE with AuthenticationPolicy
- V303 CREATE with all derived authorities
- V304 protocolVersion 2 operation upgrades v2 to v3
- V305 AuthenticationPolicy planned rotation / PRESERVE_EXISTING
- V306 AuthenticationPolicy security rotation / INVALIDATE_EXISTING
- V307 remove AuthenticationPolicy
- V308 RESET_AUTHENTICATION
- V309 initial DelegationPolicy installation
- V310 DelegationPolicy planned rotation / PRESERVE_EXISTING
- V311 DelegationPolicy security rotation / INVALIDATE_EXISTING
- V312 remove DelegationPolicy
- V313 RESET_DELEGATIONS
- V314 RECOVER / PRESERVE AssertionPolicy
- V315 RECOVER / REMOVE AssertionPolicy
- V316 RECOVER / REPLACE AssertionPolicy with complete Assertion PoP
- V317 RECOVER from DEACTIVATED
- V318 protocolVersion 2 RECOVER upgrades v2 to v3 with generations = 1
- V319 registered delegation remains usable across PRESERVE_EXISTING rotation
- V320 registered delegation is invalid after generation reset

## Invalid/security vectors

- VI301 missing Authentication PoP
- VI302 Authentication PoP signed under Controller domain
- VI303 duplicate Authentication PoP
- VI304 unauthorized Authentication method
- VI305 missing Delegation PoP
- VI306 Delegation PoP signed under Authentication domain
- VI307 duplicate Delegation PoP
- VI308 unauthorized Delegation method
- VI309 A->B rotation missing required disposition
- VI310 initial policy installation supplies forbidden disposition
- VI311 policy removal attempts PRESERVE_EXISTING
- VI312 exact A->A replacement
- VI313 generation jump greater than one
- VI314 generation decrease
- VI315 generation overflow
- VI316 RECOVER attempts to preserve AuthenticationPolicy
- VI317 RECOVER attempts to preserve DelegationPolicy
- VI318 RECOVER missing assertion disposition
- VI319 RECOVER REMOVE while AssertionPolicy absent
- VI320 RECOVER REPLACE while AssertionPolicy absent
- VI321 RECOVER REPLACE missing Assertion PoP
- VI322 stateVersion 3 downgrade attempt
- VI323 protocolVersion 1 operation applied to stateVersion 3
- VI324 malformed protocolVersion 2 proof collection
- VI325 Assertion PoP substituted for Authentication PoP
- VI326 Delegation PoP substituted for Assertion PoP
- VI327 Authentication PoP substituted for Delegation PoP
- VI328 duplicate effective public key under different method IDs in one policy
- VI329 unregistered/offline DelegationGrant presented as authoritative
- VI330 old DelegationPolicy attempts grant registration after PRESERVE rotation
- VI331 old-generation registered grant presented after INVALIDATE/reset
- VI332 CREATE incorrectly requires or supplies redundant Controller PoP

## Required invariants

Every implementation must independently reproduce identical StateBytes and StateHash for every successful state transition. Invalid vectors must fail structurally or semantically before any authoritative state mutation.
