# Protocol v2 production enforcement matrix

The production verifier is gated against the frozen Protocol v2 / IdentityState v3 corpus.

## Direct production-envelope rejection

VI301, VI321, VI324, VI329, VI330, VI331 are fed as malformed SignedOperation envelopes.
VI333, VI334, VI335 and VI336 are reconstructed as operation-only envelopes because rejection occurs before signature authorization.
VI328 is reconstructed as CREATE with the frozen duplicate-effective-key policy.

## Production mutation/invariant enforcement

VI303/VI307 duplicate proof collections are covered by duplicate Authentication/Delegation PoP tests.
VI304/VI308 unauthorized methods are covered by policy-membership PoP enforcement.
VI309-VI312 authority-disposition/no-op rules are enforced by SET_AUTHENTICATION_POLICY / SET_DELEGATION_POLICY lifecycle logic.
VI313-VI315 authority generation manipulation cannot be caller-selected: successor generation is derived internally; overflow is explicitly rejected.
VI316/VI317 recovery cannot preserve derived authority: successor AuthenticationAuthority and DelegationAuthority are derived internally as generation+1 with policy removed.
VI318-VI320 recovery assertion-disposition shape and predecessor-presence rules are enforced by recovery payload parsing/application.
VI322 state-version downgrade cannot be caller-selected: all Protocol v2 successors are canonically emitted as IdentityState v3.
VI323 Protocol v1 on v3 is rejected by the Protocol-v2 version gate.
VI332 malformed recovery shape is rejected by strict recovery payload parsing.
VI337 sequence overflow is rejected before successor construction.

## Cryptographic component/domain separation

VI302, VI306, VI325, VI326 and VI327 are wrong-domain signatures. The frozen conformance suite proves each signature verifies under its source domain and fails under its required domain. Production uses the same fixed domain strings for Authentication, Delegation, Assertion, Controller and Recovery proofs; positive and tamper tests exercise those production paths.

## Status

The production verifier derives successor StateBytes internally. It never accepts a caller-proposed successor StateBytes, generation, status, or StateHash. State-only invalid vectors therefore map to production derivation invariants rather than a second proposed-state input.
