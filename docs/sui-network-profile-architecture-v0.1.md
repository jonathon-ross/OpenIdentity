# OpenIdentity Sui Network Profile Architecture v0.1

**Status:** Exploratory product/network architecture — non-normative  
**Target:** Sui Testnet first  
**Core dependencies:** OpenIdentity Protocol v2 / IdentityState v3; OI-014 DelegationGrant v1

## 1. Purpose

This document defines the initial product architecture for using Sui as the first authoritative OpenIdentity network implementation.

Sui is a network profile, not the OpenIdentity identity model. The permanent OpenIdentity identifier MUST remain independent of the Sui object ID, Sui address, package ID, and network. A future registry implementation on another ledger or non-blockchain authoritative network must be able to represent the same OpenIdentity semantics.

The product model is:

```text
OpenIdentity Wallet
  -> OpenIdentity protocol operations / OI-015 / OI-014
  -> Sui Network Profile (canonical public state and selected authoritative grant status)
  -> OpenIdentity Gateway
  -> AD / Entra / OAuth2 / OIDC / applications / AI agents
```

## 2. Design principles

1. **Identity is not a Sui account.** OpenIdentity ID and Sui object ID are distinct.
2. **Sui does not hold private authority.** Controller, authentication, assertion, delegation, and recovery private keys remain off-chain.
3. **No PII on-chain.** Names, email addresses, AD usernames/objectGUIDs, Entra subjects, OIDC subjects, credentials, private grant resources, and wallet metadata stay off-chain.
4. **The chain commits to canonical protocol state; it does not redefine it.**
5. **Normal authentication is off-chain.** OI-015 login must not require a Sui transaction.
6. **Root-state changes are authoritative network writes.**
7. **OI-014 registration/revocation may use Sui authoritative records while GrantBytes may remain private.**
8. **Users need not own SUI.** Product flows should support sponsored transactions.
9. **Gateway compromise must not grant root/controller authority.**
10. **Wallet UX hides blockchain mechanics unless the user explicitly requests them.**

## 3. Sui primitives used

The profile relies on Sui's object model: objects have globally unique IDs, ownership, and monotonically changing versions. Move packages define the rules that mutate those objects.

Initial profile choices:

- identity registry/state objects: shared or consensus-accessible objects governed by Move validation, not wallet-owned authority tokens;
- immutable package code per published package version, with explicit package/profile upgrade governance;
- capability objects only where they model deployment authority, sponsorship, or selected persistent agent capabilities; capability possession MUST NOT replace OI-014 authorization semantics;
- Programmable Transaction Blocks for atomic multi-step registration/update operations;
- sponsored transactions for non-crypto onboarding and enterprise operation.

## 4. Identity object model

Conceptual Move model (illustrative, not frozen syntax):

```move
public struct IdentityRecord has key {
    id: UID,
    openidentity_id: vector<u8>,   // exactly 32 bytes
    state_version: u64,
    sequence: u64,
    state_hash: vector<u8>,        // canonical OpenIdentity StateHash
    status: u8,
    protocol_version: u64,
}
```

The authoritative meaning remains the canonical OpenIdentity StateBytes whose SHA2-256 Multihash is `state_hash`.

The Sui object MUST NOT become an alternate serialization of all IdentityState fields. Clients resolve the canonical state material and verify that its StateHash matches the authoritative Sui record.

### Identity lookup

A deterministic registry/index maps the 32-byte OpenIdentity ID to the current IdentityRecord object ID. The mapping mechanism is a network-profile concern and must not change the OpenIdentity ID.

### Creation

```text
Wallet generates OpenIdentity authority
 -> constructs canonical CREATE OperationBytes
 -> signs according to Protocol v2
 -> resolver/transaction builder validates operation
 -> sponsored Sui transaction calls Move package
 -> Move/network adapter records identity + resulting StateHash
 -> canonical StateBytes are distributed through resolver/indexer storage
```

The transaction must fail if the submitted transition is not an exact valid OpenIdentity transition.

### Update/recovery/deactivation

Each state-changing operation:

1. resolves current authoritative IdentityRecord;
2. resolves canonical predecessor StateBytes;
3. verifies predecessor StateHash;
4. verifies exact OpenIdentity operation and proofs;
5. derives successor StateBytes and StateHash;
6. requires exact-next sequence and protocol/state-version rules;
7. atomically updates the Sui IdentityRecord;
8. emits a structured network event containing non-sensitive identifiers/hashes.

No operation may bypass Protocol v2 transition semantics merely because the Sui sender owns or sponsors the transaction.

## 5. Canonical state availability

Sui stores the authoritative current commitment, not all private/application metadata.

Initial product architecture:

```text
Sui IdentityRecord
  openidentity_id
  sequence
  state_hash
  status
       |
       v
OpenIdentity Resolver / Indexer
  canonical StateBytes
  operation history
  Sui checkpoint / tx reference
       |
       v
Wallet / Gateway / verifier
  independently hashes StateBytes
  compares with Sui state_hash
```

StateBytes are protocol data and may be publicly distributable where the protocol requires them, but external-account bindings and credentials remain separate.

## 6. OI-014 delegation on Sui

Protocol v2 requires usable DelegationGrants to be authoritatively registered and explicitly leaves ledger representation to a network profile. OI-014 permits a minimal public anchor that omits GrantBytes and sensitive grant fields.

Initial Sui representation:

```move
public struct GrantRecord has key {
    id: UID,
    grant_id: vector<u8>,          // OI-014 SHA2-256 Multihash
    root_grantor: vector<u8>,      // OpenIdentity ID
    delegation_generation: u64,
    revision: u64,
    record_hash: vector<u8>,
    status: u8,                    // ACTIVE / REVOKED
    registered_at: u64,
}
```

Public GrantRecord MUST NOT contain private resource descriptions or arbitrary GrantBytes by default.

The authoritative registration transaction verifies the OI-014 registration conditions against the current grantor IdentityState and current DelegationAuthority generation.

Revocation follows OI-014 revision/RecordHash ordering. RESET_DELEGATIONS, invalidating policy changes, RECOVER, and deactivation are enforced during grant resolution/use according to frozen protocol semantics.

## 7. AI-agent delegation profile

AI agents are an OI-014 profile, not a new core principal type.

Example wallet policy:

```text
Agent: Property Research Agent
Capabilities:
  properties.search
  properties.read
  comps.read
Resources:
  portfolio:ross-properties
Expires:
  2026-10-10T22:00:00Z
Redelegation:
  forbidden
```

The full grant may remain encrypted/private. The Sui GrantRecord provides authoritative registration/status and generation binding.

### On-chain vs off-chain delegation

**On-chain authoritative registration recommended:**
- persistent agent authority;
- financial or production capabilities;
- long-lived enterprise delegation;
- delegation that must be independently discoverable/revocable across organizations.

**Potential profile optimization later:**
- very short-lived session permissions may be represented by a registered parent capability plus off-chain strictly attenuated proofs if OI-014/profile semantics explicitly permit it.

The first implementation SHOULD favor authoritative registration over premature optimization.

## 8. Agent capability objects

Sui capability objects can be useful as execution adapters, but they MUST NOT replace the OI-014 grant.

Conceptually:

```text
OI-014 RegisteredGrant (authority)
        |
        v
Sui AgentCapability object (execution adapter)
        |
        v
Move application operation
```

An AgentCapability must bind to `grant_id`, grant revision/generation, and the profile-defined capability/resource commitment. If the grant becomes unusable, possession of the capability object must not resurrect authority.

## 9. Sponsored transaction architecture

OpenIdentity should sponsor identity-network writes for ordinary users.

```text
Wallet builds intended OpenIdentity operation
 -> user signs OpenIdentity operation
 -> sponsor validates allowed transaction shape/rate limits
 -> sponsor supplies Sui gas
 -> required Sui transaction signatures collected
 -> transaction executes
```

The sponsor pays gas but MUST NOT gain OpenIdentity controller/authentication/delegation authority.

Sponsor policy should restrict callable package/functions, transaction size, rate, and maximum gas budget.

## 10. Wallet trust model

The wallet is the user's authority boundary.

Initial wallet responsibilities:

- generate/store OpenIdentity private keys;
- hardware-backed storage where available;
- construct and sign protocol operations;
- OI-015 authentication;
- OI-014 delegation creation/revocation;
- display current Sui-anchored state;
- connected-account management;
- recovery workflow;
- QR/deep-link authentication;
- transaction review before signing.

The wallet MUST display semantic intent, not raw blockchain calls.

Example:

```text
Delegate to: Research Agent
Can: properties.read, comps.read
Cannot: offers.submit, funds.transfer
Expires: Oct 10
Network fee: Sponsored ($0 to you)
```

## 11. Gateway trust model

Gateway provides interoperability:

- OAuth2/OIDC authorization server;
- Active Directory;
- Microsoft Entra;
- generic external OIDC;
- agent token exchange;
- resolver/cache/indexer access.

Gateway may verify OpenIdentity state and hold enterprise service credentials, but MUST NOT hold user controller/recovery private keys.

Compromise of Gateway must not permit changing canonical identity authority.

## 12. Authentication path

Normal login is transaction-free:

```text
Application
 -> Gateway authorization request
 -> Wallet receives OI-015 challenge
 -> Wallet signs OI-015 assertion
 -> Gateway resolves/caches canonical IdentityState anchored by Sui
 -> verifies assertion
 -> OAuth2/OIDC tokens
```

No Sui transaction is required unless identity state itself changes.

## 13. Sui availability and caching

Authentication must not depend on a single public RPC endpoint.

Production resolver design should support:

- multiple Sui RPC/GraphQL providers or self-operated infrastructure;
- checkpoint-aware indexing;
- locally cached verified IdentityState;
- explicit freshness policy;
- fail-closed behavior for security-sensitive state changes when freshness cannot be established;
- historical state resolution for protocol verification/audit.

Exact offline/freshness semantics require a separate security design before production.

## 14. Package upgrade strategy

Sui package IDs are deployment artifacts, not OpenIdentity identifiers.

The network profile must define:

- approved package/version registry;
- migration rules for IdentityRecord/GrantRecord;
- compatibility with frozen protocol versions;
- emergency security upgrade governance;
- client pinning and minimum-supported package versions.

A Move package upgrade MUST NOT silently change frozen OpenIdentity protocol semantics.

## 15. zkLogin position

zkLogin is optional onboarding/transaction-signing infrastructure, not OpenIdentity root authority.

Potential uses:

- easy wallet onboarding;
- additional wallet recovery factor;
- sponsored Sui transaction signing;
- optional multisig participant.

An OAuth provider compromise must not automatically become OpenIdentity ControllerPolicy authority. Any future zkLogin recovery role requires an explicit OpenIdentity security design.

## 16. Privacy boundary

Never place these directly on Sui:

- names/emails;
- AD usernames/objectGUIDs;
- Entra tenant/user subjects;
- generic OIDC subjects;
- credentials;
- private resource identifiers;
- private GrantBytes;
- private keys;
- recovery secrets.

Public commitments must be evaluated for correlation leakage before deployment.

## 17. Windows sign-in roadmap

Windows workstation authentication is a later product track, not part of the initial Sui network profile.

Target architecture:

```text
Windows Credential Provider
 -> local/QR OpenIdentity authentication request
 -> OpenIdentity Wallet
 -> OI-015 proof
 -> Credential Provider / enterprise broker
 -> Windows account/domain authentication semantics
```

The Credential Provider is an integration surface, not the OpenIdentity authority. Windows/AD/Entra account semantics remain enforced by Windows authentication components.

Roadmap questions include offline unlock, cached state freshness, domain-joined and Entra-joined machines, recovery/fallback providers, TPM/Windows Hello integration, device binding, and enterprise deployment/MDM.

## 18. Product repositories

Recommended separation:

```text
OpenIdentity
  frozen protocol, SDK, vectors, reference profiles

openidentity-sui
  Move package, resolver/indexer, sponsorship service, Sui profile tests

openidentity-wallet
  user authority, keys, authentication, recovery, delegations

openidentity-gateway
  AD, Entra, OAuth2/OIDC, agent token exchange, enterprise policy

openidentity-windows
  future Windows Credential Provider / device integration
```

## 19. v0.1 implementation milestones

### SUI-001 — Localnet object proof
- Move package with IdentityRecord.
- OpenIdentity ID remains independent of object ID.
- CREATE records StateHash.
- invalid sequence/update rejected.

### SUI-002 — Protocol transition adapter
- Java/TypeScript transaction builder consumes canonical Protocol v2 operations.
- exact successor StateHash verified before chain submission.
- ROTATE/SET_AUTHENTICATION/SET_DELEGATION/RESET/DEACTIVATE/RECOVER coverage.

### SUI-003 — Testnet + sponsorship
- publish package on Testnet;
- sponsor CREATE/update;
- user holds no SUI;
- sponsor cannot alter signed OpenIdentity intent.

### SUI-004 — Resolver/indexer
- OpenIdentity ID -> IdentityRecord;
- canonical StateBytes retrieval;
- StateHash verification;
- checkpoint/transaction provenance;
- caching/freshness policy.

### SUI-005 — Wallet alpha
- create identity;
- secure key storage;
- Sui synchronization;
- OI-015 QR/deep-link authentication;
- recovery UX foundation.

### SUI-006 — OI-014 registry
- GrantRecord register/revoke;
- generation invalidation;
- minimal public anchor;
- private GrantBytes distribution;
- adversarial vectors mapped to Sui.

### SUI-007 — AI agent alpha
- wallet delegation UI;
- agent SDK;
- Gateway token exchange;
- scope/resource attenuation;
- revocation;
- optional Move execution capability adapter.

### SUI-008 — Production hardening
- package upgrade governance;
- RPC/indexer redundancy;
- sponsor abuse controls;
- telemetry/audit;
- external security review;
- Mainnet readiness gate.

### Future — Windows sign-in
- Credential Provider prototype;
- wallet QR/local-device authentication;
- offline/freshness model;
- domain/Entra integration;
- enterprise deployment.

## 20. Decisions for v0.1

Recommended initial decisions:

1. Sui is the first production OpenIdentity Network Profile.
2. OpenIdentity ID != Sui object ID.
3. Sui stores authoritative state commitments, not user PII/private keys.
4. Protocol StateHash remains the canonical state commitment.
5. Normal OI-015 authentication performs no blockchain write.
6. Root-state changes use sponsored Sui transactions.
7. OI-014 persistent grants use authoritative Sui GrantRecords with minimal public data.
8. Wallet is the user authority boundary.
9. Gateway is an interoperability boundary and never receives root private authority.
10. Windows sign-in is explicitly on the roadmap after wallet/gateway foundations.
