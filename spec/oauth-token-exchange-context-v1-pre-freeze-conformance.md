# OpenIdentity OAuth Token Exchange Context v1 — Pre-Freeze Conformance Review

**Status:** RELEASE RECORD — OAuthTokenExchangeContextV1 FROZEN-NORMATIVE  
**Scope:** deterministic OAuthTokenExchangeContextV1 committed by frozen OI-015 contextHash  
**Normative CDDL:** `spec/cddl/openidentity-oauth-token-exchange-context-v1.cddl`

## 1. Boundary

This artifact freezes only the deterministic context object used to bind an OAuth token-exchange request into OI-015.

It does not freeze the complete OAuth bridge issuance profile, capability mapping, access-token format, metadata, error projection, lifetime policy, or deployment policy.

## 2. Current evidence

- positive vectors TX01-TX05;
- adversarial vectors TXI01-TXI40;
- deterministic Python generation;
- independent Python reconstruction/verification;
- independent Java reconstruction/verification using DeterministicCborWriter;
- no context checksum/byte-freeze yet.

Both Python and Java suites are green through TX01-TX05 + TXI01-TXI40.

## 3. Positive coverage

- TX01 — complete delegated-agent context with requested token type, canonical resources/audiences/scopes, DelegationEvidenceId, and DPoP jkt.
- TX02 — exact 16-resource count boundary.
- TX03 — exact 16-audience count boundary.
- TX04 — exact 64-scope count boundary.
- TX05 — requested_token_type absent, empty semantic collections, minimal clientId, and non-HTTP absolute authorization-server URI.

## 4. Adversarial coverage

### Version/canonical collections

- TXI01 unsupported version.
- TXI02 duplicate scope.
- TXI03 noncanonical scope ordering.
- TXI04 duplicate resource.
- TXI05 noncanonical resource ordering.
- TXI06 relative resource.
- TXI07 resource with fragment.
- TXI08 duplicate audience.
- TXI09 noncanonical audience ordering.
- TXI10 invalid scope grammar.

### Cryptographic commitments / DPoP

- TXI11 wrong DelegationEvidenceId Multihash code.
- TXI12 missing mandatory DPoP jkt.
- TXI13 wrong DPoP jkt length.
- TXI23 wrong Multihash digest-length prefix.
- TXI24 wrong DelegationEvidenceId total length.
- TXI25 invalid base64url character in jkt.
- TXI26 forbidden base64url padding.

### Bounds

- TXI14 17 resources.
- TXI15 17 audiences.
- TXI16 65 scopes.
- TXI17 authorizationServer > 2048 bytes.
- TXI18 clientId > 512 bytes.
- TXI19 requestedTokenType > 2048 bytes.
- TXI20 resource > 2048 bytes.
- TXI21 audience > 1024 bytes.
- TXI22 scope > 256 bytes.
- TXI36 empty authorizationServer.
- TXI37 empty clientId.
- TXI38 present-but-empty requestedTokenType.
- TXI39 requestedTokenType is not a URI.
- TXI40 authorizationServer is not a URI.

### Request substitution

Each substitution changes reconstructed contextHash:

- TXI27 authorization server.
- TXI28 clientId.
- TXI29 requested token type value.
- TXI30 requested token type presence/absence.
- TXI31 resource set.
- TXI32 audience set.
- TXI33 scope set.
- TXI34 DelegationEvidenceId.
- TXI35 DPoP key/jkt.

## 5. Normative v1 bounds

    authorizationServer:   1..2048 bytes
    clientId:              1..512 bytes
    requestedTokenType:    absent or 1..2048 bytes
    resources:             0..16 entries, each 1..2048 bytes
    audiences:             0..16 entries, each 1..1024 bytes
    scopes:                0..64 entries, each 1..256 bytes
    delegationEvidenceId:  exact SHA2-256 Multihash (34 bytes)
    dpopJkt:               exact 43-byte base64url-no-pad SHA-256 JWK thumbprint

Collections are duplicate-free and strictly ascending by unsigned UTF-8 bytes.

## 6. Frozen dependencies

This context profile consumes but MUST NOT modify:

- Protocol v2 / IdentityState v3;
- OI-014 DelegationGrant v1;
- OI-015 Authentication Assertion v1;
- OI-016 Delegated Subject Token v1.

The context's DelegationEvidenceId is derived from exact verified OI-016 evidence.

Its resulting contextHash is consumed by frozen OI-015.

## 7. Parser/runtime classification

Parser/unit suites remain responsible for malformed CBOR cases such as duplicate/unknown map labels, wrong major types, truncation, and non-deterministic CBOR encodings.

OAuth HTTP parsing, client authentication, complete RFC 9449 DPoP proof validation, OI-014 capability mapping, target resolution, and token issuance are broader profile/runtime responsibilities. The context vectors pin only the deterministic values after those inputs have been validly resolved.

## 8. Release evidence

The OAuthTokenExchangeContextV1 release boundary is:

- coverage: TX01-TX05 + TXI01-TXI40;
- deterministic Python generation and independent Python verification: PASS;
- independent Java reconstruction/verification: PASS;
- all previously frozen OpenIdentity commitments/artifacts: unchanged;
- exact generated bundle size: 15,073 bytes;
- committed checksum: `checksums/oauth-token-exchange-context-v1.json.sha256`;
- SHA-256: `28e2f575d2844235cb3e02ee5f96f17d6b652be40b50bd0a7464f72a04c997d3`;
- post-commit candidate-inclusive release gate: PASS.

The broader OAuth bridge issuance profile remains separately under design.

## 9. Freeze status

**NOT BYTE-FROZEN. NOT NORMATIVE.**

This status applies to OAuthTokenExchangeContextV1 only. The broader OAuth bridge profile remains separately under design.
