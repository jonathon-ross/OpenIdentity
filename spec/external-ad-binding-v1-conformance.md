# OpenIdentity External Active Directory Binding v1 — Pre-Freeze Conformance

Status: FROZEN-NORMATIVE v1

This document is the release gate for freezing External Active Directory Binding v1. It does not modify ExternalOidcBindingV1.

## Normative candidate artifacts

- spec/cddl/openidentity-external-ad-binding-v1.cddl
- spec/cddl/openidentity-external-ad-binding-context-v1.cddl
- spec/external-ad-binding-v1-errors.md
- test-vectors/external-ad-binding-v1.json
- test-vectors/external-ad-binding-v1-crypto.json

## External subject identity

ExternalSubjectKey is exactly:

    (directoryId[16], objectGuid[16])

directoryId is an opaque random OpenIdentity-assigned identifier created when a trusted AD directory profile is enrolled.

objectGuid is the exact 16 octets returned by the Active Directory objectGUID LDAP attribute. Runtime UUID/GUID memory representations and UTF-8 UUID text are not protocol values.

DN, CN, sAMAccountName, UPN, mail, displayName, objectSid, and similar attributes never substitute for the ExternalSubjectKey.

## Binding

BindingBytes is deterministic RFC 8949 CBOR of ExternalAdBindingV1.

BindingId is:

    0x12 || 0x20 || SHA-256(
      deterministic-CBOR([
        "OpenIdentity External Active Directory Binding",
        1,
        BindingBytes
      ])
    )

## Binding authorization context

ContextHash is:

    0x12 || 0x20 || SHA-256(ContextBytes)

BIND uses OI-015 purpose:

    openidentity.external-ad.bind

REVOKE uses:

    openidentity.external-ad.revoke

The registry challenge is distinct from the OI-015 verifier nonce.

Authentication mechanism codes are:

    1 KERBEROS_SPNEGO
    2 LDAP_SASL_SIGNED
    3 LDAP_TLS_SIMPLE_WITH_CHANNEL_BINDING

Authentication mechanism is committed by the authorization context but is not part of the durable ExternalSubjectKey or BindingBytes.

## AD01 cryptographic anchor

identity:
000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f

directoryId:
d0d1d2d3d4d5d6d7d8d9dadbdcdddedf

objectGuid LDAP octets:
00112233445566778899aabbccddeeff

serviceId:
openidentity-ad-link-service

authentication mechanism:
KERBEROS_SPNEGO (1)

authenticationGeneration:
3

BindingId:
1220a40d9eb66afc6b70dda6b54334e7735a4621ce5033c7d51c0a2ee8121e4fa5c7

BIND ContextHash:
1220c08eade05282510b7af797c013a381f93a8c149bad98e6a7f84f061ae35bd86a

REVOKE ContextHash:
1220bc59906922b9a2e2f724c73deaeedea015d1dd9c03b326972856343c81691b30

## objectGUID interoperability anchor

For AD LDAP octets:

    00112233445566778899aabbccddeeff

the familiar Windows GUID display is:

    33221100-5544-7766-8899-aabbccddeeff

Naively parsing that display as network-order UUID bytes yields:

    33221100554477668899aabbccddeeff

Those bytes are not the OpenIdentity objectGuid value.

## Required pre-freeze gates

The candidate may be frozen only when all of the following pass without modifying expected outputs:

    python scripts/verify-ad-objectguid-byte-order.py
    python scripts/verify-external-ad-binding-v1-crypto.py
    python scripts/verify-external-ad-binding-v1.py
    python scripts/verify-external-ad-binding-checksums.py

Expected semantic count: 38.

Any change to candidate CDDL, error semantics, vector inputs, deterministic bytes, domain strings, mechanism codes, GUID representation, BindingId, or ContextHash requires regenerating and independently reviewing the pre-freeze package before freeze.
