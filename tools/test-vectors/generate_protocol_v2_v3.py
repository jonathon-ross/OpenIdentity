#!/usr/bin/env python3
"""Generate and verify draft Protocol v2 / IdentityState v3 conformance vectors.

This tool is intentionally independent of the OpenIdentity SDK. It uses only
standard deterministic CBOR construction plus cryptography primitives.

Generated output under test-vectors/generated/ is development/reference output
until promoted through the repository's normative conformance process.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "test-vectors" / "generated" / "protocol-v2-identity-state-v3.json"


def _head(major: int, value: int) -> bytes:
    if value < 0:
        raise ValueError("CBOR length/value must be non-negative")
    if value < 24:
        return bytes([(major << 5) | value])
    if value < 256:
        return bytes([(major << 5) | 24, value])
    if value < 65536:
        return bytes([(major << 5) | 25]) + value.to_bytes(2, "big")
    if value < 2**32:
        return bytes([(major << 5) | 26]) + value.to_bytes(4, "big")
    if value < 2**64:
        return bytes([(major << 5) | 27]) + value.to_bytes(8, "big")
    raise ValueError("integer exceeds uint64")


def cbor(value) -> bytes:
    """Minimal RFC 8949 deterministic encoder for vector fixture types."""
    if value is None:
        return b"\xf6"
    if isinstance(value, int):
        return _head(0, value) if value >= 0 else _head(1, -1 - value)
    if isinstance(value, bytes):
        return _head(2, len(value)) + value
    if isinstance(value, str):
        encoded = value.encode("utf-8")
        return _head(3, len(encoded)) + encoded
    if isinstance(value, list):
        return _head(4, len(value)) + b"".join(cbor(item) for item in value)
    if isinstance(value, dict):
        encoded = [(cbor(key), cbor(item)) for key, item in value.items()]
        encoded.sort(key=lambda pair: (len(pair[0]), pair[0]))
        return _head(5, len(encoded)) + b"".join(k + v for k, v in encoded)
    raise TypeError(f"unsupported CBOR fixture type: {type(value)!r}")


def sha256_multihash(data: bytes) -> bytes:
    return b"\x12\x20" + hashlib.sha256(data).digest()


def build_v301() -> dict:
    identity = bytes(range(32))
    method_id = bytes(range(16))
    seed = hashlib.sha256(
        b"OpenIdentity protocol-v2 v3 V301 controller Ed25519 seed"
    ).digest()
    private_key = Ed25519PrivateKey.from_private_bytes(seed)
    public_key = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    cose_key = {1: 1, 3: -8, -1: 6, -2: public_key}
    method = {1: method_id, 2: cose_key}
    controller_policy = {1: 1, 2: [method]}

    operation = {
        1: 2,
        2: 1,
        3: identity,
        4: 1,
        5: None,
        6: {1: controller_policy},
    }
    operation_bytes = cbor(operation)
    signing_bytes = cbor(["OpenIdentity Operation", 1, operation_bytes])
    signature = private_key.sign(signing_bytes)

    signed_operation = {
        1: operation,
        2: [{1: method_id, 2: signature}],
    }

    state = {
        1: 3,
        2: identity,
        3: 1,
        4: 1,
        5: controller_policy,
        8: {1: 0},
        9: {1: 0},
    }
    state_bytes = cbor(state)
    state_hash = sha256_multihash(state_bytes)

    private_key.public_key().verify(signature, signing_bytes)

    return {
        "id": "V301",
        "description": "Minimal protocolVersion 2 CREATE produces IdentityState v3",
        "expected": "PASS",
        "fixture": {
            "identityHex": identity.hex(),
            "controllerMethodIdHex": method_id.hex(),
            "controllerPublicKeyHex": public_key.hex(),
        },
        "operationBytesHex": operation_bytes.hex(),
        "operationSigningBytesHex": signing_bytes.hex(),
        "controllerSignatureHex": signature.hex(),
        "signedOperationBytesHex": cbor(signed_operation).hex(),
        "stateBytesHex": state_bytes.hex(),
        "stateHashHex": state_hash.hex(),
        "assertions": {
            "protocolVersion": 2,
            "operationType": "CREATE",
            "sequence": 1,
            "previousStateHash": None,
            "stateVersion": 3,
            "status": "ACTIVE",
            "authenticationGeneration": 0,
            "authenticationPolicyPresent": False,
            "delegationGeneration": 0,
            "delegationPolicyPresent": False,
            "stateHashLength": len(state_hash),
        },
    }


def _ed25519(label: str, method_start: int):
    seed = hashlib.sha256(label.encode("ascii")).digest()
    private_key = Ed25519PrivateKey.from_private_bytes(seed)
    public_key = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    method_id = bytes(range(method_start, method_start + 16))
    method = {1: method_id, 2: {1: 1, 3: -8, -1: 6, -2: public_key}}
    return private_key, public_key, method_id, method


def _single_policy(method):
    return {1: 1, 2: [method]}


def _purpose_proof(domain: str, operation_bytes: bytes, private_key, method_id: bytes):
    signing_bytes = cbor([domain, 1, operation_bytes, method_id])
    signature = private_key.sign(signing_bytes)
    private_key.public_key().verify(signature, signing_bytes)
    return signing_bytes, {1: method_id, 2: signature}


def build_v302() -> dict:
    identity = bytes(range(32))
    cpriv, cpub, cid, cm = _ed25519(
        "OpenIdentity protocol-v2 v3 V302 controller Ed25519 seed", 0
    )
    apriv, apub, aid, am = _ed25519(
        "OpenIdentity protocol-v2 v3 V302 authentication Ed25519 seed", 16
    )
    controller_policy = _single_policy(cm)
    authentication_policy = _single_policy(am)
    operation = {
        1: 2, 2: 1, 3: identity, 4: 1, 5: None,
        6: {1: controller_policy, 4: authentication_policy},
    }
    operation_bytes = cbor(operation)
    controller_signing = cbor(["OpenIdentity Operation", 1, operation_bytes])
    controller_signature = cpriv.sign(controller_signing)
    cpriv.public_key().verify(controller_signature, controller_signing)
    auth_signing, auth_proof = _purpose_proof(
        "OpenIdentity Authentication Proof", operation_bytes, apriv, aid
    )
    signed_operation = {
        1: operation,
        2: [{1: cid, 2: controller_signature}],
        5: [auth_proof],
    }
    state = {
        1: 3, 2: identity, 3: 1, 4: 1, 5: controller_policy,
        8: {1: 0, 2: authentication_policy},
        9: {1: 0},
    }
    state_bytes = cbor(state)
    state_hash = sha256_multihash(state_bytes)
    return {
        "id": "V302",
        "description": "CREATE with AuthenticationPolicy requires authentication-domain PoP",
        "expected": "PASS",
        "fixture": {
            "identityHex": identity.hex(),
            "controllerMethodIdHex": cid.hex(),
            "controllerPublicKeyHex": cpub.hex(),
            "authenticationMethodIdHex": aid.hex(),
            "authenticationPublicKeyHex": apub.hex(),
        },
        "operationBytesHex": operation_bytes.hex(),
        "controllerSigningBytesHex": controller_signing.hex(),
        "controllerSignatureHex": controller_signature.hex(),
        "authenticationProofSigningBytesHex": auth_signing.hex(),
        "authenticationProofSignatureHex": auth_proof[2].hex(),
        "signedOperationBytesHex": cbor(signed_operation).hex(),
        "stateBytesHex": state_bytes.hex(),
        "stateHashHex": state_hash.hex(),
        "assertions": {
            "authenticationGeneration": 0,
            "authenticationPolicyPresent": True,
            "delegationGeneration": 0,
            "delegationPolicyPresent": False,
            "controllerProofCollectionPresent": False,
            "authenticationProofCollectionPresent": True,
            "stateHashLength": len(state_hash),
        },
    }


def build_v303() -> dict:
    identity = bytes(range(32))
    cpriv, cpub, cid, cm = _ed25519(
        "OpenIdentity protocol-v2 v3 V303 controller Ed25519 seed", 0
    )
    apriv, apub, aid, am = _ed25519(
        "OpenIdentity protocol-v2 v3 V303 authentication Ed25519 seed", 16
    )
    spriv, spub, sid, sm = _ed25519(
        "OpenIdentity protocol-v2 v3 V303 assertion Ed25519 seed", 32
    )
    dpriv, dpub, did, dm = _ed25519(
        "OpenIdentity protocol-v2 v3 V303 delegation Ed25519 seed", 48
    )
    controller_policy = _single_policy(cm)
    authentication_policy = _single_policy(am)
    assertion_policy = _single_policy(sm)
    delegation_policy = _single_policy(dm)
    operation = {
        1: 2, 2: 1, 3: identity, 4: 1, 5: None,
        6: {
            1: controller_policy,
            3: assertion_policy,
            4: authentication_policy,
            5: delegation_policy,
        },
    }
    operation_bytes = cbor(operation)
    controller_signing = cbor(["OpenIdentity Operation", 1, operation_bytes])
    controller_signature = cpriv.sign(controller_signing)
    cpriv.public_key().verify(controller_signature, controller_signing)
    auth_signing, auth_proof = _purpose_proof(
        "OpenIdentity Authentication Proof", operation_bytes, apriv, aid
    )
    assertion_signing, assertion_proof = _purpose_proof(
        "OpenIdentity Assertion Proof", operation_bytes, spriv, sid
    )
    delegation_signing, delegation_proof = _purpose_proof(
        "OpenIdentity Delegation Proof", operation_bytes, dpriv, did
    )
    signed_operation = {
        1: operation,
        2: [{1: cid, 2: controller_signature}],
        5: [auth_proof],
        6: [assertion_proof],
        7: [delegation_proof],
    }
    state = {
        1: 3, 2: identity, 3: 1, 4: 1, 5: controller_policy,
        7: assertion_policy,
        8: {1: 0, 2: authentication_policy},
        9: {1: 0, 2: delegation_policy},
    }
    state_bytes = cbor(state)
    state_hash = sha256_multihash(state_bytes)
    return {
        "id": "V303",
        "description": "CREATE with assertion, authentication, and delegation authorities",
        "expected": "PASS",
        "fixture": {
            "identityHex": identity.hex(),
            "controllerMethodIdHex": cid.hex(),
            "controllerPublicKeyHex": cpub.hex(),
            "authenticationMethodIdHex": aid.hex(),
            "authenticationPublicKeyHex": apub.hex(),
            "assertionMethodIdHex": sid.hex(),
            "assertionPublicKeyHex": spub.hex(),
            "delegationMethodIdHex": did.hex(),
            "delegationPublicKeyHex": dpub.hex(),
        },
        "operationBytesHex": operation_bytes.hex(),
        "controllerSigningBytesHex": controller_signing.hex(),
        "controllerSignatureHex": controller_signature.hex(),
        "authenticationProofSigningBytesHex": auth_signing.hex(),
        "authenticationProofSignatureHex": auth_proof[2].hex(),
        "assertionProofSigningBytesHex": assertion_signing.hex(),
        "assertionProofSignatureHex": assertion_proof[2].hex(),
        "delegationProofSigningBytesHex": delegation_signing.hex(),
        "delegationProofSignatureHex": delegation_proof[2].hex(),
        "signedOperationBytesHex": cbor(signed_operation).hex(),
        "stateBytesHex": state_bytes.hex(),
        "stateHashHex": state_hash.hex(),
        "assertions": {
            "assertionPolicyPresent": True,
            "authenticationGeneration": 0,
            "authenticationPolicyPresent": True,
            "delegationGeneration": 0,
            "delegationPolicyPresent": True,
            "controllerProofCollectionPresent": False,
            "authenticationProofCollectionPresent": True,
            "assertionProofCollectionPresent": True,
            "delegationProofCollectionPresent": True,
            "stateHashLength": len(state_hash),
        },
    }


def main() -> None:
    bundle = {
        "specification": "OpenIdentity Protocol v2 / IdentityState v3",
        "status": "DRAFT-NON-NORMATIVE",
        "wireSchema": "spec/cddl/openidentity-operation-v3.cddl",
        "vectors": [build_v301(), build_v302(), build_v303()],
    }
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(bundle, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {OUTPUT.relative_to(ROOT)}")
    print("V301 VERIFIED")\n    print("V302 VERIFIED")\n    print("V303 VERIFIED")


if __name__ == "__main__":
    main()
