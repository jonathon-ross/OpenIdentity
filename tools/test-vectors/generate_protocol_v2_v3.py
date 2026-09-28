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


def main() -> None:
    bundle = {
        "specification": "OpenIdentity Protocol v2 / IdentityState v3",
        "status": "DRAFT-NON-NORMATIVE",
        "wireSchema": "spec/cddl/openidentity-operation-v3.cddl",
        "vectors": [build_v301()],
    }
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(bundle, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {OUTPUT.relative_to(ROOT)}")
    print("V301 VERIFIED")


if __name__ == "__main__":
    main()
