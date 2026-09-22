"""Independent verifier for OpenIdentity OI-002 V03 canonical ordering."""

import argparse
import json
import sys
from pathlib import Path

import cbor2


SPECIFICATION = "OpenIdentity Cryptographic Agility"
VERSION = "0.1"


def fail(message: str) -> None:
    print()
    print("FAILED")
    print("------")
    print(message)
    print()
    sys.exit(1)


def passed(message: str) -> None:
    print(f"  {message}: PASS")


def load_document(path: Path, expected_id: str) -> dict:
    if not path.exists():
        fail(f"Vector file does not exist:\n{path}")

    try:
        with path.open("r", encoding="utf-8") as file:
            document = json.load(file)
    except json.JSONDecodeError as exc:
        fail(f"Invalid JSON in {path}:\n{exc}")
    except OSError as exc:
        fail(f"Unable to read {path}:\n{exc}")

    if document.get("specification") != SPECIFICATION:
        fail(
            f"{path}: unexpected specification.\n"
            f"Expected: {SPECIFICATION!r}\n"
            f"Actual: {document.get('specification')!r}"
        )

    if document.get("version") != VERSION:
        fail(
            f"{path}: unexpected version.\n"
            f"Expected: {VERSION!r}\n"
            f"Actual: {document.get('version')!r}"
        )

    vector = document.get("vector")
    if not isinstance(vector, dict):
        fail(f"{path}: missing or invalid vector object.")

    if vector.get("id") != expected_id:
        fail(
            f"{path}: expected vector {expected_id}, "
            f"got {vector.get('id')!r}."
        )

    return vector


def require_field(vector: dict, field: str):
    if field not in vector:
        fail(f"Missing required field {field!r} in {vector.get('id')}.")
    return vector[field]


def parse_hex(vector_id: str, field: str, value) -> bytes:
    if not isinstance(value, str):
        fail(f"{vector_id}.{field} must be a hexadecimal string.")

    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        fail(f"{vector_id}.{field} is invalid hexadecimal:\n{exc}")


def canonical_cbor(value) -> bytes:
    return cbor2.dumps(value, canonical=True)


def decode_and_require_canonical(
        vector_id: str,
        field: str,
        encoded: bytes,
):
    try:
        decoded = cbor2.loads(encoded)
    except Exception as exc:
        fail(f"{vector_id}.{field} is invalid CBOR:\n{exc}")

    reencoded = canonical_cbor(decoded)

    if reencoded != encoded:
        fail(
            f"{vector_id}.{field} is not canonical CBOR.\n\n"
            f"Provided:\n{encoded.hex()}\n\n"
            f"Canonical:\n{reencoded.hex()}"
        )

    return decoded


def require_equal_bytes(
        description: str,
        v02_value: bytes,
        v03_value: bytes,
) -> None:
    if v02_value != v03_value:
        fail(
            f"{description} differs.\n\n"
            f"V02:\n{v02_value.hex()}\n\n"
            f"V03:\n{v03_value.hex()}"
        )

    passed(description)


def verify(v02: dict, v03: dict) -> None:
    print()
    print("OpenIdentity OI-002")
    print("V03 Canonical Ordering Verification")
    print("=" * 44)
    print()

    # -----------------------------------------------------------------
    # Verify that V03 explicitly records reversed input ordering.
    # -----------------------------------------------------------------

    expected_order = [
        "ML-DSA-65",
        "Ed25519",
    ]

    method_order = require_field(
        v03,
        "inputMethodOrder",
    )

    proof_order = require_field(
        v03,
        "inputProofOrder",
    )

    if method_order != expected_order:
        fail(
            "V03 inputMethodOrder is not the expected reversed order.\n\n"
            f"Expected: {expected_order!r}\n"
            f"Actual:   {method_order!r}"
        )
    passed("Reversed VerificationMethod input order")

    if proof_order != expected_order:
        fail(
            "V03 inputProofOrder is not the expected reversed order.\n\n"
            f"Expected: {expected_order!r}\n"
            f"Actual:   {proof_order!r}"
        )
    passed("Reversed proof input order")

    # -----------------------------------------------------------------
    # Load canonical byte outputs.
    # -----------------------------------------------------------------

    fields = [
        "controllerPolicyHex",
        "operationBytesHex",
        "signingInputHex",
        "signedOperationHex",
    ]

    v02_bytes = {}
    v03_bytes = {}

    for field in fields:
        v02_bytes[field] = parse_hex(
            "V02",
            field,
            require_field(v02, field),
        )

        v03_bytes[field] = parse_hex(
            "V03",
            field,
            require_field(v03, field),
        )

    # -----------------------------------------------------------------
    # Independently require canonical CBOR for all four artifacts.
    # -----------------------------------------------------------------

    for field in fields:
        decode_and_require_canonical(
            "V02",
            field,
            v02_bytes[field],
        )
        decode_and_require_canonical(
            "V03",
            field,
            v03_bytes[field],
        )

    passed("V02 canonical CBOR artifacts")
    passed("V03 canonical CBOR artifacts")

    # -----------------------------------------------------------------
    # V03 MUST canonicalize to byte-for-byte V02 output.
    # -----------------------------------------------------------------

    require_equal_bytes(
        "ControllerPolicy canonical equality",
        v02_bytes["controllerPolicyHex"],
        v03_bytes["controllerPolicyHex"],
    )

    require_equal_bytes(
        "OperationBytes canonical equality",
        v02_bytes["operationBytesHex"],
        v03_bytes["operationBytesHex"],
    )

    require_equal_bytes(
        "SigningInput canonical equality",
        v02_bytes["signingInputHex"],
        v03_bytes["signingInputHex"],
    )

    require_equal_bytes(
        "SignedOperation canonical equality",
        v02_bytes["signedOperationHex"],
        v03_bytes["signedOperationHex"],
    )

    # -----------------------------------------------------------------
    # Check Java's declarative comparison flags too.
    # These are not trusted as proof; the byte comparisons above are.
    # -----------------------------------------------------------------

    flag_fields = [
        "matchesV02ControllerPolicy",
        "matchesV02OperationBytes",
        "matchesV02SigningInput",
        "matchesV02SignedOperation",
    ]

    for field in flag_fields:
        value = require_field(v03, field)

        if value is not True:
            fail(
                f"V03.{field} must be true, got {value!r}."
            )

    passed("Java V02 comparison flags")

    # -----------------------------------------------------------------
    # Structural relationship checks.
    # -----------------------------------------------------------------

    policy = decode_and_require_canonical(
        "V03",
        "controllerPolicyHex",
        v03_bytes["controllerPolicyHex"],
    )

    if not isinstance(policy, dict):
        fail("V03 ControllerPolicy must decode to a CBOR map.")

    if policy.get(1) != 2:
        fail(
            "V03 ControllerPolicy is not THRESHOLD "
            f"(expected type 2, got {policy.get(1)!r})."
        )

    if policy.get(2) != 2:
        fail(
            "V03 ControllerPolicy threshold is not 2 "
            f"(got {policy.get(2)!r})."
        )

    methods = policy.get(3)

    if not isinstance(methods, list) or len(methods) != 2:
        fail(
            "V03 ControllerPolicy must contain exactly "
            "two VerificationMethods."
        )

    try:
        method_ids = [
            method[1]
            for method in methods
        ]
    except Exception as exc:
        fail(
            "Unable to extract Verification Method IDs "
            f"from V03 ControllerPolicy:\n{exc}"
        )

    if any(
            not isinstance(method_id, bytes) or len(method_id) != 16
            for method_id in method_ids
    ):
        fail(
            "Every Verification Method ID must be a 16-byte byte string."
        )

    if method_ids != sorted(method_ids):
        fail(
            "V03 VerificationMethods are not in unsigned-bytewise "
            "lexicographic canonical order."
        )

    if len(set(method_ids)) != len(method_ids):
        fail("V03 contains duplicate Verification Method IDs.")

    passed("Canonical VerificationMethod ordering")

    # SignedOperation proof order.
    signed_operation = decode_and_require_canonical(
        "V03",
        "signedOperationHex",
        v03_bytes["signedOperationHex"],
    )

    if not isinstance(signed_operation, dict):
        fail("V03 SignedOperation must decode to a CBOR map.")

    proofs = signed_operation.get(2)

    if not isinstance(proofs, list) or len(proofs) != 2:
        fail(
            "V03 SignedOperation must contain exactly "
            "two authorization proofs."
        )

    try:
        proof_ids = [
            proof[1]
            for proof in proofs
        ]
    except Exception as exc:
        fail(
            "Unable to extract Verification Method IDs "
            f"from V03 proofs:\n{exc}"
        )

    if any(
            not isinstance(proof_id, bytes) or len(proof_id) != 16
            for proof_id in proof_ids
    ):
        fail(
            "Every proof Verification Method ID must be "
            "a 16-byte byte string."
        )

    if proof_ids != sorted(proof_ids):
        fail(
            "V03 authorization proofs are not in unsigned-bytewise "
            "lexicographic canonical order."
        )

    if len(set(proof_ids)) != len(proof_ids):
        fail("V03 contains duplicate authorization proof IDs.")

    passed("Canonical authorization-proof ordering")

    # Ensure proof order corresponds to controller-method order.
    if proof_ids != method_ids:
        fail(
            "Canonical proof IDs do not correspond to the canonical "
            "Verification Method ID ordering."
        )

    passed("Canonical method/proof ordering agreement")

    print()
    print("=" * 44)
    print("V03 CANONICAL ORDERING VERIFICATION PASSED")
    print("=" * 44)
    print()


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Verify that OpenIdentity OI-002 V03 reversed input "
            "canonicalizes to exactly the V02 byte representation."
        )
    )

    parser.add_argument(
        "v02_file",
        type=Path,
        help="Path to generated crypto-v02-java.json",
    )

    parser.add_argument(
        "v03_file",
        type=Path,
        help="Path to generated crypto-v03-java.json",
    )

    args = parser.parse_args()

    v02 = load_document(
        args.v02_file,
        "V02",
    )

    v03 = load_document(
        args.v03_file,
        "V03",
    )

    verify(v02, v03)


if __name__ == "__main__":
    main()
