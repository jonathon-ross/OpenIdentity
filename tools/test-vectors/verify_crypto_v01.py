"""
Independent verifier for OpenIdentity OI-002 V01.

V01:
    SINGLE Ed25519 CREATE

This script independently verifies output produced by:

    tools/test-vectors-java

It verifies:

1. Identity bytes
2. Verification Method ID
3. Ed25519 public key
4. COSE_Key structure
5. VerificationMethod structure
6. SINGLE ControllerPolicy
7. CREATE Operation
8. Deterministic OperationBytes
9. SigningInput
10. Ed25519 signature
11. AuthorizationProof
12. SignedOperation

This script intentionally does NOT depend on any OpenIdentity
Java implementation.
"""

import argparse
import sys

import cbor2

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey,
)


# ---------------------------------------------------------------------
# Protocol constants
# ---------------------------------------------------------------------

PROTOCOL_VERSION = 1

CREATE_OPERATION = 1

SINGLE_POLICY = 1

SIGNING_STRUCTURE_VERSION = 1

SIGNING_CONTEXT = "OpenIdentity Operation"

IDENTITY_LENGTH = 32

VERIFICATION_METHOD_ID_LENGTH = 16

ED25519_PUBLIC_KEY_LENGTH = 32

ED25519_SIGNATURE_LENGTH = 64


# COSE

COSE_KTY = 1

COSE_ALG = 3

COSE_OKP_CRV = -1

COSE_OKP_X = -2


# COSE values

COSE_KTY_OKP = 1

COSE_ALG_EDDSA = -8

COSE_CRV_ED25519 = 6


# ---------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------

def fail(message: str) -> None:
    print()
    print("FAILED")
    print("------")
    print(message)
    print()

    sys.exit(1)


def passed(message: str) -> None:
    print(f"  {message}: PASS")


def parse_hex(
        name: str,
        value: str,
) -> bytes:

    try:
        return bytes.fromhex(value)

    except ValueError as error:
        fail(
            f"{name} is not valid hexadecimal:\n"
            f"{error}"
        )


def decode_cbor(
        name: str,
        encoded: bytes,
):

    try:
        return cbor2.loads(encoded)

    except Exception as error:
        fail(
            f"{name} is not valid CBOR:\n"
            f"{error}"
        )


def canonical_cbor(value) -> bytes:
    """
    Encode using cbor2 canonical mode.

    This provides an implementation independent from the custom
    Java DeterministicCborWriter.
    """

    return cbor2.dumps(
        value,
        canonical=True,
    )


def assert_equal(
        name: str,
        actual,
        expected,
) -> None:

    if actual != expected:

        fail(
            f"{name} mismatch.\n\n"
            f"Expected:\n"
            f"{expected!r}\n\n"
            f"Actual:\n"
            f"{actual!r}"
        )


def assert_bytes_equal(
        name: str,
        actual: bytes,
        expected: bytes,
) -> None:

    if actual != expected:

        fail(
            f"{name} byte mismatch.\n\n"
            f"Expected:\n"
            f"{expected.hex()}\n\n"
            f"Actual:\n"
            f"{actual.hex()}"
        )


# ---------------------------------------------------------------------
# V01 Verification
# ---------------------------------------------------------------------

def verify(args) -> None:

    print()
    print("OpenIdentity OI-002")
    print("V01 Independent Verification")
    print("=" * 40)
    print()

    # -----------------------------------------------------------------
    # Parse Java output
    # -----------------------------------------------------------------

    identity = parse_hex(
        "identity",
        args.identity,
    )

    method_id = parse_hex(
        "method-id",
        args.method_id,
    )

    public_key = parse_hex(
        "public-key",
        args.public_key,
    )

    cose_key_bytes = parse_hex(
        "cose-key",
        args.cose_key,
    )

    verification_method_bytes = parse_hex(
        "verification-method",
        args.verification_method,
    )

    controller_policy_bytes = parse_hex(
        "controller-policy",
        args.controller_policy,
    )

    operation_bytes = parse_hex(
        "operation",
        args.operation,
    )

    signing_input = parse_hex(
        "signing-input",
        args.signing_input,
    )

    signature = parse_hex(
        "signature",
        args.signature,
    )

    authorization_proof_bytes = parse_hex(
        "authorization-proof",
        args.authorization_proof,
    )

    signed_operation_bytes = parse_hex(
        "signed-operation",
        args.signed_operation,
    )


    # -----------------------------------------------------------------
    # Basic lengths
    # -----------------------------------------------------------------

    assert_equal(
        "Identity length",
        len(identity),
        IDENTITY_LENGTH,
    )

    passed("Identity length")

    assert_equal(
        "Verification Method ID length",
        len(method_id),
        VERIFICATION_METHOD_ID_LENGTH,
    )

    passed("Verification Method ID length")

    assert_equal(
        "Ed25519 public key length",
        len(public_key),
        ED25519_PUBLIC_KEY_LENGTH,
    )

    passed("Ed25519 public key length")

    assert_equal(
        "Ed25519 signature length",
        len(signature),
        ED25519_SIGNATURE_LENGTH,
    )

    passed("Ed25519 signature length")


    # -----------------------------------------------------------------
    # COSE_Key
    # -----------------------------------------------------------------

    cose_key = decode_cbor(
        "COSE_Key",
        cose_key_bytes,
    )

    expected_cose_key = {
        COSE_KTY: COSE_KTY_OKP,
        COSE_ALG: COSE_ALG_EDDSA,
        COSE_OKP_CRV: COSE_CRV_ED25519,
        COSE_OKP_X: public_key,
    }

    assert_equal(
        "COSE_Key structure",
        cose_key,
        expected_cose_key,
    )

    passed("COSE_Key structure")

    canonical_cose_key = canonical_cbor(
        expected_cose_key
    )

    assert_bytes_equal(
        "COSE_Key canonical CBOR",
        cose_key_bytes,
        canonical_cose_key,
    )

    passed("COSE_Key canonical CBOR")


    # -----------------------------------------------------------------
    # VerificationMethod
    # -----------------------------------------------------------------

    verification_method = decode_cbor(
        "VerificationMethod",
        verification_method_bytes,
    )

    expected_verification_method = {
        1: method_id,
        2: expected_cose_key,
    }

    assert_equal(
        "VerificationMethod structure",
        verification_method,
        expected_verification_method,
    )

    passed("VerificationMethod structure")

    expected_verification_method_bytes = canonical_cbor(
        expected_verification_method
    )

    assert_bytes_equal(
        "VerificationMethod canonical CBOR",
        verification_method_bytes,
        expected_verification_method_bytes,
    )

    passed(
        "VerificationMethod canonical CBOR"
    )


    # -----------------------------------------------------------------
    # SINGLE ControllerPolicy
    # -----------------------------------------------------------------

    controller_policy = decode_cbor(
        "ControllerPolicy",
        controller_policy_bytes,
    )

    expected_controller_policy = {
        1: SINGLE_POLICY,
        2: [
            expected_verification_method
        ],
    }

    assert_equal(
        "ControllerPolicy structure",
        controller_policy,
        expected_controller_policy,
    )

    passed("ControllerPolicy structure")

    expected_controller_policy_bytes = canonical_cbor(
        expected_controller_policy
    )

    assert_bytes_equal(
        "ControllerPolicy canonical CBOR",
        controller_policy_bytes,
        expected_controller_policy_bytes,
    )

    passed(
        "ControllerPolicy canonical CBOR"
    )


    # -----------------------------------------------------------------
    # CREATE payload
    # -----------------------------------------------------------------

    expected_payload = {
        1: expected_controller_policy,
    }


    # -----------------------------------------------------------------
    # CREATE Operation
    # -----------------------------------------------------------------

    operation = decode_cbor(
        "OperationBytes",
        operation_bytes,
    )

    expected_operation = {
        1: PROTOCOL_VERSION,
        2: CREATE_OPERATION,
        3: identity,
        4: 1,
        5: None,
        6: expected_payload,
    }

    assert_equal(
        "CREATE Operation structure",
        operation,
        expected_operation,
    )

    passed("CREATE Operation structure")


    # -----------------------------------------------------------------
    # Independently reproduce OperationBytes
    # -----------------------------------------------------------------

    expected_operation_bytes = canonical_cbor(
        expected_operation
    )

    assert_bytes_equal(
        "OperationBytes",
        operation_bytes,
        expected_operation_bytes,
    )

    passed("OperationBytes")


    # -----------------------------------------------------------------
    # Signing structure
    # -----------------------------------------------------------------

    expected_signing_structure = [
        SIGNING_CONTEXT,
        SIGNING_STRUCTURE_VERSION,
        operation_bytes,
    ]

    expected_signing_input = canonical_cbor(
        expected_signing_structure
    )

    assert_bytes_equal(
        "SigningInput",
        signing_input,
        expected_signing_input,
    )

    passed("SigningInput")


    # -----------------------------------------------------------------
    # Independent Ed25519 verification
    # -----------------------------------------------------------------

    try:

        verifier = Ed25519PublicKey.from_public_bytes(
            public_key
        )

        verifier.verify(
            signature,
            signing_input,
        )

    except InvalidSignature:

        fail(
            "Ed25519 signature verification failed."
        )

    except Exception as error:

        fail(
            "Unable to verify Ed25519 signature:\n"
            f"{error}"
        )

    passed(
        "Independent Ed25519 signature"
    )


    # -----------------------------------------------------------------
    # AuthorizationProof
    # -----------------------------------------------------------------

    authorization_proof = decode_cbor(
        "AuthorizationProof",
        authorization_proof_bytes,
    )

    expected_authorization_proof = {
        1: method_id,
        2: signature,
    }

    assert_equal(
        "AuthorizationProof structure",
        authorization_proof,
        expected_authorization_proof,
    )

    passed(
        "AuthorizationProof structure"
    )

    expected_authorization_proof_bytes = canonical_cbor(
        expected_authorization_proof
    )

    assert_bytes_equal(
        "AuthorizationProof canonical CBOR",
        authorization_proof_bytes,
        expected_authorization_proof_bytes,
    )

    passed(
        "AuthorizationProof canonical CBOR"
    )


    # -----------------------------------------------------------------
    # SignedOperation
    # -----------------------------------------------------------------

    signed_operation = decode_cbor(
        "SignedOperation",
        signed_operation_bytes,
    )

    expected_signed_operation = {
        1: expected_operation,
        2: [
            expected_authorization_proof
        ],
    }

    assert_equal(
        "SignedOperation structure",
        signed_operation,
        expected_signed_operation,
    )

    passed("SignedOperation structure")

    expected_signed_operation_bytes = canonical_cbor(
        expected_signed_operation
    )

    assert_bytes_equal(
        "SignedOperation canonical CBOR",
        signed_operation_bytes,
        expected_signed_operation_bytes,
    )

    passed(
        "SignedOperation canonical CBOR"
    )


    # -----------------------------------------------------------------
    # Success
    # -----------------------------------------------------------------

    print()
    print("=" * 40)
    print("V01 INDEPENDENT VERIFICATION PASSED")
    print("=" * 40)
    print()


# ---------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------

def main() -> None:

    parser = argparse.ArgumentParser(
        description=(
            "Independently verify OpenIdentity "
            "OI-002 V01"
        )
    )

    parser.add_argument(
        "--identity",
        required=True,
    )

    parser.add_argument(
        "--method-id",
        required=True,
    )

    parser.add_argument(
        "--public-key",
        required=True,
    )

    parser.add_argument(
        "--cose-key",
        required=True,
    )

    parser.add_argument(
        "--verification-method",
        required=True,
    )

    parser.add_argument(
        "--controller-policy",
        required=True,
    )

    parser.add_argument(
        "--operation",
        required=True,
    )

    parser.add_argument(
        "--signing-input",
        required=True,
    )

    parser.add_argument(
        "--signature",
        required=True,
    )

    parser.add_argument(
        "--authorization-proof",
        required=True,
    )

    parser.add_argument(
        "--signed-operation",
        required=True,
    )

    args = parser.parse_args()

    verify(args)


if __name__ == "__main__":
    main()