"""
OpenIdentity Identity ID v0.1 conformance-vector verifier.

This program verifies identity-id-v0.1.json using two independent
Base58 implementations:

1. reference_base58.py
   Dependency-free OpenIdentity reference implementation.

2. PyPI 'base58'
   Independent third-party implementation.

The normative JSON must agree with BOTH implementations.
"""

import json
import sys
from pathlib import Path

import base58

from reference_base58 import (
    ALPHABET,
    base58btc_decode,
    base58btc_encode,
)


# ------------------------------------------------------------------
# Repository paths
# ------------------------------------------------------------------

SCRIPT_DIR = Path(__file__).resolve().parent

REPOSITORY_ROOT = (
    SCRIPT_DIR
    .parent
    .parent
)

VECTOR_FILE = (
        REPOSITORY_ROOT
        / "test-vectors"
        / "identity-id-v0.1.json"
)


# ------------------------------------------------------------------
# OpenIdentity v0.1 constants
# ------------------------------------------------------------------

SPECIFICATION_NAME = "OpenIdentity Identity Identifier"

SPECIFICATION_VERSION = "0.1"

DID_PREFIX = "did:open:"

MULTIBASE_PREFIX = "z"

IDENTIFIER_LENGTH = 32


# ------------------------------------------------------------------
# Utility
# ------------------------------------------------------------------

def fail(message: str) -> None:
    """
    Print an error and terminate verification.
    """

    print()
    print("FAILED")
    print("------")
    print(message)
    print()

    sys.exit(1)


def load_vectors() -> dict:
    """
    Load the normative OpenIdentity test-vector document.
    """

    if not VECTOR_FILE.exists():
        fail(
            "Test-vector file does not exist:\n"
            f"{VECTOR_FILE}"
        )

    try:
        with VECTOR_FILE.open(
                "r",
                encoding="utf-8"
        ) as file:

            return json.load(file)

    except json.JSONDecodeError as error:
        fail(
            "Invalid JSON in test-vector file:\n"
            f"{error}"
        )


# ------------------------------------------------------------------
# Metadata verification
# ------------------------------------------------------------------

def verify_metadata(document: dict) -> None:
    """
    Verify the metadata that exists in identity-id-v0.1.json.

    Protocol details such as DID method, identifier length and
    Multibase encoding are defined normatively in identity-id.md
    and verified through the actual vectors.
    """

    specification = document.get(
        "specification"
    )

    if specification != SPECIFICATION_NAME:
        fail(
            "Unexpected specification name.\n\n"
            f"Expected:\n{SPECIFICATION_NAME}\n\n"
            f"Actual:\n{specification}"
        )

    version = document.get(
        "version"
    )

    if version != SPECIFICATION_VERSION:
        fail(
            "Unexpected specification version.\n\n"
            f"Expected:\n{SPECIFICATION_VERSION}\n\n"
            f"Actual:\n{version}"
        )


# ------------------------------------------------------------------
# Independent Base58 implementations
# ------------------------------------------------------------------

def reference_encode(data: bytes) -> str:
    """
    Encode using the dependency-free reference implementation.
    """

    return base58btc_encode(data)


def library_encode(data: bytes) -> str:
    """
    Encode using the independent PyPI base58 library.
    """

    return (
        base58
        .b58encode(data)
        .decode("ascii")
    )


def reference_decode(value: str) -> bytes:
    """
    Decode using the dependency-free reference implementation.
    """

    return base58btc_decode(value)


def library_decode(value: str) -> bytes:
    """
    Decode using the independent PyPI base58 library.
    """

    return base58.b58decode(value)


# ------------------------------------------------------------------
# Valid vector verification
# ------------------------------------------------------------------

def verify_valid_vector(vector: dict) -> None:

    vector_id = vector["id"]

    description = vector.get(
        "description",
        ""
    )

    name = (
        f"{vector_id} - {description}"
        if description
        else vector_id
    )

    print(
        f"Verifying valid vector: {name}"
    )

    # --------------------------------------------------------------
    # Parse input bytes.
    # --------------------------------------------------------------

    try:
        raw = bytes.fromhex(
            vector["inputHex"]
        )

    except ValueError as error:
        fail(
            f"{name}: inputHex is invalid.\n\n"
            f"{error}"
        )

    # --------------------------------------------------------------
    # OpenIdentity v0.1 identifiers MUST contain exactly 32 bytes.
    # --------------------------------------------------------------

    if len(raw) != IDENTIFIER_LENGTH:
        fail(
            f"{name}: expected "
            f"{IDENTIFIER_LENGTH} input bytes, "
            f"got {len(raw)}."
        )

    # --------------------------------------------------------------
    # Encode independently.
    # --------------------------------------------------------------

    reference_encoded = reference_encode(
        raw
    )

    library_encoded = library_encode(
        raw
    )

    # --------------------------------------------------------------
    # Both independent implementations MUST agree.
    # --------------------------------------------------------------

    if reference_encoded != library_encoded:
        fail(
            f"{name}: independent Base58 "
            f"implementations disagree.\n\n"
            f"Reference implementation:\n"
            f"{reference_encoded}\n\n"
            f"Third-party library:\n"
            f"{library_encoded}"
        )

    # --------------------------------------------------------------
    # Normative JSON MUST agree with both implementations.
    # --------------------------------------------------------------

    expected_base58 = vector[
        "base58btc"
    ]

    if reference_encoded != expected_base58:
        fail(
            f"{name}: normative base58btc "
            f"value is incorrect.\n\n"
            f"JSON value:\n"
            f"{expected_base58}\n\n"
            f"Calculated value:\n"
            f"{reference_encoded}"
        )

    # --------------------------------------------------------------
    # Verify Multibase representation.
    # --------------------------------------------------------------

    expected_multibase = (
            MULTIBASE_PREFIX
            + reference_encoded
    )

    actual_multibase = vector[
        "multibase"
    ]

    if actual_multibase != expected_multibase:
        fail(
            f"{name}: multibase value mismatch.\n\n"
            f"JSON value:\n"
            f"{actual_multibase}\n\n"
            f"Expected:\n"
            f"{expected_multibase}"
        )

    # --------------------------------------------------------------
    # Verify complete DID.
    # --------------------------------------------------------------

    expected_did = (
            DID_PREFIX
            + expected_multibase
    )

    actual_did = vector[
        "did"
    ]

    if actual_did != expected_did:
        fail(
            f"{name}: DID mismatch.\n\n"
            f"JSON value:\n"
            f"{actual_did}\n\n"
            f"Expected:\n"
            f"{expected_did}"
        )

    # --------------------------------------------------------------
    # Decode using both independent implementations.
    # --------------------------------------------------------------

    reference_decoded = reference_decode(
        reference_encoded
    )

    library_decoded = library_decode(
        library_encoded
    )

    if reference_decoded != raw:
        fail(
            f"{name}: reference decoder "
            f"did not reproduce the original bytes."
        )

    if library_decoded != raw:
        fail(
            f"{name}: third-party decoder "
            f"did not reproduce the original bytes."
        )

    # --------------------------------------------------------------
    # Verify decoded lengths.
    # --------------------------------------------------------------

    if len(reference_decoded) != IDENTIFIER_LENGTH:
        fail(
            f"{name}: reference decoded length "
            f"is {len(reference_decoded)}, "
            f"expected {IDENTIFIER_LENGTH}."
        )

    if len(library_decoded) != IDENTIFIER_LENGTH:
        fail(
            f"{name}: third-party decoded length "
            f"is {len(library_decoded)}, "
            f"expected {IDENTIFIER_LENGTH}."
        )

    # --------------------------------------------------------------
    # Verify canonical encoding.
    # --------------------------------------------------------------

    reference_reencoded = reference_encode(
        reference_decoded
    )

    library_reencoded = library_encode(
        library_decoded
    )

    if reference_reencoded != reference_encoded:
        fail(
            f"{name}: reference encoding "
            f"is not canonical."
        )

    if library_reencoded != library_encoded:
        fail(
            f"{name}: third-party encoding "
            f"is not canonical."
        )

    print(
        "  Reference implementation: PASS"
    )

    print(
        "  Third-party implementation: PASS"
    )

    print(
        "  Normative JSON: PASS"
    )

    print(
        "  Round trip: PASS"
    )

    print()


# ------------------------------------------------------------------
# OpenIdentity DID validation
# ------------------------------------------------------------------

def validate_openidentity_did(
        candidate: str
) -> str | None:
    """
    Validate an OpenIdentity v0.1 root DID.

    Returns:
        None when valid.

        Otherwise returns the protocol validation error code.

    This validator exists for the conformance-vector verifier.
    The production OpenIdentity implementation will be created
    separately.
    """

    if not isinstance(candidate, str):
        return "INVALID_DID"

    if candidate == "":
        return "INVALID_DID"

    # --------------------------------------------------------------
    # DID scheme is case-sensitive in OpenIdentity canonical form.
    #
    # Explicitly detect the uppercase form used by vector I03.
    # --------------------------------------------------------------

    if (
            candidate.startswith("DID:")
            or candidate.startswith("Did:")
            or candidate.startswith("dID:")
    ):
        return "INVALID_DID_PREFIX"

    # --------------------------------------------------------------
    # Candidate must use the DID URI scheme.
    # --------------------------------------------------------------

    if not candidate.startswith("did:"):
        return "INVALID_DID_SCHEME"

    # --------------------------------------------------------------
    # Candidate must use the OpenIdentity DID method.
    # --------------------------------------------------------------

    if not candidate.startswith(DID_PREFIX):

        parts = candidate.split(
            ":",
            2
        )

        if (
                len(parts) >= 2
                and parts[0] == "did"
        ):
            return "INVALID_DID_METHOD"

        return "INVALID_DID_PREFIX"

    # --------------------------------------------------------------
    # Extract method-specific identifier.
    # --------------------------------------------------------------

    method_id = candidate[
        len(DID_PREFIX):
    ]

    if method_id == "":
        return "MISSING_METHOD_ID"

    # --------------------------------------------------------------
    # OpenIdentity v0.1 method IDs contain exactly one Multibase
    # value.
    #
    # Additional colon-delimited semantics such as:
    #
    # did:open:ed25519:z...
    # did:open:solana:z...
    # did:open:paralax:z...
    #
    # are not permitted.
    # --------------------------------------------------------------

    if ":" in method_id:
        return "INVALID_METHOD_ID"

    # --------------------------------------------------------------
    # Verify Multibase prefix.
    # --------------------------------------------------------------

    if not method_id.startswith(
            MULTIBASE_PREFIX
    ):

        # 'u' is the Multibase prefix for base64url.
        # OpenIdentity v0.1 supports only base58btc.
        if method_id.startswith("u"):
            return "UNSUPPORTED_MULTIBASE"

        return "INVALID_MULTIBASE_PREFIX"

    # --------------------------------------------------------------
    # Extract Base58btc payload.
    # --------------------------------------------------------------

    payload = method_id[1:]

    if payload == "":
        return "MISSING_BASE58BTC_PAYLOAD"

    # --------------------------------------------------------------
    # Validate Base58btc alphabet.
    # --------------------------------------------------------------

    for character in payload:

        if character not in ALPHABET:
            return "INVALID_BASE58BTC_CHARACTER"

    # --------------------------------------------------------------
    # Decode.
    # --------------------------------------------------------------

    try:
        decoded = reference_decode(
            payload
        )

    except ValueError:
        return "INVALID_BASE58BTC_CHARACTER"

    # --------------------------------------------------------------
    # Identifier bytes MUST be exactly 32 bytes.
    # --------------------------------------------------------------

    if len(decoded) != IDENTIFIER_LENGTH:
        return "INVALID_IDENTIFIER_LENGTH"

    # --------------------------------------------------------------
    # Verify canonical representation.
    # --------------------------------------------------------------

    canonical = reference_encode(
        decoded
    )

    if canonical != payload:
        return "NON_CANONICAL_ENCODING"

    return None


# ------------------------------------------------------------------
# Invalid vector verification
# ------------------------------------------------------------------

def verify_invalid_vector(
        vector: dict
) -> None:

    vector_id = vector["id"]

    print(
        f"Verifying invalid vector: "
        f"{vector_id}"
    )

    candidate = vector[
        "did"
    ]

    expected_error = vector[
        "error"
    ]

    actual_error = validate_openidentity_did(
        candidate
    )

    if actual_error is None:
        fail(
            f"{vector_id}: invalid vector "
            f"was unexpectedly accepted.\n\n"
            f"{candidate}"
        )

    if actual_error != expected_error:
        fail(
            f"{vector_id}: wrong error code.\n\n"
            f"Candidate:\n"
            f"{candidate}\n\n"
            f"Expected:\n"
            f"{expected_error}\n\n"
            f"Actual:\n"
            f"{actual_error}"
        )

    print(
        f"  Rejected correctly: "
        f"{actual_error}"
    )

    print()


# ------------------------------------------------------------------
# Main
# ------------------------------------------------------------------

def main() -> None:

    print()
    print(
        "OpenIdentity Identity ID v0.1"
    )

    print(
        "Conformance Vector Verification"
    )

    print(
        "=" * 40
    )

    print()

    document = load_vectors()

    verify_metadata(
        document
    )

    valid_vectors = document.get(
        "valid",
        []
    )

    invalid_vectors = document.get(
        "invalid",
        []
    )

    if not valid_vectors:
        fail(
            "No valid test vectors found."
        )

    if not invalid_vectors:
        fail(
            "No invalid test vectors found."
        )

    for vector in valid_vectors:
        verify_valid_vector(
            vector
        )

    for vector in invalid_vectors:
        verify_invalid_vector(
            vector
        )

    print(
        "=" * 40
    )

    print(
        "ALL TEST VECTORS PASSED"
    )

    print(
        "=" * 40
    )

    print()

    print(
        f"Valid vectors:   "
        f"{len(valid_vectors)}"
    )

    print(
        f"Invalid vectors: "
        f"{len(invalid_vectors)}"
    )

    print()


if __name__ == "__main__":
    main()