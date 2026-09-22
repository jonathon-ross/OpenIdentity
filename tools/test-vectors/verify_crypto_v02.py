"""Independent verifier for OpenIdentity OI-002 V02, including canonical IdentityState and SHA2-256 Multihash."""

import argparse
import hashlib
import json
import sys
from pathlib import Path

import cbor2
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PublicKey

SPECIFICATION = "OpenIdentity Cryptographic Agility"
VERSION = "0.1"

PROTOCOL_VERSION = 1
CREATE_OPERATION = 1
THRESHOLD_POLICY = 2
SIGNING_STRUCTURE_VERSION = 1
SIGNING_CONTEXT = "OpenIdentity Operation"

IDENTITY_STATE_VERSION = 1
IDENTITY_STATUS_ACTIVE = 1

IDENTITY_LENGTH = 32
METHOD_ID_LENGTH = 16
ED_PUBLIC_KEY_LENGTH = 32
ED_SIGNATURE_LENGTH = 64
ML_PUBLIC_KEY_LENGTH = 1952
ML_SIGNATURE_LENGTH = 3309
SHA256_MULTIHASH_LENGTH = 34

COSE_KTY = 1
COSE_ALG = 3
COSE_OKP_CRV = -1
COSE_OKP_X = -2
COSE_KTY_OKP = 1
COSE_ALG_EDDSA = -8
COSE_CRV_ED25519 = 6
COSE_AKP_PUB = -1
COSE_KTY_AKP = 7
COSE_ALG_ML_DSA_65 = -49

MULTIHASH_SHA2_256_CODE = 0x12
MULTIHASH_SHA2_256_LENGTH = 0x20


def fail(message: str) -> None:
    print("\nFAILED\n------")
    print(message)
    print()
    sys.exit(1)


def passed(message: str) -> None:
    print(f"  {message}: PASS")


def require_field(vector: dict, field: str):
    if field not in vector:
        fail(f"Missing required vector field: {field}")
    return vector[field]


def parse_hex(name: str, value) -> bytes:
    if not isinstance(value, str):
        fail(f"{name} must be a hexadecimal string.")
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        fail(f"{name} is not valid hexadecimal:\n{exc}")


def decode_cbor(name: str, encoded: bytes):
    try:
        return cbor2.loads(encoded)
    except Exception as exc:
        fail(f"{name} is not valid CBOR:\n{exc}")


def canonical_cbor(value) -> bytes:
    return cbor2.dumps(value, canonical=True)


def assert_equal(name: str, actual, expected) -> None:
    if actual != expected:
        fail(f"{name} mismatch.\n\nExpected:\n{expected!r}\n\nActual:\n{actual!r}")


def assert_bytes_equal(name: str, actual: bytes, expected: bytes) -> None:
    if actual != expected:
        fail(
            f"{name} byte mismatch.\n\n"
            f"Expected:\n{expected.hex()}\n\n"
            f"Actual:\n{actual.hex()}"
        )


def load_vector(path: Path) -> dict:
    if not path.exists():
        fail(f"Vector file does not exist:\n{path}")

    try:
        with path.open("r", encoding="utf-8") as file:
            document = json.load(file)
    except json.JSONDecodeError as exc:
        fail(f"Invalid vector JSON:\n{exc}")
    except OSError as exc:
        fail(f"Unable to read vector file:\n{exc}")

    if document.get("specification") != SPECIFICATION:
        fail(
            "Unexpected specification.\n\n"
            f"Expected: {SPECIFICATION!r}\n"
            f"Actual: {document.get('specification')!r}"
        )

    if document.get("version") != VERSION:
        fail(
            "Unexpected specification version.\n\n"
            f"Expected: {VERSION!r}\n"
            f"Actual: {document.get('version')!r}"
        )

    vector = document.get("vector")
    if not isinstance(vector, dict):
        fail("Missing or invalid vector object.")

    if vector.get("id") != "V02":
        fail(f"Expected V02 vector, got {vector.get('id')!r}.")

    return vector


def verify(vector: dict) -> None:
    print()
    print("OpenIdentity OI-002")
    print("V02 Independent Verification")
    print("=" * 48)
    print()

    identity = parse_hex("identityHex", require_field(vector, "identityHex"))
    ed_method_id = parse_hex("ed25519MethodIdHex", require_field(vector, "ed25519MethodIdHex"))
    ml_method_id = parse_hex("mlDsa65MethodIdHex", require_field(vector, "mlDsa65MethodIdHex"))
    ed_public_key = parse_hex("ed25519PublicKeyHex", require_field(vector, "ed25519PublicKeyHex"))
    ml_public_key = parse_hex("mlDsa65PublicKeyHex", require_field(vector, "mlDsa65PublicKeyHex"))
    ed_cose_bytes = parse_hex("ed25519CoseKeyHex", require_field(vector, "ed25519CoseKeyHex"))
    ml_cose_bytes = parse_hex("mlDsa65CoseKeyHex", require_field(vector, "mlDsa65CoseKeyHex"))
    ed_method_bytes = parse_hex("ed25519VerificationMethodHex", require_field(vector, "ed25519VerificationMethodHex"))
    ml_method_bytes = parse_hex("mlDsa65VerificationMethodHex", require_field(vector, "mlDsa65VerificationMethodHex"))
    policy_bytes = parse_hex("controllerPolicyHex", require_field(vector, "controllerPolicyHex"))
    operation_bytes = parse_hex("operationBytesHex", require_field(vector, "operationBytesHex"))
    signing_input = parse_hex("signingInputHex", require_field(vector, "signingInputHex"))
    ed_signature = parse_hex("ed25519SignatureHex", require_field(vector, "ed25519SignatureHex"))
    ml_signature = parse_hex("mlDsa65SignatureHex", require_field(vector, "mlDsa65SignatureHex"))
    ed_proof_bytes = parse_hex("ed25519AuthorizationProofHex", require_field(vector, "ed25519AuthorizationProofHex"))
    ml_proof_bytes = parse_hex("mlDsa65AuthorizationProofHex", require_field(vector, "mlDsa65AuthorizationProofHex"))
    signed_operation_bytes = parse_hex("signedOperationHex", require_field(vector, "signedOperationHex"))
    identity_state_bytes = parse_hex("identityStateHex", require_field(vector, "identityStateHex"))
    state_hash = parse_hex("stateHashHex", require_field(vector, "stateHashHex"))

    # Basic sizes.
    checks = [
        ("Identity length", len(identity), IDENTITY_LENGTH),
        ("Ed25519 Verification Method ID length", len(ed_method_id), METHOD_ID_LENGTH),
        ("ML-DSA-65 Verification Method ID length", len(ml_method_id), METHOD_ID_LENGTH),
        ("Ed25519 public key length", len(ed_public_key), ED_PUBLIC_KEY_LENGTH),
        ("ML-DSA-65 public key length", len(ml_public_key), ML_PUBLIC_KEY_LENGTH),
        ("Ed25519 signature length", len(ed_signature), ED_SIGNATURE_LENGTH),
        ("ML-DSA-65 signature length", len(ml_signature), ML_SIGNATURE_LENGTH),
        ("StateHash length", len(state_hash), SHA256_MULTIHASH_LENGTH),
    ]
    for name, actual, expected in checks:
        assert_equal(name, actual, expected)
        passed(name)

    if ed_method_id == ml_method_id:
        fail("Verification Method IDs must be unique.")
    passed("Verification Method IDs unique")

    optional_lengths = {
        "ed25519PublicKeyLength": ED_PUBLIC_KEY_LENGTH,
        "mlDsa65PublicKeyLength": ML_PUBLIC_KEY_LENGTH,
        "ed25519SignatureLength": ED_SIGNATURE_LENGTH,
        "mlDsa65SignatureLength": ML_SIGNATURE_LENGTH,
    }
    for field, expected in optional_lengths.items():
        if field in vector:
            assert_equal(field, vector[field], expected)
    passed("Generated length metadata")

    # COSE keys.
    expected_ed_cose = {
        COSE_KTY: COSE_KTY_OKP,
        COSE_ALG: COSE_ALG_EDDSA,
        COSE_OKP_CRV: COSE_CRV_ED25519,
        COSE_OKP_X: ed_public_key,
    }
    expected_ml_cose = {
        COSE_KTY: COSE_KTY_AKP,
        COSE_ALG: COSE_ALG_ML_DSA_65,
        COSE_AKP_PUB: ml_public_key,
    }

    assert_equal("Ed25519 COSE_Key structure", decode_cbor("Ed25519 COSE_Key", ed_cose_bytes), expected_ed_cose)
    passed("Ed25519 COSE_Key structure")
    assert_bytes_equal("Ed25519 COSE_Key canonical CBOR", ed_cose_bytes, canonical_cbor(expected_ed_cose))
    passed("Ed25519 COSE_Key canonical CBOR")

    assert_equal("ML-DSA-65 COSE_Key structure", decode_cbor("ML-DSA-65 COSE_Key", ml_cose_bytes), expected_ml_cose)
    passed("ML-DSA-65 COSE_Key structure")
    assert_bytes_equal("ML-DSA-65 COSE_Key canonical CBOR", ml_cose_bytes, canonical_cbor(expected_ml_cose))
    passed("ML-DSA-65 COSE_Key canonical CBOR")

    # VerificationMethods.
    expected_ed_method = {1: ed_method_id, 2: expected_ed_cose}
    expected_ml_method = {1: ml_method_id, 2: expected_ml_cose}

    assert_equal("Ed25519 VerificationMethod structure", decode_cbor("Ed25519 VerificationMethod", ed_method_bytes), expected_ed_method)
    passed("Ed25519 VerificationMethod structure")
    assert_bytes_equal("Ed25519 VerificationMethod canonical CBOR", ed_method_bytes, canonical_cbor(expected_ed_method))
    passed("Ed25519 VerificationMethod canonical CBOR")

    assert_equal("ML-DSA-65 VerificationMethod structure", decode_cbor("ML-DSA-65 VerificationMethod", ml_method_bytes), expected_ml_method)
    passed("ML-DSA-65 VerificationMethod structure")
    assert_bytes_equal("ML-DSA-65 VerificationMethod canonical CBOR", ml_method_bytes, canonical_cbor(expected_ml_method))
    passed("ML-DSA-65 VerificationMethod canonical CBOR")

    # Canonical policy ordering.
    methods = [
        (ed_method_id, expected_ed_method),
        (ml_method_id, expected_ml_method),
    ]
    methods.sort(key=lambda item: item[0])

    expected_policy = {
        1: THRESHOLD_POLICY,
        2: 2,
        3: [item[1] for item in methods],
    }

    policy = decode_cbor("ControllerPolicy", policy_bytes)
    assert_equal("THRESHOLD ControllerPolicy structure", policy, expected_policy)
    passed("THRESHOLD ControllerPolicy structure")
    assert_bytes_equal("ControllerPolicy canonical CBOR", policy_bytes, canonical_cbor(expected_policy))
    passed("ControllerPolicy canonical CBOR")
    assert_equal("Controller threshold", policy[2], 2)
    assert_equal("Controller method count", len(policy[3]), 2)
    passed("2-of-2 controller semantics")

    # CREATE operation.
    expected_payload = {1: expected_policy}
    expected_operation = {
        1: PROTOCOL_VERSION,
        2: CREATE_OPERATION,
        3: identity,
        4: 1,
        5: None,
        6: expected_payload,
    }

    operation = decode_cbor("OperationBytes", operation_bytes)
    assert_equal("CREATE Operation structure", operation, expected_operation)
    passed("CREATE Operation structure")
    assert_equal("protocolVersion", operation[1], 1)
    assert_equal("operationType", operation[2], 1)
    assert_equal("identity length", len(operation[3]), 32)
    assert_equal("sequence", operation[4], 1)
    assert_equal("previousStateHash", operation[5], None)
    passed("CREATE field requirements")

    assert_bytes_equal("OperationBytes", operation_bytes, canonical_cbor(expected_operation))
    passed("OperationBytes")

    # SigningInput.
    expected_signing_structure = [
        SIGNING_CONTEXT,
        SIGNING_STRUCTURE_VERSION,
        operation_bytes,
    ]
    assert_bytes_equal("SigningInput", signing_input, canonical_cbor(expected_signing_structure))
    passed("SigningInput")

    # Independent signatures.
    try:
        Ed25519PublicKey.from_public_bytes(ed_public_key).verify(ed_signature, signing_input)
    except InvalidSignature:
        fail("Independent Ed25519 signature verification failed.")
    except Exception as exc:
        fail(f"Unable to verify Ed25519 signature:\n{exc}")
    passed("Independent Ed25519 signature")

    try:
        MLDSA65PublicKey.from_public_bytes(ml_public_key).verify(ml_signature, signing_input)
    except InvalidSignature:
        fail("Independent ML-DSA-65 signature verification failed.")
    except Exception as exc:
        fail(f"Unable to verify ML-DSA-65 signature:\n{exc}")
    passed("Independent ML-DSA-65 signature")

    # Proofs.
    expected_ed_proof = {1: ed_method_id, 2: ed_signature}
    expected_ml_proof = {1: ml_method_id, 2: ml_signature}

    assert_equal("Ed25519 AuthorizationProof structure", decode_cbor("Ed25519 AuthorizationProof", ed_proof_bytes), expected_ed_proof)
    passed("Ed25519 AuthorizationProof structure")
    assert_bytes_equal("Ed25519 AuthorizationProof canonical CBOR", ed_proof_bytes, canonical_cbor(expected_ed_proof))
    passed("Ed25519 AuthorizationProof canonical CBOR")

    assert_equal("ML-DSA-65 AuthorizationProof structure", decode_cbor("ML-DSA-65 AuthorizationProof", ml_proof_bytes), expected_ml_proof)
    passed("ML-DSA-65 AuthorizationProof structure")
    assert_bytes_equal("ML-DSA-65 AuthorizationProof canonical CBOR", ml_proof_bytes, canonical_cbor(expected_ml_proof))
    passed("ML-DSA-65 AuthorizationProof canonical CBOR")

    proofs = [
        (ed_method_id, expected_ed_proof),
        (ml_method_id, expected_ml_proof),
    ]
    proofs.sort(key=lambda item: item[0])
    expected_proof_list = [item[1] for item in proofs]

    expected_signed_operation = {
        1: expected_operation,
        2: expected_proof_list,
    }

    signed_operation = decode_cbor("SignedOperation", signed_operation_bytes)
    assert_equal("SignedOperation structure", signed_operation, expected_signed_operation)
    passed("SignedOperation structure")
    assert_bytes_equal("SignedOperation canonical CBOR", signed_operation_bytes, canonical_cbor(expected_signed_operation))
    passed("SignedOperation canonical CBOR")

    assert_equal("Unique valid proof count", len({ed_method_id, ml_method_id}), 2)
    passed("2-of-2 controller threshold")

    # -----------------------------------------------------------------
    # Canonical IdentityState v1
    #
    # {
    #   1: stateVersion = 1
    #   2: identity
    #   3: sequence = 1
    #   4: status = ACTIVE (1)
    #   5: controllerPolicy
    # }
    # -----------------------------------------------------------------

    expected_identity_state = {
        1: IDENTITY_STATE_VERSION,
        2: identity,
        3: 1,
        4: IDENTITY_STATUS_ACTIVE,
        5: expected_policy,
    }

    identity_state = decode_cbor("IdentityState", identity_state_bytes)
    assert_equal("IdentityState structure", identity_state, expected_identity_state)
    passed("IdentityState structure")

    expected_identity_state_bytes = canonical_cbor(expected_identity_state)
    assert_bytes_equal("IdentityState canonical CBOR", identity_state_bytes, expected_identity_state_bytes)
    passed("IdentityState canonical CBOR")

    assert_equal("IdentityState version", identity_state[1], 1)
    assert_equal("IdentityState identity", identity_state[2], identity)
    assert_equal("IdentityState sequence", identity_state[3], 1)
    assert_equal("IdentityState status", identity_state[4], IDENTITY_STATUS_ACTIVE)
    assert_equal("IdentityState controller policy", identity_state[5], expected_policy)
    passed("IdentityState field requirements")

    # -----------------------------------------------------------------
    # StateHash:
    #
    # 0x12 || 0x20 || SHA-256(StateBytes)
    # -----------------------------------------------------------------

    digest = hashlib.sha256(identity_state_bytes).digest()

    expected_state_hash = bytes([
        MULTIHASH_SHA2_256_CODE,
        MULTIHASH_SHA2_256_LENGTH,
    ]) + digest

    assert_equal("SHA-256 digest length", len(digest), 32)
    passed("SHA-256 digest length")

    assert_bytes_equal("StateHash SHA2-256 Multihash", state_hash, expected_state_hash)
    passed("StateHash SHA2-256 Multihash")

    assert_equal("StateHash algorithm code", state_hash[0], MULTIHASH_SHA2_256_CODE)
    assert_equal("StateHash digest length code", state_hash[1], MULTIHASH_SHA2_256_LENGTH)
    assert_equal("StateHash embedded digest", state_hash[2:], digest)
    passed("StateHash Multihash structure")

    print()
    print("=" * 48)
    print("V02 INDEPENDENT VERIFICATION PASSED")
    print("INCLUDING IDENTITY STATE + STATE HASH")
    print("=" * 48)
    print()


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Independently verify OpenIdentity OI-002 V02 JSON, "
            "including canonical IdentityState and StateHash."
        )
    )
    parser.add_argument(
        "vector_file",
        type=Path,
        help="Path to generated crypto-v02-java.json",
    )
    args = parser.parse_args()
    verify(load_vector(args.vector_file))


if __name__ == "__main__":
    main()
