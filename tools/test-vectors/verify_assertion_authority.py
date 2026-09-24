#!/usr/bin/env python3
"""
Independent OI-003 Assertion Authority verifier.

A01 verifies the explicit IdentityState v1 -> v2 transition performed by
SET_ASSERTION_POLICY with a SINGLE Ed25519 AssertionPolicy.

No third-party CBOR package is required. The verifier independently builds the
deterministic CBOR bytes needed for A01 and compares them to the Java vector.

Usage from repository root:
    python tools/test-vectors/verify_assertion_authority.py

Or:
    python tools/test-vectors/verify_assertion_authority.py \
        test-vectors/generated/assertion-a01-java.json
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

try:
    from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PublicKey
except ImportError as exc:
    raise SystemExit(
        "This verifier requires cryptography >= 47.0.0 for independent "
        "Ed25519 and ML-DSA-65 verification. Install/upgrade with:\n"
        "  python -m pip install 'cryptography>=47.0.0'"
    ) from exc


def fail(message: str) -> None:
    raise AssertionError(message)


def check(label: str, condition: bool) -> None:
    if not condition:
        fail(label)
    print(f"  {label}: PASS")


def hx(value: str) -> bytes:
    return bytes.fromhex(value)


# ---------------------------------------------------------------------------
# Minimal deterministic CBOR encoder for the structures used by A01.
# ---------------------------------------------------------------------------

def _head(major: int, value: int) -> bytes:
    if value < 0:
        raise ValueError("CBOR additional value cannot be negative")
    if value < 24:
        return bytes([(major << 5) | value])
    if value <= 0xFF:
        return bytes([(major << 5) | 24, value])
    if value <= 0xFFFF:
        return bytes([(major << 5) | 25]) + value.to_bytes(2, "big")
    if value <= 0xFFFFFFFF:
        return bytes([(major << 5) | 26]) + value.to_bytes(4, "big")
    if value <= 0xFFFFFFFFFFFFFFFF:
        return bytes([(major << 5) | 27]) + value.to_bytes(8, "big")
    raise ValueError("integer too large")


def uint(value: int) -> bytes:
    return _head(0, value)


def nint(value: int) -> bytes:
    if value >= 0:
        raise ValueError("expected negative integer")
    return _head(1, -1 - value)


def integer(value: int) -> bytes:
    return uint(value) if value >= 0 else nint(value)


def bstr(value: bytes) -> bytes:
    return _head(2, len(value)) + value


def tstr(value: str) -> bytes:
    raw = value.encode("utf-8")
    return _head(3, len(raw)) + raw


def array(items: list[bytes]) -> bytes:
    return _head(4, len(items)) + b"".join(items)


def cmap(entries: list[tuple[int, bytes]]) -> bytes:
    # A01 maps use non-negative integer labels. Numeric order is also the
    # deterministic encoded-key order for these small labels.
    entries = sorted(entries, key=lambda item: item[0])
    return _head(5, len(entries)) + b"".join(
        uint(key) + value for key, value in entries
    )


def cbor_null() -> bytes:
    return b"\xf6"


# ---------------------------------------------------------------------------
# Minimal CBOR decoder used only to recover the authoritative V02 controller
# public keys from previousIdentityStateHex. This prevents the verifier from
# hard-coding controller public keys or trusting Java convenience fields.
# ---------------------------------------------------------------------------

class CborReader:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def _take(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            raise ValueError("truncated CBOR")
        out = self.data[self.pos:self.pos + n]
        self.pos += n
        return out

    def _argument(self, additional: int) -> int:
        if additional < 24:
            return additional
        if additional == 24:
            return self._take(1)[0]
        if additional == 25:
            return int.from_bytes(self._take(2), "big")
        if additional == 26:
            return int.from_bytes(self._take(4), "big")
        if additional == 27:
            return int.from_bytes(self._take(8), "big")
        raise ValueError("indefinite/reserved CBOR additional information")

    def read(self):
        initial = self._take(1)[0]
        major = initial >> 5
        additional = initial & 0x1F

        if major == 0:
            return self._argument(additional)
        if major == 1:
            return -1 - self._argument(additional)
        if major == 2:
            return self._take(self._argument(additional))
        if major == 3:
            return self._take(self._argument(additional)).decode("utf-8")
        if major == 4:
            return [self.read() for _ in range(self._argument(additional))]
        if major == 5:
            count = self._argument(additional)
            out = {}
            for _ in range(count):
                key = self.read()
                if key in out:
                    raise ValueError("duplicate CBOR map key")
                out[key] = self.read()
            return out
        if major == 7 and additional == 22:
            return None
        raise ValueError(f"unsupported CBOR major/additional: {major}/{additional}")


def decode_one(data: bytes):
    reader = CborReader(data)
    value = reader.read()
    if reader.pos != len(data):
        raise ValueError("trailing CBOR data")
    return value


def controller_keys_from_state(state_bytes: bytes):
    state = decode_one(state_bytes)
    if not isinstance(state, dict) or state.get(1) not in (1, 2):
        fail("previousIdentityStateHex is not a supported IdentityState")

    policy = state.get(5)
    if not isinstance(policy, dict) or policy.get(1) != 2 or policy.get(2) != 2:
        fail("source ControllerPolicy is not THRESHOLD 2-of-n")

    methods = policy.get(3)
    if not isinstance(methods, list):
        fail("source ControllerPolicy methods missing")

    found = {}
    for method in methods:
        if not isinstance(method, dict):
            fail("invalid VerificationMethod in source ControllerPolicy")
        method_id = method.get(1)
        cose = method.get(2)
        if not isinstance(method_id, bytes) or len(method_id) != 16:
            fail("invalid controller Verification Method ID")
        if not isinstance(cose, dict):
            fail("invalid controller COSE_Key")

        if (cose.get(1), cose.get(3), cose.get(-1)) == (1, -8, 6):
            public_key = cose.get(-2)
            if not isinstance(public_key, bytes) or len(public_key) != 32:
                fail("invalid Ed25519 controller public key")
            found["Ed25519"] = (method_id, public_key)
        elif (cose.get(1), cose.get(3)) == (7, -49):
            public_key = cose.get(-1)
            if not isinstance(public_key, bytes) or len(public_key) != 1952:
                fail("invalid ML-DSA-65 controller public key")
            found["ML-DSA-65"] = (method_id, public_key)

    if set(found) != {"Ed25519", "ML-DSA-65"}:
        fail("source ControllerPolicy does not contain expected algorithms")
    return found


def assertion_method_ids_from_state(state_bytes: bytes) -> list[bytes]:
    state = decode_one(state_bytes)
    if not isinstance(state, dict) or state.get(1) != 2:
        fail("historical assertion lookup requires IdentityState v2")
    policy = state.get(7)
    if not isinstance(policy, dict):
        return []

    policy_type = policy.get(1)
    if policy_type == 1:
        methods = policy.get(2)
    elif policy_type == 2:
        methods = policy.get(3)
    else:
        fail("unsupported AssertionPolicy type")

    if not isinstance(methods, list):
        fail("AssertionPolicy methods missing")
    ids = []
    for method in methods:
        if not isinstance(method, dict):
            fail("invalid assertion VerificationMethod")
        method_id = method.get(1)
        if not isinstance(method_id, bytes) or len(method_id) != 16:
            fail("invalid assertion Verification Method ID")
        ids.append(method_id)
    return ids


def controller_policy_bytes_from_state(state_bytes: bytes) -> bytes:
    # The vector carries canonical controllerPolicyHex. For semantic comparison
    # we decode the state and compare the decoded policy object separately.
    state = decode_one(state_bytes)
    if not isinstance(state, dict) or 5 not in state:
        fail("IdentityState ControllerPolicy missing")
    return state[5]


def verifies_ed25519(public_key: bytes, signature: bytes, message: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
        return True
    except InvalidSignature:
        return False


def verifies_mldsa65(public_key: bytes, signature: bytes, message: bytes) -> bool:
    try:
        MLDSA65PublicKey.from_public_bytes(public_key).verify(signature, message)
        return True
    except InvalidSignature:
        return False
    except UnsupportedAlgorithm as exc:
        raise RuntimeError(
            "The installed cryptography backend does not support ML-DSA-65. "
            "Use cryptography >= 47 with a backend/wheel that provides ML-DSA."
        ) from exc


# ---------------------------------------------------------------------------
# OpenIdentity structures independently reconstructed from vector primitives.
# ---------------------------------------------------------------------------

def ed25519_cose_key(public_key: bytes) -> bytes:
    if len(public_key) != 32:
        fail("Ed25519 public key must be 32 bytes")
    # COSE map contains negative integer labels, so write its known canonical
    # byte ordering exactly as RFC 8949 deterministic encoding requires:
    # 1, 3, -1, -2.
    return (
            b"\xa4"
            + uint(1) + uint(1)
            + uint(3) + integer(-8)
            + integer(-1) + uint(6)
            + integer(-2) + bstr(public_key)
    )


def mldsa65_cose_key(public_key: bytes) -> bytes:
    if len(public_key) != 1952:
        fail("ML-DSA-65 public key must be 1952 bytes")
    # Canonical COSE_Key: {1: 7, 3: -49, -1: publicKey}
    return (
            b"\xa3"
            + uint(1) + uint(7)
            + uint(3) + integer(-49)
            + integer(-1) + bstr(public_key)
    )


def verification_method(method_id: bytes, cose_key: bytes) -> bytes:
    return cmap([(1, bstr(method_id)), (2, cose_key)])


def single_policy(method: bytes) -> bytes:
    return cmap([(1, uint(1)), (2, array([method]))])


def threshold_policy(threshold: int, methods: list[tuple[bytes, bytes]]) -> bytes:
    if threshold < 1 or threshold > len(methods):
        fail("invalid threshold")
    ordered = sorted(methods, key=lambda item: item[0])
    ids = [mid for mid, _ in ordered]
    if len(ids) != len(set(ids)):
        fail("duplicate Verification Method ID")
    return cmap([
        (1, uint(2)),
        (2, uint(threshold)),
        (3, array([encoded for _, encoded in ordered])),
    ])


def set_assertion_policy_operation(
        identity: bytes,
        sequence: int,
        previous_state_hash: bytes,
        assertion_policy: bytes | None,
) -> bytes:
    payload = cmap([(1, cbor_null() if assertion_policy is None else assertion_policy)])
    return cmap([
        (1, uint(1)),  # protocolVersion
        (2, uint(5)),  # SET_ASSERTION_POLICY
        (3, bstr(identity)),
        (4, uint(sequence)),
        (5, bstr(previous_state_hash)),
        (6, payload),
    ])


def operation_signing_input(operation: bytes) -> bytes:
    return array([
        tstr("OpenIdentity Operation"),
        uint(1),
        bstr(operation),
    ])


def proposed_key_pop_input(operation: bytes, method_id: bytes) -> bytes:
    return array([
        tstr("OpenIdentity Controller Proof"),
        uint(1),
        bstr(operation),
        bstr(method_id),
    ])


def proof(method_id: bytes, signature: bytes) -> bytes:
    return cmap([(1, bstr(method_id)), (2, bstr(signature))])


def signed_operation(
        operation: bytes,
        authorization_proofs: list[tuple[bytes, bytes]],
        pop_proofs: list[tuple[bytes, bytes]],
) -> bytes:
    auth = sorted(authorization_proofs, key=lambda item: item[0])
    pops = sorted(pop_proofs, key=lambda item: item[0])

    auth_encoded = array([encoded for _, encoded in auth])
    entries = [(1, operation), (2, auth_encoded)]
    if pops:
        entries.append((3, array([encoded for _, encoded in pops])))
    return cmap(entries)


def identity_state_v2(
        identity: bytes,
        sequence: int,
        controller_policy: bytes,
        assertion_policy: bytes | None,
) -> bytes:
    entries = [
        (1, uint(2)),
        (2, bstr(identity)),
        (3, uint(sequence)),
        (4, uint(1)),  # ACTIVE
        (5, controller_policy),
    ]
    if assertion_policy is not None:
        entries.append((7, assertion_policy))
    return cmap(entries)


def state_hash(state_bytes: bytes) -> bytes:
    # sha2-256 multihash = 0x12 || 0x20 || SHA-256(StateBytes)
    return b"\x12\x20" + hashlib.sha256(state_bytes).digest()


def controller_method_ids_from_state(state_bytes: bytes) -> set[bytes]:
    keys = controller_keys_from_state(state_bytes)
    return {keys["Ed25519"][0], keys["ML-DSA-65"][0]}


def assertion_methods_from_operation(operation_bytes: bytes) -> list[dict]:
    op = decode_one(operation_bytes)
    payload = op.get(6)
    if not isinstance(payload, dict) or 1 not in payload:
        fail("SET_ASSERTION_POLICY payload missing")
    policy = payload[1]
    if policy is None:
        return []
    if not isinstance(policy, dict):
        fail("invalid AssertionPolicy")
    if policy.get(1) == 1:
        methods = policy.get(2)
    elif policy.get(1) == 2:
        methods = policy.get(3)
    else:
        fail("unsupported AssertionPolicy type")
    if not isinstance(methods, list):
        fail("AssertionPolicy methods missing")
    return methods


def ed25519_public_key_from_method(method: dict) -> bytes:
    cose = method.get(2)
    if not isinstance(cose, dict):
        fail("invalid assertion COSE_Key")
    if (cose.get(1), cose.get(3), cose.get(-1)) != (1, -8, 6):
        fail("expected Ed25519 assertion method")
    pk = cose.get(-2)
    if not isinstance(pk, bytes) or len(pk) != 32:
        fail("invalid Ed25519 assertion public key")
    return pk


def verify_assertion_invalid_vectors(document, a01, a02):
    print()
    print("AI01-AI10 Invalid/Security Verification")
    print("-" * 44)

    check("Invalid suite specification",
          document.get("specification") == "OpenIdentity Assertion Authority")
    check("Invalid suite version", document.get("version") == "0.1")
    check("Invalid suite type",
          document.get("type") == "invalid-conformance-vectors")
    check("Invalid suite wire protocol version",
          document.get("wireProtocolVersion") == 1)

    vectors = document.get("vectors")
    check("Invalid suite contains exactly 10 vectors",
          isinstance(vectors, list) and len(vectors) == 10)
    by_id = {v["id"]: v for v in vectors}
    check("Invalid suite IDs AI01-AI10",
          list(by_id.keys()) == [f"AI{i:02d}" for i in range(1, 11)])

    expected_errors = {
        "AI01": "CONTROLLER_THRESHOLD_NOT_SATISFIED",
        "AI02": "MISSING_PROOF_OF_POSSESSION",
        "AI03": "INVALID_PROOF_OF_POSSESSION",
        "AI04": "INVALID_PROOF_OF_POSSESSION",
        "AI05": "INVALID_PREVIOUS_STATE_HASH",
        "AI06": "INVALID_SEQUENCE",
        "AI07": "CONTROLLER_THRESHOLD_NOT_SATISFIED",
        "AI08": "DUPLICATE_VERIFICATION_METHOD",
        "AI09": "INVALID_ASSERTION_THRESHOLD",
        "AI10": "STATE_VERSION_DOWNGRADE",
    }
    for vid, error in expected_errors.items():
        check(f"{vid} expected error label", by_id[vid].get("expectedError") == error)

    # AI01 -- assertion key B signs as authorization. Its signature is valid,
    # but B is not a ControllerPolicy member, so it contributes zero toward
    # the current 2-of-2 controller threshold.
    v = by_id["AI01"]
    prev = hx(v["previousIdentityStateHex"])
    opb = hx(v["operationBytesHex"])
    sop = decode_one(hx(v["signedOperationHex"]))
    op = decode_one(opb)
    check("AI01 source state equals A01", prev == a01["state"])
    check("AI01 previous StateHash is authoritative",
          hx(v["previousStateHashHex"]) == state_hash(prev) == a01["hash"])
    check("AI01 operation is SET_ASSERTION_POLICY", op.get(2) == 5)
    auth = sop.get(2)
    check("AI01 contains exactly one authorization proof",
          isinstance(auth, list) and len(auth) == 1)
    auth_id, auth_sig = auth[0].get(1), auth[0].get(2)
    check("AI01 signer is historical assertion key B",
          auth_id == a01["assertion_id"])
    check("AI01 signer is not in ControllerPolicy",
          auth_id not in controller_method_ids_from_state(prev))
    a01_state = decode_one(a01["state"])
    b_method = a01_state[7][2][0]
    b_pk = ed25519_public_key_from_method(b_method)
    check("AI01 assertion-key authorization signature is cryptographically valid",
          verifies_ed25519(b_pk, auth_sig, operation_signing_input(opb)))
    check("AI01 valid non-controller signature cannot satisfy 2-of-2 ControllerPolicy",
          len({p.get(1) for p in auth
               if p.get(1) in controller_method_ids_from_state(prev)}) < 2)
    print("  AI01 REJECTED: CONTROLLER_THRESHOLD_NOT_SATISFIED")

    # AI02 -- valid controller threshold, but no field 3 / proposed-key PoP.
    v = by_id["AI02"]
    prev = hx(v["previousIdentityStateHex"])
    opb = hx(v["operationBytesHex"])
    sop = decode_one(hx(v["signedOperationHex"]))
    keys = controller_keys_from_state(prev)
    auth = sop.get(2)
    auth_input = operation_signing_input(opb)
    check("AI02 source state equals A01", prev == a01["state"])
    check("AI02 has two controller authorization proofs",
          isinstance(auth, list) and len(auth) == 2)
    valid_auth = 0
    for p in auth:
        mid, sig = p.get(1), p.get(2)
        if mid == keys["Ed25519"][0] and verifies_ed25519(keys["Ed25519"][1], sig, auth_input):
            valid_auth += 1
        elif mid == keys["ML-DSA-65"][0] and verifies_mldsa65(keys["ML-DSA-65"][1], sig, auth_input):
            valid_auth += 1
    check("AI02 controller threshold cryptographically satisfies 2-of-2",
          valid_auth == 2)
    check("AI02 proposed assertion method exists",
          len(assertion_methods_from_operation(opb)) == 1)
    check("AI02 proposed-key PoP field is absent", 3 not in sop)
    print("  AI02 REJECTED: MISSING_PROOF_OF_POSSESSION")

    # AI03 -- supplied C signature is valid over authorization-domain bytes,
    # but invalid over the required proposed-key PoP input.
    v = by_id["AI03"]
    opb = hx(v["operationBytesHex"])
    sop = decode_one(hx(v["signedOperationHex"]))
    method = assertion_methods_from_operation(opb)[0]
    mid, pk = method.get(1), ed25519_public_key_from_method(method)
    pop = sop[3][0]
    sig = pop.get(2)
    required = proposed_key_pop_input(opb, mid)
    wrong = operation_signing_input(opb)
    check("AI03 PoP claims proposed method C", pop.get(1) == mid)
    check("AI03 signature verifies over wrong authorization domain",
          verifies_ed25519(pk, sig, wrong))
    check("AI03 signature fails required PoP domain",
          not verifies_ed25519(pk, sig, required))
    print("  AI03 REJECTED: INVALID_PROOF_OF_POSSESSION")

    # AI04 -- signature is valid for operation + method B, while proof claims C.
    v = by_id["AI04"]
    opb = hx(v["operationBytesHex"])
    sop = decode_one(hx(v["signedOperationHex"]))
    method = assertion_methods_from_operation(opb)[0]
    c_id, c_pk = method.get(1), ed25519_public_key_from_method(method)
    pop = sop[3][0]
    sig = pop.get(2)
    b_id = a01["assertion_id"]
    check("AI04 PoP claims proposed method C", pop.get(1) == c_id)
    check("AI04 signature verifies when bound to wrong method B",
          verifies_ed25519(c_pk, sig, proposed_key_pop_input(opb, b_id)))
    check("AI04 signature fails required method-C binding",
          not verifies_ed25519(c_pk, sig, proposed_key_pop_input(opb, c_id)))
    print("  AI04 REJECTED: INVALID_PROOF_OF_POSSESSION")

    # AI05 -- operation hash differs from exact current state hash.
    v = by_id["AI05"]
    prev = hx(v["previousIdentityStateHex"])
    op = decode_one(hx(v["operationBytesHex"]))
    authoritative = state_hash(prev)
    check("AI05 vector previousStateHash metadata is authoritative",
          hx(v["previousStateHashHex"]) == authoritative)
    check("AI05 operation previousStateHash is different",
          op.get(5) != authoritative)
    check("AI05 mutated hash retains valid multihash length",
          isinstance(op.get(5), bytes) and len(op.get(5)) == 34)
    print("  AI05 REJECTED: INVALID_PREVIOUS_STATE_HASH")

    # AI06 -- current sequence 2, operation sequence 4 rather than 3.
    v = by_id["AI06"]
    prev = decode_one(hx(v["previousIdentityStateHex"]))
    op = decode_one(hx(v["operationBytesHex"]))
    check("AI06 current sequence is 2", prev.get(3) == 2)
    check("AI06 operation sequence is 4", op.get(4) == 4)
    check("AI06 sequence is not current + 1", op.get(4) != prev.get(3) + 1)
    print("  AI06 REJECTED: INVALID_SEQUENCE")

    # AI07 -- supplied Ed25519 controller proof is valid but only 1-of-2.
    v = by_id["AI07"]
    prevb = hx(v["previousIdentityStateHex"])
    opb = hx(v["operationBytesHex"])
    sop = decode_one(hx(v["signedOperationHex"]))
    keys = controller_keys_from_state(prevb)
    auth = sop.get(2)
    check("AI07 contains exactly one controller authorization proof",
          isinstance(auth, list) and len(auth) == 1)
    p = auth[0]
    check("AI07 supplied controller proof cryptographically verifies",
          p.get(1) == keys["Ed25519"][0]
          and verifies_ed25519(keys["Ed25519"][1], p.get(2),
                               operation_signing_input(opb)))
    check("AI07 1-of-2 is below ControllerPolicy threshold", len(auth) < 2)
    print("  AI07 REJECTED: CONTROLLER_THRESHOLD_NOT_SATISFIED")

    # AI08 -- threshold policy has two methods with the same method ID.
    v = by_id["AI08"]
    methods = assertion_methods_from_operation(hx(v["operationBytesHex"]))
    ids = [m.get(1) for m in methods]
    check("AI08 contains two proposed assertion methods", len(ids) == 2)
    check("AI08 contains duplicate Verification Method IDs",
          len(set(ids)) != len(ids))
    print("  AI08 REJECTED: DUPLICATE_VERIFICATION_METHOD")

    # AI09 -- threshold 2 with only one method.
    v = by_id["AI09"]
    op = decode_one(hx(v["operationBytesHex"]))
    policy = op[6][1]
    check("AI09 policy type is THRESHOLD", policy.get(1) == 2)
    check("AI09 threshold is 2", policy.get(2) == 2)
    check("AI09 contains one VerificationMethod",
          isinstance(policy.get(3), list) and len(policy.get(3)) == 1)
    check("AI09 threshold exceeds method count",
          policy.get(2) > len(policy.get(3)))
    print("  AI09 REJECTED: INVALID_ASSERTION_THRESHOLD")

    # AI10 -- operation itself is a valid A02 -> removal transition and its
    # controller signatures verify, but the supplied resulting state is v1.
    v = by_id["AI10"]
    prevb = hx(v["previousIdentityStateHex"])
    opb = hx(v["operationBytesHex"])
    sop = decode_one(hx(v["signedOperationHex"]))
    resultb = hx(v["invalidResultingIdentityStateHex"])
    prev = decode_one(prevb)
    result = decode_one(resultb)
    keys = controller_keys_from_state(prevb)
    auth_input = operation_signing_input(opb)
    valid_auth = 0
    for p in sop[2]:
        mid, sig = p.get(1), p.get(2)
        if mid == keys["Ed25519"][0] and verifies_ed25519(keys["Ed25519"][1], sig, auth_input):
            valid_auth += 1
        elif mid == keys["ML-DSA-65"][0] and verifies_mldsa65(keys["ML-DSA-65"][1], sig, auth_input):
            valid_auth += 1
    check("AI10 source state equals A02", prevb == a02["state"])
    check("AI10 previous StateHash is authoritative",
          hx(v["previousStateHashHex"]) == state_hash(prevb) == a02["hash"])
    check("AI10 operation controller authorization cryptographically satisfies 2-of-2",
          valid_auth == 2)
    check("AI10 source IdentityState version is 2",
          prev.get(1) == 2 and v.get("previousIdentityStateVersion") == 2)
    check("AI10 proposed resulting IdentityState version is 1",
          result.get(1) == 1 and v.get("invalidResultingIdentityStateVersion") == 1)
    check("AI10 is an explicit state-version downgrade",
          result.get(1) < prev.get(1))
    print("  AI10 REJECTED: STATE_VERSION_DOWNGRADE")

    print()
    print("AI01-AI10 VERIFIED")


def locate_generated(name: str) -> Path:
    candidates = [
        Path.cwd() / "test-vectors" / "generated" / name,
        Path(__file__).resolve().parents[2] / "test-vectors" / "generated" / name,
        ]
    for path in candidates:
        if path.exists():
            return path
    fail(f"Could not locate test-vectors/generated/{name}")


def load_vector(path: Path):
    document = json.loads(path.read_text(encoding="utf-8"))
    return document, document["vector"]


def verify_a01(document, v):
    identity = hx(v["identityHex"])
    previous_state = hx(v["previousIdentityStateHex"])
    previous_hash = hx(v["previousStateHashHex"])
    controller_policy = hx(v["controllerPolicyHex"])
    assertion_id = hx(v["assertionEd25519MethodIdHex"])
    assertion_pk = hx(v["assertionEd25519PublicKeyHex"])

    expected_cose = ed25519_cose_key(assertion_pk)
    expected_method = verification_method(assertion_id, expected_cose)
    expected_policy = single_policy(expected_method)
    expected_operation = set_assertion_policy_operation(
        identity, 2, previous_hash, expected_policy)
    expected_auth_input = operation_signing_input(expected_operation)
    expected_pop_input = proposed_key_pop_input(expected_operation, assertion_id)

    ed_auth_sig = hx(v["controllerEd25519AuthorizationSignatureHex"])
    ml_auth_sig = hx(v["controllerMlDsa65AuthorizationSignatureHex"])
    assertion_pop_sig = hx(v["assertionEd25519PopSignatureHex"])

    controller_keys = controller_keys_from_state(previous_state)
    controller_ed_id, controller_ed_pk = controller_keys["Ed25519"]
    controller_ml_id, controller_ml_pk = controller_keys["ML-DSA-65"]

    expected_ed_auth_proof = proof(controller_ed_id, ed_auth_sig)
    expected_ml_auth_proof = proof(controller_ml_id, ml_auth_sig)
    expected_pop_proof = proof(assertion_id, assertion_pop_sig)
    expected_signed = signed_operation(
        expected_operation,
        [(controller_ed_id, expected_ed_auth_proof),
         (controller_ml_id, expected_ml_auth_proof)],
        [(assertion_id, expected_pop_proof)])

    expected_state = identity_state_v2(
        identity, 2, controller_policy, expected_policy)
    expected_hash = state_hash(expected_state)

    print("A01 v1 -> v2 Assertion Authority")
    print("-" * 44)
    check("A01 vector ID", v.get("id") == "A01")
    check("A01 source vector", v.get("sourceVector") == "V02")
    check("A01 wire protocol version", document.get("wireProtocolVersion") == 1)
    check("A01 source state version",
          document.get("sourceIdentityStateVersion") == 1
          and v.get("previousIdentityStateVersion") == 1)
    check("A01 resulting state version",
          document.get("resultingIdentityStateVersion") == 2
          and v.get("resultingIdentityStateVersion") == 2)
    check("A01 sequence", v.get("sequence") == 2)
    check("A01 identity length", len(identity) == 32)
    check("A01 previous StateHash recomputed",
          previous_hash == state_hash(previous_state))
    check("A01 assertion Ed25519 COSE_Key",
          hx(v["assertionEd25519CoseKeyHex"]) == expected_cose)
    check("A01 assertion VerificationMethod",
          hx(v["assertionEd25519VerificationMethodHex"]) == expected_method)
    check("A01 SINGLE AssertionPolicy",
          v.get("assertionPolicyType") == "SINGLE"
          and v.get("assertionThreshold") == 1
          and hx(v["assertionPolicyHex"]) == expected_policy)
    check("A01 SET_ASSERTION_POLICY OperationBytes",
          hx(v["operationBytesHex"]) == expected_operation)
    check("A01 authorization signing input",
          hx(v["authorizationSigningInputHex"]) == expected_auth_input)
    check("A01 assertion-key PoP signing input",
          hx(v["assertionEd25519PopSigningInputHex"]) == expected_pop_input)
    check("A01 controller Ed25519 signature cryptographically verifies",
          verifies_ed25519(controller_ed_pk, ed_auth_sig, expected_auth_input))
    check("A01 controller ML-DSA-65 signature cryptographically verifies",
          verifies_mldsa65(controller_ml_pk, ml_auth_sig, expected_auth_input))
    check("A01 assertion Ed25519 PoP cryptographically verifies",
          verifies_ed25519(assertion_pk, assertion_pop_sig, expected_pop_input))
    check("A01 controller Ed25519 proof encoding",
          hx(v["controllerEd25519AuthorizationProofHex"]) == expected_ed_auth_proof)
    check("A01 controller ML-DSA-65 proof encoding",
          hx(v["controllerMlDsa65AuthorizationProofHex"]) == expected_ml_auth_proof)
    check("A01 assertion proof-of-possession encoding",
          hx(v["assertionEd25519ProofOfPossessionHex"]) == expected_pop_proof)
    check("A01 signed operation canonical encoding",
          hx(v["signedOperationHex"]) == expected_signed)
    check("A01 resulting IdentityState v2 encoding",
          hx(v["resultingIdentityStateHex"]) == expected_state)
    check("A01 resulting StateHash independently derived",
          hx(v["resultingStateHashHex"]) == expected_hash)
    check("A01 assertion method is not a controller method",
          assertion_id not in {controller_ed_id, controller_ml_id})
    check("A01 controller methods are not AssertionPolicy methods",
          controller_ed_id not in assertion_method_ids_from_state(expected_state)
          and controller_ml_id not in assertion_method_ids_from_state(expected_state))
    print()
    print("A01 VERIFIED")
    return {
        "identity": identity,
        "state": expected_state,
        "hash": expected_hash,
        "controller_policy": controller_policy,
        "assertion_id": assertion_id,
    }


def verify_a02(document, v, a01):
    identity = hx(v["identityHex"])
    previous_state = hx(v["previousIdentityStateHex"])
    previous_hash = hx(v["previousStateHashHex"])
    controller_policy = hx(v["controllerPolicyHex"])
    retired_id = hx(v["retiredAssertionEd25519MethodIdHex"])
    new_id = hx(v["assertionEd25519MethodIdHex"])
    new_pk = hx(v["assertionEd25519PublicKeyHex"])

    expected_cose = ed25519_cose_key(new_pk)
    expected_method = verification_method(new_id, expected_cose)
    expected_policy = single_policy(expected_method)
    expected_operation = set_assertion_policy_operation(
        identity, 3, previous_hash, expected_policy)
    expected_auth_input = operation_signing_input(expected_operation)
    expected_pop_input = proposed_key_pop_input(expected_operation, new_id)

    ed_sig = hx(v["controllerEd25519AuthorizationSignatureHex"])
    ml_sig = hx(v["controllerMlDsa65AuthorizationSignatureHex"])
    pop_sig = hx(v["assertionEd25519PopSignatureHex"])

    controller_keys = controller_keys_from_state(previous_state)
    ed_id, ed_pk = controller_keys["Ed25519"]
    ml_id, ml_pk = controller_keys["ML-DSA-65"]

    ed_proof = proof(ed_id, ed_sig)
    ml_proof = proof(ml_id, ml_sig)
    pop_proof = proof(new_id, pop_sig)
    expected_signed = signed_operation(
        expected_operation,
        [(ed_id, ed_proof), (ml_id, ml_proof)],
        [(new_id, pop_proof)])

    expected_state = identity_state_v2(
        identity, 3, controller_policy, expected_policy)
    expected_hash = state_hash(expected_state)

    print()
    print("A02 Assertion Policy Replacement")
    print("-" * 44)
    check("A02 vector ID", v.get("id") == "A02")
    check("A02 source vector", v.get("sourceVector") == "A01")
    check("A02 wire protocol version", document.get("wireProtocolVersion") == 1)
    check("A02 remains IdentityState v2",
          document.get("sourceIdentityStateVersion") == 2
          and document.get("resultingIdentityStateVersion") == 2
          and v.get("previousIdentityStateVersion") == 2
          and v.get("resultingIdentityStateVersion") == 2)
    check("A02 sequence", v.get("sequence") == 3)
    check("A02 identity preserved", identity == a01["identity"])
    check("A02 previous state equals A01 resulting state",
          previous_state == a01["state"])
    check("A02 previous StateHash equals A01 StateHash",
          previous_hash == a01["hash"])
    check("A02 previous StateHash independently recomputed",
          previous_hash == state_hash(previous_state))
    check("A02 ControllerPolicy preserved",
          controller_policy == a01["controller_policy"])
    check("A02 previous AssertionPolicy matches A01",
          hx(v["previousAssertionPolicyHex"]).hex()
          == decode_policy_bytes_from_state(a01["state"]))
    check("A02 retired method is A01 assertion method",
          retired_id == a01["assertion_id"])

    check("A02 new assertion method ID length", len(new_id) == 16)
    check("A02 new assertion public key length", len(new_pk) == 32)
    check("A02 new Ed25519 COSE_Key",
          hx(v["assertionEd25519CoseKeyHex"]) == expected_cose)
    check("A02 new VerificationMethod",
          hx(v["assertionEd25519VerificationMethodHex"]) == expected_method)
    check("A02 replacement SINGLE AssertionPolicy",
          v.get("assertionPolicyType") == "SINGLE"
          and v.get("assertionThreshold") == 1
          and hx(v["assertionPolicyHex"]) == expected_policy)

    check("A02 SET_ASSERTION_POLICY OperationBytes",
          hx(v["operationBytesHex"]) == expected_operation)
    check("A02 authorization signing input",
          hx(v["authorizationSigningInputHex"]) == expected_auth_input)
    check("A02 assertion-key PoP signing input",
          hx(v["assertionEd25519PopSigningInputHex"]) == expected_pop_input)
    check("A02 controller Ed25519 signature cryptographically verifies",
          verifies_ed25519(ed_pk, ed_sig, expected_auth_input))
    check("A02 controller ML-DSA-65 signature cryptographically verifies",
          verifies_mldsa65(ml_pk, ml_sig, expected_auth_input))
    check("A02 new assertion Ed25519 PoP cryptographically verifies",
          verifies_ed25519(new_pk, pop_sig, expected_pop_input))
    check("A02 controller Ed25519 proof encoding",
          hx(v["controllerEd25519AuthorizationProofHex"]) == ed_proof)
    check("A02 controller ML-DSA-65 proof encoding",
          hx(v["controllerMlDsa65AuthorizationProofHex"]) == ml_proof)
    check("A02 assertion proof-of-possession encoding",
          hx(v["assertionEd25519ProofOfPossessionHex"]) == pop_proof)
    check("A02 signed operation canonical encoding",
          hx(v["signedOperationHex"]) == expected_signed)

    check("A02 resulting IdentityState v2 encoding",
          hx(v["resultingIdentityStateHex"]) == expected_state)
    check("A02 resulting StateHash independently derived",
          hx(v["resultingStateHashHex"]) == expected_hash)
    check("A02 StateHash differs from A01", expected_hash != a01["hash"])

    a01_methods = assertion_method_ids_from_state(a01["state"])
    a02_methods = assertion_method_ids_from_state(expected_state)
    check("Historical A01 authorizes retired key B",
          retired_id in a01_methods)
    check("Historical A01 does not authorize new key C",
          new_id not in a01_methods)
    check("Current A02 retires key B",
          retired_id not in a02_methods)
    check("Current A02 authorizes key C",
          new_id in a02_methods)
    check("A02 assertion authorities do not accumulate",
          a02_methods == [new_id])
    check("A02 controller methods remain outside AssertionPolicy",
          ed_id not in a02_methods and ml_id not in a02_methods)
    check("A02 generator preservation markers",
          v.get("controllerPolicyPreserved") is True
          and v.get("retiredAssertionMethodRemoved") is True)
    check("A02 authorization proof count", v.get("authorizationProofCount") == 2)
    check("A02 assertion PoP count",
          v.get("assertionProofOfPossessionCount") == 1)

    print()
    print("A02 VERIFIED")
    return {
        "identity": identity,
        "state": expected_state,
        "hash": expected_hash,
        "controller_policy": controller_policy,
        "assertion_id": new_id,
        "retired_assertion_id": retired_id,
    }


def verify_a03(document, v, a01, a02):
    identity = hx(v["identityHex"])
    previous_state = hx(v["previousIdentityStateHex"])
    previous_hash = hx(v["previousStateHashHex"])
    controller_policy = hx(v["controllerPolicyHex"])
    removed_id = hx(v["removedAssertionEd25519MethodIdHex"])

    expected_operation = set_assertion_policy_operation(
        identity, 4, previous_hash, None)
    expected_auth_input = operation_signing_input(expected_operation)

    ed_sig = hx(v["controllerEd25519AuthorizationSignatureHex"])
    ml_sig = hx(v["controllerMlDsa65AuthorizationSignatureHex"])

    controller_keys = controller_keys_from_state(previous_state)
    ed_id, ed_pk = controller_keys["Ed25519"]
    ml_id, ml_pk = controller_keys["ML-DSA-65"]

    ed_proof = proof(ed_id, ed_sig)
    ml_proof = proof(ml_id, ml_sig)
    expected_signed = signed_operation(
        expected_operation,
        [(ed_id, ed_proof), (ml_id, ml_proof)],
        [])

    expected_state = identity_state_v2(
        identity, 4, controller_policy, None)
    expected_hash = state_hash(expected_state)

    decoded_operation = decode_one(expected_operation)
    decoded_payload = decoded_operation.get(6)
    decoded_signed = decode_one(expected_signed)
    decoded_state = decode_one(expected_state)

    print()
    print("A03 Assertion Policy Removal")
    print("-" * 44)

    check("A03 vector ID", v.get("id") == "A03")
    check("A03 source vector", v.get("sourceVector") == "A02")
    check("A03 wire protocol version", document.get("wireProtocolVersion") == 1)
    check("A03 remains IdentityState v2",
          document.get("sourceIdentityStateVersion") == 2
          and document.get("resultingIdentityStateVersion") == 2
          and v.get("previousIdentityStateVersion") == 2
          and v.get("resultingIdentityStateVersion") == 2)
    check("A03 sequence", v.get("sequence") == 4)
    check("A03 identity preserved", identity == a02["identity"])
    check("A03 previous state equals A02 resulting state",
          previous_state == a02["state"])
    check("A03 previous StateHash equals A02 StateHash",
          previous_hash == a02["hash"])
    check("A03 previous StateHash independently recomputed",
          previous_hash == state_hash(previous_state))
    check("A03 ControllerPolicy preserved",
          controller_policy == a02["controller_policy"])
    check("A03 previous AssertionPolicy matches A02",
          hx(v["previousAssertionPolicyHex"]).hex()
          == decode_policy_bytes_from_state(a02["state"]))
    check("A03 removed method is A02 assertion method",
          removed_id == a02["assertion_id"])

    check("A03 JSON assertionPolicy is null",
          "assertionPolicy" in v and v["assertionPolicy"] is None)
    check("A03 operation payload contains CBOR nil",
          isinstance(decoded_payload, dict)
          and 1 in decoded_payload
          and decoded_payload[1] is None)
    check("A03 SET_ASSERTION_POLICY OperationBytes",
          hx(v["operationBytesHex"]) == expected_operation)
    check("A03 authorization signing input",
          hx(v["authorizationSigningInputHex"]) == expected_auth_input)

    check("A03 controller Ed25519 signature length", len(ed_sig) == 64)
    check("A03 controller ML-DSA-65 signature length", len(ml_sig) == 3309)
    check("A03 controller Ed25519 signature cryptographically verifies",
          verifies_ed25519(ed_pk, ed_sig, expected_auth_input))
    check("A03 controller ML-DSA-65 signature cryptographically verifies",
          verifies_mldsa65(ml_pk, ml_sig, expected_auth_input))
    check("A03 controller Ed25519 proof encoding",
          hx(v["controllerEd25519AuthorizationProofHex"]) == ed_proof)
    check("A03 controller ML-DSA-65 proof encoding",
          hx(v["controllerMlDsa65AuthorizationProofHex"]) == ml_proof)

    check("A03 signed operation omits field 3",
          isinstance(decoded_signed, dict)
          and set(decoded_signed.keys()) == {1, 2})
    check("A03 signed operation canonical encoding",
          hx(v["signedOperationHex"]) == expected_signed)
    check("A03 assertion PoP count is zero",
          v.get("assertionProofOfPossessionCount") == 0)

    check("A03 resulting IdentityState v2 encoding",
          hx(v["resultingIdentityStateHex"]) == expected_state)
    check("A03 resulting state omits field 7",
          isinstance(decoded_state, dict)
          and 7 not in decoded_state)
    check("A03 resulting state does not encode field 7 as nil",
          7 not in decoded_state)
    check("A03 resulting StateHash independently derived",
          hx(v["resultingStateHashHex"]) == expected_hash)
    check("A03 StateHash differs from A02", expected_hash != a02["hash"])

    a01_methods = assertion_method_ids_from_state(a01["state"])
    a02_methods = assertion_method_ids_from_state(a02["state"])
    a03_methods = assertion_method_ids_from_state(expected_state)

    key_b = a01["assertion_id"]
    key_c = a02["assertion_id"]
    check("Historical A01 still authorizes key B", key_b in a01_methods)
    check("Historical A01 does not authorize key C", key_c not in a01_methods)
    check("Historical A02 does not authorize key B", key_b not in a02_methods)
    check("Historical A02 authorizes key C", key_c in a02_methods)
    check("Current A03 does not authorize key B", key_b not in a03_methods)
    check("Current A03 does not authorize key C", key_c not in a03_methods)
    check("Current A03 has zero assertion authority", a03_methods == [])
    check("A03 controller Ed25519 is not assertion-authorized",
          ed_id not in a03_methods)
    check("A03 controller ML-DSA-65 is not assertion-authorized",
          ml_id not in a03_methods)
    check("A03 no fallback from absent AssertionPolicy to ControllerPolicy",
          a03_methods == []
          and ed_id not in a03_methods
          and ml_id not in a03_methods)

    check("A03 generator preservation markers",
          v.get("controllerPolicyPreserved") is True
          and v.get("assertionPolicyPresent") is False
          and v.get("assertionAuthorityCount") == 0)
    check("A03 authorization proof count",
          v.get("authorizationProofCount") == 2)
    check("A03 StateHash length",
          v.get("stateHashLength") == 34 and len(expected_hash) == 34)

    print()
    print("A03 VERIFIED")
    return {
        "identity": identity,
        "state": expected_state,
        "hash": expected_hash,
        "controller_policy": controller_policy,
    }


def verify_a04(document, v, a03):
    identity = hx(v["identityHex"])
    previous_state = hx(v["previousIdentityStateHex"])
    previous_hash = hx(v["previousStateHashHex"])
    controller_policy = hx(v["controllerPolicyHex"])

    ed_id = hx(v["assertionEd25519MethodIdHex"])
    ml_id = hx(v["assertionMlDsa65MethodIdHex"])
    ed_pk = hx(v["assertionEd25519PublicKeyHex"])
    ml_pk = hx(v["assertionMlDsa65PublicKeyHex"])

    expected_ed_cose = ed25519_cose_key(ed_pk)
    expected_ml_cose = mldsa65_cose_key(ml_pk)
    expected_ed_method = verification_method(ed_id, expected_ed_cose)
    expected_ml_method = verification_method(ml_id, expected_ml_cose)

    # Independent canonicalization: feed reversed order, matching the vector's
    # normative input-order test, and require the canonical result.
    expected_policy = threshold_policy(
        2, [(ml_id, expected_ml_method), (ed_id, expected_ed_method)])

    expected_operation = set_assertion_policy_operation(
        identity, 5, previous_hash, expected_policy)
    expected_auth_input = operation_signing_input(expected_operation)
    expected_ed_pop_input = proposed_key_pop_input(expected_operation, ed_id)
    expected_ml_pop_input = proposed_key_pop_input(expected_operation, ml_id)

    controller_keys = controller_keys_from_state(previous_state)
    controller_ed_id, controller_ed_pk = controller_keys["Ed25519"]
    controller_ml_id, controller_ml_pk = controller_keys["ML-DSA-65"]

    controller_ed_sig = hx(v["controllerEd25519AuthorizationSignatureHex"])
    controller_ml_sig = hx(v["controllerMlDsa65AuthorizationSignatureHex"])
    ed_pop_sig = hx(v["assertionEd25519PopSignatureHex"])
    ml_pop_sig = hx(v["assertionMlDsa65PopSignatureHex"])

    expected_controller_ed_proof = proof(controller_ed_id, controller_ed_sig)
    expected_controller_ml_proof = proof(controller_ml_id, controller_ml_sig)
    expected_ed_pop = proof(ed_id, ed_pop_sig)
    expected_ml_pop = proof(ml_id, ml_pop_sig)

    expected_signed = signed_operation(
        expected_operation,
        [(controller_ml_id, expected_controller_ml_proof),
         (controller_ed_id, expected_controller_ed_proof)],
        [(ml_id, expected_ml_pop), (ed_id, expected_ed_pop)])

    expected_state = identity_state_v2(
        identity, 5, controller_policy, expected_policy)
    expected_hash = state_hash(expected_state)

    decoded_policy = decode_one(expected_policy)
    decoded_signed = decode_one(expected_signed)
    decoded_state = decode_one(expected_state)

    print()
    print("A04 Hybrid Threshold Assertion Authority")
    print("-" * 44)

    check("A04 vector ID", v.get("id") == "A04")
    check("A04 source vector", v.get("sourceVector") == "A03")
    check("A04 wire protocol version", document.get("wireProtocolVersion") == 1)
    check("A04 remains IdentityState v2",
          document.get("sourceIdentityStateVersion") == 2
          and document.get("resultingIdentityStateVersion") == 2
          and v.get("previousIdentityStateVersion") == 2
          and v.get("resultingIdentityStateVersion") == 2)
    check("A04 sequence", v.get("sequence") == 5)
    check("A04 identity preserved", identity == a03["identity"])
    check("A04 previous state equals A03 resulting state",
          previous_state == a03["state"])
    check("A04 previous StateHash equals A03 StateHash",
          previous_hash == a03["hash"])
    check("A04 previous StateHash independently recomputed",
          previous_hash == state_hash(previous_state))
    check("A04 ControllerPolicy preserved",
          controller_policy == a03["controller_policy"])

    check("A04 Ed25519 method ID length", len(ed_id) == 16)
    check("A04 ML-DSA-65 method ID length", len(ml_id) == 16)
    check("A04 Ed25519 public key length", len(ed_pk) == 32)
    check("A04 ML-DSA-65 public key length", len(ml_pk) == 1952)
    check("A04 Ed25519 COSE_Key",
          hx(v["assertionEd25519CoseKeyHex"]) == expected_ed_cose)
    check("A04 ML-DSA-65 COSE_Key",
          hx(v["assertionMlDsa65CoseKeyHex"]) == expected_ml_cose)
    check("A04 Ed25519 VerificationMethod",
          hx(v["assertionEd25519VerificationMethodHex"]) == expected_ed_method)
    check("A04 ML-DSA-65 VerificationMethod",
          hx(v["assertionMlDsa65VerificationMethodHex"]) == expected_ml_method)

    check("A04 Threshold 2-of-2 policy",
          v.get("assertionPolicyType") == "THRESHOLD"
          and v.get("assertionThreshold") == 2
          and v.get("assertionMethodCount") == 2
          and decoded_policy.get(1) == 2
          and decoded_policy.get(2) == 2
          and hx(v["assertionPolicyHex"]) == expected_policy)
    policy_methods = decoded_policy.get(3)
    check("A04 canonical assertion method ordering",
          isinstance(policy_methods, list)
          and [m.get(1) for m in policy_methods] == sorted([ed_id, ml_id]))
    check("A04 reversed method input marker",
          v.get("inputMethodOrder") == ["ML-DSA-65", "Ed25519"])
    check("A04 reversed PoP input marker",
          v.get("inputPopOrder") == ["ML-DSA-65", "Ed25519"])

    check("A04 SET_ASSERTION_POLICY OperationBytes",
          hx(v["operationBytesHex"]) == expected_operation)
    check("A04 authorization signing input",
          hx(v["authorizationSigningInputHex"]) == expected_auth_input)
    check("A04 Ed25519 PoP signing input",
          hx(v["assertionEd25519PopSigningInputHex"]) == expected_ed_pop_input)
    check("A04 ML-DSA-65 PoP signing input",
          hx(v["assertionMlDsa65PopSigningInputHex"]) == expected_ml_pop_input)

    check("A04 controller Ed25519 signature length", len(controller_ed_sig) == 64)
    check("A04 controller ML-DSA-65 signature length", len(controller_ml_sig) == 3309)
    check("A04 assertion Ed25519 PoP signature length", len(ed_pop_sig) == 64)
    check("A04 assertion ML-DSA-65 PoP signature length", len(ml_pop_sig) == 3309)

    check("A04 controller Ed25519 signature cryptographically verifies",
          verifies_ed25519(controller_ed_pk, controller_ed_sig, expected_auth_input))
    check("A04 controller ML-DSA-65 signature cryptographically verifies",
          verifies_mldsa65(controller_ml_pk, controller_ml_sig, expected_auth_input))
    check("A04 assertion Ed25519 PoP cryptographically verifies",
          verifies_ed25519(ed_pk, ed_pop_sig, expected_ed_pop_input))
    check("A04 assertion ML-DSA-65 PoP cryptographically verifies",
          verifies_mldsa65(ml_pk, ml_pop_sig, expected_ml_pop_input))

    check("A04 controller Ed25519 proof encoding",
          hx(v["controllerEd25519AuthorizationProofHex"]) == expected_controller_ed_proof)
    check("A04 controller ML-DSA-65 proof encoding",
          hx(v["controllerMlDsa65AuthorizationProofHex"]) == expected_controller_ml_proof)
    check("A04 assertion Ed25519 proof-of-possession encoding",
          hx(v["assertionEd25519ProofOfPossessionHex"]) == expected_ed_pop)
    check("A04 assertion ML-DSA-65 proof-of-possession encoding",
          hx(v["assertionMlDsa65ProofOfPossessionHex"]) == expected_ml_pop)

    check("A04 signed operation canonical encoding",
          hx(v["signedOperationHex"]) == expected_signed)
    check("A04 signed operation has two authorization proofs",
          isinstance(decoded_signed.get(2), list) and len(decoded_signed[2]) == 2)
    check("A04 signed operation has two PoPs",
          isinstance(decoded_signed.get(3), list) and len(decoded_signed[3]) == 2)
    check("A04 canonical authorization proof ordering",
          [p.get(1) for p in decoded_signed[2]]
          == sorted([controller_ed_id, controller_ml_id]))
    check("A04 canonical PoP ordering",
          [p.get(1) for p in decoded_signed[3]] == sorted([ed_id, ml_id]))

    check("A04 resulting IdentityState v2 encoding",
          hx(v["resultingIdentityStateHex"]) == expected_state)
    check("A04 resulting state contains exact AssertionPolicy",
          decoded_state.get(7) == decoded_policy)
    check("A04 resulting StateHash independently derived",
          hx(v["resultingStateHashHex"]) == expected_hash)
    check("A04 StateHash differs from A03", expected_hash != a03["hash"])
    check("A04 resulting StateHash length",
          v.get("stateHashLength") == 34 and len(expected_hash) == 34)

    assertion_ids = assertion_method_ids_from_state(expected_state)
    controller_ids = controller_method_ids_from_state(expected_state)
    check("A04 historical assertion authority contains exactly two methods",
          assertion_ids == sorted([ed_id, ml_id]))
    check("A04 assertion methods remain distinct from ControllerPolicy",
          ed_id not in controller_ids and ml_id not in controller_ids)
    check("A04 authorization proof count", v.get("authorizationProofCount") == 2)
    check("A04 assertion PoP count",
          v.get("assertionProofOfPossessionCount") == 2)
    check("A04 ControllerPolicy preservation marker",
          v.get("controllerPolicyPreserved") is True)

    print()
    print("A04 VERIFIED")
    return {
        "identity": identity,
        "state": expected_state,
        "hash": expected_hash,
        "controller_policy": controller_policy,
        "assertion_ed_id": ed_id,
        "assertion_ml_id": ml_id,
    }


def decode_policy_bytes_from_state(state_bytes: bytes) -> str:
    # Return canonical hex for field 7 without trusting the Java policy field.
    # Re-encode the decoded SINGLE policy used by A01/A02.
    state = decode_one(state_bytes)
    policy = state.get(7)
    if not isinstance(policy, dict) or policy.get(1) != 1:
        fail("expected SINGLE AssertionPolicy in historical state")
    methods = policy.get(2)
    if not isinstance(methods, list) or len(methods) != 1:
        fail("expected exactly one assertion VerificationMethod")
    method = methods[0]
    mid = method.get(1)
    cose = method.get(2)
    if not isinstance(mid, bytes) or not isinstance(cose, dict):
        fail("invalid assertion method")
    pk = cose.get(-2)
    return single_policy(verification_method(mid, ed25519_cose_key(pk))).hex()


def main() -> int:
    if len(sys.argv) == 1:
        a01_path = locate_generated("assertion-a01-java.json")
        a02_path = locate_generated("assertion-a02-java.json")
        a03_path = locate_generated("assertion-a03-java.json")
        a04_path = locate_generated("assertion-a04-java.json")
        invalid_path = locate_generated("assertion-invalid-java.json")
    elif len(sys.argv) == 6:
        a01_path = Path(sys.argv[1])
        a02_path = Path(sys.argv[2])
        a03_path = Path(sys.argv[3])
        a04_path = Path(sys.argv[4])
        invalid_path = Path(sys.argv[5])
    else:
        print(
            f"Usage: {Path(sys.argv[0]).name} "
            "[assertion-a01-java.json assertion-a02-java.json assertion-a03-java.json "
            "assertion-a04-java.json assertion-invalid-java.json]",
            file=sys.stderr)
        return 2

    a01_doc, a01_v = load_vector(a01_path)
    a02_doc, a02_v = load_vector(a02_path)
    a03_doc, a03_v = load_vector(a03_path)
    a04_doc, a04_v = load_vector(a04_path)
    invalid_doc = json.loads(invalid_path.read_text(encoding="utf-8"))

    print("OpenIdentity Assertion Authority")
    print("Independent Verification")
    print("=" * 44)
    print()

    a01 = verify_a01(a01_doc, a01_v)
    a02 = verify_a02(a02_doc, a02_v, a01)
    a03 = verify_a03(a03_doc, a03_v, a01, a02)
    verify_a04(a04_doc, a04_v, a03)
    verify_assertion_invalid_vectors(invalid_doc, a01, a02)

    print()
    print("=" * 44)
    print("OI-003 ASSERTION AUTHORITY A01-A04 + AI01-AI10 VERIFIED")
    print("=" * 44)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AssertionError, KeyError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        print()
        print(f"OI-003 ASSERTION AUTHORITY VERIFICATION FAILED: {exc}",
              file=sys.stderr)
        raise SystemExit(1)
