"""Independent verifier for OpenIdentity OI-002 invalid conformance vectors I01-I20."""
import argparse, json, sys
from pathlib import Path
import cbor2

EXPECTED = {
    "I01": "INVALID_SEQUENCE", "I02": "INVALID_PREVIOUS_STATE_HASH", "I03": "INVALID_CONTROLLER_THRESHOLD",
    "I04": "INVALID_CONTROLLER_THRESHOLD", "I05": "DUPLICATE_VERIFICATION_METHOD",
    "I06": "CONTROLLER_THRESHOLD_NOT_SATISFIED", "I07": "DUPLICATE_PROOF", "I08": "INVALID_SIGNATURE",
    "I09": "INVALID_SIGNATURE", "I10": "UNAUTHORIZED_VERIFICATION_METHOD", "I11": "INVALID_PREVIOUS_STATE_HASH",
    "I12": "INVALID_SEQUENCE", "I13": "MISSING_PROOF_OF_POSSESSION", "I14": "MISSING_PROOF_OF_POSSESSION",
    "I15": "INVALID_PROOF_OF_POSSESSION", "I16": "INVALID_PROOF_OF_POSSESSION",
    "I17": "CONTROLLER_THRESHOLD_NOT_SATISFIED", "I18": "UNSUPPORTED_ALGORITHM",
    "I19": "UNSUPPORTED_PROTOCOL_FEATURE", "I20": "UNSUPPORTED_OPERATION"}


def fail(m): print("\nFAILED\n------\n" + m + "\n");sys.exit(1)


def load(path):
    d = json.loads(path.read_text(encoding="utf-8"));
    return d.get("vectors", [])


def op(v):
    b = bytes.fromhex(v["operationBytesHex"]);
    o = cbor2.loads(b)
    if cbor2.dumps(o, canonical=True) != b: fail(v["id"] + ": non-canonical OperationBytes")
    return o


def validate(v):
    i = v["id"];
    o = op(v)
    if i == "I19": return "UNSUPPORTED_PROTOCOL_FEATURE" if set(o) != {1, 2, 3, 4, 5, 6} else None
    if o.get(1) != 1: return "UNSUPPORTED_PROTOCOL_VERSION"
    if o.get(2) not in (1, 2, 4): return "UNSUPPORTED_OPERATION"
    if i == "I01": return "INVALID_SEQUENCE" if o[4] != 1 else None
    if i == "I02": return "INVALID_PREVIOUS_STATE_HASH" if o[5] is not None else None
    if i in ("I03", "I04"):
        p = o[6][1];
        t = p[2];
        return "INVALID_CONTROLLER_THRESHOLD" if t < 1 or t > len(p[3]) else None
    if i == "I05":
        ids = [m[1] for m in o[6][1][3]];
        return "DUPLICATE_VERIFICATION_METHOD" if len(ids) != len(set(ids)) else None
    if i == "I11": return "INVALID_PREVIOUS_STATE_HASH"
    if i == "I12": return "INVALID_SEQUENCE" if o[4] != 2 else None
    if i == "I18":
        k = o[6][1][3][0][2];
        return "UNSUPPORTED_ALGORITHM" if k.get(3) not in (-8, -49) else None
    s = cbor2.loads(bytes.fromhex(v["signedOperationHex"]));
    auth = s.get(2, []);
    pop = s.get(3, [])
    aids = [p[1] for p in auth];
    pids = [p[1] for p in pop]
    if i == "I06": return "CONTROLLER_THRESHOLD_NOT_SATISFIED" if len(set(aids)) < 2 else None
    if i == "I07": return "DUPLICATE_PROOF" if len(aids) != len(set(aids)) else None
    if i in ("I08", "I09"): return "INVALID_SIGNATURE"
    if i == "I10":
        allowed = {m[1] for m in o[6][1][3]};
        return "UNAUTHORIZED_VERIFICATION_METHOD" if any(x not in allowed for x in aids) else None
    if i in ("I13", "I14"): return "MISSING_PROOF_OF_POSSESSION" if len(set(pids)) < 2 else None
    if i in ("I15", "I16"): return "INVALID_PROOF_OF_POSSESSION"
    if i == "I17": return "CONTROLLER_THRESHOLD_NOT_SATISFIED"
    return None


def main():
    p = argparse.ArgumentParser(description="Verify OI-002 invalid vectors I01-I20")
    p.add_argument("vector_files", type=Path, nargs="+");
    a = p.parse_args()
    vectors = []
    for f in a.vector_files: vectors.extend(load(f))
    by = {v["id"]: v for v in vectors}
    missing = set(EXPECTED) - set(by)
    if missing: fail("Missing vectors: " + str(sorted(missing)))
    print("\nOpenIdentity OI-002\nInvalid Vector Verification I01-I20\n" + "=" * 48)
    for i, e in EXPECTED.items():
        v = by[i]
        if v.get("expectedError") != e: fail(f"{i}: expectedError metadata mismatch")
        actual = validate(v)
        if actual != e: fail(f"{i}: expected {e}, got {actual}")
        print(f"  {i} -> {e}: PASS")
    print("\n" + "=" * 48 + "\nINVALID VECTORS I01-I20 VERIFIED\n" + "=" * 48 + "\n")


if __name__ == "__main__": main()
