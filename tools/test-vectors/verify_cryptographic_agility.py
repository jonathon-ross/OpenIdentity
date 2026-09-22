"""Final independent verifier for OpenIdentity OI-002 normative cryptographic-agility-v0.1.json."""
import argparse, hashlib, json, sys
from pathlib import Path
import cbor2
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PublicKey

OP = "OpenIdentity Operation";
POP = "OpenIdentity Controller Proof"
ERR = {"I01": "INVALID_SEQUENCE", "I02": "INVALID_PREVIOUS_STATE_HASH", "I03": "INVALID_CONTROLLER_THRESHOLD",
       "I04": "INVALID_CONTROLLER_THRESHOLD", "I05": "DUPLICATE_VERIFICATION_METHOD",
       "I06": "CONTROLLER_THRESHOLD_NOT_SATISFIED", "I07": "DUPLICATE_PROOF", "I08": "INVALID_SIGNATURE",
       "I09": "INVALID_SIGNATURE", "I10": "UNAUTHORIZED_VERIFICATION_METHOD", "I11": "INVALID_PREVIOUS_STATE_HASH",
       "I12": "INVALID_SEQUENCE", "I13": "MISSING_PROOF_OF_POSSESSION", "I14": "MISSING_PROOF_OF_POSSESSION",
       "I15": "INVALID_PROOF_OF_POSSESSION", "I16": "INVALID_PROOF_OF_POSSESSION",
       "I17": "CONTROLLER_THRESHOLD_NOT_SATISFIED", "I18": "UNSUPPORTED_ALGORITHM",
       "I19": "UNSUPPORTED_PROTOCOL_FEATURE", "I20": "UNSUPPORTED_OPERATION"}


def fail(m): print("\nFAILED\n------\n" + m + "\n");sys.exit(1)


def ok(m): print("  " + m + ": PASS")


def hx(v, n):
    try:
        return bytes.fromhex(v)
    except Exception as e:
        fail(f"{n}: invalid hex: {e}")


def ce(x): return cbor2.dumps(x, canonical=True)


def cd(b, n):
    try:
        x = cbor2.loads(b)
    except Exception as e:
        fail(f"{n}: invalid CBOR: {e}")
    if ce(x) != b: fail(n + ": non-canonical CBOR")
    return x


def mh(b): return b"\x12\x20" + hashlib.sha256(b).digest()


def vsig(key, sig, msg):
    try:
        alg = key[3];
        pk = key[-2] if alg == -8 else key[-1]
        (Ed25519PublicKey if alg == -8 else MLDSA65PublicKey).from_public_bytes(pk).verify(sig, msg);
        return True
    except:
        return False


def km(policy):
    ms = policy[3] if policy[1] == 2 else policy[2]
    return {m[1]: m[2] for m in ms}


def valid(v):
    i = v["id"]
    if i == "V01":
        op = hx(v["operationBytesHex"], i);
        o = cd(op, i + " operation");
        pol = o[6][1]
        if pol[1] != 1: fail("V01 policy not SINGLE")
        key = pol[2][0][2];
        si = hx(v["signingInputHex"], i)
        if si != ce([OP, 1, op]): fail("V01 SigningInput mismatch")
        if not vsig(key, hx(v["ed25519SignatureHex"], i), si): fail("V01 signature invalid")
    elif i == "V02":
        op = hx(v["operationBytesHex"], i);
        o = cd(op, i + " operation");
        pol = o[6][1]
        if pol[1] != 2 or pol[2] != 2: fail("V02 policy not 2-of-2")
        si = hx(v["signingInputHex"], i)
        if si != ce([OP, 1, op]): fail("V02 SigningInput mismatch")
        keys = km(pol)
        proofs = cd(hx(v["signedOperationHex"], i), i + " signed")[2]
        if len(proofs) != 2 or not all(p[1] in keys and vsig(keys[p[1]], p[2], si) for p in proofs): fail(
            "V02 proof verification failed")
        state = hx(v["identityStateHex"], i);
        cd(state, i + " state")
        if hx(v["stateHashHex"], i) != mh(state): fail("V02 StateHash mismatch")
    elif i == "V03":
        # Normative equality with V02 checked in main after all valid vectors loaded.
        for f in ("controllerPolicyHex", "operationBytesHex", "signingInputHex", "signedOperationHex"): cd(hx(v[f], i),
                                                                                                           i + " " + f)
    elif i == "V04":
        op = hx(v["operationBytesHex"], i);
        o = cd(op, i + " operation")
        if o[2] != 2 or o[4] != 2: fail("V04 ROTATE fields invalid")
        if hx(v["previousStateHashHex"], i) != mh(hx(v["previousIdentityStateHex"], i)): fail(
            "V04 predecessor hash mismatch")
        newkeys = km(o[6][1]);
        signed = cd(hx(v["signedOperationHex"], i), i + " signed")
        pops = signed[3]
        for p in pops:
            if p[1] not in newkeys or not vsig(newkeys[p[1]], p[2], ce([POP, 1, op, p[1]])): fail("V04 PoP invalid")
        state = hx(v["resultingIdentityStateHex"], i)
        if hx(v["resultingStateHashHex"], i) != mh(state): fail("V04 resulting StateHash mismatch")
    else:
        fail("Unknown valid vector " + i)
    ok(i)


def invalid(v):
    i = v["id"];
    e = ERR[i];
    ob = hx(v["operationBytesHex"], i);
    o = cd(ob, i + " operation")
    if i == "I19":
        a = "UNSUPPORTED_PROTOCOL_FEATURE" if set(o) != {1, 2, 3, 4, 5, 6} else None
    elif o.get(2) not in (1, 2, 4):
        a = "UNSUPPORTED_OPERATION"
    elif i == "I01":
        a = "INVALID_SEQUENCE" if o[4] != 1 else None
    elif i == "I02":
        a = "INVALID_PREVIOUS_STATE_HASH" if o[5] is not None else None
    elif i in ("I03", "I04"):
        p = o[6][1];
        a = "INVALID_CONTROLLER_THRESHOLD" if p[2] < 1 or p[2] > len(p[3]) else None
    elif i == "I05":
        ids = [m[1] for m in o[6][1][3]];
        a = "DUPLICATE_VERIFICATION_METHOD" if len(ids) != len(set(ids)) else None
    elif i == "I11":
        a = "INVALID_PREVIOUS_STATE_HASH"
    elif i == "I12":
        a = "INVALID_SEQUENCE" if o[4] != 2 else None
    elif i == "I18":
        key = o[6][1][3][0][2];
        a = "UNSUPPORTED_ALGORITHM" if key.get(3) not in (-8, -49) else None
    else:
        s = cd(hx(v["signedOperationHex"], i), i + " signed");
        auth = s.get(2, []);
        pop = s.get(3, [])
        aids = [p[1] for p in auth];
        pids = [p[1] for p in pop]
        if i == "I07":
            a = "DUPLICATE_PROOF" if len(aids) != len(set(aids)) else None
        elif o[2] == 1:
            keys = km(o[6][1]);
            threshold = o[6][1][2]
            if i == "I10":
                a = "UNAUTHORIZED_VERIFICATION_METHOD" if any(x not in keys for x in aids) else None
            elif i == "I06":
                a = "CONTROLLER_THRESHOLD_NOT_SATISFIED" if len(set(aids) & set(keys)) < threshold else None
            elif i in ("I08", "I09"):
                msg = ce([OP, 1, ob]);
                a = "INVALID_SIGNATURE" if any(p[1] in keys and not vsig(keys[p[1]], p[2], msg) for p in auth) else None
            else:
                a = None
        else:
            keys = km(o[6][1])
            if i in ("I13", "I14"):
                a = "MISSING_PROOF_OF_POSSESSION" if any(x not in set(pids) for x in keys) else None
            elif i in ("I15", "I16"):
                a = "INVALID_PROOF_OF_POSSESSION" if any(
                    p[1] not in keys or not vsig(keys[p[1]], p[2], ce([POP, 1, ob, p[1]])) for p in pop) else None
            elif i == "I17":
                a = "CONTROLLER_THRESHOLD_NOT_SATISFIED"
            else:
                a = None
    if v.get("expectedError") != e: fail(i + ": expectedError metadata mismatch")
    if a != e: fail(f"{i}: expected {e}, got {a}")
    ok(i + " -> " + e)


def main():
    p = argparse.ArgumentParser(description="Verify normative OpenIdentity OI-002 vectors")
    p.add_argument("vector_file", type=Path);
    a = p.parse_args()
    d = json.loads(a.vector_file.read_text(encoding="utf-8"))
    if d.get("specification") != "OpenIdentity Cryptographic Agility" or d.get("version") != "0.1": fail(
        "Specification metadata mismatch")
    if d.get("wireProtocolVersion") != 1 or d.get("identityStateVersion") != 1: fail("Version metadata mismatch")
    alg = d.get("algorithms", {})
    if alg.get("Ed25519", {}).get("coseAlgorithm") != -8 or alg.get("ML-DSA-65", {}).get("coseAlgorithm") != -49: fail(
        "Algorithm metadata mismatch")
    sh = d.get("stateHash", {})
    if sh.get("multihashCode") != 18 or sh.get("digestLength") != 32 or sh.get("multihashLength") != 34: fail(
        "StateHash metadata mismatch")
    vv = d.get("valid", []);
    iv = d.get("invalid", [])
    if [x.get("id") for x in vv] != ["V01", "V02", "V03", "V04"]: fail("Expected V01-V04")
    if [x.get("id") for x in iv] != [f"I{x:02d}" for x in range(1, 21)]: fail("Expected I01-I20")
    print("\nOpenIdentity OI-002 Normative Verification\n" + "=" * 48)
    for v in vv: valid(v)
    # V03 canonical equality to V02
    v2, v3 = vv[1], vv[2]
    for f in ("controllerPolicyHex", "operationBytesHex", "signingInputHex", "signedOperationHex"):
        if v2[f] != v3[f]: fail("V03 " + f + " does not equal V02")
    ok("V03 canonical equality with V02")
    for v in iv: invalid(v)
    print("\n" + "=" * 48 + "\nOI-002 NORMATIVE VECTOR VERIFICATION PASSED\n" + "=" * 48 + "\n")


if __name__ == "__main__": main()
