#!/usr/bin/env python3
import hashlib, json, sys
from pathlib import Path
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
try:
    from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PublicKey
except ImportError as exc:
    raise SystemExit(
        "This verifier requires cryptography >= 47.0.0 for ML-DSA-65. "
        "Install/upgrade with: python -m pip install 'cryptography>=47.0.0'"
    ) from exc


def fail(m): raise AssertionError(m)


def check(n, ok):
    if not ok: fail(n)
    print(f"  {n}: PASS")


def hx(s): return bytes.fromhex(s)


# Minimal independent deterministic CBOR encoder/decoder for C01.
def head(major, n):
    if n < 24: return bytes([(major << 5) | n])
    if n <= 0xff: return bytes([(major << 5) | 24, n])
    if n <= 0xffff: return bytes([(major << 5) | 25]) + n.to_bytes(2, "big")
    if n <= 0xffffffff: return bytes([(major << 5) | 26]) + n.to_bytes(4, "big")
    return bytes([(major << 5) | 27]) + n.to_bytes(8, "big")


def uint(n): return head(0, n)


def nint(n): return head(1, -1 - n)


def integer(n): return uint(n) if n >= 0 else nint(n)


def bstr(b): return head(2, len(b)) + b


def tstr(s):
    b = s.encode("utf-8");
    return head(3, len(b)) + b


def arr(xs): return head(4, len(xs)) + b"".join(xs)


def cmap(items):
    enc = [(integer(k), v) for k, v in items]
    enc.sort(key=lambda kv: (len(kv[0]), kv[0]))
    return head(5, len(enc)) + b"".join(k + v for k, v in enc)


def claim(v):
    if v is None: return b"\xf6"
    if v is True: return b"\xf5"
    if v is False: return b"\xf4"
    if isinstance(v, int): return integer(v)
    if isinstance(v, str): return tstr(v)
    if isinstance(v, (bytes, bytearray)): return bstr(bytes(v))
    if isinstance(v, list): return arr([claim(x) for x in v])
    if isinstance(v, dict):
        pairs = []
        for k, val in v.items():
            if not isinstance(k, str): fail("claim key not text")
            ek = tstr(k);
            pairs.append((ek, claim(val)))
        pairs.sort(key=lambda kv: (len(kv[0]), kv[0]))
        return head(5, len(pairs)) + b"".join(k + v for k, v in pairs)
    fail("unsupported claim type")


def read(data, i=0):
    ib = data[i];
    i += 1;
    major = ib >> 5;
    ai = ib & 31

    def arg(ai, i):
        if ai < 24: return ai, i
        nbytes = {24: 1, 25: 2, 26: 4, 27: 8}.get(ai)
        if not nbytes: fail("unsupported CBOR additional info")
        return int.from_bytes(data[i:i + nbytes], "big"), i + nbytes

    if major in (0, 1):
        n, i = arg(ai, i);
        return (n if major == 0 else -1 - n), i
    if major in (2, 3):
        n, i = arg(ai, i);
        raw = data[i:i + n];
        i += n
        return (raw if major == 2 else raw.decode()), i
    if major == 4:
        n, i = arg(ai, i);
        out = []
        for _ in range(n):
            v, i = read(data, i);
            out.append(v)
        return out, i
    if major == 5:
        n, i = arg(ai, i);
        out = {}
        for _ in range(n):
            k, i = read(data, i);
            v, i = read(data, i);
            out[k] = v
        return out, i
    if major == 7 and ai in (20, 21, 22):
        return ({20: False, 21: True, 22: None}[ai]), i
    fail("unsupported CBOR")


def decode_one(b):
    v, i = read(b, 0)
    if i != len(b): fail("trailing CBOR")
    return v


def state_hash(state): return b"\x12\x20" + hashlib.sha256(state).digest()


def verify_c01_path(p: Path):
    d = json.loads(p.read_text())
    v = d["vector"]
    print("OpenIdentity Credential C01")
    print("Independent Verification")
    print("=" * 44)
    check("C01 vector ID", v["id"] == "C01")
    check("C01 source assertion vector", v["sourceAssertionVector"] == "A01")
    check("C01 credential wire version", d["credentialWireVersion"] == 1)

    state = hx(v["historicalIdentityStateHex"])
    sh = state_hash(state)
    check("C01 historical StateHash independently recomputed", sh == hx(v["issuanceStateHashHex"]))
    st = decode_one(state)
    check("C01 historical state version is v2", st[1] == 2)
    check("C01 issuer identity equals historical identity", hx(v["issuerIdentityHex"]) == st[2])

    pol = st[7]
    check("C01 historical AssertionPolicy is SINGLE", pol[1] == 1 and len(pol[2]) == 1)
    method = pol[2][0]
    mid = method[1]
    cose = method[2]
    check("C01 proof method equals historical SINGLE method", mid == hx(v["assertionMethodIdHex"]))
    check("C01 historical assertion key is Ed25519", (cose[1], cose[3], cose[-1]) == (1, -8, 6))
    pk = cose[-2]
    check("C01 historical Ed25519 public key length", len(pk) == 32)

    claims = {"role": "member", "name": "Alice Example", "active": True}
    cred = cmap([
        (1, uint(1)), (2, bstr(hx(v["credentialIdHex"]))),
        (3, bstr(hx(v["issuerIdentityHex"]))), (4, bstr(sh)),
        (5, uint(v["validFrom"])), (6, uint(v["validUntil"])),
        (7, tstr(v["credentialProfile"])), (8, bstr(hx(v["credentialSubjectHex"]))),
        (9, claim(claims))
    ])
    check("C01 CredentialBytes independently reconstructed", cred == hx(v["credentialBytesHex"]))
    decoded = decode_one(cred)
    check("C01 credential version", decoded[1] == 1)
    check("C01 credential profile signed in payload", decoded[7] == v["credentialProfile"])
    check("C01 claims canonical content", decoded[9] == claims)

    signing = arr([tstr("OpenIdentity Credential"), uint(1), bstr(cred)])
    check("C01 signing input independently reconstructed", signing == hx(v["credentialSigningInputHex"]))
    sig = hx(v["credentialSignatureHex"])
    try:
        Ed25519PublicKey.from_public_bytes(pk).verify(sig, signing);
        ok = True
    except Exception:
        ok = False
    check("C01 Ed25519 signature cryptographically verifies", ok)

    proof = cmap([(1, bstr(mid)), (2, bstr(sig))])
    check("C01 credential proof encoding", proof == hx(v["credentialProofHex"]))
    secured = cmap([(1, cred), (2, arr([proof]))])
    check("C01 SecuredCredential independently reconstructed", secured == hx(v["securedCredentialHex"]))
    check("C01 SINGLE policy satisfied by exactly one proof", v["proofCount"] == 1 and mid == method[1])
    print("\nC01 VERIFIED")


def verifies_mldsa65(public_key: bytes, signature: bytes, message: bytes) -> bool:
    try:
        MLDSA65PublicKey.from_public_bytes(public_key).verify(signature, message)
        return True
    except InvalidSignature:
        return False
    except UnsupportedAlgorithm as exc:
        raise RuntimeError(
            "Installed cryptography backend does not support ML-DSA-65."
        ) from exc


def assertion_methods_threshold(state):
    pol = state.get(7)
    if not isinstance(pol, dict) or pol.get(1) != 2:
        fail("historical AssertionPolicy is not THRESHOLD")
    threshold = pol.get(2)
    methods = pol.get(3)
    if not isinstance(threshold, int) or not isinstance(methods, list):
        fail("invalid historical THRESHOLD AssertionPolicy")
    return threshold, methods


def verify_c02_path(p: Path):
    d = json.loads(p.read_text())
    v = d["vector"]

    print()
    print("C02 Hybrid Threshold Credential")
    print("-" * 44)

    check("C02 vector ID", v["id"] == "C02")
    check("C02 source assertion vector", v["sourceAssertionVector"] == "A04")
    check("C02 credential wire version", d["credentialWireVersion"] == 1)

    state = hx(v["historicalIdentityStateHex"])
    sh = state_hash(state)
    check("C02 historical StateHash independently recomputed",
          sh == hx(v["issuanceStateHashHex"]))

    st = decode_one(state)
    check("C02 historical state version is v2", st[1] == 2)
    check("C02 issuer identity equals historical identity",
          hx(v["issuerIdentityHex"]) == st[2])

    threshold, methods = assertion_methods_threshold(st)
    check("C02 historical AssertionPolicy is THRESHOLD 2-of-2",
          threshold == 2 and len(methods) == 2)

    by_alg = {}
    for method in methods:
        mid = method[1]
        cose = method[2]
        if (cose.get(1), cose.get(3), cose.get(-1)) == (1, -8, 6):
            pk = cose.get(-2)
            check("C02 historical Ed25519 public key length",
                  isinstance(pk, bytes) and len(pk) == 32)
            by_alg["Ed25519"] = (mid, pk)
        elif (cose.get(1), cose.get(3)) == (7, -49):
            pk = cose.get(-1)
            check("C02 historical ML-DSA-65 public key length",
                  isinstance(pk, bytes) and len(pk) == 1952)
            by_alg["ML-DSA-65"] = (mid, pk)

    check("C02 historical policy contains Ed25519 + ML-DSA-65",
          set(by_alg) == {"Ed25519", "ML-DSA-65"})

    ed_mid, ed_pk = by_alg["Ed25519"]
    ml_mid, ml_pk = by_alg["ML-DSA-65"]
    check("C02 Ed25519 proof method is historically authorized",
          ed_mid == hx(v["ed25519MethodIdHex"]))
    check("C02 ML-DSA-65 proof method is historically authorized",
          ml_mid == hx(v["mlDsa65MethodIdHex"]))
    check("C02 proof methods are distinct", ed_mid != ml_mid)

    claims = {"role": "hybrid-member", "name": "Alice Example", "active": True}
    cred = cmap([
        (1, uint(1)),
        (2, bstr(hx(v["credentialIdHex"]))),
        (3, bstr(hx(v["issuerIdentityHex"]))),
        (4, bstr(sh)),
        (5, uint(v["validFrom"])),
        (6, uint(v["validUntil"])),
        (7, tstr(v["credentialProfile"])),
        (8, bstr(hx(v["credentialSubjectHex"]))),
        (9, claim(claims)),
    ])
    check("C02 CredentialBytes independently reconstructed",
          cred == hx(v["credentialBytesHex"]))
    decoded = decode_one(cred)
    check("C02 credential version", decoded[1] == 1)
    check("C02 credential profile signed in payload",
          decoded[7] == v["credentialProfile"])
    check("C02 claims canonical content", decoded[9] == claims)

    signing = arr([tstr("OpenIdentity Credential"), uint(1), bstr(cred)])
    check("C02 signing input independently reconstructed",
          signing == hx(v["credentialSigningInputHex"]))

    ed_sig = hx(v["ed25519SignatureHex"])
    ml_sig = hx(v["mlDsa65SignatureHex"])
    check("C02 Ed25519 signature length", len(ed_sig) == 64)
    check("C02 ML-DSA-65 signature length", len(ml_sig) == 3309)

    try:
        Ed25519PublicKey.from_public_bytes(ed_pk).verify(ed_sig, signing)
        ed_ok = True
    except InvalidSignature:
        ed_ok = False
    check("C02 Ed25519 signature cryptographically verifies", ed_ok)
    check("C02 ML-DSA-65 signature cryptographically verifies",
          verifies_mldsa65(ml_pk, ml_sig, signing))

    ed_proof = cmap([(1, bstr(ed_mid)), (2, bstr(ed_sig))])
    ml_proof = cmap([(1, bstr(ml_mid)), (2, bstr(ml_sig))])
    check("C02 Ed25519 proof encoding", ed_proof == hx(v["ed25519ProofHex"]))
    check("C02 ML-DSA-65 proof encoding", ml_proof == hx(v["mlDsa65ProofHex"]))

    ordered = sorted([(ed_mid, ed_proof), (ml_mid, ml_proof)], key=lambda x: x[0])
    secured = cmap([(1, cred), (2, arr([p for _, p in ordered]))])
    check("C02 generator reversed proof input marker",
          v["inputProofOrder"] == ["ML-DSA-65", "Ed25519"])
    check("C02 canonical proof order marker",
          v["canonicalProofOrder"] == ["Ed25519", "ML-DSA-65"])
    check("C02 canonical proof ordering",
          [mid for mid, _ in ordered] == sorted([ed_mid, ml_mid]))
    check("C02 SecuredCredential independently reconstructed",
          secured == hx(v["securedCredentialHex"]))

    secured_decoded = decode_one(secured)
    proof_ids = [p[1] for p in secured_decoded[2]]
    authorized_ids = {m[1] for m in methods}
    check("C02 secured proof methods are distinct",
          len(proof_ids) == len(set(proof_ids)) == 2)
    check("C02 both proof methods authorized by historical A04",
          set(proof_ids).issubset(authorized_ids)
          and set(proof_ids) == {ed_mid, ml_mid})
    check("C02 THRESHOLD 2-of-2 satisfied",
          len(set(proof_ids)) >= threshold
          and v["proofCount"] == 2
          and v["assertionThreshold"] == 2
          and v["assertionMethodCount"] == 2)

    print()
    print("C02 VERIFIED")


def policy_info(state_bytes):
    st = decode_one(state_bytes)
    pol = st.get(7)
    if pol is None:
        return None, 0, {}
    ptype = pol.get(1)
    if ptype == 1:
        methods = pol.get(2, [])
        threshold = 1
    elif ptype == 2:
        threshold = pol.get(2)
        methods = pol.get(3, [])
    else:
        fail("unsupported AssertionPolicy type")
    return ptype, threshold, {m[1]: m[2] for m in methods}


def proof_list(secured_hex):
    sc = decode_one(hx(secured_hex))
    return sc[1], sc[2]


def verify_signature_for_cose(cose, sig, signing):
    if (cose.get(1), cose.get(3), cose.get(-1)) == (1, -8, 6):
        try:
            Ed25519PublicKey.from_public_bytes(cose[-2]).verify(sig, signing)
            return True
        except InvalidSignature:
            return False
    if (cose.get(1), cose.get(3)) == (7, -49):
        return verifies_mldsa65(cose[-1], sig, signing)
    fail("unsupported assertion key algorithm")


def verify_invalid_suite(path: Path):
    d=json.loads(path.read_text())
    vs=d["vectors"]
    print()
    print("CI01-CI10 Invalid/Security Verification")
    print("-"*44)
    check("Invalid suite specification", d.get("specification")=="OpenIdentity Credential")
    check("Invalid suite version", d.get("version")=="0.1")
    check("Invalid suite type", d.get("type")=="invalid-conformance-vectors")
    check("Invalid suite credential wire version", d.get("credentialWireVersion")==1)
    check("Invalid suite contains exactly 10 vectors", len(vs)==10)
    check("Invalid suite IDs CI01-CI10",
          [v["id"] for v in vs]==[f"CI{i:02d}" for i in range(1,11)])

    expected = {
        "CI01":"ASSERTION_THRESHOLD_NOT_SATISFIED",
        "CI02":"DUPLICATE_CREDENTIAL_PROOF",
        "CI03":"UNAUTHORIZED_CREDENTIAL_PROOF",
        "CI04":"INVALID_CREDENTIAL_SIGNATURE",
        "CI05":"INVALID_CREDENTIAL_SIGNATURE",
        "CI06":"INVALID_ISSUANCE_STATE_HASH",
        "CI07":"INVALID_CREDENTIAL_SIGNATURE",
        "CI08":"UNAUTHORIZED_CREDENTIAL_PROOF",
        "CI09":"INVALID_CREDENTIAL_SIGNATURE",
        "CI10":"NO_ASSERTION_AUTHORITY",
    }
    for v in vs: check(f'{v["id"]} expected error label',v["expectedError"]==expected[v["id"]])

    by={v["id"]:v for v in vs}

    # CI01
    v=by["CI01"]; state=hx(v["historicalIdentityStateHex"])
    _,threshold,methods=policy_info(state); secured_cred,proofs=proof_list(v["securedCredentialHex"])
    cred=hx(v["credentialBytesHex"])
    check("CI01 secured credential payload matches CredentialBytes",
          secured_cred == decode_one(cred))
    signing=arr([tstr("OpenIdentity Credential"),uint(1),bstr(cred)])
    valid=[p[1] for p in proofs if p[1] in methods and verify_signature_for_cose(methods[p[1]],p[2],signing)]
    check("CI01 historical StateHash is authoritative",state_hash(state)==hx(v["issuanceStateHashHex"]))
    check("CI01 historical threshold is 2",threshold==2)
    check("CI01 contains exactly one proof",len(proofs)==1)
    check("CI01 supplied proof cryptographically verifies",len(valid)==1)
    check("CI01 one valid distinct proof is below threshold",len(set(valid))<threshold)
    print("  CI01 REJECTED: ASSERTION_THRESHOLD_NOT_SATISFIED")

    # CI02
    v=by["CI02"]; state=hx(v["historicalIdentityStateHex"]); _,threshold,methods=policy_info(state)
    cred,proofs=proof_list(v["securedCredentialHex"]); ids=[p[1] for p in proofs]
    check("CI02 historical StateHash is authoritative",state_hash(state)==hx(v["issuanceStateHashHex"]))
    check("CI02 contains two proofs",len(proofs)==2)
    check("CI02 contains duplicate proof method IDs",len(ids)!=len(set(ids)))
    check("CI02 duplicate is the declared method",ids[0]==ids[1]==hx(v["duplicateMethodIdHex"]))
    print("  CI02 REJECTED: DUPLICATE_CREDENTIAL_PROOF")

    # CI03
    v=by["CI03"]; state=hx(v["historicalIdentityStateHex"]); _,_,methods=policy_info(state)
    cred,proofs=proof_list(v["securedCredentialHex"]); ids=[p[1] for p in proofs]
    unauth=hx(v["unauthorizedMethodIdHex"])
    check("CI03 historical StateHash is authoritative",state_hash(state)==hx(v["issuanceStateHashHex"]))
    check("CI03 contains three proofs",len(proofs)==3)
    check("CI03 unauthorized method absent from historical policy",unauth not in methods)
    check("CI03 secured proof set contains unauthorized method",unauth in ids)
    print("  CI03 REJECTED: UNAUTHORIZED_CREDENTIAL_PROOF")

    # CI04 / CI05
    for cid, alg in [("CI04","Ed25519"),("CI05","ML-DSA-65")]:
        v=by[cid]; state=hx(v["historicalIdentityStateHex"]); _,_,methods=policy_info(state)
        secured_cred,proofs=proof_list(v["securedCredentialHex"])
        cred=hx(v["credentialBytesHex"])
        check(f"{cid} secured credential payload matches CredentialBytes",
              secured_cred == decode_one(cred))
        signing=arr([tstr("OpenIdentity Credential"),uint(1),bstr(cred)])
        invalid=[]
        for p in proofs:
            if p[1] in methods and not verify_signature_for_cose(methods[p[1]],p[2],signing):
                invalid.append(p)
        check(f"{cid} historical StateHash is authoritative",state_hash(state)==hx(v["issuanceStateHashHex"]))
        check(f"{cid} contains exactly one invalid authorized signature",len(invalid)==1)
        check(f"{cid} corrupted {alg} signature is rejected",invalid[0][2]==hx(v["invalidSignatureHex"]))
        print(f"  {cid} REJECTED: INVALID_CREDENTIAL_SIGNATURE")

    # CI06
    v=by["CI06"]; state=hx(v["historicalIdentityStateHex"]); cred=decode_one(hx(v["credentialBytesHex"]))
    authoritative=state_hash(state)
    check("CI06 authoritative StateHash independently recomputed",authoritative==hx(v["authoritativeStateHashHex"]))
    check("CI06 credential embeds declared mutated StateHash",cred[4]==hx(v["credentialIssuanceStateHashHex"]))
    check("CI06 credential StateHash differs from authoritative state",cred[4]!=authoritative)
    print("  CI06 REJECTED: INVALID_ISSUANCE_STATE_HASH")

    # CI07
    v=by["CI07"]; state=hx(v["historicalIdentityStateHex"]); _,_,methods=policy_info(state)
    secured_cred,proofs=proof_list(v["securedCredentialHex"])
    cred=hx(v["credentialBytesHex"])
    check("CI07 secured credential payload matches CredentialBytes",
          secured_cred == decode_one(cred))
    required=arr([tstr("OpenIdentity Credential"),uint(1),bstr(cred)])
    wrong=hx(v["wrongSigningInputHex"])
    check("CI07 required signing input independently reconstructed",required==hx(v["requiredSigningInputHex"]))
    check("CI07 wrong signing domain differs from required domain",wrong!=required)
    wrong_ok=all(verify_signature_for_cose(methods[p[1]],p[2],wrong) for p in proofs)
    required_ok=all(verify_signature_for_cose(methods[p[1]],p[2],required) for p in proofs)
    check("CI07 signatures verify over wrong domain",wrong_ok)
    check("CI07 signatures fail required credential domain",not required_ok)
    print("  CI07 REJECTED: INVALID_CREDENTIAL_SIGNATURE")

    # CI08
    v=by["CI08"]; state=hx(v["historicalIdentityStateHex"]); _,_,methods=policy_info(state)
    _,proofs=proof_list(v["securedCredentialHex"]); ids=[p[1] for p in proofs]
    rebound=hx(v["reboundUnauthorizedMethodIdHex"])
    check("CI08 original method is historically authorized",hx(v["originalAuthorizedMethodIdHex"]) in methods)
    check("CI08 rebound method is not historically authorized",rebound not in methods)
    check("CI08 secured proof claims rebound unauthorized method",rebound in ids)
    print("  CI08 REJECTED: UNAUTHORIZED_CREDENTIAL_PROOF")

    # CI09
    v=by["CI09"]; state=hx(v["historicalIdentityStateHex"]); _,_,methods=policy_info(state)
    secured_modified,proofs=proof_list(v["securedCredentialHex"])
    modified=hx(v["credentialBytesHex"])
    check("CI09 secured credential payload matches modified CredentialBytes",
          secured_modified == decode_one(modified))
    original=hx(v["originalCredentialBytesHex"]); sig=hx(v["originalSignatureHex"])
    mid=proofs[0][1]; cose=methods[mid]
    original_signing=arr([tstr("OpenIdentity Credential"),uint(1),bstr(original)])
    modified_signing=arr([tstr("OpenIdentity Credential"),uint(1),bstr(modified)])
    check("CI09 historical StateHash is authoritative",state_hash(state)==hx(v["issuanceStateHashHex"]))
    check("CI09 modified credential differs from original",modified!=original)
    check("CI09 original signature verifies original credential",verify_signature_for_cose(cose,sig,original_signing))
    check("CI09 original signature fails modified credential",not verify_signature_for_cose(cose,sig,modified_signing))
    print("  CI09 REJECTED: INVALID_CREDENTIAL_SIGNATURE")

    # CI10
    v=by["CI10"]; state=hx(v["historicalIdentityStateHex"]); ptype,threshold,methods=policy_info(state)
    decoded,_=proof_list(v["securedCredentialHex"])
    check("CI10 historical StateHash independently recomputed",state_hash(state)==hx(v["issuanceStateHashHex"]))
    check("CI10 credential binds to exact historical StateHash",decoded[4]==state_hash(state))
    check("CI10 historical state has no AssertionPolicy",ptype is None and threshold==0 and methods=={})
    print("  CI10 REJECTED: NO_ASSERTION_AUTHORITY")

    print()
    print("CI01-CI10 VERIFIED")

def locate(name: str) -> Path:
    candidates = [
        Path.cwd() / "test-vectors" / "generated" / name,
        Path(__file__).resolve().parents[2] / "test-vectors" / "generated" / name,
        ]
    for p in candidates:
        if p.exists():
            return p
    fail(f"Could not locate test-vectors/generated/{name}")


def main():
    if len(sys.argv) == 1:
        c01 = locate("credential-c01-java.json")
        c02 = locate("credential-c02-java.json")
        invalid = locate("credential-invalid-java.json")
    elif len(sys.argv) == 4:
        c01, c02, invalid = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
    else:
        print(
            f"Usage: {Path(sys.argv[0]).name} "
            "[credential-c01-java.json credential-c02-java.json credential-invalid-java.json]",
            file=sys.stderr)
        return 2

    print("OpenIdentity Credential")
    print("Independent Verification")
    print("=" * 44)
    verify_c01_path(c01)
    verify_c02_path(c02)
    verify_invalid_suite(invalid)

    print()
    print("=" * 44)
    print("OI-003 CREDENTIAL C01-C02 + CI01-CI10 VERIFIED")
    print("=" * 44)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AssertionError, KeyError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        print()
        print(f"OI-003 CREDENTIAL VERIFICATION FAILED: {exc}", file=sys.stderr)
        raise SystemExit(1)
