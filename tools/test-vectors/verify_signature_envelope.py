#!/usr/bin/env python3
"""Independent verifier for OpenIdentity OI-010 SE01-SE10."""
import hashlib, json, sys
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

SPEC = "OpenIdentity Signature Envelope";
VER = "0.1"
OP = "OpenIdentity Operation";
POP = "OpenIdentity Controller Proof";
REC = "OpenIdentity Recovery"


def head(m, n):
    if n < 24: return bytes([(m << 5) | n])
    if n <= 255: return bytes([(m << 5) | 24, n])
    if n <= 65535: return bytes([(m << 5) | 25]) + n.to_bytes(2, "big")
    if n <= 4294967295: return bytes([(m << 5) | 26]) + n.to_bytes(4, "big")
    return bytes([(m << 5) | 27]) + n.to_bytes(8, "big")


def integer(n): return head(0, n) if n >= 0 else head(1, -1 - n)


def bstr(b): return head(2, len(b)) + b


def tstr(s):
    b = s.encode("utf-8");
    return head(3, len(b)) + b


def arr(xs): return head(4, len(xs)) + b"".join(xs)


def dmap(es):
    es = [(integer(k), v) for k, v in es];
    es.sort(key=lambda x: (len(x[0]), x[0]))
    return head(5, len(es)) + b"".join(k + v for k, v in es)


def enc(v):
    if v is None: return b"\xf6"
    if isinstance(v, bool): return b"\xf5" if v else b"\xf4"
    if isinstance(v, int): return integer(v)
    if isinstance(v, bytes): return bstr(v)
    if isinstance(v, str): return tstr(v)
    if isinstance(v, list): return arr([enc(x) for x in v])
    if isinstance(v, dict): return dmap([(k, enc(x)) for k, x in v.items()])
    raise TypeError(type(v))


def _u(d, p, a):
    if a < 24: return a, p
    w = {24: 1, 25: 2, 26: 4, 27: 8}.get(a)
    if not w: raise ValueError("indefinite/reserved CBOR")
    return int.from_bytes(d[p:p + w], "big"), p + w


def one(d, p=0):
    ib = d[p];
    p += 1;
    m, a = ib >> 5, ib & 31
    if m in (0, 1):
        n, p = _u(d, p, a);
        return (n if m == 0 else -1 - n), p
    if m in (2, 3):
        n, p = _u(d, p, a);
        x = d[p:p + n];
        p += n;
        return (x if m == 2 else x.decode()), p
    if m == 4:
        n, p = _u(d, p, a);
        o = []
        for _ in range(n): x, p = one(d, p);o.append(x)
        return o, p
    if m == 5:
        n, p = _u(d, p, a);
        o = {}
        for _ in range(n):
            k, p = one(d, p);
            v, p = one(d, p)
            if k in o: raise ValueError("duplicate map key")
            o[k] = v
        return o, p
    if m == 7 and a == 20: return False, p
    if m == 7 and a == 21: return True, p
    if m == 7 and a == 22: return None, p
    raise ValueError("unsupported CBOR")


def dec(d):
    x, p = one(d)
    if p != len(d): raise ValueError("trailing CBOR")
    return x


def hx(v, n):
    try:
        return bytes.fromhex(v)
    except Exception as e:
        raise AssertionError(f"{n}: invalid hex: {e}")


def ck(n, x):
    print(f"  {n}: " + ("PASS" if x else "FAIL"))
    if not x: raise AssertionError(n)


def same(n, a, b): ck(n, a == b)


def edv(pk, sig, msg):
    try:
        Ed25519PublicKey.from_public_bytes(pk).verify(sig, msg);return True
    except Exception:
        return False


def oin(op, v=1): return enc([OP, v, op])


def pin(op, mid): return enc([POP, 1, op, mid])


def rin(op, mid): return enc([REC, 1, op, mid])


def cose(pk): return {1: 1, 3: -8, -1: 6, -2: pk}


def vm(mid, pk): return {1: mid, 2: cose(pk)}


def single(mid, pk): return {1: 1, 2: [vm(mid, pk)]}


def rotate(i, seq, prev, pol): return {1: 1, 2: 2, 3: i, 4: seq, 5: prev, 6: {1: pol}}


def proof(mid, sig): return {1: mid, 2: sig}


def load(path):
    d = json.loads(path.read_text(encoding="utf-8"))
    ck("suite specification", d.get("specification") == SPEC)
    ck("suite version", d.get("version") == VER)
    ck("wire protocol version", d.get("wireProtocolVersion") == 1)
    ck("signing-structure version", d.get("signingStructureVersion") == 1)
    ck("ordinary authorization domain", d.get("ordinaryAuthorizationDomain") == OP)
    ck("controller proof domain", d.get("controllerProofDomain") == POP)
    ck("recovery domain", d.get("recoveryDomain") == REC)
    vs = d.get("vectors")
    ck("suite contains exactly 10 vectors", isinstance(vs, list) and len(vs) == 10)
    ck("vector IDs SE01-SE10", [v.get("id") for v in vs] == [f"SE{i:02d}" for i in range(1, 11)])
    return vs


def se01(v):
    print("\nSE01 Valid Ordinary Authorization\n--------------------------------------------")
    ck("SE01 expected ACCEPT", v["expectedResult"] == "ACCEPT")
    i = hx(v["identityHex"], "identity");
    prev = hx(v["previousStateHashHex"], "prev")
    mid = hx(v["controllerMethodIdHex"], "mid");
    pk = hx(v["controllerPublicKeyHex"], "pk")
    nmid = hx(v["proposedControllerMethodIdHex"], "nmid");
    npk = hx(v["proposedControllerPublicKeyHex"], "npk")
    ck("SE01 identity length", len(i) == 32);
    ck("SE01 StateHash length", len(prev) == 34)
    ck("SE01 method ID lengths", len(mid) == 16 and len(nmid) == 16)
    ck("SE01 public key lengths", len(pk) == 32 and len(npk) == 32)
    pol = single(nmid, npk);
    same("SE01 proposed policy reconstructed", enc(pol), hx(v["proposedControllerPolicyHex"], "policy"))
    op = enc(rotate(i, 2, prev, pol));
    same("SE01 OperationBytes reconstructed", op, hx(v["operationBytesHex"], "op"))
    ai = oin(op);
    same("SE01 authorization SigningInput reconstructed", ai, hx(v["authorizationSigningInputHex"], "ai"))
    sig = hx(v["authorizationSignatureHex"], "sig");
    ck("SE01 authorization signature verifies", edv(pk, sig, ai))
    same("SE01 authorization proof reconstructed", enc(proof(mid, sig)), hx(v["authorizationProofHex"], "aproof"))
    pi = pin(op, nmid);
    same("SE01 PoP SigningInput reconstructed", pi, hx(v["controllerPopSigningInputHex"], "pi"))
    ps = hx(v["controllerPopSignatureHex"], "ps");
    ck("SE01 PoP signature verifies", edv(npk, ps, pi))
    same("SE01 controller proof reconstructed", enc(proof(nmid, ps)), hx(v["controllerProofHex"], "pproof"))
    so = {1: rotate(i, 2, prev, pol), 2: [proof(mid, sig)], 3: [proof(nmid, ps)]}
    same("SE01 SignedOperation reconstructed", enc(so), hx(v["signedOperationHex"], "signed"))
    ck("SE01 authorization rejected in PoP domain", not edv(pk, sig, pin(op, mid)))
    return {"op": op, "ai": ai, "sig": sig, "pk": pk, "mid": mid}


def mutation(v, b, name):
    print(f"\n{v['id']} {name}\n--------------------------------------------")
    ck(v["id"] + " expected REJECT", v["expectedResult"] == "REJECT")
    ck(v["id"] + " expected INVALID_SIGNATURE", v["expectedError"] == "INVALID_SIGNATURE")
    op = hx(v["operationBytesHex"], "op");
    same(v["id"] + " canonical mutated OperationBytes", op, enc(dec(op)))
    mi = oin(op);
    same(v["id"] + " mutated SigningInput reconstructed", mi, hx(v["mutatedSigningInputHex"], "mi"))
    sig = hx(v["originalAuthorizationSignatureHex"], "sig");
    same(v["id"] + " retains SE01 signature", sig, b["sig"])
    ck(v["id"] + " OperationBytes differ from SE01", op != b["op"])
    ck(v["id"] + " SigningInput differs from SE01", mi != b["ai"])
    ck(v["id"] + " original signature rejected", not edv(b["pk"], sig, mi))
    return dec(op)


def substitution(v, b, source_fn, source_name, target_fn, target_name, expected):
    print(f"\n{v['id']} {source_name} -> {target_name}\n--------------------------------------------")
    ck(v["id"] + " expected REJECT", v["expectedResult"] == "REJECT")
    ck(v["id"] + " expected error", v["expectedError"] == expected)
    op = hx(v["operationBytesHex"], "op");
    sig = hx(v["substitutedSignatureHex"], "sig")
    src = hx(v["signatureWasCreatedOverHex"], "src");
    dst = hx(v["requiredSigningInputHex"], "dst")
    same(v["id"] + " source input reconstructed", src, source_fn(op, b["mid"]))
    same(v["id"] + " required input reconstructed", dst, target_fn(op, b["mid"]))
    ck(v["id"] + " signature verifies in source domain", edv(b["pk"], sig, src))
    ck(v["id"] + " signature fails required domain", not edv(b["pk"], sig, dst))


def verify_generated_suite():
    root = Path(__file__).resolve().parents[2]
    path = Path(sys.argv[1]) if len(
        sys.argv) > 1 else root / "test-vectors" / "generated" / "signature-envelope-se01-se10-java.json"
    print(
        "\nOpenIdentity OI-010 Signature Envelope\nIndependent Verification\n================================================")
    vs = load(path);
    by = {v["id"]: v for v in vs};
    b = se01(by["SE01"])
    o2 = mutation(by["SE02"], b, "Identity Mutation")
    ck("SE02 identity actually changed", o2[3] != dec(b["op"])[3])
    o3 = mutation(by["SE03"], b, "Sequence Mutation");
    ck("SE03 sequence is 3", o3[4] == 3)
    o4 = mutation(by["SE04"], b, "previousStateHash Mutation");
    ck("SE04 predecessor actually changed", o4[5] != dec(b["op"])[5])
    o5 = mutation(by["SE05"], b, "Payload Mutation");
    ck("SE05 payload actually changed", o5[6] != dec(b["op"])[6])
    substitution(by["SE06"], b, lambda o, m: oin(o), OP, lambda o, m: pin(o, m), POP, "INVALID_PROOF_OF_POSSESSION")
    substitution(by["SE07"], b, lambda o, m: pin(o, m), POP, lambda o, m: oin(o), OP, "INVALID_SIGNATURE")
    substitution(by["SE08"], b, lambda o, m: rin(o, m), REC, lambda o, m: oin(o), OP, "INVALID_SIGNATURE")
    v = by["SE09"];
    print("\nSE09 Signing-Structure Version Mutation\n--------------------------------------------")
    ck("SE09 expected REJECT", v["expectedResult"] == "REJECT");
    ck("SE09 expected INVALID_SIGNATURE", v["expectedError"] == "INVALID_SIGNATURE")
    op = hx(v["operationBytesHex"], "op");
    sig = hx(v["authorizationSignatureHex"], "sig")
    src = hx(v["signatureWasCreatedOverHex"], "src");
    mut = hx(v["mutatedSigningInputHex"], "mut")
    same("SE09 version-1 input reconstructed", src, oin(op, 1));
    same("SE09 version-2 input reconstructed", mut, oin(op, 2))
    ck("SE09 metadata versions 1 -> 2",
       v["originalSigningStructureVersion"] == 1 and v["mutatedSigningStructureVersion"] == 2)
    ck("SE09 signature verifies over version 1", edv(b["pk"], sig, src));
    ck("SE09 signature fails over version 2", not edv(b["pk"], sig, mut))
    o10 = mutation(by["SE10"], b, "Operation Type Mutation");
    ck("SE10 operation type is DEACTIVATE (4)", o10[2] == 4)
    print("\nSE01-SE10 VERIFIED")
    print("\n============================================")
    print("OI-010 SIGNATURE ENVELOPE SE01-SE10 VERIFIED")
    print("============================================")
    return vs


FROZEN_SHA256 = "61ea787161c408332354c3bbc04a3538d9cb568524340408b00afe2c391189b5"


def verify_normative_bundle(generated_vectors):
    root = Path(__file__).resolve().parents[2]
    bundle_path = root / "test-vectors" / "signature-envelope-v0.1.json"
    checksum_path = root / "test-vectors" / "signature-envelope-v0.1.json.sha256"

    print("\nNormative Signature Envelope Bundle")
    print("--------------------------------------------")

    raw = bundle_path.read_bytes()
    d = json.loads(raw.decode("utf-8"))

    ck("normative specification", d.get("specification") == SPEC)
    ck("normative suite version", d.get("version") == VER)
    ck("normative wire protocol version", d.get("wireProtocolVersion") == 1)
    ck("normative signing-structure version",
       d.get("signingStructureVersion") == 1)

    domains = d.get("domains")
    ck("normative domains object", isinstance(domains, dict))
    ck("normative ordinary authorization domain",
       domains.get("ordinaryAuthorization") == OP)
    ck("normative controller PoP domain",
       domains.get("controllerProofOfPossession") == POP)
    ck("normative recovery authorization domain",
       domains.get("recoveryAuthorization") == REC)

    coverage = d.get("coverage")
    ck("normative coverage object", isinstance(coverage, dict))
    ck("normative covered operation fields",
       coverage.get("operationFieldsCovered") == [
           "protocolVersion",
           "operationType",
           "identity",
           "sequence",
           "previousStateHash",
           "payload",
       ])
    ck("normative proof collections excluded from OperationBytes",
       coverage.get("proofCollectionsExcludedFromOperationBytes") is True)
    ck("normative signing version independent of protocol version",
       coverage.get(
           "signingStructureVersionIndependentOfProtocolVersion") is True)

    vectors = d.get("vectors")
    ck("normative bundle contains exactly 10 vectors",
       isinstance(vectors, list) and len(vectors) == 10)
    ck("normative vector IDs SE01-SE10",
       [v.get("id") for v in vectors] ==
       [f"SE{i:02d}" for i in range(1, 11)])
    ck("normative SE01 is ACCEPT",
       vectors[0].get("expectedResult") == "ACCEPT")
    ck("normative SE02-SE10 are REJECT",
       all(v.get("expectedResult") == "REJECT" for v in vectors[1:]))
    ck("normative SE02-SE10 contain expected errors",
       all(isinstance(v.get("expectedError"), str)
           and bool(v.get("expectedError")) for v in vectors[1:]))

    # The normative bundle must preserve the exact independently verified
    # generated vector objects; consolidation is not allowed to rewrite them.
    ck("normative SE01-SE10 exactly equal verified generated suite",
       vectors == generated_vectors)

    # Re-run the most fundamental independent reconstruction directly against
    # the normative SE01 object, rather than relying only on object equality.
    v = vectors[0]
    identity = hx(v["identityHex"], "normative identity")
    prev = hx(v["previousStateHashHex"], "normative predecessor")
    mid = hx(v["controllerMethodIdHex"], "normative controller method")
    pk = hx(v["controllerPublicKeyHex"], "normative controller key")
    nmid = hx(v["proposedControllerMethodIdHex"],
              "normative proposed method")
    npk = hx(v["proposedControllerPublicKeyHex"],
             "normative proposed key")

    policy = single(nmid, npk)
    operation = enc(rotate(identity, 2, prev, policy))
    ck("normative SE01 OperationBytes independently reconstructed",
       operation == hx(v["operationBytesHex"], "normative operation"))

    auth_input = oin(operation)
    ck("normative SE01 SigningInput independently reconstructed",
       auth_input ==
       hx(v["authorizationSigningInputHex"], "normative signing input"))

    signature = hx(v["authorizationSignatureHex"],
                   "normative authorization signature")
    ck("normative SE01 authorization cryptographically verifies",
       edv(pk, signature, auth_input))

    pop_input = pin(operation, nmid)
    pop_signature = hx(v["controllerPopSignatureHex"],
                       "normative PoP signature")
    ck("normative SE01 PoP input independently reconstructed",
       pop_input ==
       hx(v["controllerPopSigningInputHex"], "normative PoP input"))
    ck("normative SE01 PoP cryptographically verifies",
       edv(npk, pop_signature, pop_input))

    # Check exact checksum-file semantics and exact bundle bytes.
    line = checksum_path.read_text(encoding="utf-8").strip()
    parts = line.split()
    ck("normative checksum file format", len(parts) >= 2)
    ck("normative checksum filename",
       parts[-1] == "signature-envelope-v0.1.json")

    expected = parts[0].lower()
    actual = hashlib.sha256(raw).hexdigest()
    ck("normative SHA-256 independently verifies", actual == expected)
    ck("normative SHA-256 matches frozen candidate",
       actual == FROZEN_SHA256)

    print("\nsignature-envelope-v0.1.json: VERIFIED")
    print("SHA-256:", actual)
    return 0


def main():
    generated_vectors = verify_generated_suite()
    verify_normative_bundle(generated_vectors)

    print("\n============================================")
    print("OI-010 SIGNATURE ENVELOPE")
    print("SE01-SE10 + NORMATIVE BUNDLE VERIFIED")
    print("============================================")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError:
        raise SystemExit(1)
