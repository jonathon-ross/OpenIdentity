#!/usr/bin/env python3
"""Independent verifier for OpenIdentity OI-011 StateHash SH01-SH10."""
import hashlib, json, sys
from pathlib import Path

SPEC = "OpenIdentity StateHash";
VERSION = "0.1"


def head(m, n):
    if n < 24: return bytes([(m << 5) | n])
    if n <= 255: return bytes([(m << 5) | 24, n])
    if n <= 65535: return bytes([(m << 5) | 25]) + n.to_bytes(2, "big")
    if n <= 4294967295: return bytes([(m << 5) | 26]) + n.to_bytes(4, "big")
    return bytes([(m << 5) | 27]) + n.to_bytes(8, "big")


def integer(n): return head(0, n) if n >= 0 else head(1, -1 - n)


def bstr(b): return head(2, len(b)) + b


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
        p += n
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
    if m == 7 and a == 22: return None, p
    raise ValueError("unsupported CBOR")


def dec(d):
    x, p = one(d)
    if p != len(d): raise ValueError("trailing CBOR")
    return x


def sh(b): return b"\x12\x20" + hashlib.sha256(b).digest()


def hx(v, n):
    try:
        return bytes.fromhex(v)
    except Exception as e:
        raise AssertionError(f"{n}: {e}")


def ck(n, x):
    print(f"  {n}: " + ("PASS" if x else "FAIL"))
    if not x: raise AssertionError(n)


def same(n, a, b): ck(n, a == b)


def canonical(v, sid):
    s = hx(v["stateBytesHex"], sid + " state");
    h = hx(v["stateHashHex"], sid + " hash")
    o = dec(s);
    same(sid + " deterministic CBOR", s, enc(o))
    ck(sid + " hash metadata length", v.get("stateHashLength") == 34)
    ck(sid + " Multihash code", h[:1] == b"\x12")
    ck(sid + " digest-length prefix", h[1:2] == b"\x20")
    ck(sid + " total length", len(h) == 34)
    same(sid + " independently derived StateHash", h, sh(s))
    return s, h, o


def verify_generated_suite():
    root = Path(__file__).resolve().parents[2]
    p = Path(sys.argv[1]) if len(
        sys.argv) > 1 else root / "test-vectors" / "generated" / "state-hash-sh01-sh10-java.json"
    d = json.loads(p.read_text(encoding="utf-8"))
    print("\nOpenIdentity OI-011 StateHash\nIndependent Verification\n" + "=" * 48)
    ck("suite specification", d.get("specification") == SPEC);
    ck("suite version", d.get("version") == VERSION)
    ck("IdentityState versions", d.get("identityStateVersions") == [1, 2])
    pr = d.get("profile", {})
    ck("profile SHA-256", pr.get("hashAlgorithm") == "SHA-256");
    ck("profile Multihash code", pr.get("multihashCode") == 18)
    ck("profile digest length", pr.get("digestLength") == 32);
    ck("profile StateHash length", pr.get("stateHashLength") == 34)
    ck("profile formula", pr.get("formula") == "0x12 || 0x20 || SHA-256(StateBytes)")
    vs = d.get("vectors");
    ck("exactly 10 vectors", isinstance(vs, list) and len(vs) == 10)
    ck("IDs SH01-SH10", [x.get("id") for x in vs] == [f"SH{i:02d}" for i in range(1, 11)])
    v = {x["id"]: x for x in vs}

    print("\nSH01 IdentityState v1\n" + "-" * 44)
    s1, h1, o1 = canonical(v["SH01"], "SH01")
    ck("SH01 v1", o1[1] == 1);
    ck("SH01 sequence 1", o1[3] == 1);
    ck("SH01 ACTIVE", o1[4] == 1)
    ck("SH01 optional fields absent", 6 not in o1 and 7 not in o1)

    print("\nSH02 IdentityState v2\n" + "-" * 44)
    s2, h2, o2 = canonical(v["SH02"], "SH02")
    ck("SH02 v2", o2[1] == 2);
    ck("SH02 sequence 5", o2[3] == 5);
    ck("SH02 ACTIVE", o2[4] == 1);
    ck("SH02 AssertionPolicy present", 7 in o2)
    same("SH02 AssertionPolicy bytes", enc(o2[7]), hx(v["SH02"]["assertionPolicyHex"], "SH02 assertion"))
    ck("SH02 hash differs from SH01", h2 != h1)

    for sid, label in [("SH03", "sequence"), ("SH04", "status"), ("SH05", "ControllerPolicy"),
                       ("SH06", "recoveryCommitment"), ("SH07", "AssertionPolicy")]:
        print(f"\n{sid} {label} mutation\n" + "-" * 44)
        s, h, o = canonical(v[sid], sid);
        bs = hx(v[sid]["baselineStateBytesHex"], sid + " baseline state");
        bh = hx(v[sid]["baselineStateHashHex"], sid + " baseline hash");
        bo = dec(bs)
        same(sid + " baseline hash derived", bh, sh(bs));
        ck(sid + " StateBytes changed", v[sid].get("stateBytesChanged") is True and s != bs);
        ck(sid + " StateHash changed", v[sid].get("stateHashChanged") is True and h != bh)
        if sid == "SH03":
            ck("SH03 sequence 1 -> 2", bo[3] == 1 and o[3] == 2);
            ck("SH03 other fields preserved", all(o[k] == bo[k] for k in bo if k != 3))
        elif sid == "SH04":
            ck("SH04 ACTIVE -> DEACTIVATED", bo[4] == 1 and o[4] == 2);
            ck("SH04 other fields preserved", all(o[k] == bo[k] for k in bo if k != 4))
        elif sid == "SH05":
            ck("SH05 policy changed", o[5] != bo[5]);
            ck("SH05 other fields preserved", all(o[k] == bo[k] for k in bo if k != 5))
            same("SH05 baseline policy metadata", enc(bo[5]), hx(v[sid]["baselineControllerPolicyHex"], "base policy"));
            same("SH05 mutated policy metadata", enc(o[5]), hx(v[sid]["mutatedControllerPolicyHex"], "mut policy"))
        elif sid == "SH06":
            ck("SH06 baseline omits commitment", 6 not in bo);
            ck("SH06 commitment present", 6 in o);
            same("SH06 commitment metadata", o[6], hx(v[sid]["mutatedRecoveryCommitmentHex"], "commitment"))
            ck("SH06 other fields preserved", all(o[k] == bo[k] for k in bo))
        elif sid == "SH07":
            ck("SH07 v2 states", bo[1] == 2 and o[1] == 2);
            ck("SH07 assertion changed", bo[7] != o[7]);
            ck("SH07 other fields preserved", all(o[k] == bo[k] for k in bo if k != 7))
            same("SH07 baseline assertion metadata", enc(bo[7]),
                 hx(v[sid]["baselineAssertionPolicyHex"], "base assertion"));
            same("SH07 mutated assertion metadata", enc(o[7]), hx(v[sid]["mutatedAssertionPolicyHex"], "mut assertion"))

    print("\nSH08 Canonical ordering invariance\n" + "-" * 44)
    s8, h8, o8 = canonical(v["SH08"], "SH08");
    bs = hx(v["SH08"]["baselineStateBytesHex"], "SH08 base state");
    bh = hx(v["SH08"]["baselineStateHashHex"], "SH08 base hash")
    ck("SH08 reversed input marker", v["SH08"].get("inputMethodOrder") == ["ML-DSA-65", "Ed25519"])
    ck("SH08 match markers",
       v["SH08"].get("canonicalStateBytesMatch") is True and v["SH08"].get("canonicalStateHashMatch") is True)
    same("SH08 StateBytes equal baseline", s8, bs);
    same("SH08 StateHash equal baseline", h8, bh);
    same("SH08 baseline is SH01 state", bs, s1);
    same("SH08 baseline is SH01 hash", bh, h1)
    mids = [m[1] for m in o8[5][3]];
    ck("SH08 canonical method-ID order", mids == sorted(mids))

    print("\nSH09 Raw SHA-256 is not StateHash\n" + "-" * 44)
    s9, h9, _ = canonical(v["SH09"], "SH09");
    raw = hashlib.sha256(s9).digest()
    same("SH09 raw digest derived", raw, hx(v["SH09"]["rawSha256DigestHex"], "raw digest"));
    ck("SH09 raw digest 32 bytes", len(raw) == 32 and v["SH09"].get("rawDigestLength") == 32)
    ck("SH09 StateHash 34 bytes", len(h9) == 34);
    ck("SH09 raw digest != StateHash", raw != h9 and v["SH09"].get("rawDigestIsStateHash") is False);
    same("SH09 digest follows Multihash prefix", h9[2:], raw)

    print("\nSH10 Non-StateBytes representation\n" + "-" * 44)
    s10, h10, _ = canonical(v["SH10"], "SH10");
    alt = hx(v["SH10"]["alternateBytesHex"], "alternate bytes");
    ah = sh(alt)
    ck("SH10 alternate is OperationBytes", v["SH10"].get("alternateRepresentation") == "OperationBytes");
    same("SH10 alternate Multihash derived", ah, hx(v["SH10"]["alternateMultihashHex"], "alternate hash"))
    ck("SH10 alternate bytes differ", alt != s10);
    ck("SH10 alternate hash differs", ah != h10);
    ck("SH10 alternate not authoritative", v["SH10"].get("alternateHashIsAuthoritativeStateHash") is False)

    print("\nSH01-SH10 VERIFIED")
    print("\n============================================")
    print("OI-011 STATEHASH SH01-SH10 VERIFIED")
    print("============================================")
    return vs


FROZEN_SHA256 = "6de35a98941f6aff846cd662ccd796473f8f22c5c891ce3589e9a593588bf937"


def verify_normative_bundle(generated_vectors):
    root = Path(__file__).resolve().parents[2]
    bundle = root / "test-vectors" / "state-hash-v0.1.json"
    checksum = root / "test-vectors" / "state-hash-v0.1.json.sha256"

    print("\nNormative StateHash Bundle")
    print("-" * 44)

    raw = bundle.read_bytes()
    d = json.loads(raw.decode("utf-8"))

    ck("normative specification", d.get("specification") == SPEC)
    ck("normative version", d.get("version") == VERSION)
    ck("normative IdentityState versions",
       d.get("identityStateVersions") == [1, 2])

    pr = d.get("profile", {})
    ck("normative profile SHA-256",
       pr.get("hashAlgorithm") == "SHA-256")
    ck("normative profile Multihash code",
       pr.get("multihashCode") == 18)
    ck("normative profile digest length",
       pr.get("digestLength") == 32)
    ck("normative profile StateHash length",
       pr.get("stateHashLength") == 34)
    ck("normative profile formula",
       pr.get("formula") ==
       "0x12 || 0x20 || SHA-256(StateBytes)")

    sem = d.get("semantics", {})
    ck("normative input is canonical StateBytes",
       sem.get("input") == "canonical StateBytes")
    ck("normative complete IdentityState commitment",
       sem.get("completeIdentityStateCommitted") is True)
    ck("normative exact binary Multihash comparison",
       sem.get("exactBinaryMultihashComparison") is True)
    ck("normative raw digest distinction",
       sem.get("rawSha256DigestIsNotStateHash") is True)
    ck("normative non-StateBytes distinction",
       sem.get("nonStateBytesHashIsNotAuthoritative") is True)

    vectors = d.get("vectors")
    ck("normative contains exactly 10 vectors",
       isinstance(vectors, list) and len(vectors) == 10)
    ck("normative IDs SH01-SH10",
       [x.get("id") for x in vectors] ==
       [f"SH{i:02d}" for i in range(1, 11)])

    # Consolidation must preserve the exact independently verified vectors.
    ck("normative vectors exactly equal verified generated suite",
       vectors == generated_vectors)

    # Independently re-hash every normative vector directly.
    for vector in vectors:
        sid = vector["id"]
        state = hx(vector["stateBytesHex"], sid + " normative StateBytes")
        expected = hx(vector["stateHashHex"], sid + " normative StateHash")
        ck(sid + " normative StateHash is 34 bytes",
           len(expected) == 34)
        ck(sid + " normative Multihash prefix is 0x12 0x20",
           expected[:2] == b"\x12\x20")
        same(sid + " normative StateHash independently derived",
             expected, sh(state))

    # Re-prove the special SH08-SH10 invariants from normative data.
    sh08 = vectors[7]
    same("normative SH08 canonical StateBytes equal baseline",
         hx(sh08["stateBytesHex"], "SH08 state"),
         hx(sh08["baselineStateBytesHex"], "SH08 baseline state"))
    same("normative SH08 canonical StateHash equal baseline",
         hx(sh08["stateHashHex"], "SH08 hash"),
         hx(sh08["baselineStateHashHex"], "SH08 baseline hash"))

    sh09 = vectors[8]
    sh09_state = hx(sh09["stateBytesHex"], "SH09 state")
    raw_digest = hashlib.sha256(sh09_state).digest()
    same("normative SH09 raw digest independently derived",
         raw_digest,
         hx(sh09["rawSha256DigestHex"], "SH09 raw digest"))
    ck("normative SH09 raw digest is not StateHash",
       raw_digest != hx(sh09["stateHashHex"], "SH09 StateHash"))

    sh10 = vectors[9]
    alternate = hx(sh10["alternateBytesHex"], "SH10 alternate bytes")
    alternate_hash = sh(alternate)
    same("normative SH10 alternate Multihash independently derived",
         alternate_hash,
         hx(sh10["alternateMultihashHex"], "SH10 alternate hash"))
    ck("normative SH10 alternate hash is not authoritative StateHash",
       alternate_hash != hx(sh10["stateHashHex"], "SH10 StateHash"))

    line = checksum.read_text(encoding="utf-8").strip()
    parts = line.split()
    ck("normative checksum file format", len(parts) >= 2)
    ck("normative checksum filename",
       parts[-1] == "state-hash-v0.1.json")

    expected_checksum = parts[0].lower()
    actual_checksum = hashlib.sha256(raw).hexdigest()
    ck("normative SHA-256 independently verifies",
       actual_checksum == expected_checksum)
    ck("normative SHA-256 matches frozen candidate",
       actual_checksum == FROZEN_SHA256)

    print("\nstate-hash-v0.1.json: VERIFIED")
    print("SHA-256:", actual_checksum)


def main():
    generated_vectors = verify_generated_suite()
    verify_normative_bundle(generated_vectors)

    print("\n============================================")
    print("OI-011 STATEHASH")
    print("SH01-SH10 + NORMATIVE BUNDLE VERIFIED")
    print("============================================")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AssertionError, KeyError, ValueError, json.JSONDecodeError) as e:
        print(f"\nOI-011 STATEHASH VERIFICATION FAILED: {e}",
              file=sys.stderr)
        raise SystemExit(1)
