#!/usr/bin/env python3
"""
Independent verifier for OpenIdentity W3C projection vectors.

P01 is derived independently from the normative OI-002 V01 source.  The
verifier does not trust duplicated identity, method, key, DID, or policy values
from the Java-generated projection vector.

Usage from repository root:
    python tools/test-vectors/verify_w3c_projection.py

Or:
    python tools/test-vectors/verify_w3c_projection.py \
        test-vectors/cryptographic-agility-v0.1.json \
        test-vectors/w3c-projection-v0.1.json
"""
from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
OI_CONTEXT = "https://openidentity.foundation/ns/v1"
DID_CONTEXT = "https://www.w3.org/ns/did/v1"
MULTIKEY_CONTEXT = "https://w3id.org/security/multikey/v1"
ED25519_PUB_MULTICODEC = 0xED
ML_DSA_65_PUB_MULTICODEC = 0x1211


def fail(msg: str) -> None:
    raise AssertionError(msg)


def check(label: str, condition: bool) -> None:
    if not condition:
        fail(label)
    print(f"  {label}: PASS")


def load_json(path: Path):
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def vector(doc, vector_id: str):
    for v in doc.get("valid", []):
        if v.get("id") == vector_id:
            return v
    fail(f"Missing normative source vector {vector_id}")


def projection(doc, vector_id: str):
    for v in doc.get("vectors", []):
        if v.get("id") == vector_id:
            return v
    fail(f"Missing projection vector {vector_id}")


def b58encode(raw: bytes) -> str:
    if not raw:
        return ""
    zeros = len(raw) - len(raw.lstrip(b"\x00"))
    n = int.from_bytes(raw, "big")
    out = ""
    while n:
        n, rem = divmod(n, 58)
        out = B58[rem] + out
    return ("1" * zeros) + out


def multibase58(raw: bytes) -> str:
    return "z" + b58encode(raw)


def uvarint(n: int) -> bytes:
    if n < 0:
        fail("negative unsigned varint")
    out = bytearray()
    while True:
        b = n & 0x7f
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def b64url_no_pad(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def resolve_default_paths():
    cwd = Path.cwd()
    candidates = [
        cwd,
        cwd.parent,
        cwd.parent.parent,
        Path(__file__).resolve().parents[2] if "__file__" in globals() else cwd,
    ]
    for root in candidates:
        source = root / "test-vectors" / "cryptographic-agility-v0.1.json"
        projected = root / "test-vectors" / "w3c-projection-v0.1.json"
        if source.exists() and projected.exists():
            return source, projected
    fail("Could not locate both test-vectors/cryptographic-agility-v0.1.json "
         "and test-vectors/w3c-projection-v0.1.json")


def verify_p02(source, projected) -> None:
    v02 = vector(source, "V02")
    p02 = projection(projected, "P02")

    identity = bytes.fromhex(v02["identityHex"])
    ed_id = bytes.fromhex(v02["ed25519MethodIdHex"])
    ml_id = bytes.fromhex(v02["mlDsa65MethodIdHex"])
    ed_pk = bytes.fromhex(v02["ed25519PublicKeyHex"])
    ml_pk = bytes.fromhex(v02["mlDsa65PublicKeyHex"])

    root = "did:open:" + multibase58(identity)

    def method(mid: bytes, pk: bytes, algorithm: str):
        fragment = "vm-u" + b64url_no_pad(mid)
        url = root + "#" + fragment
        if algorithm == "Ed25519":
            prefix = uvarint(ED25519_PUB_MULTICODEC)
            mb = multibase58(prefix + pk)
            codec = "0xed"
            encoding = "base58btc"
        else:
            prefix = uvarint(ML_DSA_65_PUB_MULTICODEC)
            mb = "u" + b64url_no_pad(prefix + pk)
            codec = "0x1211"
            encoding = "base64url-no-pad"
        meta = {
            "algorithm": algorithm,
            "methodIdHex": mid.hex(),
            "methodFragment": fragment,
            "methodDidUrl": url,
            "publicKeyHex": pk.hex(),
            "multicodec": codec,
            "multibaseEncoding": encoding,
            "publicKeyMultibase": mb,
        }
        vm = {"id": url, "type": "Multikey",
              "controller": root, "publicKeyMultibase": mb}
        return mid, meta, vm

    methods = [
        method(ed_id, ed_pk, "Ed25519"),
        method(ml_id, ml_pk, "ML-DSA-65"),
    ]
    methods.sort(key=lambda x: x[0])
    expected_meta = [x[1] for x in methods]
    expected_vms = [x[2] for x in methods]
    urls = [x[1]["methodDidUrl"] for x in methods]

    policy = {
        "id": root + "#controller-policy",
        "type": "Threshold",
        "appliesTo": "capabilityInvocation",
        "threshold": 2,
        "verificationMethod": urls,
    }
    did = {
        "@context": [DID_CONTEXT, MULTIKEY_CONTEXT, OI_CONTEXT],
        "id": root,
        "verificationMethod": expected_vms,
        "capabilityInvocation": urls,
        "openIdentityVerificationPolicy": policy,
    }

    print()
    print("P02 Hybrid Threshold Verification")
    print("-" * 44)
    check("P02 source vector", p02.get("sourceVector") == "V02")
    check("P02 identity length", len(identity) == 32)
    check("P02 Ed25519 method ID length", len(ed_id) == 16)
    check("P02 ML-DSA-65 method ID length", len(ml_id) == 16)
    check("P02 Ed25519 public key length", len(ed_pk) == 32)
    check("P02 ML-DSA-65 public key length", len(ml_pk) == 1952)
    check("P02 root DID derivation", p02.get("rootDid") == root)
    check("P02 Ed25519 multicodec varint",
          uvarint(ED25519_PUB_MULTICODEC) == bytes.fromhex("ed01"))
    check("P02 ML-DSA-65 multicodec varint",
          uvarint(ML_DSA_65_PUB_MULTICODEC) == bytes.fromhex("9124"))
    check("P02 projected method metadata",
          p02.get("verificationMethods") == expected_meta)
    check("P02 canonical method ordering",
          p02.get("canonicalVerificationMethodOrder") == urls)
    check("P02 capabilityInvocation",
          p02.get("capabilityInvocation") == urls)
    check("P02 Threshold 2-of-2 policy",
          p02.get("verificationPolicy") == policy)
    check("P02 DID document structure",
          p02.get("didDocument") == did)

    ml_meta = next(x for x in expected_meta if x["algorithm"] == "ML-DSA-65")
    ml_value = ml_meta["publicKeyMultibase"]
    check("P02 ML-DSA-65 Multibase prefix", ml_value.startswith("u"))
    padded = ml_value[1:] + "=" * (-len(ml_value[1:]) % 4)
    decoded = base64.urlsafe_b64decode(padded)
    check("P02 ML-DSA-65 Multikey decodes to multicodec + raw key",
          decoded == bytes.fromhex("9124") + ml_pk)
    check("P02 ML-DSA-65 decoded raw key length",
          len(decoded[2:]) == 1952)

    forbidden = {"authentication", "assertionMethod", "keyAgreement",
                 "capabilityDelegation"}
    check("P02 no accidental additional verification authority",
          not any(k in did for k in forbidden))
    print()
    print("P02 VERIFIED")



def verify_p03(source, projected) -> None:
    v03 = vector(source, "V03")
    p02 = projection(projected, "P02")
    p03 = projection(projected, "P03")

    expected_reversed = ["ML-DSA-65", "Ed25519"]

    print()
    print("P03 Canonical Invariance Verification")
    print("-" * 44)

    check("P03 source vector", p03.get("sourceVector") == "V03")
    check("P03 normative reversed method input",
          v03.get("inputMethodOrder") == expected_reversed)
    check("P03 normative reversed proof input",
          v03.get("inputProofOrder") == expected_reversed)
    check("P03 preserves reversed method input metadata",
          p03.get("inputMethodOrder") == expected_reversed)
    check("P03 preserves reversed proof input metadata",
          p03.get("inputProofOrder") == expected_reversed)

    # Independently derive the canonical order from P03 method IDs rather than
    # trusting either Java's canonicalVerificationMethodOrder or P02's order.
    methods = p03.get("verificationMethods")
    check("P03 has exactly two projected methods",
          isinstance(methods, list) and len(methods) == 2)

    method_ids = [bytes.fromhex(m["methodIdHex"]) for m in methods]
    independently_sorted = sorted(method_ids)
    check("P03 independent canonical method ordering",
          method_ids == independently_sorted)

    independently_derived_urls = [
        p03["rootDid"] + "#vm-u" + b64url_no_pad(mid)
        for mid in independently_sorted
    ]
    check("P03 canonical method URLs independently derived",
          p03.get("canonicalVerificationMethodOrder")
          == independently_derived_urls)

    # P03's purpose is invariance: after canonicalization, every semantic
    # projection component must equal P02.
    check("P03 root DID equals P02",
          p03.get("rootDid") == p02.get("rootDid"))
    check("P03 verification methods equal P02",
          p03.get("verificationMethods") == p02.get("verificationMethods"))
    check("P03 capabilityInvocation equals P02",
          p03.get("capabilityInvocation") == p02.get("capabilityInvocation"))
    check("P03 Threshold policy equals P02",
          p03.get("verificationPolicy") == p02.get("verificationPolicy"))
    check("P03 DID document equals P02",
          p03.get("didDocument") == p02.get("didDocument"))

    policy = p03.get("verificationPolicy", {})
    check("P03 Threshold remains 2-of-2",
          policy.get("type") == "Threshold"
          and policy.get("threshold") == 2
          and policy.get("appliesTo") == "capabilityInvocation"
          and policy.get("verificationMethod")
          == independently_derived_urls)

    did = p03.get("didDocument", {})
    check("P03 DID document uses canonical order",
          [vm.get("id") for vm in did.get("verificationMethod", [])]
          == independently_derived_urls
          and did.get("capabilityInvocation")
          == independently_derived_urls)

    check("P03 canonicalProjectionMatches marker",
          p03.get("canonicalProjectionMatches") == "P02")

    forbidden = {"authentication", "assertionMethod", "keyAgreement",
                 "capabilityDelegation"}
    check("P03 no accidental additional verification authority",
          not any(k in did for k in forbidden))

    print()
    print("P03 VERIFIED")



def verify_p04(source, projected) -> None:
    v04 = vector(source, "V04")
    p02 = projection(projected, "P02")
    p04 = projection(projected, "P04")

    identity = bytes.fromhex(v04["identityHex"])
    old_ed_id = bytes.fromhex(v04["oldEd25519MethodIdHex"])
    old_ml_id = bytes.fromhex(v04["oldMlDsa65MethodIdHex"])
    new_ed_id = bytes.fromhex(v04["newEd25519MethodIdHex"])
    new_ml_id = bytes.fromhex(v04["newMlDsa65MethodIdHex"])
    new_ed_pk = bytes.fromhex(v04["newEd25519PublicKeyHex"])
    new_ml_pk = bytes.fromhex(v04["newMlDsa65PublicKeyHex"])

    root = "did:open:" + multibase58(identity)

    def project(mid: bytes, pk: bytes, algorithm: str):
        fragment = "vm-u" + b64url_no_pad(mid)
        url = root + "#" + fragment
        if algorithm == "Ed25519":
            prefix = uvarint(ED25519_PUB_MULTICODEC)
            mb = multibase58(prefix + pk)
            codec = "0xed"
            encoding = "base58btc"
        else:
            prefix = uvarint(ML_DSA_65_PUB_MULTICODEC)
            mb = "u" + b64url_no_pad(prefix + pk)
            codec = "0x1211"
            encoding = "base64url-no-pad"
        meta = {
            "algorithm": algorithm,
            "methodIdHex": mid.hex(),
            "methodFragment": fragment,
            "methodDidUrl": url,
            "publicKeyHex": pk.hex(),
            "multicodec": codec,
            "multibaseEncoding": encoding,
            "publicKeyMultibase": mb,
        }
        vm = {
            "id": url,
            "type": "Multikey",
            "controller": root,
            "publicKeyMultibase": mb,
        }
        return mid, meta, vm

    new_methods = [
        project(new_ed_id, new_ed_pk, "Ed25519"),
        project(new_ml_id, new_ml_pk, "ML-DSA-65"),
    ]
    new_methods.sort(key=lambda x: x[0])
    expected_meta = [x[1] for x in new_methods]
    expected_vms = [x[2] for x in new_methods]
    new_urls = [x[1]["methodDidUrl"] for x in new_methods]

    old_urls = sorted([
        root + "#vm-u" + b64url_no_pad(old_ed_id),
        root + "#vm-u" + b64url_no_pad(old_ml_id),
        ])

    policy = {
        "id": root + "#controller-policy",
        "type": "Threshold",
        "appliesTo": "capabilityInvocation",
        "threshold": 2,
        "verificationMethod": new_urls,
    }
    did = {
        "@context": [DID_CONTEXT, MULTIKEY_CONTEXT, OI_CONTEXT],
        "id": root,
        "verificationMethod": expected_vms,
        "capabilityInvocation": new_urls,
        "openIdentityVerificationPolicy": policy,
    }

    print()
    print("P04 Controller Rotation Verification")
    print("-" * 44)

    check("P04 source vector", p04.get("sourceVector") == "V04")
    check("P04 previous projection", p04.get("previousProjection") == "P02")
    check("P04 sequence",
          p04.get("sequence") == v04.get("sequence") == 2)
    check("P04 identity length", len(identity) == 32)
    check("P04 stable root DID",
          p04.get("rootDid") == root == p02.get("rootDid"))
    check("P04 DID document preserves identity",
          p04.get("didDocument", {}).get("id")
          == p02.get("didDocument", {}).get("id")
          == root)

    check("P04 old Ed25519 method ID length", len(old_ed_id) == 16)
    check("P04 old ML-DSA-65 method ID length", len(old_ml_id) == 16)
    check("P04 new Ed25519 method ID length", len(new_ed_id) == 16)
    check("P04 new ML-DSA-65 method ID length", len(new_ml_id) == 16)
    check("P04 new Ed25519 public key length", len(new_ed_pk) == 32)
    check("P04 new ML-DSA-65 public key length", len(new_ml_pk) == 1952)

    check("P04 removed methods independently derived",
          p04.get("removedVerificationMethods") == old_urls)
    check("P04 removed methods equal P02 authority",
          set(old_urls) == set(p02.get("capabilityInvocation", [])))
    check("P04 projected new methods independently derived",
          p04.get("verificationMethods") == expected_meta)
    check("P04 canonical new-method ordering",
          p04.get("canonicalVerificationMethodOrder") == new_urls)

    check("P04 old/new authority disjoint",
          set(old_urls).isdisjoint(new_urls))
    check("P04 capabilityInvocation contains only new methods",
          p04.get("capabilityInvocation") == new_urls
          and set(p04.get("capabilityInvocation", [])).isdisjoint(old_urls))

    check("P04 Threshold remains 2-of-2",
          v04.get("oldControllerThreshold") == 2
          and v04.get("newControllerThreshold") == 2
          and p04.get("verificationPolicy") == policy)

    check("P04 DID document contains no old authority",
          not (set(old_urls)
               & {vm.get("id") for vm in
                  p04.get("didDocument", {}).get("verificationMethod", [])})
          and set(p04.get("didDocument", {}).get("capabilityInvocation", []))
          .isdisjoint(old_urls))

    check("P04 DID document structure",
          p04.get("didDocument") == did)

    ml_meta = next(x for x in expected_meta
                   if x["algorithm"] == "ML-DSA-65")
    ml_value = ml_meta["publicKeyMultibase"]
    check("P04 new ML-DSA-65 Multibase prefix",
          ml_value.startswith("u"))
    padded = ml_value[1:] + "=" * (-len(ml_value[1:]) % 4)
    decoded = base64.urlsafe_b64decode(padded)
    check("P04 new ML-DSA-65 Multikey decodes correctly",
          decoded == bytes.fromhex("9124") + new_ml_pk)

    forbidden = {"authentication", "assertionMethod", "keyAgreement",
                 "capabilityDelegation"}
    check("P04 no accidental additional verification authority",
          not any(k in did for k in forbidden))

    print()
    print("P04 VERIFIED")


def main():
    if len(sys.argv) == 3:
        source_path, projection_path = map(Path, sys.argv[1:3])
    elif len(sys.argv) == 1:
        source_path, projection_path = resolve_default_paths()
    else:
        print(f"Usage: {Path(sys.argv[0]).name} [cryptographic-agility-v0.1.json w3c-projection-v0.1.json]",
              file=sys.stderr)
        return 2

    source = load_json(source_path)
    projected = load_json(projection_path)
    v01 = vector(source, "V01")
    p01 = projection(projected, "P01")

    identity = bytes.fromhex(v01["identityHex"])
    method_id = bytes.fromhex(v01["ed25519MethodIdHex"])
    public_key = bytes.fromhex(v01["ed25519PublicKeyHex"])

    expected_root = "did:open:" + multibase58(identity)
    expected_fragment = "vm-u" + b64url_no_pad(method_id)
    expected_vm_id = expected_root + "#" + expected_fragment
    expected_key_mb = multibase58(uvarint(ED25519_PUB_MULTICODEC) + public_key)

    expected_vm = {
        "id": expected_vm_id,
        "type": "Multikey",
        "controller": expected_root,
        "publicKeyMultibase": expected_key_mb,
    }
    expected_policy = {
        "id": expected_root + "#controller-policy",
        "type": "Single",
        "appliesTo": "capabilityInvocation",
        "verificationMethod": [expected_vm_id],
    }
    expected_doc = {
        "@context": [DID_CONTEXT, MULTIKEY_CONTEXT, OI_CONTEXT],
        "id": expected_root,
        "verificationMethod": [expected_vm],
        "capabilityInvocation": [expected_vm_id],
        "openIdentityVerificationPolicy": expected_policy,
    }

    print("OpenIdentity W3C Projection")
    print("Independent Verification")
    print("=" * 44)
    print()

    check("P01 source vector", p01.get("sourceVector") == "V01")
    check("Identity length", len(identity) == 32)
    check("Verification Method ID length", len(method_id) == 16)
    check("Ed25519 public key length",
          len(public_key) == 32 and source["algorithms"]["Ed25519"]["publicKeyLength"] == 32)
    check("Root DID derivation", p01.get("rootDid") == expected_root)
    check("Method fragment derivation", p01.get("methodFragment") == expected_fragment)
    check("Verification Method DID URL", p01.get("methodDidUrl") == expected_vm_id)
    check("Ed25519 multicodec varint", uvarint(ED25519_PUB_MULTICODEC) == bytes.fromhex("ed01"))
    check("Ed25519 publicKeyMultibase", p01.get("publicKeyMultibase") == expected_key_mb)

    doc = p01.get("didDocument")
    check("Multikey structure",
          isinstance(doc, dict) and doc.get("verificationMethod") == [expected_vm])
    check("Controller binding", doc["verificationMethod"][0]["controller"] == expected_root)
    check("capabilityInvocation",
          p01.get("capabilityInvocation") == [expected_vm_id]
          and doc.get("capabilityInvocation") == [expected_vm_id])
    check("SINGLE policy semantics",
          p01.get("verificationPolicy") == expected_policy
          and doc.get("openIdentityVerificationPolicy") == expected_policy)
    check("OpenIdentity context",
          doc.get("@context") == [DID_CONTEXT, MULTIKEY_CONTEXT, OI_CONTEXT])
    check("DID document structure", doc == expected_doc)

    forbidden = {"authentication", "assertionMethod", "keyAgreement",
                 "capabilityDelegation"}
    check("No accidental additional verification authority",
          not any(k in doc for k in forbidden))

    # Ensure projection convenience copies are actually linked to the normative source.
    check("Projection source fields match V01",
          p01.get("identityHex") == v01["identityHex"]
          and p01.get("methodIdHex") == v01["ed25519MethodIdHex"]
          and p01.get("publicKeyHex") == v01["ed25519PublicKeyHex"]
          and p01.get("algorithm") == "Ed25519")

    print()
    print("P01 VERIFIED")

    verify_p02(source, projected)
    verify_p03(source, projected)
    verify_p04(source, projected)

    print()
    print("=" * 44)
    print("W3C PROJECTION P01-P04 VERIFIED")
    print("=" * 44)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AssertionError, KeyError, ValueError, json.JSONDecodeError) as e:
        print()
        print(f"W3C PROJECTION VERIFICATION FAILED: {e}", file=sys.stderr)
        raise SystemExit(1)
