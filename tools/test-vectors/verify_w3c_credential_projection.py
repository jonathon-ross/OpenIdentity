#!/usr/bin/env python3
import base64, json, sys
from datetime import datetime, timezone
from pathlib import Path

ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
CONTEXTS = [
    "https://www.w3.org/ns/credentials/v2",
    "https://openidentity.foundation/ns/v2",
    "https://openidentity.foundation/test/credentials/basic/v1/context",
]
TYPES = [
    "VerifiableCredential",
    "OpenIdentityCredential",
    "OpenIdentityBasicCredential",
]
PROFILE = "https://openidentity.foundation/test/credentials/basic/v1"


def check(label, ok):
    if not ok:
        raise AssertionError(label)
    print(f"  {label}: PASS")


def hx(s): return bytes.fromhex(s)


def mb64(b):
    return "u" + base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def b58(b):
    n = int.from_bytes(b, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = ALPHABET[r] + out
    zeros = len(b) - len(b.lstrip(b"\x00"))
    return "1" * zeros + (out or ("" if zeros else "1"))


def mb58(b): return "z" + b58(b)


def did_open(identity): return "did:open:" + mb58(identity)


def timestamp(seconds):
    return datetime.fromtimestamp(seconds, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def verify_one(wp_doc, native_doc, wp_id, native_id, expected_role):
    w = wp_doc["vector"]
    n = native_doc["vector"]

    print()
    print(f"{wp_id} W3C Credential Projection")
    print("-" * 44)

    check(f"{wp_id} specification", wp_doc["specification"] == "OpenIdentity W3C Credential Projection")
    check(f"{wp_id} projection suite version", wp_doc["version"] == "0.1")
    check(f"{wp_id} vector ID", w["id"] == wp_id)
    check(f"{wp_id} source credential vector", w["sourceCredentialVector"] == native_id)
    check(f"{wp_id} native source ID", n["id"] == native_id)
    check(f"{wp_id} projection version", w["projectionVersion"] == 1)

    credential_id = hx(n["credentialIdHex"])
    issuer = hx(n["issuerIdentityHex"])
    state_hash = hx(n["issuanceStateHashHex"])
    subject = hx(n["credentialSubjectHex"])
    secured = hx(n["securedCredentialHex"])

    check(f"{wp_id} credential ID length", len(credential_id) == 32)
    check(f"{wp_id} issuer identity length", len(issuer) == 32)
    check(f"{wp_id} issuance StateHash length", len(state_hash) == 34)
    check(f"{wp_id} Basic v1 profile", n["credentialProfile"] == PROFILE)
    check(f"{wp_id} subject exact bytes", subject == b"alice@example.test")
    check(f"{wp_id} Basic v1 claims exactly present",
          set(n["claims"]) == {"name", "role", "active"})
    check(f"{wp_id} name claim", n["claims"]["name"] == "Alice Example")
    check(f"{wp_id} role claim", n["claims"]["role"] == expected_role)
    check(f"{wp_id} active claim", n["claims"]["active"] is True)

    expected_id = "urn:openidentity:credential:" + mb64(credential_id)
    expected_issuer = did_open(issuer)
    expected_subject_id = "urn:openidentity:test-subject:" + mb64(subject)
    expected_state = mb58(state_hash)
    expected_secured = mb64(secured)
    expected_from = timestamp(n["validFrom"])
    expected_until = timestamp(n["validUntil"])

    check(f"{wp_id} credential ID URI independently derived",
          w["credentialIdUri"] == expected_id)
    check(f"{wp_id} issuer DID independently derived",
          w["issuerDid"] == expected_issuer)
    check(f"{wp_id} contexts exact and ordered", w["contexts"] == CONTEXTS)
    check(f"{wp_id} types exact and ordered", w["types"] == TYPES)
    check(f"{wp_id} validFrom independently derived", w["validFrom"] == expected_from)
    check(f"{wp_id} validUntil independently derived", w["validUntil"] == expected_until)
    check(f"{wp_id} credential profile preserved", w["credentialProfile"] == PROFILE)
    check(f"{wp_id} issuance StateHash Multibase independently derived",
          w["issuanceStateHashMultibase"] == expected_state)
    check(f"{wp_id} SecuredCredential Multibase independently derived",
          w["securedCredentialMultibase"] == expected_secured)

    # Round-trip exact native bytes, not just string equality.
    encoded = w["securedCredentialMultibase"]
    pad = "=" * ((4 - len(encoded[1:]) % 4) % 4)
    decoded_secured = base64.urlsafe_b64decode(encoded[1:] + pad)
    check(f"{wp_id} native SecuredCredential exact round-trip",
          decoded_secured == secured)

    expected_subject = {
        "id": expected_subject_id,
        "name": "Alice Example",
        "role": expected_role,
        "active": True,
    }
    check(f"{wp_id} Basic v1 credentialSubject independently derived",
          w["credentialSubject"] == expected_subject)

    expected_projection = {
        "@context": CONTEXTS,
        "id": expected_id,
        "type": TYPES,
        "issuer": expected_issuer,
        "validFrom": expected_from,
        "validUntil": expected_until,
        "credentialSubject": expected_subject,
        "openIdentityCredentialProfile": PROFILE,
        "openIdentityIssuanceStateHash": expected_state,
        "openIdentitySecuredCredential": expected_secured,
    }
    check(f"{wp_id} complete semantic W3C projection independently reconstructed",
          w["w3cCredential"] == expected_projection)
    check(f"{wp_id} W3C proof absent",
          "proof" not in w["w3cCredential"] and w["containsW3cProof"] is False)

    print()
    print(f"{wp_id} VERIFIED")


def decode_mb64(value):
    if not isinstance(value, str) or not value.startswith("u"):
        raise ValueError("expected multibase base64url value")
    raw=value[1:]
    raw += "=" * ((4 - len(raw) % 4) % 4)
    return base64.urlsafe_b64decode(raw)


def expected_projection_from_native(n):
    credential_id=hx(n["credentialIdHex"])
    issuer=hx(n["issuerIdentityHex"])
    state_hash=hx(n["issuanceStateHashHex"])
    subject=hx(n["credentialSubjectHex"])
    secured=hx(n["securedCredentialHex"])
    claims=n["claims"]
    subject_obj={
        "id":"urn:openidentity:test-subject:"+mb64(subject),
        "name":claims["name"],
        "role":claims["role"],
        "active":claims["active"],
    }
    return {
        "@context": CONTEXTS,
        "id":"urn:openidentity:credential:"+mb64(credential_id),
        "type":TYPES,
        "issuer":did_open(issuer),
        "validFrom":timestamp(n["validFrom"]),
        "validUntil":timestamp(n["validUntil"]),
        "credentialSubject":subject_obj,
        "openIdentityCredentialProfile":n["credentialProfile"],
        "openIdentityIssuanceStateHash":mb58(state_hash),
        "openIdentitySecuredCredential":mb64(secured),
    }


def verify_invalid_suite(doc, c01_doc):
    print()
    print("WPI01-WPI10 Invalid/Security Verification")
    print("-"*44)

    vectors=doc["vectors"]
    check("Invalid suite specification",
          doc["specification"]=="OpenIdentity W3C Credential Projection")
    check("Invalid suite version",doc["version"]=="0.1")
    check("Invalid suite type",doc["type"]=="invalid-conformance-vectors")
    check("Invalid suite projection version",doc["projectionVersion"]==1)
    check("Invalid suite contains exactly 10 vectors",len(vectors)==10)
    check("Invalid suite IDs WPI01-WPI10",
          [v["id"] for v in vectors]==[f"WPI{i:02d}" for i in range(1,11)])

    expected_errors={
        "WPI01":"INVALID_PROJECTED_ISSUER",
        "WPI02":"INVALID_PROJECTED_CREDENTIAL_ID",
        "WPI03":"INVALID_PROJECTED_VALIDITY",
        "WPI04":"INVALID_PROJECTED_ISSUANCE_STATE_HASH",
        "WPI05":"INVALID_NATIVE_SECURED_CREDENTIAL",
        "WPI06":"INVALID_PROJECTED_SUBJECT",
        "WPI07":"INVALID_PROJECTED_CLAIMS",
        "WPI08":"UNSUPPORTED_PROJECTION_CONTEXT",
        "WPI09":"MISLEADING_W3C_PROOF",
        "WPI10":"HISTORICAL_ASSERTION_AUTHORITY_REQUIRED",
    }
    by={v["id"]:v for v in vectors}
    for cid,err in expected_errors.items():
        check(f"{cid} expected error label",by[cid]["expectedError"]==err)
        check(f"{cid} source projection is WP01",
              by[cid]["sourceProjectionVector"]=="WP01")

    n=c01_doc["vector"]
    expected=expected_projection_from_native(n)
    native_secured=hx(n["securedCredentialHex"])
    native_state_hash=hx(n["issuanceStateHashHex"])

    # WPI01
    p=by["WPI01"]["w3cCredential"]
    check("WPI01 native issuer independently derived",
          expected["issuer"]==did_open(hx(n["issuerIdentityHex"])))
    check("WPI01 projected issuer differs from signed native issuer",
          p["issuer"]!=expected["issuer"])
    print("  WPI01 REJECTED: INVALID_PROJECTED_ISSUER")

    # WPI02
    p=by["WPI02"]["w3cCredential"]
    check("WPI02 native credential ID URI independently derived",
          expected["id"]=="urn:openidentity:credential:"+mb64(hx(n["credentialIdHex"])))
    check("WPI02 projected credential ID differs from signed native credentialId",
          p["id"]!=expected["id"])
    print("  WPI02 REJECTED: INVALID_PROJECTED_CREDENTIAL_ID")

    # WPI03
    p=by["WPI03"]["w3cCredential"]
    check("WPI03 native validFrom independently derived",
          expected["validFrom"]==timestamp(n["validFrom"]))
    check("WPI03 projected validFrom differs from signed native validFrom",
          p["validFrom"]!=expected["validFrom"])
    check("WPI03 projected validUntil remains authoritative",
          p["validUntil"]==expected["validUntil"])
    print("  WPI03 REJECTED: INVALID_PROJECTED_VALIDITY")

    # WPI04
    p=by["WPI04"]["w3cCredential"]
    check("WPI04 native issuance StateHash Multibase independently derived",
          expected["openIdentityIssuanceStateHash"]==mb58(native_state_hash))
    check("WPI04 projected issuance StateHash differs from signed native StateHash",
          p["openIdentityIssuanceStateHash"]!=expected["openIdentityIssuanceStateHash"])
    check("WPI04 embedded native SecuredCredential remains intact",
          decode_mb64(p["openIdentitySecuredCredential"])==native_secured)
    print("  WPI04 REJECTED: INVALID_PROJECTED_ISSUANCE_STATE_HASH")

    # WPI05
    p=by["WPI05"]["w3cCredential"]
    corrupted=decode_mb64(p["openIdentitySecuredCredential"])
    check("WPI05 embedded SecuredCredential decodes",isinstance(corrupted,bytes))
    check("WPI05 embedded native bytes differ from authoritative C01",
          corrupted!=native_secured)
    check("WPI05 corruption preserves byte length",
          len(corrupted)==len(native_secured))
    print("  WPI05 REJECTED: INVALID_NATIVE_SECURED_CREDENTIAL")

    # WPI06
    p=by["WPI06"]["w3cCredential"]
    expected_subject=expected["credentialSubject"]
    check("WPI06 Basic v1 subject URN independently derived",
          expected_subject["id"]=="urn:openidentity:test-subject:"
          +mb64(hx(n["credentialSubjectHex"])))
    check("WPI06 projected subject ID differs from Basic v1 derivation",
          p["credentialSubject"]["id"]!=expected_subject["id"])
    check("WPI06 projected claims otherwise unchanged",
          {k:p["credentialSubject"][k] for k in ("name","role","active")}
          =={k:expected_subject[k] for k in ("name","role","active")})
    print("  WPI06 REJECTED: INVALID_PROJECTED_SUBJECT")

    # WPI07
    p=by["WPI07"]["w3cCredential"]
    check("WPI07 signed native role is member",n["claims"]["role"]=="member")
    check("WPI07 projected role differs from signed native role",
          p["credentialSubject"]["role"]!=n["claims"]["role"])
    check("WPI07 projected name and active remain authoritative",
          p["credentialSubject"]["name"]==n["claims"]["name"]
          and p["credentialSubject"]["active"]==n["claims"]["active"])
    print("  WPI07 REJECTED: INVALID_PROJECTED_CLAIMS")

    # WPI08
    p=by["WPI08"]["w3cCredential"]
    check("WPI08 required context order independently known",CONTEXTS[1]
          =="https://openidentity.foundation/ns/v2")
    check("WPI08 projection does not use required context set",
          p["@context"]!=CONTEXTS)
    check("WPI08 substitutes immutable /ns/v1 for required /ns/v2",
          p["@context"][1]=="https://openidentity.foundation/ns/v1")
    print("  WPI08 REJECTED: UNSUPPORTED_PROJECTION_CONTEXT")

    # WPI09
    p=by["WPI09"]["w3cCredential"]
    check("WPI09 misleading W3C proof is present","proof" in p)
    check("WPI09 proof claims DataIntegrityProof",
          p["proof"].get("type")=="DataIntegrityProof")
    check("WPI09 proof claims assertionMethod purpose",
          p["proof"].get("proofPurpose")=="assertionMethod")
    check("WPI09 native SecuredCredential is still separately present",
          decode_mb64(p["openIdentitySecuredCredential"])==native_secured)
    print("  WPI09 REJECTED: MISLEADING_W3C_PROOF")

    # WPI10
    v=by["WPI10"]; p=v["w3cCredential"]
    required=hx(v["requiredHistoricalStateHashHex"])
    substituted=hx(v["substitutedCurrentStateHashHex"])
    check("WPI10 required historical vector is A01",
          v["requiredHistoricalAssertionVector"]=="A01")
    check("WPI10 substituted vector is A02",
          v["substitutedAssertionVector"]=="A02")
    check("WPI10 C01 issuance StateHash equals required historical A01 hash",
          native_state_hash==required)
    check("WPI10 substituted A02 StateHash differs from C01 issuance StateHash",
          substituted!=native_state_hash)
    check("WPI10 projection still carries exact C01 historical StateHash",
          p["openIdentityIssuanceStateHash"]==mb58(native_state_hash))
    check("WPI10 projection still embeds exact native C01 SecuredCredential",
          decode_mb64(p["openIdentitySecuredCredential"])==native_secured)
    check("WPI10 substituted current IdentityState is non-empty",
          len(hx(v["substitutedCurrentIdentityStateHex"]))>0)
    print("  WPI10 REJECTED: HISTORICAL_ASSERTION_AUTHORITY_REQUIRED")

    print()
    print("WPI01-WPI10 VERIFIED")

def locate(name):
    candidates = [
        Path.cwd() / "test-vectors" / "generated" / name,
        Path(__file__).resolve().parents[2] / "test-vectors" / "generated" / name,
        ]
    for p in candidates:
        if p.exists():
            return p
    raise FileNotFoundError(name)


def main():
    if len(sys.argv) == 1:
        wp01 = locate("w3c-credential-wp01-java.json")
        wp02 = locate("w3c-credential-wp02-java.json")
        c01 = locate("credential-c01-java.json")
        c02 = locate("credential-c02-java.json")
        invalid = locate("w3c-credential-invalid-java.json")
    elif len(sys.argv) == 6:
        wp01, wp02, c01, c02, invalid = map(Path, sys.argv[1:])
    else:
        print(f"Usage: {Path(sys.argv[0]).name} [wp01.json wp02.json c01.json c02.json invalid.json]", file=sys.stderr)
        return 2

    print("OpenIdentity W3C Credential Projection")
    print("Independent Verification")
    print("=" * 44)

    c01_doc=load(c01)
    c02_doc=load(c02)
    verify_one(load(wp01), c01_doc, "WP01", "C01", "member")
    verify_one(load(wp02), c02_doc, "WP02", "C02", "hybrid-member")
    verify_invalid_suite(load(invalid), c01_doc)

    print()
    print("=" * 44)
    print("OI-003 W3C CREDENTIAL PROJECTION")
    print("WP01-WP02 + WPI01-WPI10 VERIFIED")
    print("=" * 44)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AssertionError, KeyError, ValueError, FileNotFoundError, json.JSONDecodeError) as exc:
        print()
        print(f"W3C CREDENTIAL PROJECTION VERIFICATION FAILED: {exc}", file=sys.stderr)
        raise SystemExit(1)
