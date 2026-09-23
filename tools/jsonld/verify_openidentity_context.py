import argparse, json, sys
from pathlib import Path

try:
    from pyld import jsonld
except ImportError:
    print("Install PyLD: pip install PyLD", file=sys.stderr);
    sys.exit(2)
NS = "https://openidentity.foundation/ns#";
XSD = "http://www.w3.org/2001/XMLSchema#integer";
URL = "https://openidentity.foundation/ns/v1"


def fail(m): print("\nFAILED\n------\n" + m);sys.exit(1)


def ok(m): print("  " + m + ": PASS")


def main():
    p = argparse.ArgumentParser();
    p.add_argument("context_file", type=Path);
    a = p.parse_args()
    ctx = json.loads(a.context_file.read_text(encoding="utf-8"));
    c = ctx.get("@context")
    if not isinstance(c, dict): fail("Missing object @context")

    def loader(url, options=None):
        if url == URL: return {"contextUrl": None, "documentUrl": url, "document": ctx}
        raise jsonld.JsonLdError("Remote context blocked", "loading document failed", details={"url": url})

    print("\nOpenIdentity JSON-LD Context Verification\n" + "=" * 48)
    req = {"openIdentityVerificationPolicy", "appliesTo", "threshold", "Single", "Threshold"}
    if c.get("@protected") is not True or not req.issubset(c): fail("C01 structure invalid")
    ok("C01 context structure/load")
    local = {"id": "@id", "type": "@type",
             "verificationMethod": {"@id": "https://www.w3.org/ns/did#verificationMethod", "@type": "@id",
                                    "@container": "@set"},
             "capabilityInvocation": {"@id": "https://www.w3.org/ns/did#capabilityInvocation", "@type": "@id",
                                      "@container": "@set"}}
    tc = [URL, local]
    d = {"@context": tc, "id": "did:open:zExample#controller-policy", "type": "Threshold",
         "appliesTo": "capabilityInvocation", "threshold": 2,
         "verificationMethod": ["did:open:zExample#vm-A", "did:open:zExample#vm-B"]}
    try:
        e = jsonld.expand(d, options={"documentLoader": loader})
    except Exception as x:
        fail("C02 expansion: " + str(x))
    if not e or NS + "Threshold" not in e[0].get("@type", []): fail("C02 Threshold type wrong")
    vals = e[0].get(NS + "threshold", [])
    if not vals or vals[0].get("@value") != 2 or vals[0].get("@type") != XSD: fail("C02 threshold wrong")
    ok("C02 Threshold expansion")
    s = dict(d);
    s["type"] = "Single";
    s.pop("threshold");
    s["verificationMethod"] = ["did:open:zExample#vm-A"]
    try:
        se = jsonld.expand(s, options={"documentLoader": loader})
    except Exception as x:
        fail("C03 expansion: " + str(x))
    if not se or NS + "Single" not in se[0].get("@type", []): fail("C03 Single type wrong")
    ok("C03 SINGLE expansion")
    try:
        compact = jsonld.compact(e, tc, options={"documentLoader": loader});
        e2 = jsonld.expand(compact, options={"documentLoader": loader})
    except Exception as x:
        fail("C04 round trip: " + str(x))
    if json.dumps(e, sort_keys=True) != json.dumps(e2, sort_keys=True): fail(
        "C04 semantic round trip changed expansion")
    ok("C04 semantic round trip")
    bad = {"@context": [URL, {"threshold": "https://evil.example/threshold"}], "threshold": 2}
    try:
        jsonld.expand(bad, options={"documentLoader": loader})
    except Exception:
        ok("C05 protected-term redefinition rejected")
    else:
        fail("C05 protected term redefinition accepted")
    if "@vocab" in c: fail("C06 context MUST NOT define @vocab")
    u = {"@context": URL, "totallyUnknownOpenIdentityTerm": "value"}
    try:
        ue = jsonld.expand(u, options={"documentLoader": loader})
    except Exception as x:
        fail("C06 expansion: " + str(x))
    if ue and NS + "totallyUnknownOpenIdentityTerm" in ue[0]: fail("C06 unknown term leaked into OI vocabulary")
    ok("C06 no accidental vocabulary leakage")
    vp = c["openIdentityVerificationPolicy"]
    if isinstance(vp, dict) and vp.get("@type") == "@id": fail(
        "DESIGN REVIEW: remove @type:@id from openIdentityVerificationPolicy; its value is an embedded policy object.")
    print("\n" + "=" * 48 + "\nOPENIDENTITY JSON-LD CONTEXT CANDIDATE PASSED\n" + "=" * 48)


if __name__ == "__main__": main()
