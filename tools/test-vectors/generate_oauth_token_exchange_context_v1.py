#!/usr/bin/env python3
"""Generate draft OpenIdentity OAuth token-exchange context vectors."""
import base64,hashlib,json
from pathlib import Path
import cbor2
ROOT=Path(__file__).resolve().parents[2]
OUT=ROOT/"test-vectors"/"generated"/"oauth-token-exchange-context-v1.json"
def h(b):return hashlib.sha256(b).digest()
def mh(b):return b"\x12\x20"+h(b)
def enc(x):return cbor2.dumps(x,canonical=True)
def tx01():
    eid=mh(b"OpenIdentity OAuth TX01 delegation evidence")
    # Deterministic RFC 9449-shaped jkt fixture: base64url-no-pad of 32 bytes.
    jkt=base64.urlsafe_b64encode(h(b"OpenIdentity OAuth TX01 DPoP public JWK")).rstrip(b"=")
    resources=sorted([b"https://api.example.test/v2",b"https://api.example.test/v1"])
    audiences=sorted([b"records-service",b"audit-service"])
    scopes=sorted([b"records.write",b"records.read"])
    ctx={1:1,2:b"https://as.example.test",3:b"agent-client-016",
         4:b"urn:ietf:params:oauth:token-type:access_token",
         5:resources,6:audiences,7:scopes,8:eid,9:jkt}
    cb=enc(ctx);ch=mh(cb)
    return {"id":"TX01","description":"Canonical delegated-agent token-exchange context with DPoP","expected":"PASS",
      "authorizationServer":"https://as.example.test","clientId":"agent-client-016",
      "requestedTokenType":"urn:ietf:params:oauth:token-type:access_token",
      "resources":[x.decode() for x in resources],"audiences":[x.decode() for x in audiences],"scopes":[x.decode() for x in scopes],
      "delegationEvidenceIdHex":eid.hex(),"dpopJkt":jkt.decode(),"contextBytesHex":cb.hex(),"contextHashHex":ch.hex()}


def boundary_context(resources,audiences,scopes,label):
    eid=mh(("OpenIdentity OAuth "+label+" evidence").encode())
    jkt=base64.urlsafe_b64encode(h(("OpenIdentity OAuth "+label+" DPoP").encode())).rstrip(b"=")
    ctx={1:1,2:b"https://as.example.test",3:b"boundary-client",5:sorted(resources),6:sorted(audiences),
         7:sorted(scopes),8:eid,9:jkt}
    cb=enc(ctx)
    return {"id":label,"description":"Exact collection-count boundary","expected":"PASS",
            "resourceCount":len(resources),"audienceCount":len(audiences),"scopeCount":len(scopes),
            "contextBytesHex":cb.hex(),"contextHashHex":mh(cb).hex()}

def tx02():
    return boundary_context([f"https://api{i:02d}.example.test/".encode() for i in range(16)],[],[],"TX02")
def tx03():
    return boundary_context([],[f"aud-{i:02d}".encode() for i in range(16)],[],"TX03")
def tx04():
    return boundary_context([],[],[f"s{i:02d}".encode() for i in range(64)],"TX04")


def invalids():
    out=[]
    def add(i,e,a,**kw):out.append({"id":i,"expectedError":e,"attack":a,**kw})
    add("TXI01","INVALID_CONTEXT_VERSION","unsupported-context-version",submittedVersion=2,supportedVersion=1)
    add("TXI02","DUPLICATE_SCOPE","duplicate-scope-token",scopes=["records.read","records.read"])
    add("TXI03","NONCANONICAL_SCOPE_ORDER","unsorted-scope-set",scopes=["records.write","records.read"],canonicalScopes=["records.read","records.write"])
    add("TXI04","DUPLICATE_RESOURCE","duplicate-resource",resources=["https://api.example.test/v1","https://api.example.test/v1"])
    add("TXI05","NONCANONICAL_RESOURCE_ORDER","unsorted-resource-set",
        resources=["https://api.example.test/v2","https://api.example.test/v1"],
        canonicalResources=["https://api.example.test/v1","https://api.example.test/v2"])
    add("TXI06","INVALID_RESOURCE","resource-not-absolute-uri",resource="/relative/resource")
    add("TXI07","INVALID_RESOURCE","resource-has-fragment",resource="https://api.example.test/v1#fragment")
    add("TXI08","DUPLICATE_AUDIENCE","duplicate-audience",audiences=["records-service","records-service"])
    add("TXI09","NONCANONICAL_AUDIENCE_ORDER","unsorted-audience-set",
        audiences=["records-service","audit-service"],canonicalAudiences=["audit-service","records-service"])
    add("TXI10","INVALID_SCOPE","scope-token-contains-space",scope="records read")
    add("TXI11","INVALID_DELEGATION_EVIDENCE_ID","wrong-multihash-code",
        submittedHex=(b"\x13\x20"+h(b"wrong hash profile")).hex(),expectedMultihashCode=0x12,submittedMultihashCode=0x13)
    add("TXI12","INVALID_DPOP_JKT","missing-dpop-jkt",dpopJktPresent=False,required=True)
    add("TXI13","INVALID_DPOP_JKT","wrong-dpop-jkt-length",dpopJktLength=42,requiredLength=43)
    add("TXI14","TOO_MANY_RESOURCES","resource-count-over-limit",count=17,maximum=16)
    add("TXI15","TOO_MANY_AUDIENCES","audience-count-over-limit",count=17,maximum=16)
    add("TXI16","TOO_MANY_SCOPES","scope-count-over-limit",count=65,maximum=64)
    add("TXI17","INVALID_AUTHORIZATION_SERVER","authorization-server-too-long",length=2049,maximum=2048)
    add("TXI18","INVALID_CLIENT_ID","client-id-too-long",length=513,maximum=512)
    add("TXI19","INVALID_REQUESTED_TOKEN_TYPE","requested-token-type-too-long",length=2049,maximum=2048)
    add("TXI20","INVALID_RESOURCE","resource-too-long",length=2049,maximum=2048)
    add("TXI21","INVALID_AUDIENCE","audience-too-long",length=1025,maximum=1024)
    add("TXI22","INVALID_SCOPE","scope-too-long",length=257,maximum=256)
    add("TXI23","INVALID_DELEGATION_EVIDENCE_ID","malformed-multihash-length-prefix",
        submittedHex=(b"\x12\x1f"+bytes(32)).hex(),submittedDigestLengthPrefix=31,requiredDigestLengthPrefix=32)
    add("TXI24","INVALID_DELEGATION_EVIDENCE_ID","malformed-multihash-total-length",submittedLength=33,requiredLength=34)
    add("TXI25","INVALID_DPOP_JKT","invalid-base64url-character",
        dpopJkt=("A"*42)+"+",length=43,invalidCharacter="+")
    add("TXI26","INVALID_DPOP_JKT","padding-not-allowed",
        dpopJkt=("A"*42)+"=",length=43,invalidCharacter="=")

    return out

def main():
    d={"specification":"OpenIdentity OAuth Token Exchange Context v1","status":"DRAFT-NON-NORMATIVE","vectors":[tx01(),tx02(),tx03(),tx04()],"invalidVectors":invalids()}
    OUT.parent.mkdir(parents=True,exist_ok=True);OUT.write_text(json.dumps(d,indent=2)+"\n",encoding="utf-8",newline="\n")
    print("Wrote",OUT.relative_to(ROOT));print("TX01-TX04 GENERATED");print("TXI01-TXI26 GENERATED")
if __name__=="__main__":main()
