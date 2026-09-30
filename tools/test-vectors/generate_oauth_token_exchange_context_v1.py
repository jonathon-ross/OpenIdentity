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
    return out

def main():
    d={"specification":"OpenIdentity OAuth Token Exchange Context v1","status":"DRAFT-NON-NORMATIVE","vectors":[tx01()],"invalidVectors":invalids()}
    OUT.parent.mkdir(parents=True,exist_ok=True);OUT.write_text(json.dumps(d,indent=2)+"\n",encoding="utf-8",newline="\n")
    print("Wrote",OUT.relative_to(ROOT));print("TX01 GENERATED");print("TXI01-TXI13 GENERATED")
if __name__=="__main__":main()
