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
def main():
    d={"specification":"OpenIdentity OAuth Token Exchange Context v1","status":"DRAFT-NON-NORMATIVE","vectors":[tx01()],"invalidVectors":[]}
    OUT.parent.mkdir(parents=True,exist_ok=True);OUT.write_text(json.dumps(d,indent=2)+"\n",encoding="utf-8",newline="\n")
    print("Wrote",OUT.relative_to(ROOT));print("TX01 GENERATED")
if __name__=="__main__":main()
