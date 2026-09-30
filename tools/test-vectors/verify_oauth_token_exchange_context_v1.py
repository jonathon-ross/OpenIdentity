#!/usr/bin/env python3
"""Independently verify draft OAuth token-exchange context TX01."""
import base64,hashlib,json
from pathlib import Path
import cbor2
ROOT=Path(__file__).resolve().parents[2];P=ROOT/"test-vectors"/"generated"/"oauth-token-exchange-context-v1.json"
def h(b):return hashlib.sha256(b).digest()
def mh(b):return b"\x12\x20"+h(b)
def enc(x):return cbor2.dumps(x,canonical=True)
def req(n,v):
    if not v:raise AssertionError(n)
    print(" ",n+": PASS")
def main():
    d=json.loads(P.read_text());req("suite specification",d["specification"]=="OpenIdentity OAuth Token Exchange Context v1")
    req("draft status",d["status"]=="DRAFT-NON-NORMATIVE");req("TX01 only",[x["id"] for x in d["vectors"]]==["TX01"])
    v=d["vectors"][0];eid=mh(b"OpenIdentity OAuth TX01 delegation evidence")
    jkt=base64.urlsafe_b64encode(h(b"OpenIdentity OAuth TX01 DPoP public JWK")).rstrip(b"=")
    resources=sorted([b"https://api.example.test/v2",b"https://api.example.test/v1"])
    audiences=sorted([b"records-service",b"audit-service"]);scopes=sorted([b"records.write",b"records.read"])
    req("TX01 resources canonical order",[x.decode() for x in resources]==v["resources"])
    req("TX01 audiences canonical order",[x.decode() for x in audiences]==v["audiences"])
    req("TX01 scopes canonical order",[x.decode() for x in scopes]==v["scopes"])
    req("TX01 DPoP jkt length",len(jkt)==43 and v["dpopJkt"]==jkt.decode())
    ctx={1:1,2:b"https://as.example.test",3:b"agent-client-016",4:b"urn:ietf:params:oauth:token-type:access_token",
         5:resources,6:audiences,7:scopes,8:eid,9:jkt}
    cb=enc(ctx);req("TX01 context bytes",v["contextBytesHex"]==cb.hex());req("TX01 contextHash",v["contextHashHex"]==mh(cb).hex())
    print("\n============================================");print("OPENIDENTITY OAUTH TOKEN EXCHANGE CONTEXT v1 TX01 VERIFIED");print("============================================")
if __name__=="__main__":main()
