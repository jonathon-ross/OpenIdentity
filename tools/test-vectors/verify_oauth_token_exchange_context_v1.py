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
    req("draft status",d["status"]=="DRAFT-NON-NORMATIVE");req("vector IDs TX01-TX04",[x["id"] for x in d["vectors"]]==["TX01","TX02","TX03","TX04"])
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
    inv={x["id"]:x for x in d["invalidVectors"]};req("invalid vector IDs TXI01-TXI35",set(inv)=={f"TXI{i:02d}" for i in range(1,36)})
    errors=["INVALID_CONTEXT_VERSION","DUPLICATE_SCOPE","NONCANONICAL_SCOPE_ORDER","DUPLICATE_RESOURCE","NONCANONICAL_RESOURCE_ORDER",
            "INVALID_RESOURCE","INVALID_RESOURCE","DUPLICATE_AUDIENCE","NONCANONICAL_AUDIENCE_ORDER","INVALID_SCOPE",
            "INVALID_DELEGATION_EVIDENCE_ID","INVALID_DPOP_JKT","INVALID_DPOP_JKT","TOO_MANY_RESOURCES","TOO_MANY_AUDIENCES","TOO_MANY_SCOPES",
            "INVALID_AUTHORIZATION_SERVER","INVALID_CLIENT_ID","INVALID_REQUESTED_TOKEN_TYPE","INVALID_RESOURCE","INVALID_AUDIENCE","INVALID_SCOPE",
            "INVALID_DELEGATION_EVIDENCE_ID","INVALID_DELEGATION_EVIDENCE_ID","INVALID_DPOP_JKT","INVALID_DPOP_JKT",
            "AUTHORIZATION_SERVER_MISMATCH","CLIENT_ID_MISMATCH","REQUESTED_TOKEN_TYPE_MISMATCH","REQUESTED_TOKEN_TYPE_MISMATCH",
            "RESOURCE_SET_MISMATCH","AUDIENCE_SET_MISMATCH","SCOPE_SET_MISMATCH","DELEGATION_EVIDENCE_MISMATCH","DPOP_KEY_MISMATCH"]
    req("TXI01-TXI35 stable errors",all(inv[f"TXI{i:02d}"]["expectedError"]==errors[i-1] for i in range(1,36)))
    req("TXI01 unsupported version",inv["TXI01"]["submittedVersion"]!=inv["TXI01"]["supportedVersion"])
    req("TXI02 duplicate scope",len(set(inv["TXI02"]["scopes"]))!=len(inv["TXI02"]["scopes"]))
    req("TXI03 scope order noncanonical",inv["TXI03"]["scopes"]!=inv["TXI03"]["canonicalScopes"])
    req("TXI04 duplicate resource",len(set(inv["TXI04"]["resources"]))!=len(inv["TXI04"]["resources"]))
    req("TXI05 resource order noncanonical",inv["TXI05"]["resources"]!=inv["TXI05"]["canonicalResources"])
    req("TXI06 relative resource rejected",not inv["TXI06"]["resource"].startswith(("http://","https://")))
    req("TXI07 resource fragment rejected","#" in inv["TXI07"]["resource"])
    req("TXI08 duplicate audience",len(set(inv["TXI08"]["audiences"]))!=len(inv["TXI08"]["audiences"]))
    req("TXI09 audience order noncanonical",inv["TXI09"]["audiences"]!=inv["TXI09"]["canonicalAudiences"])
    req("TXI10 scope contains forbidden space"," " in inv["TXI10"]["scope"])
    req("TXI11 wrong DelegationEvidenceId multihash",inv["TXI11"]["submittedMultihashCode"]!=inv["TXI11"]["expectedMultihashCode"])
    req("TXI12 DPoP jkt mandatory",inv["TXI12"]["required"] and not inv["TXI12"]["dpopJktPresent"])
    req("TXI13 DPoP jkt exact length",inv["TXI13"]["dpopJktLength"]!=inv["TXI13"]["requiredLength"])

    req("TX02 exact resource count",d["vectors"][1]["resourceCount"]==16)
    req("TX03 exact audience count",d["vectors"][2]["audienceCount"]==16)
    req("TX04 exact scope count",d["vectors"][3]["scopeCount"]==64)
    for n in ("TXI14","TXI15","TXI16"):req(n+" count over limit",inv[n]["count"]==inv[n]["maximum"]+1)
    for n in ("TXI17","TXI18","TXI19","TXI20","TXI21","TXI22"):req(n+" length over limit",inv[n]["length"]==inv[n]["maximum"]+1)
    req("TXI23 wrong digest-length prefix",inv["TXI23"]["submittedDigestLengthPrefix"]!=inv["TXI23"]["requiredDigestLengthPrefix"])
    req("TXI24 wrong multihash total length",inv["TXI24"]["submittedLength"]!=inv["TXI24"]["requiredLength"])
    allowed=set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
    req("TXI25 invalid base64url character",any(c not in allowed for c in inv["TXI25"]["dpopJkt"]))
    req("TXI26 base64url padding forbidden","=" in inv["TXI26"]["dpopJkt"])

    for n in range(27,36):
        x=inv[f"TXI{n:02d}"];req(f"TXI{n:02d} substitution changes contextHash",x["originalContextHashHex"]!=x["substitutedContextHashHex"])

    print("\n============================================");print("OPENIDENTITY OAUTH TOKEN EXCHANGE CONTEXT v1 TX01-TX04 + TXI01-TXI35 VERIFIED");print("============================================")
if __name__=="__main__":main()
