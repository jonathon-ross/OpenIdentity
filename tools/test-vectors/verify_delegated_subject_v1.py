#!/usr/bin/env python3
"""Independently verify draft OI-016 DS01."""
import hashlib,json
from pathlib import Path
import cbor2
ROOT=Path(__file__).resolve().parents[2]
P=ROOT/"test-vectors"/"generated"/"delegated-subject-v1.json"
def h(b):return hashlib.sha256(b).digest()
def mh(b):return b"\x12\x20"+h(b)
def enc(x):return cbor2.dumps(x,canonical=True)
def req(n,v):
    if not v:raise AssertionError(n)
    print(" ",n+": PASS")
def main():
    d=json.loads(P.read_text());req("suite specification",d["specification"]=="OpenIdentity OI-016 Delegated Subject Token v1")
    req("draft status",d["status"]=="DRAFT-NON-NORMATIVE");req("vector IDs DS01-DS02",[x["id"] for x in d["vectors"]]==["DS01","DS02"])
    v=d["vectors"][0];root=bytes(range(32));delegate=bytes(range(32,64))
    ph=mh(b"OI-016 DS01 capability profile");grant={1:1,2:root,3:{1:1,2:root},4:{1:1,2:delegate},
      5:[{1:{1:{1:1,2:ph},2:b"document.read"}}],7:2002003600,9:h(b"OpenIdentity OI-016 DS01 grant nonce")}
    gb=enc(grant);gid=mh(gb);req("DS01 GrantBytes",v["grantBytesHex"]==gb.hex());req("DS01 GrantId",v["grantIdHex"]==gid.hex())
    evidence={1:1,2:b"openidentity:test:oi016:ds01",3:[{1:gb,2:gid}]};eb=enc(evidence);eid=mh(eb)
    req("DS01 DelegationEvidenceBytes",v["delegationEvidenceBytesHex"]==eb.hex());req("DS01 DelegationEvidenceId",v["delegationEvidenceIdHex"]==eid.hex())
    assertion={1:1,2:delegate,3:mh(b"OI-016 DS01 actor state"),4:5,5:b"oi016-test-verifier",6:"openidentity.authentication",
      7:2002000000,8:2002000120,9:bytes(range(64,96)),10:mh(eid)}
    ab=enc(assertion);aid=mh(ab);req("DS01 actor AssertionBytes",v["actorAssertionBytesHex"]==ab.hex());req("DS01 actorAssertionId",v["actorAssertionIdHex"]==aid.hex())
    token={1:1,2:evidence,3:aid};tb=enc(token);req("DS01 token bytes",v["delegatedSubjectTokenBytesHex"]==tb.hex());req("DS01 token id",v["delegatedSubjectTokenIdHex"]==mh(tb).hex())
    req("DS01 actor equals terminal delegate",v["terminalDelegateHex"]==delegate.hex())
    v2=d["vectors"][1];root2=bytes(range(96,128));d1=bytes(range(128,160));d2=bytes(range(160,192))
    ph2=mh(b"OI-016 DS02 capability profile");pr2={1:1,2:ph2};cr2={1:pr2,2:b"records.read"}
    rp2={1:1,2:root2};d1p={1:1,2:d1};d2p={1:1,2:d2}
    parent={1:1,2:root2,3:rp2,4:d1p,5:[{1:cr2,2:b"tenant/alpha/*"}],7:2002013600,9:h(b"OpenIdentity OI-016 DS02 parent nonce")}
    pbytes=enc(parent);pid=mh(pbytes)
    child={1:1,2:root2,3:d1p,4:d2p,5:[{1:cr2,2:b"tenant/alpha/record/42"}],7:2002011800,8:pid,9:h(b"OpenIdentity OI-016 DS02 child nonce")}
    cbytes=enc(child);cid=mh(cbytes)
    req("DS02 parent GrantId",v2["parentGrantIdHex"]==pid.hex());req("DS02 child GrantId",v2["childGrantIdHex"]==cid.hex())
    req("DS02 child parentGrantId links parent",v2["childParentGrantIdHex"]==pid.hex())
    req("DS02 child issuer equals parent delegate",v2["childIssuerHex"]==v2["parentDelegateHex"]==d1.hex())
    req("DS02 rootGrantor preserved",v2["rootGrantorHex"]==root2.hex())
    evidence2={1:1,2:b"openidentity:test:oi016:ds02",3:[{1:pbytes,2:pid},{1:cbytes,2:cid}]};eb2=enc(evidence2);eid2=mh(eb2)
    req("DS02 DelegationEvidenceBytes",v2["delegationEvidenceBytesHex"]==eb2.hex());req("DS02 DelegationEvidenceId",v2["delegationEvidenceIdHex"]==eid2.hex())
    actor2={1:1,2:d2,3:mh(b"OI-016 DS02 actor state"),4:11,5:b"oi016-ds02-verifier",6:"openidentity.authentication",
            7:2002010000,8:2002010120,9:bytes(range(192,224)),10:mh(eid2)}
    ab2=enc(actor2);aid2=mh(ab2);req("DS02 actorAssertionId",v2["actorAssertionIdHex"]==aid2.hex())
    req("DS02 actor equals terminal delegate",v2["terminalDelegateHex"]==d2.hex())
    tb2=enc({1:1,2:evidence2,3:aid2});req("DS02 token bytes",v2["delegatedSubjectTokenBytesHex"]==tb2.hex());req("DS02 token id",v2["delegatedSubjectTokenIdHex"]==mh(tb2).hex())

    print("\n============================================");print("OI-016 DELEGATED SUBJECT v1 DS01-DS02 VERIFIED");print("============================================")
if __name__=="__main__":main()
