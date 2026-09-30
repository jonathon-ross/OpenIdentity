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
    req("draft status",d["status"]=="DRAFT-NON-NORMATIVE");req("DS01 only",[x["id"] for x in d["vectors"]]==["DS01"])
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
    print("\n============================================");print("OI-016 DELEGATED SUBJECT v1 DS01 VERIFIED");print("============================================")
if __name__=="__main__":main()
