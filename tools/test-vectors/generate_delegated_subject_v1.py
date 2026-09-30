#!/usr/bin/env python3
"""Generate draft OI-016 Delegated Subject Token vectors. Draft/non-normative."""
import hashlib,json
from pathlib import Path
import cbor2
ROOT=Path(__file__).resolve().parents[2]
OUT=ROOT/"test-vectors"/"generated"/"delegated-subject-v1.json"
def h(b):return hashlib.sha256(b).digest()
def mh(b):return b"\x12\x20"+h(b)
def enc(x):return cbor2.dumps(x,canonical=True)

def ds01():
    # Minimal direct OI-014-shaped grant fixture. This vector pins OI-016
    # deterministic evidence/binding bytes; later vectors expand full path semantics.
    root=bytes(range(32));delegate=bytes(range(32,64))
    profile_hash=mh(b"OI-016 DS01 capability profile")
    profile_ref={1:1,2:profile_hash}
    cap_ref={1:profile_ref,2:b"document.read"}
    delegated_cap={1:cap_ref}
    root_principal={1:1,2:root}
    delegate_principal={1:1,2:delegate}
    grant={1:1,2:root,3:root_principal,4:delegate_principal,5:[delegated_cap],
           7:2002003600,9:h(b"OpenIdentity OI-016 DS01 grant nonce")}
    gb=enc(grant);gid=mh(gb)
    registry=b"openidentity:test:oi016:ds01"
    evidence={1:1,2:registry,3:[{1:gb,2:gid}]}
    eb=enc(evidence);eid=mh(eb)
    # OI-015 AssertionId is a derived commitment to exact assertion bytes.
    actor_assertion={1:1,2:delegate,3:mh(b"OI-016 DS01 actor state"),4:5,
                     5:b"oi016-test-verifier",6:"openidentity.authentication",
                     7:2002000000,8:2002000120,9:bytes(range(64,96)),10:mh(eid)}
    actor_bytes=enc(actor_assertion);aid=mh(actor_bytes)
    token={1:1,2:evidence,3:aid};tb=enc(token);tid=mh(tb)
    return {"id":"DS01","description":"Direct grant evidence bound to exact OI-015 AssertionId","expected":"PASS",
      "grantBytesHex":gb.hex(),"grantIdHex":gid.hex(),"registryDomainHex":registry.hex(),
      "delegationEvidenceBytesHex":eb.hex(),"delegationEvidenceIdHex":eid.hex(),
      "actorAssertionBytesHex":actor_bytes.hex(),"actorAssertionIdHex":aid.hex(),
      "delegatedSubjectTokenBytesHex":tb.hex(),"delegatedSubjectTokenIdHex":tid.hex(),
      "rootGrantorHex":root.hex(),"terminalDelegateHex":delegate.hex()}

def main():
    data={"specification":"OpenIdentity OI-016 Delegated Subject Token v1","status":"DRAFT-NON-NORMATIVE",
          "vectors":[ds01()],"invalidVectors":[]}
    OUT.parent.mkdir(parents=True,exist_ok=True)
    OUT.write_text(json.dumps(data,indent=2)+"\n",encoding="utf-8",newline="\n")
    print("Wrote",OUT.relative_to(ROOT));print("DS01 GENERATED")
if __name__=="__main__":main()
