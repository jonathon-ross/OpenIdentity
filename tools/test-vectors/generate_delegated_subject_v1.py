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


def ds02():
    root=bytes(range(96,128));delegate1=bytes(range(128,160));delegate2=bytes(range(160,192))
    profile_hash=mh(b"OI-016 DS02 capability profile")
    profile_ref={1:1,2:profile_hash};cap_ref={1:profile_ref,2:b"records.read"}
    parent_cap={1:cap_ref,2:b"tenant/alpha/*"}
    child_cap={1:cap_ref,2:b"tenant/alpha/record/42"}
    root_p={1:1,2:root};d1_p={1:1,2:delegate1};d2_p={1:1,2:delegate2}
    parent={1:1,2:root,3:root_p,4:d1_p,5:[parent_cap],7:2002013600,
            9:h(b"OpenIdentity OI-016 DS02 parent nonce")}
    pbytes=enc(parent);pid=mh(pbytes)
    child={1:1,2:root,3:d1_p,4:d2_p,5:[child_cap],7:2002011800,8:pid,
           9:h(b"OpenIdentity OI-016 DS02 child nonce")}
    cbytes=enc(child);cid=mh(cbytes)
    registry=b"openidentity:test:oi016:ds02"
    evidence={1:1,2:registry,3:[{1:pbytes,2:pid},{1:cbytes,2:cid}]}
    eb=enc(evidence);eid=mh(eb)
    actor={1:1,2:delegate2,3:mh(b"OI-016 DS02 actor state"),4:11,5:b"oi016-ds02-verifier",
           6:"openidentity.authentication",7:2002010000,8:2002010120,9:bytes(range(192,224)),10:mh(eid)}
    ab=enc(actor);aid=mh(ab)
    token={1:1,2:evidence,3:aid};tb=enc(token)
    return {"id":"DS02","description":"Two-grant root-to-child path bound to terminal delegate OI-015 assertion","expected":"PASS",
      "parentGrantBytesHex":pbytes.hex(),"parentGrantIdHex":pid.hex(),"childGrantBytesHex":cbytes.hex(),"childGrantIdHex":cid.hex(),
      "childParentGrantIdHex":pid.hex(),"rootGrantorHex":root.hex(),"parentDelegateHex":delegate1.hex(),
      "childIssuerHex":delegate1.hex(),"terminalDelegateHex":delegate2.hex(),"delegationEvidenceBytesHex":eb.hex(),
      "delegationEvidenceIdHex":eid.hex(),"actorAssertionBytesHex":ab.hex(),"actorAssertionIdHex":aid.hex(),
      "delegatedSubjectTokenBytesHex":tb.hex(),"delegatedSubjectTokenIdHex":mh(tb).hex()}



def invalids():
    out=[]
    def add(i,e,a,**kw):out.append({"id":i,"expectedError":e,"attack":a,**kw})
    add("DSI01","INVALID_DELEGATED_SUBJECT_VERSION","unsupported-version",submittedVersion=2,supportedVersion=1)
    add("DSI02","EMPTY_DELEGATION_PATH","empty-path",pathLength=0,minimumPathLength=1)
    add("DSI03","DELEGATION_PATH_TOO_DEEP","path-over-hard-ceiling",pathLength=17,maximumPathLength=16)

    base=ds02()
    parent=bytes.fromhex(base["parentGrantBytesHex"]);pid=bytes.fromhex(base["parentGrantIdHex"])
    mutated=bytearray(parent);mutated[-1]^=1
    add("DSI04","GRANT_ID_MISMATCH","mutated-grant-bytes-unchanged-id",
        mutatedGrantBytesHex=bytes(mutated).hex(),submittedGrantIdHex=pid.hex(),recomputedGrantIdHex=mh(bytes(mutated)).hex())
    alt=b"\x13\x20"+h(parent)
    add("DSI05","INVALID_GRANT_EVIDENCE","unsupported-grantid-hash-profile",
        submittedGrantIdHex=alt.hex(),expectedMultihashCode=0x12,submittedMultihashCode=0x13)

    add("DSI06","PARENT_GRANT_MISMATCH","child-parent-id-does-not-match-previous",
        previousGrantIdHex=base["parentGrantIdHex"],childParentGrantIdHex=mh(b"wrong-parent").hex())
    add("DSI07","ROOT_GRANTOR_MISMATCH","root-grantor-changes-mid-path",
        rootGrantorHex=base["rootGrantorHex"],childRootGrantorHex=bytes(range(1,33)).hex())
    add("DSI08","ISSUER_DELEGATE_MISMATCH","child-issuer-not-parent-delegate",
        parentDelegateHex=base["parentDelegateHex"],childIssuerHex=bytes(range(1,33)).hex())
    add("DSI09","INVALID_DELEGATION_EVIDENCE","reordered-valid-grants",
        originalGrantIdsHex=[base["parentGrantIdHex"],base["childGrantIdHex"]],
        submittedGrantIdsHex=[base["childGrantIdHex"],base["parentGrantIdHex"]])
    return out

def main():
    data={"specification":"OpenIdentity OI-016 Delegated Subject Token v1","status":"DRAFT-NON-NORMATIVE",
          "vectors":[ds01(),ds02()],"invalidVectors":invalids()}
    OUT.parent.mkdir(parents=True,exist_ok=True)
    OUT.write_text(json.dumps(data,indent=2)+"\n",encoding="utf-8",newline="\n")
    print("Wrote",OUT.relative_to(ROOT));print("DS01 GENERATED");print("DS02 GENERATED");print("DSI01-DSI09 GENERATED")
if __name__=="__main__":main()
