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




def synthetic_grant(root,issuer,delegate,parent_id,idx,padding=b""):
    ph=mh(b"OI-016 boundary profile")
    cap={1:{1:{1:1,2:ph},2:b"boundary.read"},2:(b"r/"+bytes([idx]))+padding}
    grant={1:1,2:root,3:{1:1,2:issuer},4:{1:1,2:delegate},5:[cap],
           7:2003000000-idx,9:h(b"OI-016 boundary nonce "+bytes([idx]))}
    if parent_id is not None:grant[8]=parent_id
    gb=enc(grant);return gb,mh(gb)

def ds03():
    root=bytes(range(32));issuer=root;parent=None;entries=[];terminal=None
    for i in range(16):
        delegate=bytes(((64+i+j)&255 for j in range(32)))
        gb,gid=synthetic_grant(root,issuer,delegate,parent,i)
        entries.append({1:gb,2:gid});issuer=delegate;parent=gid;terminal=delegate
    evidence={1:1,2:b"oi016-max-depth",3:entries};eb=enc(evidence);eid=mh(eb)
    actor={1:1,2:terminal,3:mh(b"DS03 actor state"),4:1,5:b"ds03",6:"openidentity.authentication",
           7:2002990000,8:2002990120,9:bytes(range(16,48)),10:mh(eid)}
    aid=mh(enc(actor));tb=enc({1:1,2:evidence,3:aid})
    return {"id":"DS03","description":"Exact OI-016 hard maximum path depth of 16","expected":"PASS",
      "pathLength":16,"grantIdsHex":[x[2].hex() for x in entries],"delegationEvidenceBytesHex":eb.hex(),
      "delegationEvidenceIdHex":eid.hex(),"terminalDelegateHex":terminal.hex(),"actorAssertionIdHex":aid.hex(),
      "delegatedSubjectTokenIdHex":mh(tb).hex()}

def ds04():
    # Exact 1 MiB evidence boundary using 16 valid-shaped grants and bounded resource constraints.
    target=1048576;root=bytes(range(32));registry=b"oi016-size-boundary"
    def build(extra):
        issuer=root;parent=None;entries=[]
        # Distribute padding across legal <=4096 resourceConstraint fields by using
        # multiple capabilities per grant. GrantBytes themselves remain <=65536.
        remaining=extra
        for i in range(16):
            delegate=bytes(((96+i+j)&255 for j in range(32)))
            caps=[];slot=0
            while remaining>0 and slot<15:
                n=min(4096,remaining);ph=mh(b"OI-016 DS04 profile "+bytes([i,slot]))
                caps.append({1:{1:{1:1,2:ph},2:b"boundary.read"},2:bytes([65+(i%26)])*n})
                remaining-=n;slot+=1
            if not caps:
                ph=mh(b"OI-016 DS04 base profile "+bytes([i]));caps=[{1:{1:{1:1,2:ph},2:b"boundary.read"},2:b"x"}]
            grant={1:1,2:root,3:{1:1,2:issuer},4:{1:1,2:delegate},5:caps,7:2003000000-i,
                   9:h(b"OI-016 DS04 nonce "+bytes([i]))}
            if parent is not None:grant[8]=parent
            gb=enc(grant)
            if len(gb)>65536:return None
            gid=mh(gb);entries.append({1:gb,2:gid});issuer=delegate;parent=gid
        if remaining:return None
        return enc({1:1,2:registry,3:entries}),entries
    # Find the greatest valid evidence size <= target, preferring exact target.
    lo,hi=0,16*15*4096;best=None
    while lo<=hi:
        mid=(lo+hi)//2;r=build(mid)
        if r is None:hi=mid-1;continue
        eb,entries=r;L=len(eb)
        if L<=target:
            best=(mid,eb,entries)
            if L==target:break
            lo=mid+1
        else:hi=mid-1
    if best is None:raise AssertionError("DS04 boundary fixture unavailable")
    extra,eb,entries=best
    return {"id":"DS04","description":"Maximum constructed valid evidence envelope at or below 1 MiB ceiling","expected":"PASS",
      "grantCount":16,"delegationEvidenceLength":len(eb),"maximumDelegationEvidenceLength":target,
      "exactBoundaryReached":len(eb)==target,"paddingBytes":extra,"delegationEvidenceIdHex":mh(eb).hex(),
      "allGrantBytesWithinLimit":all(len(x[1])<=65536 for x in entries)}

def ds05():
    registry=bytes(range(128))
    v=ds01();gb=bytes.fromhex(v["grantBytesHex"]);gid=bytes.fromhex(v["grantIdHex"])
    evidence={1:1,2:registry,3:[{1:gb,2:gid}]};eb=enc(evidence)
    return {"id":"DS05","description":"Exact 128-byte opaque registryDomain boundary","expected":"PASS",
      "registryDomainHex":registry.hex(),"registryDomainLength":len(registry),"delegationEvidenceBytesHex":eb.hex(),
      "delegationEvidenceIdHex":mh(eb).hex()}

def ds06():
    v=ds02();eb=bytes.fromhex(v["delegationEvidenceBytesHex"]);eid=mh(eb)
    context={1:1,2:b"https://as.example.test",3:b"client-016",4:eid,5:b"https://api.example.test",6:b"records.read"}
    cb=enc(context);ch=mh(cb)
    return {"id":"DS06","description":"Integration context commits exact DelegationEvidenceId","expected":"PASS",
      "delegationEvidenceIdHex":eid.hex(),"contextBytesHex":cb.hex(),"contextHashHex":ch.hex(),
      "purpose":"openidentity.oauth.token-exchange"}


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
    # DSI10-DSI15: immutable evidence remains valid; authoritative current state controls usability.
    base2=ds02()
    add("DSI10","DELEGATION_NOT_CURRENTLY_USABLE","current-record-revoked",
        embeddedEvidenceValid=True,authoritativeStateAvailable=True,currentStatus="REVOKED")
    add("DSI11","DELEGATION_NOT_CURRENTLY_USABLE","ancestor-relinquished",
        embeddedEvidenceValid=True,authoritativeStateAvailable=True,ancestorRelinquished=True)
    add("DSI12","DELEGATION_NOT_CURRENTLY_USABLE","root-delegation-generation-invalidated",
        embeddedEvidenceValid=True,authoritativeStateAvailable=True,boundDelegationGeneration=7,currentDelegationGeneration=8)
    add("DSI13","DELEGATION_NOT_CURRENTLY_USABLE","root-identity-deactivated",
        embeddedEvidenceValid=True,authoritativeStateAvailable=True,currentRootStatus="DEACTIVATED")
    add("DSI14","DELEGATION_NOT_CURRENTLY_USABLE","expired-ancestor",
        embeddedEvidenceValid=True,authoritativeStateAvailable=True,verificationTime=2002014000,ancestorExpiresAt=2002013999)
    add("DSI15","DELEGATION_STATE_UNAVAILABLE","authoritative-current-record-unavailable",
        embeddedEvidenceValid=True,authoritativeStateAvailable=False,
        requiredRegistryDomainHex=b"openidentity:test:oi016:ds02".hex(),requiredGrantIdHex=base2["parentGrantIdHex"])

    # DSI16-DSI19: OI-016 <-> OI-015 cross-object binding attacks.
    ds=ds02();expected_aid=bytes.fromhex(ds["actorAssertionIdHex"])
    other_assertion={1:1,2:bytes(range(160,192)),3:mh(b"OI-016 DSI16 alternate actor state"),4:11,
                     5:b"oi016-ds02-verifier",6:"openidentity.authentication",7:2002010001,8:2002010121,
                     9:bytes(range(224,256)),10:mh(bytes.fromhex(ds["delegationEvidenceIdHex"]))}
    other_ab=enc(other_assertion);other_aid=mh(other_ab)
    add("DSI16","ACTOR_ASSERTION_ID_MISMATCH","subject-token-binds-different-assertion",
        tokenActorAssertionIdHex=expected_aid.hex(),suppliedActorAssertionIdHex=other_aid.hex(),
        suppliedAssertionBytesHex=other_ab.hex())

    wrong_actor=bytes(range(1,33))
    wrong_actor_assertion={1:1,2:wrong_actor,3:mh(b"OI-016 DSI17 wrong actor state"),4:3,
                           5:b"oi016-ds02-verifier",6:"openidentity.authentication",7:2002010000,8:2002010120,
                           9:bytes(range(64,96)),10:mh(bytes.fromhex(ds["delegationEvidenceIdHex"]))}
    wrong_actor_ab=enc(wrong_actor_assertion)
    add("DSI17","ACTOR_IDENTITY_MISMATCH","authenticated-actor-not-terminal-delegate",
        terminalDelegateHex=ds["terminalDelegateHex"],authenticatedActorHex=wrong_actor.hex(),
        actorAssertionIdHex=mh(wrong_actor_ab).hex())

    other_eid=mh(b"OI-016 DSI18 different delegation evidence")
    context_for_other=mh(other_eid)
    add("DSI18","DELEGATION_CONTEXT_MISMATCH","actor-context-binds-different-evidence",
        expectedDelegationEvidenceIdHex=ds["delegationEvidenceIdHex"],boundDelegationEvidenceIdHex=other_eid.hex(),
        boundContextHashHex=context_for_other.hex())

    same_actor=bytes.fromhex(ds["terminalDelegateHex"])
    fresh_assertion={1:1,2:same_actor,3:mh(b"OI-016 DSI19 fresh same-actor state"),4:11,
                     5:b"oi016-ds02-verifier",6:"openidentity.authentication",7:2002010002,8:2002010122,
                     9:bytes(range(32,64)),10:mh(bytes.fromhex(ds["delegationEvidenceIdHex"]))}
    fresh_ab=enc(fresh_assertion);fresh_aid=mh(fresh_ab)
    add("DSI19","ACTOR_ASSERTION_ID_MISMATCH","different-valid-same-actor-assertion-swapped",
        terminalDelegateHex=ds["terminalDelegateHex"],tokenActorAssertionIdHex=expected_aid.hex(),
        substitutedActorAssertionIdHex=fresh_aid.hex(),substitutedAssertionBytesHex=fresh_ab.hex())

    # DSI20-DSI22: envelope size, path splicing, and cycle/duplicate defenses.
    add("DSI20","DELEGATION_EVIDENCE_TOO_LARGE","evidence-one-byte-over-ceiling",
        delegationEvidenceLength=1048577,maximumDelegationEvidenceLength=1048576)

    path_a=ds02()
    # Independent valid direct grant/path B; individually valid but unrelated to path A.
    root_b=bytes(range(1,33));delegate_b=bytes(range(33,65))
    ph_b=mh(b"OI-016 DSI21 independent profile");pr_b={1:1,2:ph_b};cr_b={1:pr_b,2:b"other.read"}
    grant_b={1:1,2:root_b,3:{1:1,2:root_b},4:{1:1,2:delegate_b},5:[{1:cr_b}],
             7:2002020000,9:h(b"OpenIdentity OI-016 DSI21 nonce")}
    gb_b=enc(grant_b);gid_b=mh(gb_b)
    add("DSI21","INVALID_DELEGATION_EVIDENCE","independent-valid-paths-spliced",
        pathARootGrantorHex=path_a["rootGrantorHex"],pathBRootGrantorHex=root_b.hex(),
        pathALastGrantIdHex=path_a["childGrantIdHex"],splicedNextGrantIdHex=gid_b.hex(),
        splicedNextParentGrantIdPresent=False,individualPathBGrantIdValid=(gid_b==mh(gb_b)))

    duplicate_id=path_a["parentGrantIdHex"]
    add("DSI22","INVALID_DELEGATION_EVIDENCE","duplicate-path-element-cycle",
        submittedGrantIdsHex=[duplicate_id,path_a["childGrantIdHex"],duplicate_id],
        duplicateGrantIdHex=duplicate_id)

    # DSI23-DSI28: pre-freeze taxonomy and structural gap closure.
    add("DSI23","INVALID_DELEGATED_SUBJECT_TOKEN","malformed-top-level-token-shape",
        submittedTopLevelType="array",requiredTopLevelType="map")
    base1=ds01()
    child_like=bytes.fromhex(ds02()["childGrantBytesHex"])
    add("DSI24","INVALID_ROOT_GRANT","first-path-element-is-child-grant",
        firstGrantBytesHex=child_like.hex(),parentGrantIdPresent=True)
    add("DSI25","INVALID_DELEGATION_EVIDENCE","empty-registry-domain",
        registryDomainLength=0,minimumRegistryDomainLength=1)
    add("DSI26","INVALID_DELEGATION_EVIDENCE","registry-domain-too-long",
        registryDomainLength=129,maximumRegistryDomainLength=128)
    add("DSI27","INVALID_GRANT_EVIDENCE","malformed-grantid-length",
        submittedGrantIdLength=33,requiredGrantIdLength=34)
    add("DSI28","INVALID_DELEGATED_SUBJECT_TOKEN","malformed-actor-assertion-id-length",
        submittedActorAssertionIdLength=33,requiredActorAssertionIdLength=34)

    return out

def main():
    data={"specification":"OpenIdentity OI-016 Delegated Subject Token v1","status":"DRAFT-NON-NORMATIVE",
          "vectors":[ds01(),ds02(),ds03(),ds04(),ds05(),ds06()],"invalidVectors":invalids()}
    OUT.parent.mkdir(parents=True,exist_ok=True)
    OUT.write_text(json.dumps(data,indent=2)+"\n",encoding="utf-8",newline="\n")
    print("Wrote",OUT.relative_to(ROOT));print("DS01 GENERATED");print("DS02 GENERATED");print("DS03-DS06 GENERATED");print("DSI01-DSI28 GENERATED")
if __name__=="__main__":main()
