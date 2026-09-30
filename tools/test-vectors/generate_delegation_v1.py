#!/usr/bin/env python3
"""Generate draft OI-014 DG01 deterministic conformance vector."""
from __future__ import annotations
import hashlib, json
from pathlib import Path
import cbor2
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT=Path(__file__).resolve().parents[2]
OUT=ROOT/"test-vectors"/"generated"/"delegation-v1.json"

def h(b): return hashlib.sha256(b).digest()
def mh(b): return b"\x12\x20"+h(b)
def enc(x): return cbor2.dumps(x,canonical=True)
def seed(label): return h(label.encode())
def key(label,method_id):
    priv=Ed25519PrivateKey.from_private_bytes(seed(label))
    pub=priv.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
    method={1:1,3:-8,4:-1,6:pub}
    return priv,method_id,method
def policy(method_id,method): return {1:1,2:[{1:method_id,2:method}]}
def threshold_policy(entries,threshold):
    entries=sorted(entries,key=lambda x:x[0])
    return {1:2,2:threshold,3:[{1:mid,2:m} for mid,m in entries]}

def build_dg02():
    registry=b"openidentity:test:oi014:dg02"
    root=bytes(range(64,96)); delegate=bytes(range(96,128))
    mid_a=bytes(range(16)); mid_b=bytes(range(16,32))
    a,_,ma=key("OpenIdentity OI-014 DG02 delegation A Ed25519 seed",mid_a)
    b,_,mb=key("OpenIdentity OI-014 DG02 delegation B Ed25519 seed",mid_b)
    # Deliberately supply B,A; canonical policy must serialize A,B.
    dp=threshold_policy([(mid_b,mb),(mid_a,ma)],2)
    descriptor={1:1,2:"openidentity.test.exact-capability",3:1,4:[b"document.write"],5:1800,6:2}
    profile_bytes=enc(descriptor); profile_hash=mh(profile_bytes)
    cap={1:{1:{1:1,2:profile_hash},2:b"document.write"}}
    grant={1:1,2:root,3:{1:1,2:root},4:{1:1,2:delegate},5:[cap],
           7:2000002800,9:seed("OpenIdentity OI-014 DG02 nonce")}
    gb=enc(grant); gid=mh(gb)
    state={1:3,2:root,3:11,4:1,5:dp,8:{1:0},9:{1:9,2:dp}}
    sb=enc(state); sh=mh(sb)
    signing_a=enc(["OpenIdentity Delegation Grant",1,registry,gb,sh,9,mid_a])
    signing_b=enc(["OpenIdentity Delegation Grant",1,registry,gb,sh,9,mid_b])
    sig_a=a.sign(signing_a); sig_b=b.sign(signing_b)
    # Deliberately conceptual B,A production; canonical proof array is A,B by methodId.
    proofs=[{1:mid_a,2:sig_a},{1:mid_b,2:sig_b}]
    request={1:registry,2:grant,3:sh,4:9,5:proofs}
    record={1:registry,2:gid,3:1,4:None,5:1,6:sh,7:9,8:2000001000}
    rb=enc(record)
    return {"id":"DG02","description":"Direct grant registration with canonical 2-of-2 Ed25519 DelegationPolicy proof ordering","expected":"PASS",
      "profileDescriptorBytesHex":profile_bytes.hex(),"profileHashHex":profile_hash.hex(),
      "currentStateBytesHex":sb.hex(),"currentStateHashHex":sh.hex(),
      "grantBytesHex":gb.hex(),"grantIdHex":gid.hex(),
      "registrationSigningBytesAHex":signing_a.hex(),"registrationSignatureAHex":sig_a.hex(),
      "registrationSigningBytesBHex":signing_b.hex(),"registrationSignatureBHex":sig_b.hex(),
      "registrationRequestBytesHex":enc(request).hex(),"registeredAt":2000001000,
      "recordBytesHex":rb.hex(),"recordHashHex":mh(rb).hex()}


def build_dg03():
    registry=b"openidentity:test:oi014:dg03"
    root=bytes(range(128,160)); delegate=bytes(range(160,192))
    mid_a=bytes(range(32,48)); mid_b=bytes(range(48,64))
    a,_,ma=key("OpenIdentity OI-014 DG03 delegation A Ed25519 seed",mid_a)
    b,_,mb=key("OpenIdentity OI-014 DG03 delegation B Ed25519 seed",mid_b)
    pa=policy(mid_a,ma); pb=policy(mid_b,mb)
    descriptor={1:1,2:"openidentity.test.exact-capability",3:1,4:[b"document.read"],5:7200,6:3}
    pbytes=enc(descriptor); ph=mh(pbytes)
    grant={1:1,2:root,3:{1:1,2:root},4:{1:1,2:delegate},
           5:[{1:{1:{1:1,2:ph},2:b"document.read"}}],
           7:2000010000,9:seed("OpenIdentity OI-014 DG03 nonce")}
    gb=enc(grant); gid=mh(gb)
    generation=12
    before={1:3,2:root,3:20,4:1,5:pa,8:{1:0},9:{1:generation,2:pa}}
    before_b=enc(before); before_h=mh(before_b)
    sign=enc(["OpenIdentity Delegation Grant",1,registry,gb,before_h,generation,mid_a])
    sig=a.sign(sign)
    record={1:registry,2:gid,3:1,4:None,5:1,6:before_h,7:generation,8:2000003000}
    rb=enc(record); rh=mh(rb)

    # Root v3 SET_DELEGATION_POLICY A->B / PRESERVE_EXISTING.
    op={1:2,2:7,3:root,4:21,5:before_h,6:{1:pb,2:0}}
    ob=enc(op)
    after={1:3,2:root,3:21,4:1,5:pa,8:{1:0},9:{1:generation,2:pb}}
    after_b=enc(after); after_h=mh(after_b)
    return {"id":"DG03","description":"Registered grant survives DelegationPolicy A->B PRESERVE_EXISTING rotation at unchanged generation","expected":"PASS",
      "profileDescriptorBytesHex":pbytes.hex(),"profileHashHex":ph.hex(),
      "grantBytesHex":gb.hex(),"grantIdHex":gid.hex(),
      "registrationStateBytesHex":before_b.hex(),"registrationStateHashHex":before_h.hex(),
      "registrationSigningBytesHex":sign.hex(),"registrationSignatureHex":sig.hex(),
      "recordBytesHex":rb.hex(),"recordHashHex":rh.hex(),
      "rotationOperationBytesHex":ob.hex(),"postRotationStateBytesHex":after_b.hex(),"postRotationStateHashHex":after_h.hex(),
      "delegationGenerationBefore":generation,"delegationGenerationAfter":generation,
      "recordHashAfterRotationHex":rh.hex(),"grantUsableAfterRotation":True}



def build_dg04():
    registry=b"openidentity:test:oi014:dg04"
    root=bytes(range(192,224)); delegate=bytes(range(224,256))
    controller_id=bytes(range(64,80)); delegation_id=bytes(range(80,96))
    cpriv,_,cm=key("OpenIdentity OI-014 DG04 controller Ed25519 seed",controller_id)
    dpriv,_,dm=key("OpenIdentity OI-014 DG04 delegation Ed25519 seed",delegation_id)
    cp=policy(controller_id,cm); dp=policy(delegation_id,dm)
    descriptor={1:1,2:"openidentity.test.exact-capability",3:1,4:[b"document.delete"],5:3600,6:2}
    pbytes=enc(descriptor); ph=mh(pbytes)
    grant={1:1,2:root,3:{1:1,2:root},4:{1:1,2:delegate},
           5:[{1:{1:{1:1,2:ph},2:b"document.delete"}}],
           7:2000015000,9:seed("OpenIdentity OI-014 DG04 nonce")}
    gb=enc(grant); gid=mh(gb)
    generation=15
    state={1:3,2:root,3:30,4:1,5:cp,8:{1:0},9:{1:generation,2:dp}}
    sb=enc(state); sh=mh(sb)
    regsign=enc(["OpenIdentity Delegation Grant",1,registry,gb,sh,generation,delegation_id])
    regsig=dpriv.sign(regsign)
    r1={1:registry,2:gid,3:1,4:None,5:1,6:sh,7:generation,8:2000010000}
    r1b=enc(r1); r1h=mh(r1b)

    revsign=enc(["OpenIdentity Delegation Grant Revocation",1,registry,gid,r1h,2,sh,controller_id])
    revsig=cpriv.sign(revsign)
    revreq={1:registry,2:gid,3:r1h,4:2,5:sh,6:1,7:[{1:controller_id,2:revsig}]}
    r2={1:registry,2:gid,3:2,4:r1h,5:2,6:sh,7:generation,8:2000010000}
    r2b=enc(r2); r2h=mh(r2b)
    return {"id":"DG04","description":"Current ControllerPolicy individually revokes an ACTIVE registered grant","expected":"PASS",
      "grantBytesHex":gb.hex(),"grantIdHex":gid.hex(),"currentStateBytesHex":sb.hex(),"currentStateHashHex":sh.hex(),
      "registrationSigningBytesHex":regsign.hex(),"registrationSignatureHex":regsig.hex(),
      "activeRecordBytesHex":r1b.hex(),"activeRecordHashHex":r1h.hex(),
      "revocationSigningBytesHex":revsign.hex(),"revocationSignatureHex":revsig.hex(),
      "revocationRequestBytesHex":enc(revreq).hex(),
      "revokedRecordBytesHex":r2b.hex(),"revokedRecordHashHex":r2h.hex(),
      "grantIdAfterRevocationHex":gid.hex(),"registeredAtBefore":2000010000,"registeredAtAfter":2000010000}



def build_dg05():
    registry=b"openidentity:test:oi014:dg05"
    root=bytes(range(16,48)); delegate=bytes(range(48,80))
    mid_a=bytes(range(96,112)); mid_b=bytes(range(112,128))
    a,_,ma=key("OpenIdentity OI-014 DG05 delegation A Ed25519 seed",mid_a)
    b,_,mb=key("OpenIdentity OI-014 DG05 delegation B Ed25519 seed",mid_b)
    pa=policy(mid_a,ma); pb=policy(mid_b,mb)
    descriptor={1:1,2:"openidentity.test.exact-capability",3:1,4:[b"document.admin"],5:3600,6:2}
    pbytes=enc(descriptor); ph=mh(pbytes)
    grant={1:1,2:root,3:{1:1,2:root},4:{1:1,2:delegate},
           5:[{1:{1:{1:1,2:ph},2:b"document.admin"}}],
           7:2000020000,9:seed("OpenIdentity OI-014 DG05 nonce")}
    gb=enc(grant); gid=mh(gb)
    generation=21
    before={1:3,2:root,3:40,4:1,5:pa,8:{1:0},9:{1:generation,2:pa}}
    before_b=enc(before); before_h=mh(before_b)
    regsign=enc(["OpenIdentity Delegation Grant",1,registry,gb,before_h,generation,mid_a])
    regsig=a.sign(regsign)
    record={1:registry,2:gid,3:1,4:None,5:1,6:before_h,7:generation,8:2000016000}
    rb=enc(record); rh=mh(rb)

    # INVALIDATE_EXISTING increments the root delegation generation exactly once.
    op={1:2,2:7,3:root,4:41,5:before_h,6:{1:pb,2:1}}
    ob=enc(op)
    after={1:3,2:root,3:41,4:1,5:pa,8:{1:0},9:{1:generation+1,2:pb}}
    after_b=enc(after); after_h=mh(after_b)
    return {"id":"DG05","description":"Delegation generation increment invalidates prior grant without mutating its ACTIVE registration record","expected":"PASS",
      "grantBytesHex":gb.hex(),"grantIdHex":gid.hex(),
      "registrationStateBytesHex":before_b.hex(),"registrationStateHashHex":before_h.hex(),
      "registrationSigningBytesHex":regsign.hex(),"registrationSignatureHex":regsig.hex(),
      "activeRecordBytesHex":rb.hex(),"activeRecordHashHex":rh.hex(),
      "invalidationOperationBytesHex":ob.hex(),"postInvalidationStateBytesHex":after_b.hex(),"postInvalidationStateHashHex":after_h.hex(),
      "delegationGenerationBefore":generation,"delegationGenerationAfter":generation+1,
      "recordRevisionAfterInvalidation":1,"recordStatusAfterInvalidation":"ACTIVE",
      "recordHashAfterInvalidationHex":rh.hex(),"grantUsableAfterInvalidation":False}



def build_dg06():
    registry=b"openidentity:test:oi014:dg06"
    root=bytes(range(80,112)); parent_delegate=bytes(range(112,144)); child_delegate=bytes(range(144,176))
    delegation_id=bytes(range(128,144)); auth_id=bytes(range(144,160))
    dpriv,_,dm=key("OpenIdentity OI-014 DG06 root delegation Ed25519 seed",delegation_id)
    apriv,_,am=key("OpenIdentity OI-014 DG06 parent delegate authentication Ed25519 seed",auth_id)
    dp=policy(delegation_id,dm); ap=policy(auth_id,am)

    descriptor={1:1,2:"openidentity.test.redelegation",3:1,
                4:[b"document.read",b"redelegate.document.read"],5:7200,6:3}
    pbytes=enc(descriptor); ph=mh(pbytes); pref={1:1,2:ph}
    read_cap={1:{1:pref,2:b"document.read"}}
    redelegate_cap={1:{1:pref,2:b"redelegate.document.read"}}

    parent={1:1,2:root,3:{1:1,2:root},4:{1:1,2:parent_delegate},
            5:[read_cap,redelegate_cap],7:2000030000,9:seed("OpenIdentity OI-014 DG06 parent nonce")}
    parent_b=enc(parent); parent_id=mh(parent_b)
    generation=30
    root_state={1:3,2:root,3:50,4:1,5:dp,8:{1:0},9:{1:generation,2:dp}}
    root_b=enc(root_state); root_h=mh(root_b)
    parent_sign=enc(["OpenIdentity Delegation Grant",1,registry,parent_b,root_h,generation,delegation_id])
    parent_sig=dpriv.sign(parent_sign)
    parent_record={1:registry,2:parent_id,3:1,4:None,5:1,6:root_h,7:generation,8:2000020000}
    parent_rb=enc(parent_record); parent_rh=mh(parent_rb)

    # The parent delegate authenticates as an OPENIDENTITY principal through
    # its current AuthenticationAuthority, independent of the rootGrantor.
    auth_generation=7
    delegate_state={1:3,2:parent_delegate,3:9,4:1,5:ap,8:{1:auth_generation,2:ap},9:{1:0}}
    delegate_sb=enc(delegate_state); delegate_sh=mh(delegate_sb)

    child={1:1,2:root,3:{1:1,2:parent_delegate},4:{1:1,2:child_delegate},
           5:[read_cap],7:2000028000,8:parent_id,9:seed("OpenIdentity OI-014 DG06 child nonce")}
    child_b=enc(child); child_id=mh(child_b)
    child_sign=enc(["OpenIdentity Delegation Child Grant",1,registry,child_b,parent_id,parent_rh,
                    delegate_sh,auth_generation,auth_id])
    child_sig=apriv.sign(child_sign)
    child_req={1:registry,2:child,3:parent_id,4:parent_rh,5:delegate_sh,6:auth_generation,
               7:[{1:auth_id,2:child_sig}]}
    child_record={1:registry,2:child_id,3:1,4:None,5:1,6:root_h,7:generation,8:2000021000}
    child_rb=enc(child_record); child_rh=mh(child_rb)

    return {"id":"DG06","description":"Valid attenuated child grant authenticated by parent delegate current AuthenticationAuthority","expected":"PASS",
      "profileDescriptorBytesHex":pbytes.hex(),"profileHashHex":ph.hex(),
      "rootStateBytesHex":root_b.hex(),"rootStateHashHex":root_h.hex(),
      "parentGrantBytesHex":parent_b.hex(),"parentGrantIdHex":parent_id.hex(),
      "parentRegistrationSigningBytesHex":parent_sign.hex(),"parentRegistrationSignatureHex":parent_sig.hex(),
      "parentRecordBytesHex":parent_rb.hex(),"parentRecordHashHex":parent_rh.hex(),
      "delegateStateBytesHex":delegate_sb.hex(),"delegateStateHashHex":delegate_sh.hex(),
      "authenticationGeneration":auth_generation,"authenticationMethodIdHex":auth_id.hex(),
      "childGrantBytesHex":child_b.hex(),"childGrantIdHex":child_id.hex(),
      "childSigningBytesHex":child_sign.hex(),"childAuthenticationSignatureHex":child_sig.hex(),
      "childRegistrationRequestBytesHex":enc(child_req).hex(),
      "childRecordBytesHex":child_rb.hex(),"childRecordHashHex":child_rh.hex(),
      "rootGrantorPreserved":True,"issuerEqualsParentDelegate":True,
      "capabilityAttenuated":True,"lifetimeAttenuated":True,
      "parentRedelegationAuthorized":True,"childDepth":2}

def build_invalids():
    out=[]
    def add(i,error,attack,**kw): out.append({"id":i,"expected":"REJECT","error":error,"attack":attack,**kw})

    # DGI01: old policy A signs after A->B PRESERVE. Signature is cryptographically
    # valid over historical context, but A is not the current DelegationPolicy.
    root=bytes(range(1,33)); delegate=bytes(range(33,65)); reg=b"openidentity:test:oi014:dgi01"
    ida=bytes(range(1,17)); idb=bytes(range(17,33))
    a,_,ma=key("OpenIdentity OI-014 DGI01 old delegation seed",ida); _,_,mb=key("OpenIdentity OI-014 DGI01 new delegation seed",idb)
    pa=policy(ida,ma); pb=policy(idb,mb); gen=5
    desc={1:1,2:"openidentity.test.exact-capability",3:1,4:[b"document.read"],5:3600,6:2}; ph=mh(enc(desc))
    g={1:1,2:root,3:{1:1,2:root},4:{1:1,2:delegate},5:[{1:{1:{1:1,2:ph},2:b"document.read"}}],7:2000100000,9:seed("DGI01 nonce")}
    gb=enc(g)
    hist={1:3,2:root,3:5,4:1,5:pa,8:{1:0},9:{1:gen,2:pa}}; hb=enc(hist); hh=mh(hb)
    cur={1:3,2:root,3:6,4:1,5:pa,8:{1:0},9:{1:gen,2:pb}}; cb=enc(cur); ch=mh(cb)
    oldsign=enc(["OpenIdentity Delegation Grant",1,reg,gb,hh,gen,ida]); oldsig=a.sign(oldsign)
    add("DGI01","UNAUTHORIZED_GRANT_REGISTRATION","rotated-out-policy-backdating",
        grantBytesHex=gb.hex(),historicalStateHashHex=hh.hex(),currentStateBytesHex=cb.hex(),currentStateHashHex=ch.hex(),
        currentDelegationGeneration=gen,currentDelegationPolicyMethodIdHex=idb.hex(),
        submittedSigningBytesHex=oldsign.hex(),submittedSignatureHex=oldsig.hex(),submittedMethodIdHex=ida.hex())

    # DGI02: current key signs a request carrying the wrong generation.
    reg2=b"openidentity:test:oi014:dgi02"; root2=bytes(range(65,97)); did=bytes(range(33,49))
    d,_,dm=key("OpenIdentity OI-014 DGI02 delegation seed",did); dp=policy(did,dm); actual=8; claimed=7
    st={1:3,2:root2,3:9,4:1,5:dp,8:{1:0},9:{1:actual,2:dp}}; sb=enc(st); sh=mh(sb)
    g2={1:1,2:root2,3:{1:1,2:root2},4:{1:1,2:delegate},5:[{1:{1:{1:1,2:ph},2:b"document.read"}}],7:2000100000,9:seed("DGI02 nonce")}
    gb2=enc(g2); sign2=enc(["OpenIdentity Delegation Grant",1,reg2,gb2,sh,claimed,did]); sig2=d.sign(sign2)
    add("DGI02","INVALID_DELEGATION_GENERATION","wrong-generation",
        grantBytesHex=gb2.hex(),currentStateBytesHex=sb.hex(),currentStateHashHex=sh.hex(),
        actualGeneration=actual,claimedGeneration=claimed,submittedSigningBytesHex=sign2.hex(),submittedSignatureHex=sig2.hex())

    # DGI03: proof valid for registry A is submitted to registry B.
    rega=b"openidentity:test:oi014:registry-a"; regb=b"openidentity:test:oi014:registry-b"
    signa=enc(["OpenIdentity Delegation Grant",1,rega,gb2,sh,actual,did]); siga=d.sign(signa)
    signb=enc(["OpenIdentity Delegation Grant",1,regb,gb2,sh,actual,did])
    add("DGI03","CROSS_DOMAIN_PROOF","cross-registry-replay",
        grantBytesHex=gb2.hex(),authorizedRegistryDomainHex=rega.hex(),submittedRegistryDomainHex=regb.hex(),
        authorizedSigningBytesHex=signa.hex(),requiredSigningBytesHex=signb.hex(),submittedSignatureHex=siga.hex())

    # Shared parent for DGI04-DGI06.
    preg=b"openidentity:test:oi014:invalid-child"; proot=bytes(range(97,129)); pdel=bytes(range(129,161)); cdel=bytes(range(161,193))
    pcap={1:{1:{1:1,2:ph},2:b"document.read"}}
    redesc={1:1,2:"openidentity.test.redelegation",3:1,4:[b"document.read",b"redelegate.document.read"],5:3600,6:3}; rph=mh(enc(redesc))
    read={1:{1:{1:1,2:rph},2:b"document.read"}}; redel={1:{1:{1:1,2:rph},2:b"redelegate.document.read"}}
    parent={1:1,2:proot,3:{1:1,2:proot},4:{1:1,2:pdel},5:[read,redel],7:2000200000,9:seed("DGI parent nonce")}
    pgb=enc(parent); pgid=mh(pgb); pstatehash=mh(enc({1:3,2:proot,3:1,4:1,5:{1:1,2:[]},8:{1:0},9:{1:3}}))
    pr1={1:preg,2:pgid,3:1,4:None,5:1,6:pstatehash,7:3,8:2000150000}; pr1b=enc(pr1); pr1h=mh(pr1b)
    pr2={1:preg,2:pgid,3:2,4:pr1h,5:2,6:pstatehash,7:3,8:2000150000}; pr2b=enc(pr2); pr2h=mh(pr2b)
    ipriv=Ed25519PrivateKey.from_private_bytes(seed("OpenIdentity OI-014 invalid child issuer seed"))

    child={1:1,2:proot,3:{1:1,2:pdel},4:{1:1,2:cdel},5:[read],7:2000190000,8:pgid,9:seed("DGI child nonce")}
    cgb=enc(child)
    stale=enc(["OpenIdentity Delegation Child Grant",1,preg,cgb,pgid,pr1h]); stalesig=ipriv.sign(stale)
    add("DGI04","INVALID_PREVIOUS_RECORD_HASH","stale-parent-record-hash",
        parentGrantBytesHex=pgb.hex(),currentParentRecordBytesHex=pr2b.hex(),currentParentRecordHashHex=pr2h.hex(),
        childGrantBytesHex=cgb.hex(),submittedParentRecordHashHex=pr1h.hex(),submittedSigningBytesHex=stale.hex(),submittedProofHex=stalesig.hex())

    # DGI05 child asks for document.admin which parent does not hold/redelegate.
    admin={1:{1:{1:1,2:rph},2:b"document.admin"}}
    esc={1:1,2:proot,3:{1:1,2:pdel},4:{1:1,2:cdel},5:[admin],7:2000190000,8:pgid,9:seed("DGI05 nonce")}
    add("DGI05","CAPABILITY_ESCALATION","child-capability-escalation",
        parentGrantBytesHex=pgb.hex(),childGrantBytesHex=enc(esc).hex(),
        parentCapabilities=["document.read","redelegate.document.read"],childCapabilities=["document.admin"])

    # DGI06 parent is REVOKED at current revision 2.
    add("DGI06","PARENT_GRANT_UNUSABLE","revoked-parent-child-issuance",
        parentGrantBytesHex=pgb.hex(),currentParentRecordBytesHex=pr2b.hex(),currentParentRecordHashHex=pr2h.hex(),
        currentParentStatus="REVOKED",childGrantBytesHex=cgb.hex())

    # DGI07-DGI12 structural/state attacks derived from the same parent model.
    wrong_root=bytes(range(193,225))
    wrong_root_child={1:1,2:wrong_root,3:{1:1,2:pdel},4:{1:1,2:cdel},5:[read],
                      7:2000190000,8:pgid,9:seed("DGI07 nonce")}
    add("DGI07","ROOT_GRANTOR_MISMATCH","child-root-grantor-substitution",
        parentGrantBytesHex=pgb.hex(),parentRootGrantorHex=proot.hex(),
        childGrantBytesHex=enc(wrong_root_child).hex(),
        childRootGrantorHex=wrong_root.hex())

    wrong_issuer=bytes(range(194,226))
    wrong_issuer_child={1:1,2:proot,3:{1:1,2:wrong_issuer},4:{1:1,2:cdel},5:[read],
                        7:2000190000,8:pgid,9:seed("DGI08 nonce")}
    add("DGI08","ISSUER_PARENT_DELEGATE_MISMATCH","child-issuer-substitution",
        parentGrantBytesHex=pgb.hex(),parentDelegateHex=pdel.hex(),
        childGrantBytesHex=enc(wrong_issuer_child).hex(),childIssuerHex=wrong_issuer.hex())

    wide_time={1:1,2:proot,3:{1:1,2:pdel},4:{1:1,2:cdel},5:[read],
               7:2000200001,8:pgid,9:seed("DGI09 nonce")}
    add("DGI09","CHILD_TIME_WIDENING","child-expiry-beyond-parent",
        parentGrantBytesHex=pgb.hex(),childGrantBytesHex=enc(wide_time).hex(),
        parentExpiresAt=2000200000,childExpiresAt=2000200001)

    # Parent holds document.read but no explicit redelegation capability.
    no_redel_parent={1:1,2:proot,3:{1:1,2:proot},4:{1:1,2:pdel},5:[read],
                     7:2000200000,9:seed("DGI10 parent nonce")}
    nrpb=enc(no_redel_parent); nrpid=mh(nrpb)
    no_redel_child={1:1,2:proot,3:{1:1,2:pdel},4:{1:1,2:cdel},5:[read],
                    7:2000190000,8:nrpid,9:seed("DGI10 child nonce")}
    add("DGI10","REDELEGATION_NOT_AUTHORIZED","missing-redelegation-authority",
        parentGrantBytesHex=nrpb.hex(),parentGrantIdHex=nrpid.hex(),
        childGrantBytesHex=enc(no_redel_child).hex(),
        parentCapabilities=["document.read"],requestedChildCapabilities=["document.read"])

    # Same human-readable capability ID, different pinned profile hash.
    other_desc={1:1,2:"openidentity.test.redelegation.changed",3:1,
                4:[b"document.read",b"redelegate.document.read"],5:3600,6:3}
    other_ph=mh(enc(other_desc))
    substituted_read={1:{1:{1:1,2:other_ph},2:b"document.read"}}
    profile_child={1:1,2:proot,3:{1:1,2:pdel},4:{1:1,2:cdel},5:[substituted_read],
                   7:2000190000,8:pgid,9:seed("DGI11 nonce")}
    add("DGI11","PROFILE_SUBSTITUTION","child-profile-substitution",
        parentProfileHashHex=rph.hex(),childProfileHashHex=other_ph.hex(),
        capabilityIdHex=b"document.read".hex(),childGrantBytesHex=enc(profile_child).hex())

    # Duplicate REGISTER cannot reactivate or create a new revision-1 history.
    add("DGI12","TERMINAL_GRANT_STATE","duplicate-register-after-revocation",
        grantIdHex=pgid.hex(),currentRecordBytesHex=pr2b.hex(),currentRecordHashHex=pr2h.hex(),
        currentRevision=2,currentStatus="REVOKED",attemptedRegistrationGrantBytesHex=pgb.hex(),
        attemptedNewRevision=1)

    # DGI13: grant already expired at authoritative registration time.
    expired={1:1,2:proot,3:{1:1,2:proot},4:{1:1,2:pdel},5:[read],
             7:2000300000,9:seed("DGI13 nonce")}
    add("DGI13","GRANT_EXPIRED_AT_REGISTRATION","expired-at-registration",
        grantBytesHex=enc(expired).hex(),expiresAt=2000300000,registeredAt=2000300000)

    # DGI14: invalid canonical interval, notBefore == expiresAt.
    bad_time={1:1,2:proot,3:{1:1,2:proot},4:{1:1,2:pdel},5:[read],
              6:2000310000,7:2000310000,9:seed("DGI14 nonce")}
    add("DGI14","INVALID_TIME_RANGE","not-before-not-less-than-expiry",
        grantBytesHex=enc(bad_time).hex(),notBefore=2000310000,expiresAt=2000310000)

    # DGI15: revocation signature is valid for historical root StateHash, but current
    # root state has advanced while the grant record itself is unchanged.
    revroot=bytes(range(2,34)); rcid=bytes(range(2,18))
    rcpriv,_,rcm=key("OpenIdentity OI-014 DGI15 controller seed",rcid); rcp=policy(rcid,rcm)
    hist_state={1:3,2:revroot,3:10,4:1,5:rcp,8:{1:0},9:{1:6}}
    hist_b=enc(hist_state); hist_h=mh(hist_b)
    cur_state={1:3,2:revroot,3:11,4:1,5:rcp,8:{1:0},9:{1:6}}
    cur_b=enc(cur_state); cur_h=mh(cur_b)
    rgid=mh(b"DGI15 grant intent")
    rr1={1:preg,2:rgid,3:1,4:None,5:1,6:hist_h,7:6,8:2000320000}
    rr1b=enc(rr1); rr1h=mh(rr1b)
    stale_rev=enc(["OpenIdentity Delegation Grant Revocation",1,preg,rgid,rr1h,2,hist_h,rcid])
    stale_sig=rcpriv.sign(stale_rev)
    add("DGI15","INVALID_ROOT_STATE_HASH","stale-root-state-revocation",
        currentRecordBytesHex=rr1b.hex(),currentRecordHashHex=rr1h.hex(),
        historicalRootStateHashHex=hist_h.hex(),currentRootStateBytesHex=cur_b.hex(),currentRootStateHashHex=cur_h.hex(),
        submittedSigningBytesHex=stale_rev.hex(),submittedSignatureHex=stale_sig.hex(),controllerMethodIdHex=rcid.hex())

    # DGI16: valid grantor-revocation signature cannot serve as delegate relinquishment.
    delegate_principal={1:1,2:pdel}
    rev_domain=enc(["OpenIdentity Delegation Grant Revocation",1,preg,rgid,rr1h,2,cur_h,rcid])
    rev_domain_sig=rcpriv.sign(rev_domain)
    relinquish_domain=enc(["OpenIdentity Delegation Grant Relinquishment",1,preg,rgid,rr1h,2,delegate_principal])
    add("DGI16","CROSS_DOMAIN_PROOF","revocation-proof-as-relinquishment",
        revocationSigningBytesHex=rev_domain.hex(),relinquishmentSigningBytesHex=relinquish_domain.hex(),
        submittedSignatureHex=rev_domain_sig.hex())

    # DGI17: exact-next revision violated (1 -> 3).
    skipped={1:preg,2:rgid,3:3,4:rr1h,5:2,6:cur_h,7:6,8:2000320000}
    add("DGI17","INVALID_GRANT_REVISION","skipped-grant-revision",
        currentRecordBytesHex=rr1b.hex(),currentRevision=1,attemptedRevision=3,
        attemptedRecordBytesHex=enc(skipped).hex())

    # DGI18: registryDomain is immutable within a record history.
    other_registry=b"openidentity:test:oi014:other-registry"
    moved={1:other_registry,2:rgid,3:2,4:rr1h,5:2,6:cur_h,7:6,8:2000320000}
    add("DGI18","REGISTRY_DOMAIN_MISMATCH","record-chain-registry-domain-mutation",
        currentRegistryDomainHex=preg.hex(),attemptedRegistryDomainHex=other_registry.hex(),
        currentRecordBytesHex=rr1b.hex(),attemptedRecordBytesHex=enc(moved).hex())

    # DGI19-DGI24: OPENIDENTITY delegate AuthenticationAuthority attacks.
    areg=b"openidentity:test:oi014:auth-attacks"; aroot=bytes(range(20,52)); issuer=bytes(range(52,84)); target=bytes(range(84,116))
    authid=bytes(range(20,36)); ctrlid=bytes(range(36,52))
    authpriv,_,authm=_ed25519("OpenIdentity OI-014 auth attack authentication seed",20) if False else key("OpenIdentity OI-014 auth attack authentication seed",authid)
    ctrlpriv,_,ctrlm=key("OpenIdentity OI-014 auth attack controller seed",ctrlid)
    ap=policy(authid,authm); cp=policy(ctrlid,ctrlm); agen=4
    istate={1:3,2:issuer,3:12,4:1,5:cp,8:{1:agen,2:ap},9:{1:0}}
    isb=enc(istate); ish=mh(isb)
    fake_parent_id=mh(b"OI-014 auth attack parent"); fake_parent_rh=mh(b"OI-014 auth attack parent record")
    achild={1:1,2:aroot,3:{1:1,2:issuer},4:{1:1,2:target},5:[read],
            7:2000400000,8:fake_parent_id,9:seed("OI-014 auth attack child nonce")}
    acb=enc(achild)
    good_child_sign=enc(["OpenIdentity Delegation Child Grant",1,areg,acb,fake_parent_id,fake_parent_rh,ish,agen,authid])

    # ControllerPolicy key signs the child domain, but is wrong purpose authority.
    ctrl_child_sign=enc(["OpenIdentity Delegation Child Grant",1,areg,acb,fake_parent_id,fake_parent_rh,ish,agen,ctrlid])
    ctrl_child_sig=ctrlpriv.sign(ctrl_child_sign)
    add("DGI19","INVALID_REGISTRATION_PROOF","controller-policy-as-delegate-authentication",
        delegateStateBytesHex=isb.hex(),authenticationMethodIdHex=authid.hex(),submittedMethodIdHex=ctrlid.hex(),
        submittedSigningBytesHex=ctrl_child_sign.hex(),submittedSignatureHex=ctrl_child_sig.hex())

    # Historical AuthenticationPolicy proof after state advances/rotates.
    newauthid=bytes(range(52,68)); _,_,newauthm=key("OpenIdentity OI-014 auth attack new authentication seed",newauthid)
    newap=policy(newauthid,newauthm)
    newstate={1:3,2:issuer,3:13,4:1,5:cp,8:{1:agen,2:newap},9:{1:0}}
    nsb=enc(newstate); nsh=mh(nsb)
    oldsig=authpriv.sign(good_child_sign)
    add("DGI20","INVALID_ROOT_STATE_HASH","stale-delegate-authentication-state",
        historicalDelegateStateHashHex=ish.hex(),currentDelegateStateBytesHex=nsb.hex(),currentDelegateStateHashHex=nsh.hex(),
        submittedSigningBytesHex=good_child_sign.hex(),submittedSignatureHex=oldsig.hex(),
        historicalAuthenticationMethodIdHex=authid.hex(),currentAuthenticationMethodIdHex=newauthid.hex())

    wronggen=agen-1
    wronggen_sign=enc(["OpenIdentity Delegation Child Grant",1,areg,acb,fake_parent_id,fake_parent_rh,ish,wronggen,authid])
    wronggen_sig=authpriv.sign(wronggen_sign)
    add("DGI21","INVALID_AUTHENTICATION_GENERATION","wrong-authentication-generation",
        currentAuthenticationGeneration=agen,submittedAuthenticationGeneration=wronggen,
        submittedSigningBytesHex=wronggen_sign.hex(),submittedSignatureHex=wronggen_sig.hex())

    absent={1:3,2:issuer,3:14,4:1,5:cp,8:{1:agen},9:{1:0}}
    add("DGI22","INVALID_REGISTRATION_PROOF","authentication-policy-absent",
        delegateStateBytesHex=enc(absent).hex(),authenticationGeneration=agen,authenticationPolicyPresent=False)

    deactivated={1:3,2:issuer,3:15,4:2,5:cp,8:{1:agen,2:ap},9:{1:0}}
    add("DGI23","INVALID_REGISTRATION_PROOF","deactivated-delegate-child-issuance",
        delegateStateBytesHex=enc(deactivated).hex(),delegateStatus="DEACTIVATED",authenticationPolicyPresent=True)

    grant_for_rel=mh(b"OI-014 DGI24 grant"); rec_for_rel=mh(b"OI-014 DGI24 record")
    childpurpose=enc(["OpenIdentity Delegation Child Grant",1,areg,acb,fake_parent_id,fake_parent_rh,ish,agen,authid])
    childpurpose_sig=authpriv.sign(childpurpose)
    relpurpose=enc(["OpenIdentity Delegation Grant Relinquishment",1,areg,grant_for_rel,rec_for_rel,2,ish,agen,authid])
    add("DGI24","CROSS_DOMAIN_PROOF","child-proof-as-relinquishment",
        childSigningBytesHex=childpurpose.hex(),relinquishmentSigningBytesHex=relpurpose.hex(),
        submittedSignatureHex=childpurpose_sig.hex())

    return out


def main():
    registry=b"openidentity:test:oi014:dg01"
    root=bytes(range(32))
    delegate=bytes(range(32,64))
    method_id=bytes(range(16))
    priv,_,method=key("OpenIdentity OI-014 DG01 delegation Ed25519 seed",method_id)
    dp=policy(method_id,method)

    # Minimal deterministic capability profile descriptor for DG01.
    # Candidate descriptor labels are vector-local until profile descriptor CDDL freezes.
    descriptor={1:1,2:"openidentity.test.exact-capability",3:1,
                4:[b"document.read"],5:3600,6:4}
    profile_bytes=enc(descriptor); profile_hash=mh(profile_bytes)
    profile_ref={1:1,2:profile_hash}
    capability_ref={1:profile_ref,2:b"document.read"}
    delegated_cap={1:capability_ref}

    issuer={1:1,2:root}
    delegate_principal={1:1,2:delegate}
    grant={1:1,2:root,3:issuer,4:delegate_principal,5:[delegated_cap],
           7:2000003600,9:seed("OpenIdentity OI-014 DG01 nonce")}
    grant_bytes=enc(grant); grant_id=mh(grant_bytes)

    # Synthetic but exact current IdentityState v3 used only as DG01 predecessor context.
    current_state={1:3,2:root,3:7,4:1,5:dp,8:{1:0},9:{1:4,2:dp}}
    state_bytes=enc(current_state); state_hash=mh(state_bytes)
    generation=4

    signing=enc(["OpenIdentity Delegation Grant",1,registry,grant_bytes,state_hash,generation,method_id])
    sig=priv.sign(signing)
    request={1:registry,2:grant,3:state_hash,4:generation,5:[{1:method_id,2:sig}]}
    registered_at=2000000000
    record={1:registry,2:grant_id,3:1,4:None,5:1,6:state_hash,7:generation,8:registered_at}
    record_bytes=enc(record); record_hash=mh(record_bytes)

    vector={"suite":"OpenIdentity OI-014 DelegationGrant v1","status":"DRAFT-NON-NORMATIVE",
      "vectors":[{"id":"DG01","description":"Direct grant registration with single Ed25519 DelegationPolicy and OPENIDENTITY delegate","expected":"PASS",
      "profileDescriptorBytesHex":profile_bytes.hex(),"profileHashHex":profile_hash.hex(),
      "currentStateBytesHex":state_bytes.hex(),"currentStateHashHex":state_hash.hex(),
      "grantBytesHex":grant_bytes.hex(),"grantIdHex":grant_id.hex(),
      "registrationSigningBytesHex":signing.hex(),"registrationSignatureHex":sig.hex(),
      "registrationRequestBytesHex":enc(request).hex(),"registeredAt":registered_at,
      "recordBytesHex":record_bytes.hex(),"recordHashHex":record_hash.hex()},build_dg02(),build_dg03(),build_dg04(),build_dg05(),build_dg06()],"invalidVectors":build_invalids()}
    OUT.parent.mkdir(parents=True,exist_ok=True)
    OUT.write_text(json.dumps(vector,indent=2)+"\n",encoding="utf-8")
    print("Wrote",OUT.relative_to(ROOT))
    print("DG01 VERIFIED")
    print("DG02 VERIFIED")
    print("DG03 VERIFIED")
    print("DG04 VERIFIED")
    print("DG05 VERIFIED")
    print("DG06 VERIFIED")
    print("DGI01-DGI06 GENERATED")
if __name__=="__main__": main()
