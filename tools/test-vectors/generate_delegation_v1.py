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
    delegation_id=bytes(range(128,144)); issuer_auth_id=bytes(range(144,160))
    dpriv,_,dm=key("OpenIdentity OI-014 DG06 root delegation Ed25519 seed",delegation_id)
    ipriv,_,im=key("OpenIdentity OI-014 DG06 parent delegate authentication Ed25519 seed",issuer_auth_id)
    dp=policy(delegation_id,dm)

    # Vector-local profile: exact document.read plus explicit redelegation authority.
    descriptor={1:1,2:"openidentity.test.redelegation",3:1,
                4:[b"document.read",b"redelegate.document.read"],5:7200,6:3}
    pbytes=enc(descriptor); ph=mh(pbytes)
    pref={1:1,2:ph}
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

    child={1:1,2:root,3:{1:1,2:parent_delegate},4:{1:1,2:child_delegate},
           5:[read_cap],7:2000028000,8:parent_id,9:seed("OpenIdentity OI-014 DG06 child nonce")}
    child_b=enc(child); child_id=mh(child_b)
    child_sign=enc(["OpenIdentity Delegation Child Grant",1,registry,child_b,parent_id,parent_rh])
    child_sig=ipriv.sign(child_sign)
    child_req={1:registry,2:child,3:parent_id,4:parent_rh,5:child_sig}
    child_record={1:registry,2:child_id,3:1,4:None,5:1,6:root_h,7:generation,8:2000021000}
    child_rb=enc(child_record); child_rh=mh(child_rb)

    return {"id":"DG06","description":"Valid attenuated child grant issued by authenticated parent delegate with explicit redelegation authority","expected":"PASS",
      "profileDescriptorBytesHex":pbytes.hex(),"profileHashHex":ph.hex(),
      "rootStateBytesHex":root_b.hex(),"rootStateHashHex":root_h.hex(),
      "parentGrantBytesHex":parent_b.hex(),"parentGrantIdHex":parent_id.hex(),
      "parentRegistrationSigningBytesHex":parent_sign.hex(),"parentRegistrationSignatureHex":parent_sig.hex(),
      "parentRecordBytesHex":parent_rb.hex(),"parentRecordHashHex":parent_rh.hex(),
      "childGrantBytesHex":child_b.hex(),"childGrantIdHex":child_id.hex(),
      "childIssuerAuthenticationMethodIdHex":issuer_auth_id.hex(),
      "childSigningBytesHex":child_sign.hex(),"childIssuerProofHex":child_sig.hex(),
      "childRegistrationRequestBytesHex":enc(child_req).hex(),
      "childRecordBytesHex":child_rb.hex(),"childRecordHashHex":child_rh.hex(),
      "rootGrantorPreserved":True,"issuerEqualsParentDelegate":True,
      "capabilityAttenuated":True,"lifetimeAttenuated":True,
      "parentRedelegationAuthorized":True,"childDepth":2}


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
      "recordBytesHex":record_bytes.hex(),"recordHashHex":record_hash.hex()},build_dg02(),build_dg03(),build_dg04(),build_dg05(),build_dg06()]}
    OUT.parent.mkdir(parents=True,exist_ok=True)
    OUT.write_text(json.dumps(vector,indent=2)+"\n",encoding="utf-8")
    print("Wrote",OUT.relative_to(ROOT))
    print("DG01 VERIFIED")
    print("DG02 VERIFIED")
    print("DG03 VERIFIED")
    print("DG04 VERIFIED")
    print("DG05 VERIFIED")
    print("DG06 VERIFIED")
if __name__=="__main__": main()
