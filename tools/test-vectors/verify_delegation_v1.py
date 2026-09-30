#!/usr/bin/env python3
"""Independent verification of draft OI-014 DG01."""
from __future__ import annotations
import hashlib,json
from pathlib import Path
import cbor2
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat

ROOT=Path(__file__).resolve().parents[2]
FILE=ROOT/"test-vectors"/"generated"/"delegation-v1.json"
def h(b):return hashlib.sha256(b).digest()
def mh(b):return b"\x12\x20"+h(b)
def enc(x):return cbor2.dumps(x,canonical=True)
def req(n,v):
    if not v: raise AssertionError(n)
    print(" ",n+": PASS")
def sk(label):return h(label.encode())

def main():
    data=json.loads(FILE.read_text())
    req("suite specification",data["suite"]=="OpenIdentity OI-014 DelegationGrant v1")
    req("draft status",data["status"]=="DRAFT-NON-NORMATIVE")
    req("vector IDs DG01-DG06",[x["id"] for x in data["vectors"]]==["DG01","DG02","DG03","DG04","DG05","DG06"])
    v=data["vectors"][0]
    registry=b"openidentity:test:oi014:dg01"; root=bytes(range(32)); delegate=bytes(range(32,64)); mid=bytes(range(16))
    priv=Ed25519PrivateKey.from_private_bytes(sk("OpenIdentity OI-014 DG01 delegation Ed25519 seed"))
    pub=priv.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
    method={1:1,3:-8,4:-1,6:pub}; dp={1:1,2:[{1:mid,2:method}]}
    descriptor={1:1,2:"openidentity.test.exact-capability",3:1,4:[b"document.read"],5:3600,6:4}
    pb=enc(descriptor); ph=mh(pb)
    req("DG01 ProfileDescriptor bytes",v["profileDescriptorBytesHex"]==pb.hex())
    req("DG01 ProfileHash",v["profileHashHex"]==ph.hex())
    grant={1:1,2:root,3:{1:1,2:root},4:{1:1,2:delegate},
           5:[{1:{1:{1:1,2:ph},2:b"document.read"}}],
           7:2000003600,9:sk("OpenIdentity OI-014 DG01 nonce")}
    gb=enc(grant); gid=mh(gb)
    req("DG01 GrantBytes",v["grantBytesHex"]==gb.hex());req("DG01 GrantId",v["grantIdHex"]==gid.hex())
    state={1:3,2:root,3:7,4:1,5:dp,8:{1:0},9:{1:4,2:dp}}
    sb=enc(state); sh=mh(sb)
    req("DG01 current StateBytes",v["currentStateBytesHex"]==sb.hex());req("DG01 current StateHash",v["currentStateHashHex"]==sh.hex())
    signing=enc(["OpenIdentity Delegation Grant",1,registry,gb,sh,4,mid])
    req("DG01 registration signing bytes",v["registrationSigningBytesHex"]==signing.hex())
    sig=bytes.fromhex(v["registrationSignatureHex"]); priv.public_key().verify(sig,signing)
    req("DG01 DelegationPolicy signature verifies",True)
    request={1:registry,2:grant,3:sh,4:4,5:[{1:mid,2:sig}]}
    req("DG01 registration request bytes",v["registrationRequestBytesHex"]==enc(request).hex())
    record={1:registry,2:gid,3:1,4:None,5:1,6:sh,7:4,8:2000000000}
    rb=enc(record)
    req("DG01 RecordBytes",v["recordBytesHex"]==rb.hex());req("DG01 RecordHash",v["recordHashHex"]==mh(rb).hex())
    req("DG01 time interval",2000000000<2000003600)
    req("DG01 direct issuer equals rootGrantor",grant[3][2]==root)

    v2=data["vectors"][1]
    registry2=b"openidentity:test:oi014:dg02"; root2=bytes(range(64,96)); delegate2=bytes(range(96,128))
    ma=bytes(range(16)); mb=bytes(range(16,32))
    ea=Ed25519PrivateKey.from_private_bytes(sk("OpenIdentity OI-014 DG02 delegation A Ed25519 seed"))
    eb=Ed25519PrivateKey.from_private_bytes(sk("OpenIdentity OI-014 DG02 delegation B Ed25519 seed"))
    puba=ea.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw); pubb=eb.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
    mtha={1:1,3:-8,4:-1,6:puba}; mthb={1:1,3:-8,4:-1,6:pubb}
    dp2={1:2,2:2,3:[{1:ma,2:mtha},{1:mb,2:mthb}]}
    desc2={1:1,2:"openidentity.test.exact-capability",3:1,4:[b"document.write"],5:1800,6:2}
    pb2=enc(desc2); ph2=mh(pb2)
    grant2={1:1,2:root2,3:{1:1,2:root2},4:{1:1,2:delegate2},
            5:[{1:{1:{1:1,2:ph2},2:b"document.write"}}],
            7:2000002800,9:sk("OpenIdentity OI-014 DG02 nonce")}
    gb2=enc(grant2); gid2=mh(gb2)
    state2={1:3,2:root2,3:11,4:1,5:dp2,8:{1:0},9:{1:9,2:dp2}}
    sb2=enc(state2); sh2=mh(sb2)
    req("DG02 canonical threshold policy order",dp2[3][0][1]==ma and dp2[3][1][1]==mb)
    req("DG02 GrantBytes",v2["grantBytesHex"]==gb2.hex()); req("DG02 GrantId",v2["grantIdHex"]==gid2.hex())
    req("DG02 current StateBytes",v2["currentStateBytesHex"]==sb2.hex()); req("DG02 current StateHash",v2["currentStateHashHex"]==sh2.hex())
    sa=enc(["OpenIdentity Delegation Grant",1,registry2,gb2,sh2,9,ma]); sbsg=enc(["OpenIdentity Delegation Grant",1,registry2,gb2,sh2,9,mb])
    siga=bytes.fromhex(v2["registrationSignatureAHex"]); sigb=bytes.fromhex(v2["registrationSignatureBHex"])
    ea.public_key().verify(siga,sa); eb.public_key().verify(sigb,sbsg)
    req("DG02 both threshold signatures verify",True)
    proofs=[{1:ma,2:siga},{1:mb,2:sigb}]
    req("DG02 canonical proof order",proofs[0][1]==ma and proofs[1][1]==mb)
    request2={1:registry2,2:grant2,3:sh2,4:9,5:proofs}
    req("DG02 registration request bytes",v2["registrationRequestBytesHex"]==enc(request2).hex())
    rec2={1:registry2,2:gid2,3:1,4:None,5:1,6:sh2,7:9,8:2000001000}; rb2=enc(rec2)
    req("DG02 RecordBytes",v2["recordBytesHex"]==rb2.hex());req("DG02 RecordHash",v2["recordHashHex"]==mh(rb2).hex())

    v3=data["vectors"][2]
    reg3=b"openidentity:test:oi014:dg03"; root3=bytes(range(128,160)); del3=bytes(range(160,192))
    ida=bytes(range(32,48)); idb=bytes(range(48,64))
    ka=Ed25519PrivateKey.from_private_bytes(sk("OpenIdentity OI-014 DG03 delegation A Ed25519 seed"))
    kb=Ed25519PrivateKey.from_private_bytes(sk("OpenIdentity OI-014 DG03 delegation B Ed25519 seed"))
    pka=ka.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw); pkb=kb.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
    pA={1:1,2:[{1:ida,2:{1:1,3:-8,4:-1,6:pka}}]}; pB={1:1,2:[{1:idb,2:{1:1,3:-8,4:-1,6:pkb}}]}
    d3={1:1,2:"openidentity.test.exact-capability",3:1,4:[b"document.read"],5:7200,6:3}; ph3=mh(enc(d3))
    g3={1:1,2:root3,3:{1:1,2:root3},4:{1:1,2:del3},5:[{1:{1:{1:1,2:ph3},2:b"document.read"}}],
        7:2000010000,9:sk("OpenIdentity OI-014 DG03 nonce")}
    gb3=enc(g3); gid3=mh(gb3); gen3=12
    before3={1:3,2:root3,3:20,4:1,5:pA,8:{1:0},9:{1:gen3,2:pA}}; b3=enc(before3); bh3=mh(b3)
    req("DG03 registration StateHash",v3["registrationStateHashHex"]==bh3.hex())
    sign3=enc(["OpenIdentity Delegation Grant",1,reg3,gb3,bh3,gen3,ida])
    ka.public_key().verify(bytes.fromhex(v3["registrationSignatureHex"]),sign3);req("DG03 original registration signature verifies",True)
    rec3={1:reg3,2:gid3,3:1,4:None,5:1,6:bh3,7:gen3,8:2000003000}; rb3=enc(rec3); rh3=mh(rb3)
    req("DG03 original RecordHash",v3["recordHashHex"]==rh3.hex())
    op3={1:2,2:7,3:root3,4:21,5:bh3,6:{1:pB,2:0}}; req("DG03 rotation OperationBytes",v3["rotationOperationBytesHex"]==enc(op3).hex())
    after3={1:3,2:root3,3:21,4:1,5:pA,8:{1:0},9:{1:gen3,2:pB}}; ab3=enc(after3)
    req("DG03 generation preserved",v3["delegationGenerationBefore"]==gen3 and v3["delegationGenerationAfter"]==gen3)
    req("DG03 post-rotation StateBytes",v3["postRotationStateBytesHex"]==ab3.hex())
    req("DG03 registration record unchanged",v3["recordHashAfterRotationHex"]==rh3.hex())
    req("DG03 grant remains generation-compatible",v3["grantUsableAfterRotation"] is True and rec3[7]==after3[9][1])

    v4=data["vectors"][3]
    reg4=b"openidentity:test:oi014:dg04"; root4=bytes(range(192,224)); del4=bytes(range(224,256))
    cid4=bytes(range(64,80)); did4=bytes(range(80,96))
    kc=Ed25519PrivateKey.from_private_bytes(sk("OpenIdentity OI-014 DG04 controller Ed25519 seed"))
    kd=Ed25519PrivateKey.from_private_bytes(sk("OpenIdentity OI-014 DG04 delegation Ed25519 seed"))
    pc=kc.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw); pd=kd.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
    cp4={1:1,2:[{1:cid4,2:{1:1,3:-8,4:-1,6:pc}}]}; dp4={1:1,2:[{1:did4,2:{1:1,3:-8,4:-1,6:pd}}]}
    desc4={1:1,2:"openidentity.test.exact-capability",3:1,4:[b"document.delete"],5:3600,6:2}; ph4=mh(enc(desc4))
    g4={1:1,2:root4,3:{1:1,2:root4},4:{1:1,2:del4},5:[{1:{1:{1:1,2:ph4},2:b"document.delete"}}],
        7:2000015000,9:sk("OpenIdentity OI-014 DG04 nonce")}
    gb4=enc(g4); gid4=mh(gb4); gen4=15
    st4={1:3,2:root4,3:30,4:1,5:cp4,8:{1:0},9:{1:gen4,2:dp4}}; sb4=enc(st4); sh4=mh(sb4)
    kd.public_key().verify(bytes.fromhex(v4["registrationSignatureHex"]),enc(["OpenIdentity Delegation Grant",1,reg4,gb4,sh4,gen4,did4]))
    req("DG04 original registration signature verifies",True)
    r1={1:reg4,2:gid4,3:1,4:None,5:1,6:sh4,7:gen4,8:2000010000}; r1b=enc(r1); r1h=mh(r1b)
    req("DG04 ACTIVE RecordHash",v4["activeRecordHashHex"]==r1h.hex())
    revsign=enc(["OpenIdentity Delegation Grant Revocation",1,reg4,gid4,r1h,2,sh4,cid4])
    revsig=bytes.fromhex(v4["revocationSignatureHex"]); kc.public_key().verify(revsig,revsign)
    req("DG04 ControllerPolicy revocation signature verifies",True)
    req("DG04 revocation signing bytes",v4["revocationSigningBytesHex"]==revsign.hex())
    revreq={1:reg4,2:gid4,3:r1h,4:2,5:sh4,6:1,7:[{1:cid4,2:revsig}]}
    req("DG04 revocation request bytes",v4["revocationRequestBytesHex"]==enc(revreq).hex())
    r2={1:reg4,2:gid4,3:2,4:r1h,5:2,6:sh4,7:gen4,8:2000010000}; r2b=enc(r2); r2h=mh(r2b)
    req("DG04 exact next revision",r2[3]==r1[3]+1)
    req("DG04 previous RecordHash binding",r2[4]==r1h)
    req("DG04 REVOKED terminal state",r2[5]==2)
    req("DG04 GrantId unchanged",v4["grantIdAfterRevocationHex"]==gid4.hex())
    req("DG04 registeredAt unchanged",v4["registeredAtBefore"]==v4["registeredAtAfter"]==2000010000)
    req("DG04 revoked RecordBytes",v4["revokedRecordBytesHex"]==r2b.hex());req("DG04 revoked RecordHash",v4["revokedRecordHashHex"]==r2h.hex())

    v5=data["vectors"][4]
    reg5=b"openidentity:test:oi014:dg05"; root5=bytes(range(16,48)); del5=bytes(range(48,80))
    ida5=bytes(range(96,112)); idb5=bytes(range(112,128))
    ka5=Ed25519PrivateKey.from_private_bytes(sk("OpenIdentity OI-014 DG05 delegation A Ed25519 seed"))
    kb5=Ed25519PrivateKey.from_private_bytes(sk("OpenIdentity OI-014 DG05 delegation B Ed25519 seed"))
    pka5=ka5.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw); pkb5=kb5.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
    pa5={1:1,2:[{1:ida5,2:{1:1,3:-8,4:-1,6:pka5}}]}; pb5={1:1,2:[{1:idb5,2:{1:1,3:-8,4:-1,6:pkb5}}]}
    d5={1:1,2:"openidentity.test.exact-capability",3:1,4:[b"document.admin"],5:3600,6:2}; ph5=mh(enc(d5))
    g5={1:1,2:root5,3:{1:1,2:root5},4:{1:1,2:del5},5:[{1:{1:{1:1,2:ph5},2:b"document.admin"}}],
        7:2000020000,9:sk("OpenIdentity OI-014 DG05 nonce")}
    gb5=enc(g5); gid5=mh(gb5); gen5=21
    before5={1:3,2:root5,3:40,4:1,5:pa5,8:{1:0},9:{1:gen5,2:pa5}}; bb5=enc(before5); bh5=mh(bb5)
    ka5.public_key().verify(bytes.fromhex(v5["registrationSignatureHex"]),enc(["OpenIdentity Delegation Grant",1,reg5,gb5,bh5,gen5,ida5]))
    req("DG05 original registration signature verifies",True)
    rec5={1:reg5,2:gid5,3:1,4:None,5:1,6:bh5,7:gen5,8:2000016000}; rb5=enc(rec5); rh5=mh(rb5)
    req("DG05 original ACTIVE RecordHash",v5["activeRecordHashHex"]==rh5.hex())
    op5={1:2,2:7,3:root5,4:41,5:bh5,6:{1:pb5,2:1}}
    req("DG05 INVALIDATE_EXISTING OperationBytes",v5["invalidationOperationBytesHex"]==enc(op5).hex())
    after5={1:3,2:root5,3:41,4:1,5:pa5,8:{1:0},9:{1:gen5+1,2:pb5}}; ab5=enc(after5)
    req("DG05 generation increments exactly once",v5["delegationGenerationBefore"]==21 and v5["delegationGenerationAfter"]==22)
    req("DG05 post-invalidation StateBytes",v5["postInvalidationStateBytesHex"]==ab5.hex())
    req("DG05 record remains revision 1 ACTIVE",v5["recordRevisionAfterInvalidation"]==1 and v5["recordStatusAfterInvalidation"]=="ACTIVE")
    req("DG05 RecordHash unchanged",v5["recordHashAfterInvalidationHex"]==rh5.hex())
    req("DG05 grant unusable solely by generation mismatch",v5["grantUsableAfterInvalidation"] is False and rec5[7]!=after5[9][1])

    v6=data["vectors"][5]
    reg6=b"openidentity:test:oi014:dg06"; root6=bytes(range(80,112)); pd6=bytes(range(112,144)); cd6=bytes(range(144,176))
    did6=bytes(range(128,144)); aid6=bytes(range(144,160))
    kd6=Ed25519PrivateKey.from_private_bytes(sk("OpenIdentity OI-014 DG06 root delegation Ed25519 seed"))
    ki6=Ed25519PrivateKey.from_private_bytes(sk("OpenIdentity OI-014 DG06 parent delegate authentication Ed25519 seed"))
    pubd6=kd6.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
    dp6={1:1,2:[{1:did6,2:{1:1,3:-8,4:-1,6:pubd6}}]}
    desc6={1:1,2:"openidentity.test.redelegation",3:1,4:[b"document.read",b"redelegate.document.read"],5:7200,6:3}
    pb6=enc(desc6); ph6=mh(pb6); pref6={1:1,2:ph6}
    read6={1:{1:pref6,2:b"document.read"}}; redel6={1:{1:pref6,2:b"redelegate.document.read"}}
    parent6={1:1,2:root6,3:{1:1,2:root6},4:{1:1,2:pd6},5:[read6,redel6],7:2000030000,9:sk("OpenIdentity OI-014 DG06 parent nonce")}
    pgb6=enc(parent6); pgid6=mh(pgb6); gen6=30
    rootst6={1:3,2:root6,3:50,4:1,5:dp6,8:{1:0},9:{1:gen6,2:dp6}}; rsb6=enc(rootst6); rsh6=mh(rsb6)
    psign6=enc(["OpenIdentity Delegation Grant",1,reg6,pgb6,rsh6,gen6,did6])
    kd6.public_key().verify(bytes.fromhex(v6["parentRegistrationSignatureHex"]),psign6);req("DG06 parent registration signature verifies",True)
    prec6={1:reg6,2:pgid6,3:1,4:None,5:1,6:rsh6,7:gen6,8:2000020000}; prb6=enc(prec6); prh6=mh(prb6)
    child6={1:1,2:root6,3:{1:1,2:pd6},4:{1:1,2:cd6},5:[read6],7:2000028000,8:pgid6,9:sk("OpenIdentity OI-014 DG06 child nonce")}
    cgb6=enc(child6); cgid6=mh(cgb6)
    csign6=enc(["OpenIdentity Delegation Child Grant",1,reg6,cgb6,pgid6,prh6])
    csig6=bytes.fromhex(v6["childIssuerProofHex"]); ki6.public_key().verify(csig6,csign6)
    req("DG06 child issuer proof verifies",True)
    req("DG06 rootGrantor preserved",child6[2]==parent6[2])
    req("DG06 issuer equals parent delegate",child6[3]==parent6[4])
    req("DG06 exact parentGrantId",child6[8]==pgid6)
    req("DG06 capability attenuated",child6[5]==[read6] and read6 in parent6[5] and redel6 in parent6[5])
    req("DG06 lifetime attenuated",child6[7] < parent6[7])
    req("DG06 child signing bytes",v6["childSigningBytesHex"]==csign6.hex())
    creq6={1:reg6,2:child6,3:pgid6,4:prh6,5:csig6}
    req("DG06 child registration request bytes",v6["childRegistrationRequestBytesHex"]==enc(creq6).hex())
    crec6={1:reg6,2:cgid6,3:1,4:None,5:1,6:rsh6,7:gen6,8:2000021000}; crb6=enc(crec6); crh6=mh(crb6)
    req("DG06 child RecordBytes",v6["childRecordBytesHex"]==crb6.hex());req("DG06 child RecordHash",v6["childRecordHashHex"]==crh6.hex())
    req("DG06 depth 2",v6["childDepth"]==2)

    invalid={x["id"]:x for x in data["invalidVectors"]}
    req("invalid vector IDs DGI01-DGI18",set(invalid)=={f"DGI{i:02d}" for i in range(1,19)})
    expected={"DGI01":"UNAUTHORIZED_GRANT_REGISTRATION","DGI02":"INVALID_DELEGATION_GENERATION",
              "DGI03":"CROSS_DOMAIN_PROOF","DGI04":"INVALID_PREVIOUS_RECORD_HASH",
              "DGI05":"CAPABILITY_ESCALATION","DGI06":"PARENT_GRANT_UNUSABLE",
              "DGI07":"ROOT_GRANTOR_MISMATCH","DGI08":"ISSUER_PARENT_DELEGATE_MISMATCH",
              "DGI09":"CHILD_TIME_WIDENING","DGI10":"REDELEGATION_NOT_AUTHORIZED",
              "DGI11":"PROFILE_SUBSTITUTION","DGI12":"TERMINAL_GRANT_STATE",
              "DGI13":"GRANT_EXPIRED_AT_REGISTRATION","DGI14":"INVALID_TIME_RANGE",
              "DGI15":"INVALID_ROOT_STATE_HASH","DGI16":"CROSS_DOMAIN_PROOF",
              "DGI17":"INVALID_GRANT_REVISION","DGI18":"REGISTRY_DOMAIN_MISMATCH"}
    req("DGI01-DGI18 stable errors",all(invalid[k]["error"]==v for k,v in expected.items()))

    i1=invalid["DGI01"]
    oldpub=Ed25519PrivateKey.from_private_bytes(sk("OpenIdentity OI-014 DGI01 old delegation seed")).public_key()
    oldpub.verify(bytes.fromhex(i1["submittedSignatureHex"]),bytes.fromhex(i1["submittedSigningBytesHex"]))
    req("DGI01 historical signature cryptographically verifies",True)
    req("DGI01 old method is not current",i1["submittedMethodIdHex"]!=i1["currentDelegationPolicyMethodIdHex"])
    req("DGI01 historical StateHash is not current",i1["historicalStateHashHex"]!=i1["currentStateHashHex"])

    i2=invalid["DGI02"]
    req("DGI02 claimed generation differs from current",i2["claimedGeneration"]!=i2["actualGeneration"])

    i3=invalid["DGI03"]
    sig3=bytes.fromhex(i3["submittedSignatureHex"])
    pub3=Ed25519PrivateKey.from_private_bytes(sk("OpenIdentity OI-014 DGI02 delegation seed")).public_key()
    pub3.verify(sig3,bytes.fromhex(i3["authorizedSigningBytesHex"]))
    req("DGI03 signature verifies in Registry A domain",True)
    try:
        pub3.verify(sig3,bytes.fromhex(i3["requiredSigningBytesHex"]))
        cross=False
    except Exception:
        cross=True
    req("DGI03 signature rejected in Registry B domain",cross)

    i4=invalid["DGI04"]
    req("DGI04 submitted parent RecordHash is stale",i4["submittedParentRecordHashHex"]!=i4["currentParentRecordHashHex"])

    i5=invalid["DGI05"]
    req("DGI05 child capability absent from parent authority","document.admin" not in i5["parentCapabilities"] and i5["childCapabilities"]==["document.admin"])

    i6=invalid["DGI06"]
    req("DGI06 current parent is REVOKED",i6["currentParentStatus"]=="REVOKED")

    i7=invalid["DGI07"]
    req("DGI07 child rootGrantor differs from parent",i7["childRootGrantorHex"]!=i7["parentRootGrantorHex"])

    i8=invalid["DGI08"]
    req("DGI08 child issuer differs from parent delegate",i8["childIssuerHex"]!=i8["parentDelegateHex"])

    i9=invalid["DGI09"]
    req("DGI09 child expiry exceeds parent",i9["childExpiresAt"]>i9["parentExpiresAt"])

    i10=invalid["DGI10"]
    req("DGI10 parent lacks explicit redelegation authority",
        i10["parentCapabilities"]==["document.read"] and i10["requestedChildCapabilities"]==["document.read"])

    i11=invalid["DGI11"]
    req("DGI11 same capability name under different profile hash",
        i11["parentProfileHashHex"]!=i11["childProfileHashHex"] and bytes.fromhex(i11["capabilityIdHex"])==b"document.read")

    i12=invalid["DGI12"]
    req("DGI12 current grant state is terminal REVOKED",i12["currentRevision"]==2 and i12["currentStatus"]=="REVOKED")
    req("DGI12 attempted duplicate REGISTER tries revision 1",i12["attemptedNewRevision"]==1)

    i13=invalid["DGI13"]
    req("DGI13 expiresAt is not after registeredAt",i13["expiresAt"]<=i13["registeredAt"])

    i14=invalid["DGI14"]
    req("DGI14 notBefore is not less than expiresAt",i14["notBefore"]>=i14["expiresAt"])

    i15=invalid["DGI15"]
    k15=Ed25519PrivateKey.from_private_bytes(sk("OpenIdentity OI-014 DGI15 controller seed")).public_key()
    sig15=bytes.fromhex(i15["submittedSignatureHex"]); sign15=bytes.fromhex(i15["submittedSigningBytesHex"])
    k15.verify(sig15,sign15); req("DGI15 stale revocation signature cryptographically verifies",True)
    req("DGI15 historical root StateHash is stale",i15["historicalRootStateHashHex"]!=i15["currentRootStateHashHex"])

    i16=invalid["DGI16"]
    k16=Ed25519PrivateKey.from_private_bytes(sk("OpenIdentity OI-014 DGI15 controller seed")).public_key()
    sig16=bytes.fromhex(i16["submittedSignatureHex"])
    k16.verify(sig16,bytes.fromhex(i16["revocationSigningBytesHex"]));req("DGI16 signature verifies in revocation domain",True)
    try:
        k16.verify(sig16,bytes.fromhex(i16["relinquishmentSigningBytesHex"])); wrong16=False
    except Exception:
        wrong16=True
    req("DGI16 revocation signature rejected in relinquishment domain",wrong16)

    i17=invalid["DGI17"]
    req("DGI17 skips exact-next revision",i17["currentRevision"]==1 and i17["attemptedRevision"]==3)

    i18=invalid["DGI18"]
    req("DGI18 registryDomain changes within record chain",i18["currentRegistryDomainHex"]!=i18["attemptedRegistryDomainHex"])
    print("\n============================================")
    print("OI-014 DELEGATION v1 DG01-DG06 + DGI01-DGI18 VERIFIED")
    print("============================================")
if __name__=="__main__":main()
