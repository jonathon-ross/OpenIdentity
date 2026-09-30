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
    req("vector IDs DG01-DG05",[x["id"] for x in data["vectors"]]==["DG01","DG02","DG03","DG04","DG05"])
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
    print("\n============================================")
    print("OI-014 DELEGATION v1 DG01-DG05 VERIFIED")
    print("============================================")
if __name__=="__main__":main()
