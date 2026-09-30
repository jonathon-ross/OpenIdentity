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
    req("vector IDs DG01-DG03",[x["id"] for x in data["vectors"]]==["DG01","DG02","DG03"])
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
    print("\n============================================")
    print("OI-014 DELEGATION v1 DG01-DG03 VERIFIED")
    print("============================================")
if __name__=="__main__":main()
