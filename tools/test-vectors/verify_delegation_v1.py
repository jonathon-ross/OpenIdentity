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
    req("DG01 only",[x["id"] for x in data["vectors"]]==["DG01"])
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
    print("\n============================================")
    print("OI-014 DELEGATION v1 DG01 VERIFIED")
    print("============================================")
if __name__=="__main__":main()
