#!/usr/bin/env python3
"""Independently verify draft OI-015 AA01."""
import hashlib,json
from pathlib import Path
import cbor2
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat

ROOT=Path(__file__).resolve().parents[2]
P=ROOT/"test-vectors"/"generated"/"authentication-assertion-v1.json"
def h(b):return hashlib.sha256(b).digest()
def mh(b):return b"\x12\x20"+h(b)
def enc(x):return cbor2.dumps(x,canonical=True)
def sk(s):return h(s.encode())
def req(n,v):
    if not v:raise AssertionError(n)
    print(" ",n+": PASS")
def method(mid,pub):return {1:1,3:-8,4:-1,6:pub}
def policy(mid,pub):return {1:1,2:[{1:mid,2:method(mid,pub)}]}

def main():
    d=json.loads(P.read_text())
    req("suite specification",d["specification"]=="OpenIdentity OI-015 Authentication Assertion v1")
    req("draft status",d["status"]=="DRAFT-NON-NORMATIVE")
    req("AA01 only",[x["id"] for x in d["vectors"]]==["AA01"] and d["invalidVectors"]==[])
    v=d["vectors"][0]
    identity=bytes(range(32));mid=bytes(range(32,48))
    k=Ed25519PrivateKey.from_private_bytes(sk("OpenIdentity OI-015 AA01 authentication seed"))
    pub=k.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
    ap=policy(mid,pub)
    cid=bytes(range(48,64));ck=Ed25519PrivateKey.from_private_bytes(sk("OpenIdentity OI-015 AA01 controller seed"))
    cpub=ck.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw);cp=policy(cid,cpub)
    state={1:3,2:identity,3:21,4:1,5:cp,8:{1:7,2:ap},9:{1:0}}
    sb=enc(state);sh=mh(sb)
    req("AA01 StateBytes",v["stateBytesHex"]==sb.hex());req("AA01 StateHash",v["stateHashHex"]==sh.hex())
    context=b"OpenIdentity OI-015 AA01 test context v1";ch=mh(context)
    assertion={1:1,2:identity,3:sh,4:7,5:b"https://verifier.example.test",6:"openidentity.authentication",
               7:2001000000,8:2001000240,9:bytes(range(64,96)),10:ch}
    ab=enc(assertion);aid=mh(ab)
    req("AA01 AssertionBytes",v["assertionBytesHex"]==ab.hex());req("AA01 AssertionId",v["assertionIdHex"]==aid.hex())
    req("AA01 lifetime <= 300",assertion[8]-assertion[7]==240)
    signing=enc(["OpenIdentity Authentication Assertion",1,ab,mid]);sig=bytes.fromhex(v["signatureHex"])
    req("AA01 signing bytes",v["signingBytesHex"]==signing.hex())
    k.public_key().verify(sig,signing);req("AA01 AuthenticationPolicy signature verifies",True)
    secured={1:assertion,2:[{1:mid,2:sig}]}
    req("AA01 secured assertion bytes",v["securedAssertionBytesHex"]==enc(secured).hex())
    print("\n============================================")
    print("OI-015 AUTHENTICATION ASSERTION v1 AA01 VERIFIED")
    print("============================================")

if __name__=="__main__":main()
