#!/usr/bin/env python3
import hashlib,json,pathlib

ROOT=pathlib.Path(__file__).resolve().parents[1]
VECTORS=ROOT/"test-vectors"/"external-oidc-binding-v1.json"

def head(m,n):
    if n<24:return bytes([(m<<5)|n])
    if n<256:return bytes([(m<<5)|24,n])
    if n<65536:return bytes([(m<<5)|25])+n.to_bytes(2,"big")
    if n<2**32:return bytes([(m<<5)|26])+n.to_bytes(4,"big")
    return bytes([(m<<5)|27])+n.to_bytes(8,"big")

def cbor(x):
    if x is None:return b"\xf6"
    if isinstance(x,int):return head(0,x)
    if isinstance(x,bytes):return head(2,len(x))+x
    if isinstance(x,str):
        b=x.encode("utf-8");return head(3,len(b))+b
    if isinstance(x,list):return head(4,len(x))+b"".join(cbor(v) for v in x)
    if isinstance(x,dict):
        pairs=sorted(((cbor(k),cbor(v)) for k,v in x.items()),key=lambda p:p[0])
        return head(5,len(pairs))+b"".join(k+v for k,v in pairs)
    raise TypeError(type(x))

def multihash(data):return b"\x12\x20"+hashlib.sha256(data).digest()

data=json.loads(VECTORS.read_text())
for v in data["vectors"]:
    identity=bytes.fromhex(v["identityHex"])
    binding={1:1,2:identity,3:v["issuer"],4:v["subject"],5:v["clientId"],6:v["createdAt"],7:v["expiresAt"],8:v["authenticationGeneration"]}
    bb=cbor(binding)
    bid=multihash(cbor(["OpenIdentity External OIDC Binding",1,bb]))
    challenge=bytes.fromhex(v["registryChallengeHex"])
    ctx={1:1,2:1,3:identity,4:v["issuer"],5:v["subject"],6:v["clientId"],7:challenge,8:v["authenticationGeneration"],9:v["createdAt"],10:v["expiresAt"]}
    cb=cbor(ctx);ch=multihash(cb)
    assert bb.hex()==v["bindingBytesHex"],v["id"]+" BindingBytes"
    assert bid.hex()==v["bindingIdHex"],v["id"]+" BindingId"
    assert cb.hex()==v["bindContextBytesHex"],v["id"]+" ContextBytes"
    assert ch.hex()==v["bindContextHashHex"],v["id"]+" ContextHash"
    print(v["id"],"VERIFIED")
