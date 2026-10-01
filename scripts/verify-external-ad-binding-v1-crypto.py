#!/usr/bin/env python3
from pathlib import Path
import hashlib,json,sys
ROOT=Path(__file__).resolve().parents[1]
def head(m,n):
 if n<24:return bytes([(m<<5)|n])
 if n<256:return bytes([(m<<5)|24,n])
 if n<65536:return bytes([(m<<5)|25])+n.to_bytes(2,"big")
 if n<2**32:return bytes([(m<<5)|26])+n.to_bytes(4,"big")
 return bytes([(m<<5)|27])+n.to_bytes(8,"big")
def e(x):
 if x is None:return b"\xf6"
 if isinstance(x,int) and x>=0:return head(0,x)
 if isinstance(x,bytes):return head(2,len(x))+x
 if isinstance(x,str):b=x.encode();return head(3,len(b))+b
 if isinstance(x,list):return head(4,len(x))+b"".join(e(v) for v in x)
 if isinstance(x,dict):
  p=sorted(((e(k),e(v)) for k,v in x.items()),key=lambda z:z[0]);return head(5,len(p))+b"".join(k+v for k,v in p)
 raise TypeError()
def mh(x):return b"\x12\x20"+hashlib.sha256(x).digest()
v=json.loads((ROOT/"test-vectors/external-ad-binding-v1-crypto.json").read_text())["referenceVectors"][0]
hx=bytes.fromhex;identity=hx(v["identityHex"]);directory=hx(v["directoryIdHex"]);guid=hx(v["objectGuidLdapOctetsHex"])
assert len(identity)==32 and len(directory)==16 and len(guid)==16
assert guid==hx("00112233445566778899aabbccddeeff")
b={1:1,2:identity,3:directory,4:guid,5:v["serviceId"],6:v["createdAt"],7:v["expiresAt"],8:v["authenticationGeneration"]}
bb=e(b);assert bb.hex()==v["bindingBytesHex"]
assert mh(e(["OpenIdentity External Active Directory Binding",1,bb])).hex()==v["bindingIdHex"]
bc=e({1:1,2:1,3:identity,4:directory,5:guid,6:v["serviceId"],7:v["authenticationMechanismCode"],8:hx(v["registryChallengeHex"]),9:v["authenticationGeneration"],10:v["createdAt"],11:v["expiresAt"]})
assert bc.hex()==v["bindContextBytesHex"] and mh(bc).hex()==v["bindContextHashHex"]
rc=e({1:1,2:2,3:identity,4:directory,5:guid,6:v["serviceId"],7:v["authenticationMechanismCode"],8:hx(v["revokeRegistryChallengeHex"]),9:v["authenticationGeneration"],10:v["createdAt"],11:v["expiresAt"],12:hx(v["bindingIdHex"])})
assert rc.hex()==v["revokeContextBytesHex"] and mh(rc).hex()==v["revokeContextHashHex"]
print("AD01 CRYPTO VERIFIED")
