#!/usr/bin/env python3
from pathlib import Path
import hashlib,json

ROOT=Path(__file__).resolve().parents[1]
def head(major,n):
 if n<24:return bytes([(major<<5)|n])
 if n<256:return bytes([(major<<5)|24,n])
 if n<65536:return bytes([(major<<5)|25])+n.to_bytes(2,"big")
 if n<2**32:return bytes([(major<<5)|26])+n.to_bytes(4,"big")
 return bytes([(major<<5)|27])+n.to_bytes(8,"big")
def enc(x):
 if x is None:return b"\xf6"
 if isinstance(x,int) and x>=0:return head(0,x)
 if isinstance(x,bytes):return head(2,len(x))+x
 if isinstance(x,str):
  b=x.encode();return head(3,len(b))+b
 if isinstance(x,list):return head(4,len(x))+b"".join(enc(v) for v in x)
 if isinstance(x,dict):
  pairs=sorted(((enc(k),enc(v)) for k,v in x.items()),key=lambda kv:kv[0])
  return head(5,len(pairs))+b"".join(k+v for k,v in pairs)
 raise TypeError(type(x))
def mh(data):return b"\x12\x20"+hashlib.sha256(data).digest()

identity=bytes(range(32))
directory=bytes.fromhex("d0d1d2d3d4d5d6d7d8d9dadbdcdddedf")
guid=bytes.fromhex("00112233445566778899aabbccddeeff")
service="openidentity-ad-link-service"
created=1790841600;expires=None;generation=3
challenge=bytes(range(0x40,0x60));revoke_challenge=bytes(range(0x60,0x80))
mechanism=1
binding={1:1,2:identity,3:directory,4:guid,5:service,6:created,7:expires,8:generation}
bb=enc(binding);bid=mh(enc(["OpenIdentity External Active Directory Binding",1,bb]))
bindctx={1:1,2:1,3:identity,4:directory,5:guid,6:service,7:mechanism,8:challenge,9:generation,10:created,11:expires}
bc=enc(bindctx);bch=mh(bc)
revctx={1:1,2:2,3:identity,4:directory,5:guid,6:service,7:mechanism,8:revoke_challenge,9:generation,10:created,11:expires,12:bid}
rc=enc(revctx);rch=mh(rc)
out={
 "suite":"openidentity-external-ad-binding-v1-pre-freeze",
 "referenceVectors":[{
  "id":"AD01","valid":True,
  "identityHex":identity.hex(),"directoryIdHex":directory.hex(),"objectGuidLdapOctetsHex":guid.hex(),
  "serviceId":service,"authenticationMechanism":"KERBEROS_SPNEGO","authenticationMechanismCode":mechanism,
  "createdAt":created,"expiresAt":expires,"authenticationGeneration":generation,
  "registryChallengeHex":challenge.hex(),"bindingBytesHex":bb.hex(),"bindingIdHex":bid.hex(),
  "bindContextBytesHex":bc.hex(),"bindContextHashHex":bch.hex(),
  "revokeRegistryChallengeHex":revoke_challenge.hex(),"revokeContextBytesHex":rc.hex(),"revokeContextHashHex":rch.hex()
 }]
}
path=ROOT/"test-vectors/external-ad-binding-v1-crypto-pre-freeze.json"
path.write_text(json.dumps(out,indent=2)+"\n")
print("AD01 CRYPTO VECTOR GENERATED")
print("BindingId:",bid.hex());print("BindContextHash:",bch.hex());print("RevokeContextHash:",rch.hex())
