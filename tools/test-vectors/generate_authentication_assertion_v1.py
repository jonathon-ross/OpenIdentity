#!/usr/bin/env python3
"""Generate draft OI-015 Authentication Assertion vectors. Draft/non-normative."""
import hashlib,json
from pathlib import Path
import cbor2
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat

ROOT=Path(__file__).resolve().parents[2]
OUT=ROOT/"test-vectors"/"generated"/"authentication-assertion-v1.json"

def h(b):return hashlib.sha256(b).digest()
def mh(b):return b"\x12\x20"+h(b)
def enc(x):return cbor2.dumps(x,canonical=True)
def seed(s):return h(s.encode())
def method(mid,pub):return {1:1,3:-8,4:-1,6:pub}
def policy(mid,pub):return {1:1,2:[{1:mid,2:method(mid,pub)}]}

def aa01():
    identity=bytes(range(32))
    mid=bytes(range(32,48))
    priv=Ed25519PrivateKey.from_private_bytes(seed("OpenIdentity OI-015 AA01 authentication seed"))
    pub=priv.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
    ap=policy(mid,pub)
    generation=7
    # Frozen IdentityState v3 shape: controller policy is present; AuthenticationAuthority
    # is current generation 7 with SINGLE AuthenticationPolicy; DelegationAuthority absent.
    controller_id=bytes(range(48,64))
    cpriv=Ed25519PrivateKey.from_private_bytes(seed("OpenIdentity OI-015 AA01 controller seed"))
    cpub=cpriv.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
    cp=policy(controller_id,cpub)
    state={1:3,2:identity,3:21,4:1,5:cp,8:{1:generation,2:ap},9:{1:0}}
    sb=enc(state); sh=mh(sb)

    audience=b"https://verifier.example.test"
    purpose="openidentity.authentication"
    issued=2001000000; expires=2001000240
    nonce=bytes(range(64,96))
    context=b"OpenIdentity OI-015 AA01 test context v1"
    ch=mh(context)
    assertion={1:1,2:identity,3:sh,4:generation,5:audience,6:purpose,
               7:issued,8:expires,9:nonce,10:ch}
    ab=enc(assertion); aid=mh(ab)
    signing=enc(["OpenIdentity Authentication Assertion",1,ab,mid])
    sig=priv.sign(signing)
    secured={1:assertion,2:[{1:mid,2:sig}]}
    return {
      "id":"AA01","description":"SINGLE current AuthenticationPolicy assertion","expected":"PASS",
      "identityHex":identity.hex(),"authenticationMethodIdHex":mid.hex(),
      "authenticationPublicKeyHex":pub.hex(),"stateBytesHex":sb.hex(),"stateHashHex":sh.hex(),
      "authenticationGeneration":generation,"audienceHex":audience.hex(),"purpose":purpose,
      "issuedAt":issued,"expiresAt":expires,"nonceHex":nonce.hex(),"contextBytesHex":context.hex(),
      "contextHashHex":ch.hex(),"assertionBytesHex":ab.hex(),"assertionIdHex":aid.hex(),
      "signingBytesHex":signing.hex(),"signatureHex":sig.hex(),
      "securedAssertionBytesHex":enc(secured).hex()
    }

def main():
    data={"specification":"OpenIdentity OI-015 Authentication Assertion v1",
          "status":"DRAFT-NON-NORMATIVE","vectors":[aa01()],"invalidVectors":[]}
    OUT.parent.mkdir(parents=True,exist_ok=True)
    OUT.write_text(json.dumps(data,indent=2)+"\n",encoding="utf-8",newline="\n")
    print("Wrote",OUT.relative_to(ROOT))
    print("AA01 GENERATED")

if __name__=="__main__":main()
