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


def threshold_policy(entries,threshold):
    return {1:2,2:threshold,3:[{1:mid,2:method(mid,pub)} for mid,pub in sorted(entries,key=lambda x:x[0])]}

def aa02():
    identity=bytes(range(96,128))
    # Deliberately define/sign methods in noncanonical order C,A,B.
    aid=bytes(range(16,32));bid=bytes(range(32,48));cid=bytes(range(48,64))
    ak=Ed25519PrivateKey.from_private_bytes(seed("OpenIdentity OI-015 AA02 auth A seed"))
    bk=Ed25519PrivateKey.from_private_bytes(seed("OpenIdentity OI-015 AA02 auth B seed"))
    ck=Ed25519PrivateKey.from_private_bytes(seed("OpenIdentity OI-015 AA02 auth C seed"))
    apub=ak.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
    bpub=bk.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
    cpub=ck.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
    ap=threshold_policy([(cid,cpub),(aid,apub),(bid,bpub)],2)
    controller_id=bytes(range(64,80))
    ctrl=Ed25519PrivateKey.from_private_bytes(seed("OpenIdentity OI-015 AA02 controller seed"))
    ctrlpub=ctrl.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
    cp=policy(controller_id,ctrlpub)
    generation=12
    state={1:3,2:identity,3:34,4:1,5:cp,8:{1:generation,2:ap},9:{1:0}}
    sb=enc(state);sh=mh(sb)
    context=b"OpenIdentity OI-015 AA02 threshold context"
    assertion={1:1,2:identity,3:sh,4:generation,5:b"threshold-verifier",6:"openidentity.authentication",
               7:2001001000,8:2001001180,9:bytes(range(128,160)),10:mh(context)}
    ab=enc(assertion);assertion_id=mh(ab)
    # Sign C then A; canonical secured proof order must be A then C.
    csign=enc(["OpenIdentity Authentication Assertion",1,ab,cid]);csig=ck.sign(csign)
    asign=enc(["OpenIdentity Authentication Assertion",1,ab,aid]);asig=ak.sign(asign)
    proofs=sorted([{1:cid,2:csig},{1:aid,2:asig}],key=lambda p:p[1])
    secured={1:assertion,2:proofs}
    return {"id":"AA02","description":"2-of-3 AuthenticationPolicy with canonical proof ordering","expected":"PASS",
      "stateBytesHex":sb.hex(),"stateHashHex":sh.hex(),"assertionBytesHex":ab.hex(),"assertionIdHex":assertion_id.hex(),
      "methodAIdHex":aid.hex(),"methodCIdHex":cid.hex(),"signingABytesHex":asign.hex(),"signingCBytesHex":csign.hex(),
      "signatureAHex":asig.hex(),"signatureCHex":csig.hex(),
      "generatedProofOrder":["C","A"],"canonicalProofOrder":["A","C"],
      "securedAssertionBytesHex":enc(secured).hex()}



def aa03():
    identity=bytes(range(160,192));mid=bytes(range(80,96))
    priv=Ed25519PrivateKey.from_private_bytes(seed("OpenIdentity OI-015 AA03 authentication seed"))
    pub=priv.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw);ap=policy(mid,pub)
    controller_id=bytes(range(96,112))
    ctrl=Ed25519PrivateKey.from_private_bytes(seed("OpenIdentity OI-015 AA03 controller seed"))
    ctrlpub=ctrl.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw);cp=policy(controller_id,ctrlpub)
    generation=19
    state={1:3,2:identity,3:55,4:1,5:cp,8:{1:generation,2:ap},9:{1:0}}
    sb=enc(state);sh=mh(sb)
    issued=2001002000;expires=issued+300
    context=b"OpenIdentity OI-015 AA03 exact lifetime boundary"
    assertion={1:1,2:identity,3:sh,4:generation,5:b"lifetime-boundary-verifier",
               6:"openidentity.authentication",7:issued,8:expires,9:bytes(range(192,224)),10:mh(context)}
    ab=enc(assertion);aid=mh(ab)
    signing=enc(["OpenIdentity Authentication Assertion",1,ab,mid]);sig=priv.sign(signing)
    secured={1:assertion,2:[{1:mid,2:sig}]}
    return {"id":"AA03","description":"Exact normative 300-second assertion lifetime boundary","expected":"PASS",
      "stateBytesHex":sb.hex(),"stateHashHex":sh.hex(),"issuedAt":issued,"expiresAt":expires,
      "assertionBytesHex":ab.hex(),"assertionIdHex":aid.hex(),"authenticationMethodIdHex":mid.hex(),
      "signingBytesHex":signing.hex(),"signatureHex":sig.hex(),"securedAssertionBytesHex":enc(secured).hex()}



def invalids():
    out=[]
    def add(i,e,a,**kw):out.append({"id":i,"expectedError":e,"attack":a,**kw})
    identity=bytes(range(224,256));mid=bytes(range(112,128))
    k=Ed25519PrivateKey.from_private_bytes(seed("OpenIdentity OI-015 invalid authentication seed"))
    pub=k.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw);ap=policy(mid,pub)
    ctrlid=bytes(range(0,16));ctrl=Ed25519PrivateKey.from_private_bytes(seed("OpenIdentity OI-015 invalid controller seed"))
    cp=policy(ctrlid,ctrl.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw))
    historical={1:3,2:identity,3:70,4:1,5:cp,8:{1:8,2:ap},9:{1:0}}
    current={1:3,2:identity,3:71,4:1,5:cp,8:{1:9,2:ap},9:{1:0}}
    hsh=mh(enc(historical));csh=mh(enc(current))
    base={1:1,2:identity,3:csh,4:9,5:b"expected-verifier",6:"openidentity.authentication",
          7:2001003000,8:2001003120,9:bytes(range(16,48)),10:mh(b"expected-context")}
    stale=dict(base);stale[3]=hsh;stale[4]=8
    stale_b=enc(stale);stale_sign=enc(["OpenIdentity Authentication Assertion",1,stale_b,mid]);stale_sig=k.sign(stale_sign)
    add("AAI01","INVALID_STATE_HASH","historical-state-valid-signature",
        historicalStateHashHex=hsh.hex(),currentStateHashHex=csh.hex(),signingBytesHex=stale_sign.hex(),signatureHex=stale_sig.hex())
    add("AAI02","INVALID_AUTHENTICATION_GENERATION","stale-authentication-generation",
        assertedGeneration=8,currentGeneration=9)
    deactivated=dict(current);deactivated[4]=2
    add("AAI03","IDENTITY_NOT_ACTIVE","deactivated-identity",currentStateBytesHex=enc(deactivated).hex(),currentStatus="DEACTIVATED")
    noap={1:3,2:identity,3:72,4:1,5:cp,8:{1:9},9:{1:0}}
    add("AAI04","AUTHENTICATION_POLICY_ABSENT","authentication-policy-absent",currentStateBytesHex=enc(noap).hex(),authenticationPolicyPresent=False)
    wrongaud=dict(base);wrongaud[5]=b"other-verifier"
    add("AAI05","AUDIENCE_MISMATCH","wrong-audience",expectedAudienceHex=base[5].hex(),assertedAudienceHex=wrongaud[5].hex())
    wrongpurpose=dict(base);wrongpurpose[6]="openidentity.oauth.token-exchange"
    add("AAI06","PURPOSE_MISMATCH","wrong-purpose",expectedPurpose=base[6],assertedPurpose=wrongpurpose[6])
    wrongnonce=dict(base);wrongnonce[9]=bytes(range(48,80))
    add("AAI07","NONCE_MISMATCH","wrong-nonce",expectedNonceHex=base[9].hex(),assertedNonceHex=wrongnonce[9].hex())
    wrongctx=dict(base);wrongctx[10]=mh(b"attacker-context")
    add("AAI08","CONTEXT_HASH_MISMATCH","context-substitution",expectedContextHashHex=base[10].hex(),assertedContextHashHex=wrongctx[10].hex())
    return out

def main():
    data={"specification":"OpenIdentity OI-015 Authentication Assertion v1",
          "status":"DRAFT-NON-NORMATIVE","vectors":[aa01(),aa02(),aa03()],"invalidVectors":invalids()}
    OUT.parent.mkdir(parents=True,exist_ok=True)
    OUT.write_text(json.dumps(data,indent=2)+"\n",encoding="utf-8",newline="\n")
    print("Wrote",OUT.relative_to(ROOT))
    print("AA01 GENERATED")
    print("AA02 GENERATED")
    print("AA03 GENERATED")
    print("AAI01-AAI08 GENERATED")

if __name__=="__main__":main()
