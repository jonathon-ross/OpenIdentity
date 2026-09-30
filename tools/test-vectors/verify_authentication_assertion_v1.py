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
    req("vector IDs AA01-AA03",[x["id"] for x in d["vectors"]]==["AA01","AA02","AA03"])
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
    v2=d["vectors"][1]
    identity2=bytes(range(96,128));aid=bytes(range(16,32));bid=bytes(range(32,48));cid2=bytes(range(48,64))
    ak=Ed25519PrivateKey.from_private_bytes(sk("OpenIdentity OI-015 AA02 auth A seed"))
    bk=Ed25519PrivateKey.from_private_bytes(sk("OpenIdentity OI-015 AA02 auth B seed"))
    ck2=Ed25519PrivateKey.from_private_bytes(sk("OpenIdentity OI-015 AA02 auth C seed"))
    apub=ak.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
    bpub=bk.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
    cpub=ck2.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
    entries=sorted([(aid,apub),(bid,bpub),(cid2,cpub)],key=lambda x:x[0])
    ap2={1:2,2:2,3:[{1:i,2:method(i,p)} for i,p in entries]}
    ctrlid=bytes(range(64,80));ctrl=Ed25519PrivateKey.from_private_bytes(sk("OpenIdentity OI-015 AA02 controller seed"))
    ctrlpub=ctrl.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw);cp2=policy(ctrlid,ctrlpub)
    state2={1:3,2:identity2,3:34,4:1,5:cp2,8:{1:12,2:ap2},9:{1:0}}
    sb2=enc(state2);sh2=mh(sb2)
    req("AA02 StateBytes",v2["stateBytesHex"]==sb2.hex());req("AA02 StateHash",v2["stateHashHex"]==sh2.hex())
    ctx2=b"OpenIdentity OI-015 AA02 threshold context"
    assertion2={1:1,2:identity2,3:sh2,4:12,5:b"threshold-verifier",6:"openidentity.authentication",
                7:2001001000,8:2001001180,9:bytes(range(128,160)),10:mh(ctx2)}
    ab2=enc(assertion2);req("AA02 AssertionBytes",v2["assertionBytesHex"]==ab2.hex());req("AA02 AssertionId",v2["assertionIdHex"]==mh(ab2).hex())
    asign=enc(["OpenIdentity Authentication Assertion",1,ab2,aid]);csign=enc(["OpenIdentity Authentication Assertion",1,ab2,cid2])
    asig=bytes.fromhex(v2["signatureAHex"]);csig=bytes.fromhex(v2["signatureCHex"])
    ak.public_key().verify(asig,asign);ck2.public_key().verify(csig,csign);req("AA02 both threshold signatures verify",True)
    req("AA02 generated order intentionally noncanonical",v2["generatedProofOrder"]==["C","A"])
    req("AA02 canonical proof order",v2["canonicalProofOrder"]==["A","C"] and aid<cid2)
    secured2={1:assertion2,2:[{1:aid,2:asig},{1:cid2,2:csig}]}
    req("AA02 secured assertion bytes",v2["securedAssertionBytesHex"]==enc(secured2).hex())

    v3=d["vectors"][2]
    identity3=bytes(range(160,192));mid3=bytes(range(80,96))
    k3=Ed25519PrivateKey.from_private_bytes(sk("OpenIdentity OI-015 AA03 authentication seed"))
    pub3=k3.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw);ap3=policy(mid3,pub3)
    ctrlid3=bytes(range(96,112));ctrl3=Ed25519PrivateKey.from_private_bytes(sk("OpenIdentity OI-015 AA03 controller seed"))
    ctrlpub3=ctrl3.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw);cp3=policy(ctrlid3,ctrlpub3)
    state3={1:3,2:identity3,3:55,4:1,5:cp3,8:{1:19,2:ap3},9:{1:0}};sb3=enc(state3);sh3=mh(sb3)
    req("AA03 StateBytes",v3["stateBytesHex"]==sb3.hex());req("AA03 StateHash",v3["stateHashHex"]==sh3.hex())
    issued3=2001002000;expires3=issued3+300;ctx3=b"OpenIdentity OI-015 AA03 exact lifetime boundary"
    assertion3={1:1,2:identity3,3:sh3,4:19,5:b"lifetime-boundary-verifier",6:"openidentity.authentication",
                7:issued3,8:expires3,9:bytes(range(192,224)),10:mh(ctx3)}
    ab3=enc(assertion3);req("AA03 AssertionBytes",v3["assertionBytesHex"]==ab3.hex());req("AA03 AssertionId",v3["assertionIdHex"]==mh(ab3).hex())
    req("AA03 exact 300-second lifetime",expires3-issued3==300)
    sign3=enc(["OpenIdentity Authentication Assertion",1,ab3,mid3]);sig3=bytes.fromhex(v3["signatureHex"])
    k3.public_key().verify(sig3,sign3);req("AA03 signature verifies",True)
    req("AA03 secured assertion bytes",v3["securedAssertionBytesHex"]==enc({1:assertion3,2:[{1:mid3,2:sig3}]}).hex())

    invalid={x["id"]:x for x in d["invalidVectors"]}
    req("invalid vector IDs AAI01-AAI08",set(invalid)=={f"AAI{i:02d}" for i in range(1,9)})
    expected={"AAI01":"INVALID_STATE_HASH","AAI02":"INVALID_AUTHENTICATION_GENERATION","AAI03":"IDENTITY_NOT_ACTIVE",
              "AAI04":"AUTHENTICATION_POLICY_ABSENT","AAI05":"AUDIENCE_MISMATCH","AAI06":"PURPOSE_MISMATCH",
              "AAI07":"NONCE_MISMATCH","AAI08":"CONTEXT_HASH_MISMATCH"}
    req("AAI01-AAI08 stable errors",all(invalid[k]["expectedError"]==e for k,e in expected.items()))
    i1=invalid["AAI01"];ik=Ed25519PrivateKey.from_private_bytes(sk("OpenIdentity OI-015 invalid authentication seed"))
    ik.public_key().verify(bytes.fromhex(i1["signatureHex"]),bytes.fromhex(i1["signingBytesHex"]))
    req("AAI01 historical signature cryptographically verifies",True)
    req("AAI01 historical StateHash is not current",i1["historicalStateHashHex"]!=i1["currentStateHashHex"])
    i2=invalid["AAI02"];req("AAI02 authentication generation stale",i2["assertedGeneration"]!=i2["currentGeneration"])
    req("AAI03 identity DEACTIVATED",invalid["AAI03"]["currentStatus"]=="DEACTIVATED")
    req("AAI04 AuthenticationPolicy absent",invalid["AAI04"]["authenticationPolicyPresent"] is False)
    req("AAI05 audience mismatch",invalid["AAI05"]["expectedAudienceHex"]!=invalid["AAI05"]["assertedAudienceHex"])
    req("AAI06 purpose mismatch",invalid["AAI06"]["expectedPurpose"]!=invalid["AAI06"]["assertedPurpose"])
    req("AAI07 nonce mismatch",invalid["AAI07"]["expectedNonceHex"]!=invalid["AAI07"]["assertedNonceHex"])
    req("AAI08 contextHash mismatch",invalid["AAI08"]["expectedContextHashHex"]!=invalid["AAI08"]["assertedContextHashHex"])

    print("\n============================================")
    print("OI-015 AUTHENTICATION ASSERTION v1 AA01-AA03 + AAI01-AAI08 VERIFIED")
    print("============================================")

if __name__=="__main__":main()
