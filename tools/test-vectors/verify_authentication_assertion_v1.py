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
    req("vector IDs AA01-AA06",[x["id"] for x in d["vectors"]]==["AA01","AA02","AA03","AA04","AA05","AA06"])
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

    v4=d["vectors"][3]
    audience4=bytes([0x00,0xff,0x80,0x41,0x2f,0x00,0xfe])
    req("AA04 audience exact opaque bytes",v4["audienceHex"]==audience4.hex())
    try: audience4.decode("utf-8");utf8=False
    except UnicodeDecodeError:utf8=True
    req("AA04 audience need not be UTF-8",utf8)

    v5=d["vectors"][4];identity5=bytes(range(64,96));oldmid5=bytes(range(0,16));newmid5=bytes(range(16,32));gen5=42
    oldk5=Ed25519PrivateKey.from_private_bytes(sk("OpenIdentity OI-015 AA05 old authentication seed"))
    newk5=Ed25519PrivateKey.from_private_bytes(sk("OpenIdentity OI-015 AA05 new authentication seed"))
    oldap5=policy(oldmid5,oldk5.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw))
    newap5=policy(newmid5,newk5.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw))
    ctrlid5=bytes(range(32,48));ctrl5=Ed25519PrivateKey.from_private_bytes(sk("OpenIdentity OI-015 AA05 controller seed"))
    cp5=policy(ctrlid5,ctrl5.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw))
    before5={1:3,2:identity5,3:80,4:1,5:cp5,8:{1:gen5,2:oldap5},9:{1:0}}
    after5={1:3,2:identity5,3:81,4:1,5:cp5,8:{1:gen5,2:newap5},9:{1:0}}
    req("AA05 generation preserved",v5["generationBefore"]==gen5 and v5["generationAfter"]==gen5)
    req("AA05 rotation changes StateHash",v5["preRotationStateHashHex"]==mh(enc(before5)).hex() and v5["stateHashHex"]==mh(enc(after5)).hex() and mh(enc(before5))!=mh(enc(after5)))
    sign5=bytes.fromhex(v5["signingBytesHex"]);sig5=bytes.fromhex(v5["signatureHex"]);newk5.public_key().verify(sig5,sign5);req("AA05 current new policy signature verifies",True)

    v6=d["vectors"][5]
    oauthctx6=enc({1:b"https://as.example.test",2:b"client-123",3:b"https://api.example.test",4:b"urn:ietf:params:oauth:grant-type:token-exchange"})
    req("AA06 deterministic OAuth context bytes",v6["contextBytesHex"]==oauthctx6.hex())
    req("AA06 contextHash",v6["contextHashHex"]==mh(oauthctx6).hex())
    req("AA06 OAuth purpose",v6["purpose"]=="openidentity.oauth.token-exchange")

    invalid={x["id"]:x for x in d["invalidVectors"]}
    req("invalid vector IDs AAI01-AAI31",set(invalid)=={f"AAI{i:02d}" for i in range(1,32)})
    expected={"AAI01":"INVALID_STATE_HASH","AAI02":"INVALID_AUTHENTICATION_GENERATION","AAI03":"IDENTITY_NOT_ACTIVE",
              "AAI04":"AUTHENTICATION_POLICY_ABSENT","AAI05":"AUDIENCE_MISMATCH","AAI06":"PURPOSE_MISMATCH",
              "AAI07":"NONCE_MISMATCH","AAI08":"CONTEXT_HASH_MISMATCH","AAI09":"INVALID_TIME_RANGE",
              "AAI10":"ASSERTION_LIFETIME_EXCEEDED","AAI11":"ASSERTION_EXPIRED","AAI12":"ASSERTION_NOT_YET_VALID",
              "AAI13":"UNAUTHORIZED_AUTHENTICATION_PROOF","AAI14":"DUPLICATE_AUTHENTICATION_PROOF",
              "AAI15":"UNAUTHORIZED_AUTHENTICATION_PROOF","AAI16":"INVALID_AUTHENTICATION_SIGNATURE",
              "AAI17":"AUTHENTICATION_POLICY_NOT_SATISFIED","AAI18":"PURPOSE_MISMATCH","AAI19":"AUDIENCE_MISMATCH",
              "AAI20":"INVALID_AUTHENTICATION_GENERATION","AAI21":"INVALID_AUTHENTICATION_ASSERTION",
              "AAI22":"INVALID_AUTHENTICATION_ASSERTION","AAI23":"INVALID_AUTHENTICATION_ASSERTION",
              "AAI24":"INVALID_ASSERTION_VERSION","AAI25":"IDENTITY_MISMATCH","AAI26":"INVALID_PROOF_SET",
              "AAI27":"INVALID_AUTHENTICATION_ASSERTION","AAI28":"INVALID_AUTHENTICATION_ASSERTION",
              "AAI29":"INVALID_AUTHENTICATION_ASSERTION","AAI30":"INVALID_TIME_RANGE","AAI31":"ASSERTION_LIFETIME_EXCEEDED"}
    req("AAI01-AAI31 stable errors",all(invalid[k]["expectedError"]==e for k,e in expected.items()))
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

    i9=invalid["AAI09"];req("AAI09 invalid zero time range",i9["expiresAt"]<=i9["issuedAt"])
    i10=invalid["AAI10"];req("AAI10 lifetime exceeds 300",i10["expiresAt"]-i10["issuedAt"]>i10["maximumLifetime"])
    i11=invalid["AAI11"];req("AAI11 expiresAt boundary is expired",i11["verificationTime"]>=i11["expiresAt"])
    i12=invalid["AAI12"];req("AAI12 before issuedAt",i12["verificationTime"]<i12["issuedAt"])
    i13=invalid["AAI13"];req("AAI13 controller method not in AuthenticationPolicy",i13["submittedMethodIdHex"] not in i13["authenticationMethodIdsHex"])
    i14=invalid["AAI14"];req("AAI14 duplicate proof method",len(set(i14["submittedMethodIdsHex"]))!=len(i14["submittedMethodIdsHex"]))
    i15=invalid["AAI15"];req("AAI15 threshold is otherwise satisfied",sum(x in i15["authorizedMethodIdsHex"] for x in i15["submittedMethodIdsHex"])>=i15["authorizedThreshold"])
    req("AAI15 unauthorized extra method exists",any(x not in i15["authorizedMethodIdsHex"] for x in i15["submittedMethodIdsHex"]))
    i16=invalid["AAI16"];pk=Ed25519PrivateKey.from_private_bytes(sk("OpenIdentity OI-015 proof attack A seed")).public_key()
    pk.verify(bytes.fromhex(i16["validSignatureHex"]),bytes.fromhex(i16["signingBytesHex"]));req("AAI16 valid baseline signature verifies",True)
    try:
        pk.verify(bytes.fromhex(i16["invalidSignatureHex"]),bytes.fromhex(i16["signingBytesHex"]));bad16=False
    except Exception: bad16=True
    req("AAI16 corrupted signature rejected",bad16)
    i17=invalid["AAI17"];req("AAI17 threshold not satisfied",len(i17["submittedMethodIdsHex"])<i17["threshold"])

    rk=Ed25519PrivateKey.from_private_bytes(sk("OpenIdentity OI-015 replay authentication seed")).public_key()
    for n in ("AAI18","AAI19","AAI20"):
        x=invalid[n];rk.verify(bytes.fromhex(x["signatureHex"]),bytes.fromhex(x["signingBytesHex"]))
    req("AAI18 replay signature cryptographically valid",True)
    req("AAI18 purpose replay rejected",invalid["AAI18"]["signedPurpose"]!=invalid["AAI18"]["requestedPurpose"])
    req("AAI19 audience replay rejected",invalid["AAI19"]["signedAudienceHex"]!=invalid["AAI19"]["requestedAudienceHex"])
    req("AAI20 reset generation invalidates assertion",invalid["AAI20"]["assertedGeneration"]!=invalid["AAI20"]["currentGeneration"])
    req("AAI20 post-reset StateHash differs",invalid["AAI20"]["preResetStateHashHex"]!=invalid["AAI20"]["postResetStateHashHex"])
    import re
    purpose_re=re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,253}[a-z0-9])?$")
    req("AAI21 purpose violates lowercase ASCII grammar",purpose_re.fullmatch(invalid["AAI21"]["purpose"]) is None)
    req("AAI22 nonce below minimum",invalid["AAI22"]["nonceLength"]<invalid["AAI22"]["minimumNonceLength"])
    req("AAI23 unsupported contextHash multihash",invalid["AAI23"]["submittedMultihashCode"]!=invalid["AAI23"]["expectedMultihashCode"])

    req("AAI24 unsupported assertion version",invalid["AAI24"]["assertionVersion"]!=invalid["AAI24"]["supportedVersion"])
    req("AAI25 identity mismatch",invalid["AAI25"]["assertedIdentityHex"]!=invalid["AAI25"]["currentStateIdentityHex"])
    ids26=[bytes.fromhex(x) for x in invalid["AAI26"]["submittedMethodIdsHex"]]
    req("AAI26 proof order noncanonical",ids26!=sorted(ids26))
    req("AAI27 nonce above maximum",invalid["AAI27"]["nonceLength"]>invalid["AAI27"]["maximumNonceLength"])
    req("AAI28 audience above maximum",invalid["AAI28"]["audienceLength"]>invalid["AAI28"]["maximumAudienceLength"])
    req("AAI29 unsupported StateHash multihash",invalid["AAI29"]["submittedMultihashCode"]!=invalid["AAI29"]["expectedMultihashCode"])
    req("AAI30 uint64 maximum zero range",invalid["AAI30"]["expiresAt"]<=invalid["AAI30"]["issuedAt"])
    req("AAI31 exact uint64-safe lifetime is 301",invalid["AAI31"]["expiresAt"]-invalid["AAI31"]["issuedAt"]==invalid["AAI31"]["exactLifetime"]==301)

    print("\n============================================")
    print("OI-015 AUTHENTICATION ASSERTION v1 AA01-AA06 + AAI01-AAI31 VERIFIED")
    print("============================================")

if __name__=="__main__":main()
