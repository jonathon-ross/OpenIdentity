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
    rchallenge=bytes.fromhex(v["revokeRegistryChallengeHex"])
    rctx={1:1,2:2,3:identity,4:v["issuer"],5:v["subject"],6:v["clientId"],7:rchallenge,8:v["authenticationGeneration"],9:v["createdAt"],10:v["expiresAt"],11:bid}
    rcb=cbor(rctx);rch=multihash(rcb)
    assert rcb.hex()==v["revokeContextBytesHex"],v["id"]+" RevokeContextBytes"
    assert rch.hex()==v["revokeContextHashHex"],v["id"]+" RevokeContextHash"
    print(v["id"],"CRYPTO VERIFIED")

allowed_labels={"OK","OIDC_PROVIDER_UNTRUSTED","OIDC_PRINCIPAL_INVALID","OIDC_CLIENT_NOT_ALLOWED","BINDING_CHALLENGE_INVALID","BINDING_AUTHORIZATION_INVALID","BINDING_CONTEXT_MISMATCH","BINDING_GENERATION_STALE","BINDING_EXPIRED","BINDING_CONFLICT","BINDING_NOT_FOUND","BINDING_REVOKED","BINDING_ID_MISMATCH","IDENTITY_INACTIVE","ASSURANCE_INSUFFICIENT","BINDING_REPLAY"}
seen=set()
for sv in data.get("semanticVectors",[]):
    assert sv["id"] not in seen,"duplicate semantic vector "+sv["id"]
    seen.add(sv["id"])
    assert sv["expected"] in allowed_labels,sv["id"]+" unknown error label"
    assert (sv["expected"]=="OK")==bool(sv["valid"]),sv["id"]+" valid/expected mismatch"
print(len(data.get("semanticVectors",[])),"SEMANTIC VECTOR CONTRACTS VERIFIED")


# Executable semantic reference model. This deliberately models only the
# external-binding profile boundary; OI-015 cryptographic verification is
# represented by an already-verified authorization boolean/purpose/context.
class Failure(Exception):
    def __init__(self,label): self.label=label

def require(ok,label):
    if not ok: raise Failure(label)

BASE=data["vectors"][0]
BASE_KEY=(BASE["issuer"],BASE["subject"])
BASE_ID=BASE["identityHex"]
BASE_BID=BASE["bindingIdHex"]

def execute(op):
    issuer=BASE["issuer"]; subject=BASE["subject"]; client=BASE["clientId"]
    identity=BASE_ID; generation=BASE["authenticationGeneration"]; stored_generation=generation
    trusted=True; active_identity=True; status="ACTIVE"; expires=None; now=BASE["createdAt"]+60
    allowed_clients={client,"alternate-client"}; assurance=True
    stored_bid=BASE_BID; recomputed_bid=BASE_BID
    auth_ok=True; purpose="bind"; context_ok=True; challenge_ok=True; replay=False
    existing_owner=identity

    if op=="RESOLVE": pass
    elif op=="REVOKE": purpose="revoke"
    elif op=="RESOLVE_AFTER_GENERATION_RESET": generation+=1
    elif op=="BIND_SECOND_EXTERNAL_SUBJECT_SAME_IDENTITY": subject="subject-456"; existing_owner=None
    elif op=="RESOLVE_ALLOWED_ALTERNATE_CLIENT": client="alternate-client"
    elif op=="RESOLVE_DIFFERENT_ISSUER": issuer="https://other.example.test"
    elif op=="RESOLVE_DIFFERENT_SUBJECT": subject="other-subject"
    elif op=="RESOLVE_DISALLOWED_CLIENT": client="blocked-client"
    elif op=="RESOLVE_EMAIL_ONLY": subject="email-derived-not-sub"
    elif op=="BIND_INVALID_OI015": auth_ok=False
    elif op in ("BIND_ISSUER_CONTEXT_MISMATCH","BIND_SUBJECT_CONTEXT_MISMATCH","BIND_CLIENT_CONTEXT_MISMATCH"): context_ok=False
    elif op=="BIND_DUPLICATE_EXTERNAL_SUBJECT_OTHER_IDENTITY": existing_owner="ff"*32
    elif op=="RESOLVE_REVOKED": status="REVOKED"
    elif op=="RESOLVE_STALE_GENERATION": generation+=1
    elif op=="RESOLVE_INACTIVE_IDENTITY": active_identity=False
    elif op=="RESOLVE_UNTRUSTED_ISSUER": trusted=False
    elif op=="BIND_ADMIN_ONLY": auth_ok=False
    elif op=="RESOLVE_BINDING_ID_MISMATCH": recomputed_bid="00"*34
    elif op=="RESOLVE_EXPIRED": expires=now-1
    elif op=="BIND_REPLAYED_CHALLENGE": challenge_ok=False
    elif op=="BIND_REPLAYED_AUTHORIZATION": replay=True
    elif op=="REVOKE_WITH_BIND_PURPOSE": purpose="bind"
    elif op=="BIND_WITH_REVOKE_PURPOSE": purpose="revoke"
    elif op=="REVOKE_DIFFERENT_BINDING_ID": purpose="revoke"; context_ok=False
    elif op=="RESOLVE_INSUFFICIENT_ASSURANCE": assurance=False
    elif op=="PARSE_NONDETERMINISTIC_BINDING_BYTES": raise Failure("OIDC_PRINCIPAL_INVALID")
    else: raise AssertionError("unknown operation "+op)

    is_bind=op.startswith("BIND_")
    is_revoke=op=="REVOKE" or op.startswith("REVOKE_")
    is_resolve=op.startswith("RESOLVE")

    if is_bind:
        require(trusted,"OIDC_PROVIDER_UNTRUSTED")
        require(client in allowed_clients,"OIDC_CLIENT_NOT_ALLOWED")
        require(challenge_ok,"BINDING_CHALLENGE_INVALID")
        require(auth_ok,"BINDING_AUTHORIZATION_INVALID")
        require(purpose=="bind","BINDING_AUTHORIZATION_INVALID")
        require(context_ok,"BINDING_CONTEXT_MISMATCH")
        require(not replay,"BINDING_REPLAY")
        require(existing_owner is None or existing_owner==identity,"BINDING_CONFLICT")
        return "OK"

    if is_revoke:
        require(status=="ACTIVE","BINDING_REVOKED")
        require(recomputed_bid==stored_bid,"BINDING_ID_MISMATCH")
        require(active_identity,"IDENTITY_INACTIVE")
        require(auth_ok and purpose=="revoke","BINDING_AUTHORIZATION_INVALID")
        require(context_ok,"BINDING_CONTEXT_MISMATCH")
        require(not replay,"BINDING_REPLAY")
        return "OK"

    if is_resolve:
        require(trusted,"OIDC_PROVIDER_UNTRUSTED")
        require((issuer,subject)==BASE_KEY,"BINDING_NOT_FOUND")
        require(status=="ACTIVE","BINDING_REVOKED")
        require(recomputed_bid==stored_bid,"BINDING_ID_MISMATCH")
        require(active_identity,"IDENTITY_INACTIVE")
        require(generation==stored_generation,"BINDING_GENERATION_STALE")
        require(expires is None or now<expires,"BINDING_EXPIRED")
        require(client in allowed_clients,"OIDC_CLIENT_NOT_ALLOWED")
        require(assurance,"ASSURANCE_INSUFFICIENT")
        return "OK"

    raise AssertionError("unclassified operation "+op)

for sv in data.get("semanticVectors",[]):
    try:
        actual=execute(sv["operation"])
    except Failure as e:
        actual=e.label
    assert actual==sv["expected"],sv["id"]+" expected "+sv["expected"]+" got "+actual
    print(sv["id"],actual)
print(len(data.get("semanticVectors",[])),"EXECUTABLE SEMANTIC VECTORS VERIFIED")
