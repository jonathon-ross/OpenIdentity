#!/usr/bin/env python3
"""Independent verification for draft Protocol v2 / IdentityState v3 vectors.

Do not import the generator. This verifier reconstructs canonical structures
from deterministic public fixture rules and compares them byte-for-byte with
the generated bundle.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


ROOT = Path(__file__).resolve().parents[2]
BUNDLE = ROOT / "test-vectors" / "generated" / "protocol-v2-identity-state-v3.json"


def head(major: int, value: int) -> bytes:
    if value < 24: return bytes([(major << 5) | value])
    if value < 256: return bytes([(major << 5) | 24, value])
    if value < 65536: return bytes([(major << 5) | 25]) + value.to_bytes(2, "big")
    if value < 2**32: return bytes([(major << 5) | 26]) + value.to_bytes(4, "big")
    if value < 2**64: return bytes([(major << 5) | 27]) + value.to_bytes(8, "big")
    raise ValueError("uint64 overflow")


def enc(v) -> bytes:
    if v is None: return b"\xf6"
    if isinstance(v, int): return head(0, v) if v >= 0 else head(1, -1-v)
    if isinstance(v, bytes): return head(2, len(v)) + v
    if isinstance(v, str):
        b=v.encode(); return head(3, len(b))+b
    if isinstance(v, list): return head(4,len(v))+b"".join(enc(x) for x in v)
    if isinstance(v, dict):
        pairs=[(enc(k),enc(x)) for k,x in v.items()]
        pairs.sort(key=lambda p:(len(p[0]),p[0]))
        return head(5,len(pairs))+b"".join(k+x for k,x in pairs)
    raise TypeError(type(v))


def mh(b: bytes) -> bytes:
    return b"\x12\x20"+hashlib.sha256(b).digest()


def key(label: str, start: int):
    seed=hashlib.sha256(label.encode("ascii")).digest()
    priv=Ed25519PrivateKey.from_private_bytes(seed)
    pub=priv.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
    mid=bytes(range(start,start+16))
    method={1:mid,2:{1:1,3:-8,-1:6,-2:pub}}
    return priv,pub,mid,method


def policy(method):
    return {1:1,2:[method]}


def require(name, condition):
    if not condition:
        raise AssertionError(name)
    print(f"  {name}: PASS")


def verify_signature(pubkey, signature_hex, signing_bytes):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    Ed25519PublicKey.from_public_bytes(pubkey).verify(
        bytes.fromhex(signature_hex), signing_bytes
    )


def verify_v301(v):
    identity=bytes(range(32))
    priv,pub,mid,method=key("OpenIdentity protocol-v2 v3 V301 controller Ed25519 seed",0)
    cp=policy(method)
    op={1:2,2:1,3:identity,4:1,5:None,6:{1:cp}}
    ob=enc(op)
    si=enc(["OpenIdentity Operation",1,ob])
    require("V301 OperationBytes", v["operationBytesHex"]==ob.hex())
    require("V301 signing input", v["operationSigningBytesHex"]==si.hex())
    verify_signature(pub,v["controllerSignatureHex"],si)
    require("V301 controller signature verifies", True)
    state={1:3,2:identity,3:1,4:1,5:cp,8:{1:0},9:{1:0}}
    sb=enc(state)
    require("V301 StateBytes",v["stateBytesHex"]==sb.hex())
    require("V301 StateHash",v["stateHashHex"]==mh(sb).hex())


def verify_v302(v):
    identity=bytes(range(32))
    _,cpub,cid,cm=key("OpenIdentity protocol-v2 v3 V302 controller Ed25519 seed",0)
    _,apub,aid,am=key("OpenIdentity protocol-v2 v3 V302 authentication Ed25519 seed",16)
    cp,ap=policy(cm),policy(am)
    op={1:2,2:1,3:identity,4:1,5:None,6:{1:cp,4:ap}}
    ob=enc(op)
    csi=enc(["OpenIdentity Operation",1,ob])
    asi=enc(["OpenIdentity Authentication Proof",1,ob,aid])
    require("V302 OperationBytes",v["operationBytesHex"]==ob.hex())
    verify_signature(cpub,v["controllerSignatureHex"],csi)
    require("V302 controller authorization verifies",True)
    verify_signature(apub,v["authenticationProofSignatureHex"],asi)
    require("V302 authentication PoP verifies",True)
    state={1:3,2:identity,3:1,4:1,5:cp,8:{1:0,2:ap},9:{1:0}}
    sb=enc(state)
    require("V302 StateBytes",v["stateBytesHex"]==sb.hex())
    require("V302 StateHash",v["stateHashHex"]==mh(sb).hex())


def verify_v303(v):
    identity=bytes(range(32))
    _,cpub,cid,cm=key("OpenIdentity protocol-v2 v3 V303 controller Ed25519 seed",0)
    _,apub,aid,am=key("OpenIdentity protocol-v2 v3 V303 authentication Ed25519 seed",16)
    _,spub,sid,sm=key("OpenIdentity protocol-v2 v3 V303 assertion Ed25519 seed",32)
    _,dpub,did,dm=key("OpenIdentity protocol-v2 v3 V303 delegation Ed25519 seed",48)
    cp,ap,sp,dp=policy(cm),policy(am),policy(sm),policy(dm)
    op={1:2,2:1,3:identity,4:1,5:None,6:{1:cp,3:sp,4:ap,5:dp}}
    ob=enc(op)
    require("V303 OperationBytes",v["operationBytesHex"]==ob.hex())
    verify_signature(cpub,v["controllerSignatureHex"],enc(["OpenIdentity Operation",1,ob]))
    require("V303 controller authorization verifies",True)
    for label,pub,mid,field in [
        ("Authentication",apub,aid,"authenticationProofSignatureHex"),
        ("Assertion",spub,sid,"assertionProofSignatureHex"),
        ("Delegation",dpub,did,"delegationProofSignatureHex"),
    ]:
        verify_signature(pub,v[field],enc([f"OpenIdentity {label} Proof",1,ob,mid]))
        require(f"V303 {label.lower()} PoP verifies",True)
    state={1:3,2:identity,3:1,4:1,5:cp,7:sp,8:{1:0,2:ap},9:{1:0,2:dp}}
    sb=enc(state)
    require("V303 StateBytes",v["stateBytesHex"]==sb.hex())
    require("V303 StateHash",v["stateHashHex"]==mh(sb).hex())


def verify_v304(v):
    identity=bytes(range(32))
    _,cpub,cid,cm=key("OpenIdentity protocol-v2 v3 V304 controller Ed25519 seed",0)
    _,apub,aid,am=key("OpenIdentity protocol-v2 v3 V304 authentication Ed25519 seed",16)
    cp,ap=policy(cm),policy(am)
    previous={1:2,2:identity,3:1,4:1,5:cp}
    psb=enc(previous); psh=mh(psb)
    require("V304 predecessor is v2",v["previousStateVersion"]==2)
    require("V304 previous StateBytes",v["previousStateBytesHex"]==psb.hex())
    require("V304 previous StateHash",v["previousStateHashHex"]==psh.hex())
    op={1:2,2:6,3:identity,4:2,5:psh,6:{1:ap}}
    ob=enc(op)
    require("V304 OperationBytes",v["operationBytesHex"]==ob.hex())
    verify_signature(cpub,v["controllerSignatureHex"],enc(["OpenIdentity Operation",1,ob]))
    require("V304 controller authorization verifies",True)
    verify_signature(apub,v["authenticationProofSignatureHex"],
                     enc(["OpenIdentity Authentication Proof",1,ob,aid]))
    require("V304 authentication PoP verifies",True)
    state={1:3,2:identity,3:2,4:1,5:cp,8:{1:0,2:ap},9:{1:0}}
    sb=enc(state)
    require("V304 resulting state is v3",state[1]==3)
    require("V304 StateBytes",v["stateBytesHex"]==sb.hex())
    require("V304 StateHash",v["stateHashHex"]==mh(sb).hex())


def main():
    data=json.loads(BUNDLE.read_text(encoding="utf-8"))
    print("OpenIdentity Protocol v2 / IdentityState v3")
    print("Independent Verification")
    print("="*48)
    require("suite specification",data["specification"]=="OpenIdentity Protocol v2 / IdentityState v3")
    require("draft status",data["status"]=="DRAFT-NON-NORMATIVE")
    require("wire schema",data["wireSchema"]=="spec/cddl/openidentity-operation-v3.cddl")
    vectors={v["id"]:v for v in data["vectors"]}
    require("vector IDs V301-V304",set(vectors)=={"V301","V302","V303","V304"})
    verify_v301(vectors["V301"])
    verify_v302(vectors["V302"])
    verify_v303(vectors["V303"])
    verify_v304(vectors["V304"])
    print()
    print("="*48)
    print("PROTOCOL V2 / IDENTITYSTATE V3 V301-V304 VERIFIED")
    print("="*48)


if __name__=="__main__":
    main()
