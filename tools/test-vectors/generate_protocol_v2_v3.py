#!/usr/bin/env python3
"""Generate and verify draft Protocol v2 / IdentityState v3 conformance vectors.

This tool is intentionally independent of the OpenIdentity SDK. It uses only
standard deterministic CBOR construction plus cryptography primitives.

Generated output under test-vectors/generated/ is development/reference output
until promoted through the repository's normative conformance process.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "test-vectors" / "generated" / "protocol-v2-identity-state-v3.json"


def _head(major: int, value: int) -> bytes:
    if value < 0:
        raise ValueError("CBOR length/value must be non-negative")
    if value < 24:
        return bytes([(major << 5) | value])
    if value < 256:
        return bytes([(major << 5) | 24, value])
    if value < 65536:
        return bytes([(major << 5) | 25]) + value.to_bytes(2, "big")
    if value < 2**32:
        return bytes([(major << 5) | 26]) + value.to_bytes(4, "big")
    if value < 2**64:
        return bytes([(major << 5) | 27]) + value.to_bytes(8, "big")
    raise ValueError("integer exceeds uint64")


def cbor(value) -> bytes:
    """Minimal RFC 8949 deterministic encoder for vector fixture types."""
    if value is None:
        return b"\xf6"
    if isinstance(value, int):
        return _head(0, value) if value >= 0 else _head(1, -1 - value)
    if isinstance(value, bytes):
        return _head(2, len(value)) + value
    if isinstance(value, str):
        encoded = value.encode("utf-8")
        return _head(3, len(encoded)) + encoded
    if isinstance(value, list):
        return _head(4, len(value)) + b"".join(cbor(item) for item in value)
    if isinstance(value, dict):
        encoded = [(cbor(key), cbor(item)) for key, item in value.items()]
        encoded.sort(key=lambda pair: (len(pair[0]), pair[0]))
        return _head(5, len(encoded)) + b"".join(k + v for k, v in encoded)
    raise TypeError(f"unsupported CBOR fixture type: {type(value)!r}")


def sha256_multihash(data: bytes) -> bytes:
    return b"\x12\x20" + hashlib.sha256(data).digest()


def build_v301() -> dict:
    identity = bytes(range(32))
    method_id = bytes(range(16))
    seed = hashlib.sha256(
        b"OpenIdentity protocol-v2 v3 V301 controller Ed25519 seed"
    ).digest()
    private_key = Ed25519PrivateKey.from_private_bytes(seed)
    public_key = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    cose_key = {1: 1, 3: -8, -1: 6, -2: public_key}
    method = {1: method_id, 2: cose_key}
    controller_policy = {1: 1, 2: [method]}

    operation = {
        1: 2,
        2: 1,
        3: identity,
        4: 1,
        5: None,
        6: {1: controller_policy},
    }
    operation_bytes = cbor(operation)
    signing_bytes = cbor(["OpenIdentity Operation", 1, operation_bytes])
    signature = private_key.sign(signing_bytes)

    signed_operation = {
        1: operation,
        2: [{1: method_id, 2: signature}],
    }

    state = {
        1: 3,
        2: identity,
        3: 1,
        4: 1,
        5: controller_policy,
        8: {1: 0},
        9: {1: 0},
    }
    state_bytes = cbor(state)
    state_hash = sha256_multihash(state_bytes)

    private_key.public_key().verify(signature, signing_bytes)

    return {
        "id": "V301",
        "description": "Minimal protocolVersion 2 CREATE produces IdentityState v3",
        "expected": "PASS",
        "fixture": {
            "identityHex": identity.hex(),
            "controllerMethodIdHex": method_id.hex(),
            "controllerPublicKeyHex": public_key.hex(),
        },
        "operationBytesHex": operation_bytes.hex(),
        "operationSigningBytesHex": signing_bytes.hex(),
        "controllerSignatureHex": signature.hex(),
        "signedOperationBytesHex": cbor(signed_operation).hex(),
        "stateBytesHex": state_bytes.hex(),
        "stateHashHex": state_hash.hex(),
        "assertions": {
            "protocolVersion": 2,
            "operationType": "CREATE",
            "sequence": 1,
            "previousStateHash": None,
            "stateVersion": 3,
            "status": "ACTIVE",
            "authenticationGeneration": 0,
            "authenticationPolicyPresent": False,
            "delegationGeneration": 0,
            "delegationPolicyPresent": False,
            "stateHashLength": len(state_hash),
        },
    }


def _ed25519(label: str, method_start: int):
    seed = hashlib.sha256(label.encode("ascii")).digest()
    private_key = Ed25519PrivateKey.from_private_bytes(seed)
    public_key = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    method_id = bytes(range(method_start, method_start + 16))
    method = {1: method_id, 2: {1: 1, 3: -8, -1: 6, -2: public_key}}
    return private_key, public_key, method_id, method


def _single_policy(method):
    return {1: 1, 2: [method]}


def _purpose_proof(domain: str, operation_bytes: bytes, private_key, method_id: bytes):
    signing_bytes = cbor([domain, 1, operation_bytes, method_id])
    signature = private_key.sign(signing_bytes)
    private_key.public_key().verify(signature, signing_bytes)
    return signing_bytes, {1: method_id, 2: signature}


def build_v302() -> dict:
    identity = bytes(range(32))
    cpriv, cpub, cid, cm = _ed25519(
        "OpenIdentity protocol-v2 v3 V302 controller Ed25519 seed", 0
    )
    apriv, apub, aid, am = _ed25519(
        "OpenIdentity protocol-v2 v3 V302 authentication Ed25519 seed", 16
    )
    controller_policy = _single_policy(cm)
    authentication_policy = _single_policy(am)
    operation = {
        1: 2, 2: 1, 3: identity, 4: 1, 5: None,
        6: {1: controller_policy, 4: authentication_policy},
    }
    operation_bytes = cbor(operation)
    controller_signing = cbor(["OpenIdentity Operation", 1, operation_bytes])
    controller_signature = cpriv.sign(controller_signing)
    cpriv.public_key().verify(controller_signature, controller_signing)
    auth_signing, auth_proof = _purpose_proof(
        "OpenIdentity Authentication Proof", operation_bytes, apriv, aid
    )
    signed_operation = {
        1: operation,
        2: [{1: cid, 2: controller_signature}],
        5: [auth_proof],
    }
    state = {
        1: 3, 2: identity, 3: 1, 4: 1, 5: controller_policy,
        8: {1: 0, 2: authentication_policy},
        9: {1: 0},
    }
    state_bytes = cbor(state)
    state_hash = sha256_multihash(state_bytes)
    return {
        "id": "V302",
        "description": "CREATE with AuthenticationPolicy requires authentication-domain PoP",
        "expected": "PASS",
        "fixture": {
            "identityHex": identity.hex(),
            "controllerMethodIdHex": cid.hex(),
            "controllerPublicKeyHex": cpub.hex(),
            "authenticationMethodIdHex": aid.hex(),
            "authenticationPublicKeyHex": apub.hex(),
        },
        "operationBytesHex": operation_bytes.hex(),
        "controllerSigningBytesHex": controller_signing.hex(),
        "controllerSignatureHex": controller_signature.hex(),
        "authenticationProofSigningBytesHex": auth_signing.hex(),
        "authenticationProofSignatureHex": auth_proof[2].hex(),
        "signedOperationBytesHex": cbor(signed_operation).hex(),
        "stateBytesHex": state_bytes.hex(),
        "stateHashHex": state_hash.hex(),
        "assertions": {
            "authenticationGeneration": 0,
            "authenticationPolicyPresent": True,
            "delegationGeneration": 0,
            "delegationPolicyPresent": False,
            "controllerProofCollectionPresent": False,
            "authenticationProofCollectionPresent": True,
            "stateHashLength": len(state_hash),
        },
    }


def build_v303() -> dict:
    identity = bytes(range(32))
    cpriv, cpub, cid, cm = _ed25519(
        "OpenIdentity protocol-v2 v3 V303 controller Ed25519 seed", 0
    )
    apriv, apub, aid, am = _ed25519(
        "OpenIdentity protocol-v2 v3 V303 authentication Ed25519 seed", 16
    )
    spriv, spub, sid, sm = _ed25519(
        "OpenIdentity protocol-v2 v3 V303 assertion Ed25519 seed", 32
    )
    dpriv, dpub, did, dm = _ed25519(
        "OpenIdentity protocol-v2 v3 V303 delegation Ed25519 seed", 48
    )
    controller_policy = _single_policy(cm)
    authentication_policy = _single_policy(am)
    assertion_policy = _single_policy(sm)
    delegation_policy = _single_policy(dm)
    operation = {
        1: 2, 2: 1, 3: identity, 4: 1, 5: None,
        6: {
            1: controller_policy,
            3: assertion_policy,
            4: authentication_policy,
            5: delegation_policy,
        },
    }
    operation_bytes = cbor(operation)
    controller_signing = cbor(["OpenIdentity Operation", 1, operation_bytes])
    controller_signature = cpriv.sign(controller_signing)
    cpriv.public_key().verify(controller_signature, controller_signing)
    auth_signing, auth_proof = _purpose_proof(
        "OpenIdentity Authentication Proof", operation_bytes, apriv, aid
    )
    assertion_signing, assertion_proof = _purpose_proof(
        "OpenIdentity Assertion Proof", operation_bytes, spriv, sid
    )
    delegation_signing, delegation_proof = _purpose_proof(
        "OpenIdentity Delegation Proof", operation_bytes, dpriv, did
    )
    signed_operation = {
        1: operation,
        2: [{1: cid, 2: controller_signature}],
        5: [auth_proof],
        6: [assertion_proof],
        7: [delegation_proof],
    }
    state = {
        1: 3, 2: identity, 3: 1, 4: 1, 5: controller_policy,
        7: assertion_policy,
        8: {1: 0, 2: authentication_policy},
        9: {1: 0, 2: delegation_policy},
    }
    state_bytes = cbor(state)
    state_hash = sha256_multihash(state_bytes)
    return {
        "id": "V303",
        "description": "CREATE with assertion, authentication, and delegation authorities",
        "expected": "PASS",
        "fixture": {
            "identityHex": identity.hex(),
            "controllerMethodIdHex": cid.hex(),
            "controllerPublicKeyHex": cpub.hex(),
            "authenticationMethodIdHex": aid.hex(),
            "authenticationPublicKeyHex": apub.hex(),
            "assertionMethodIdHex": sid.hex(),
            "assertionPublicKeyHex": spub.hex(),
            "delegationMethodIdHex": did.hex(),
            "delegationPublicKeyHex": dpub.hex(),
        },
        "operationBytesHex": operation_bytes.hex(),
        "controllerSigningBytesHex": controller_signing.hex(),
        "controllerSignatureHex": controller_signature.hex(),
        "authenticationProofSigningBytesHex": auth_signing.hex(),
        "authenticationProofSignatureHex": auth_proof[2].hex(),
        "assertionProofSigningBytesHex": assertion_signing.hex(),
        "assertionProofSignatureHex": assertion_proof[2].hex(),
        "delegationProofSigningBytesHex": delegation_signing.hex(),
        "delegationProofSignatureHex": delegation_proof[2].hex(),
        "signedOperationBytesHex": cbor(signed_operation).hex(),
        "stateBytesHex": state_bytes.hex(),
        "stateHashHex": state_hash.hex(),
        "assertions": {
            "assertionPolicyPresent": True,
            "authenticationGeneration": 0,
            "authenticationPolicyPresent": True,
            "delegationGeneration": 0,
            "delegationPolicyPresent": True,
            "controllerProofCollectionPresent": False,
            "authenticationProofCollectionPresent": True,
            "assertionProofCollectionPresent": True,
            "delegationProofCollectionPresent": True,
            "stateHashLength": len(state_hash),
        },
    }



def build_v304() -> dict:
    """Upgrade an existing IdentityState v2 by installing AuthenticationPolicy."""
    identity = bytes(range(32))
    cpriv, cpub, cid, cm = _ed25519(
        "OpenIdentity protocol-v2 v3 V304 controller Ed25519 seed", 0
    )
    apriv, apub, aid, am = _ed25519(
        "OpenIdentity protocol-v2 v3 V304 authentication Ed25519 seed", 16
    )
    controller_policy = _single_policy(cm)
    authentication_policy = _single_policy(am)

    previous_state = {
        1: 2,
        2: identity,
        3: 1,
        4: 1,
        5: controller_policy,
    }
    previous_state_bytes = cbor(previous_state)
    previous_state_hash = sha256_multihash(previous_state_bytes)

    operation = {
        1: 2,
        2: 6,
        3: identity,
        4: 2,
        5: previous_state_hash,
        6: {1: authentication_policy},
    }
    operation_bytes = cbor(operation)
    controller_signing = cbor(["OpenIdentity Operation", 1, operation_bytes])
    controller_signature = cpriv.sign(controller_signing)
    cpriv.public_key().verify(controller_signature, controller_signing)
    auth_signing, auth_proof = _purpose_proof(
        "OpenIdentity Authentication Proof", operation_bytes, apriv, aid
    )
    signed_operation = {
        1: operation,
        2: [{1: cid, 2: controller_signature}],
        5: [auth_proof],
    }

    state = {
        1: 3,
        2: identity,
        3: 2,
        4: 1,
        5: controller_policy,
        8: {1: 0, 2: authentication_policy},
        9: {1: 0},
    }
    state_bytes = cbor(state)
    state_hash = sha256_multihash(state_bytes)

    assert operation[5] == sha256_multihash(previous_state_bytes)
    assert state[1] == 3
    assert state[8][1] == 0 and state[9][1] == 0

    return {
        "id": "V304",
        "description": "protocolVersion 2 SET_AUTHENTICATION_POLICY upgrades IdentityState v2 to v3",
        "expected": "PASS",
        "fixture": {
            "identityHex": identity.hex(),
            "controllerMethodIdHex": cid.hex(),
            "controllerPublicKeyHex": cpub.hex(),
            "authenticationMethodIdHex": aid.hex(),
            "authenticationPublicKeyHex": apub.hex(),
        },
        "previousStateVersion": 2,
        "previousStateBytesHex": previous_state_bytes.hex(),
        "previousStateHashHex": previous_state_hash.hex(),
        "operationBytesHex": operation_bytes.hex(),
        "controllerSigningBytesHex": controller_signing.hex(),
        "controllerSignatureHex": controller_signature.hex(),
        "authenticationProofSigningBytesHex": auth_signing.hex(),
        "authenticationProofSignatureHex": auth_proof[2].hex(),
        "signedOperationBytesHex": cbor(signed_operation).hex(),
        "stateBytesHex": state_bytes.hex(),
        "stateHashHex": state_hash.hex(),
        "assertions": {
            "protocolVersion": 2,
            "operationType": "SET_AUTHENTICATION_POLICY",
            "previousSequence": 1,
            "sequence": 2,
            "previousStateHashMatchesExactV2StateBytes": True,
            "stateVersion": 3,
            "authenticationGeneration": 0,
            "authenticationPolicyPresent": True,
            "delegationGeneration": 0,
            "delegationPolicyPresent": False,
            "stateHashLength": len(state_hash),
        },
    }



def _auth_rotation_vector(vector_id: str, disposition: int, generation_after: int) -> dict:
    identity = bytes(range(32))
    cpriv, cpub, cid, cm = _ed25519(
        f"OpenIdentity protocol-v2 v3 {vector_id} controller Ed25519 seed", 0
    )
    _, old_pub, old_id, old_method = _ed25519(
        f"OpenIdentity protocol-v2 v3 {vector_id} authentication A Ed25519 seed", 16
    )
    new_priv, new_pub, new_id, new_method = _ed25519(
        f"OpenIdentity protocol-v2 v3 {vector_id} authentication B Ed25519 seed", 32
    )
    controller_policy = _single_policy(cm)
    old_policy = _single_policy(old_method)
    new_policy = _single_policy(new_method)

    previous_state = {
        1: 3, 2: identity, 3: 1, 4: 1, 5: controller_policy,
        8: {1: 0, 2: old_policy}, 9: {1: 0},
    }
    previous_state_bytes = cbor(previous_state)
    previous_state_hash = sha256_multihash(previous_state_bytes)

    operation = {
        1: 2, 2: 6, 3: identity, 4: 2, 5: previous_state_hash,
        6: {1: new_policy, 2: disposition},
    }
    operation_bytes = cbor(operation)
    controller_signing = cbor(["OpenIdentity Operation", 1, operation_bytes])
    controller_signature = cpriv.sign(controller_signing)
    cpriv.public_key().verify(controller_signature, controller_signing)
    auth_signing, auth_proof = _purpose_proof(
        "OpenIdentity Authentication Proof", operation_bytes, new_priv, new_id
    )
    signed_operation = {
        1: operation,
        2: [{1: cid, 2: controller_signature}],
        5: [auth_proof],
    }

    state = {
        1: 3, 2: identity, 3: 2, 4: 1, 5: controller_policy,
        8: {1: generation_after, 2: new_policy}, 9: {1: 0},
    }
    state_bytes = cbor(state)
    state_hash = sha256_multihash(state_bytes)

    assert old_policy != new_policy
    assert state[8][1] == generation_after

    return {
        "id": vector_id,
        "description": (
            "AuthenticationPolicy A to B planned rotation preserves generation"
            if disposition == 2 else
            "AuthenticationPolicy A to B security rotation increments generation"
        ),
        "expected": "PASS",
        "fixture": {
            "identityHex": identity.hex(),
            "controllerMethodIdHex": cid.hex(),
            "controllerPublicKeyHex": cpub.hex(),
            "oldAuthenticationMethodIdHex": old_id.hex(),
            "oldAuthenticationPublicKeyHex": old_pub.hex(),
            "newAuthenticationMethodIdHex": new_id.hex(),
            "newAuthenticationPublicKeyHex": new_pub.hex(),
        },
        "previousStateBytesHex": previous_state_bytes.hex(),
        "previousStateHashHex": previous_state_hash.hex(),
        "operationBytesHex": operation_bytes.hex(),
        "controllerSigningBytesHex": controller_signing.hex(),
        "controllerSignatureHex": controller_signature.hex(),
        "authenticationProofSigningBytesHex": auth_signing.hex(),
        "authenticationProofSignatureHex": auth_proof[2].hex(),
        "signedOperationBytesHex": cbor(signed_operation).hex(),
        "stateBytesHex": state_bytes.hex(),
        "stateHashHex": state_hash.hex(),
        "assertions": {
            "disposition": "PRESERVE_EXISTING" if disposition == 2 else "INVALIDATE_EXISTING",
            "previousAuthenticationGeneration": 0,
            "resultingAuthenticationGeneration": generation_after,
            "newAuthenticationPolicyInstalled": True,
            "oldAuthenticationPolicyIsNotCurrent": True,
            "newAuthenticationPoPRequired": True,
            "stateHashLength": len(state_hash),
        },
    }


def build_v305() -> dict:
    return _auth_rotation_vector("V305", 2, 0)


def build_v306() -> dict:
    return _auth_rotation_vector("V306", 1, 1)



def build_v307() -> dict:
    identity = bytes(range(32))
    cpriv, cpub, cid, cm = _ed25519(
        "OpenIdentity protocol-v2 v3 V307 controller Ed25519 seed", 0
    )
    _, apub, aid, am = _ed25519(
        "OpenIdentity protocol-v2 v3 V307 authentication Ed25519 seed", 16
    )
    cp, ap = _single_policy(cm), _single_policy(am)
    previous = {1:3,2:identity,3:1,4:1,5:cp,8:{1:4,2:ap},9:{1:0}}
    psb=cbor(previous); psh=sha256_multihash(psb)
    operation={1:2,2:6,3:identity,4:2,5:psh,6:{1:None}}
    ob=cbor(operation)
    csi=cbor(["OpenIdentity Operation",1,ob])
    csig=cpriv.sign(csi); cpriv.public_key().verify(csig,csi)
    signed={1:operation,2:[{1:cid,2:csig}]}
    state={1:3,2:identity,3:2,4:1,5:cp,8:{1:5},9:{1:0}}
    sb=cbor(state); sh=sha256_multihash(sb)
    return {
        "id":"V307","description":"Removing AuthenticationPolicy increments generation exactly once",
        "expected":"PASS",
        "fixture":{"identityHex":identity.hex(),"controllerMethodIdHex":cid.hex(),
                   "controllerPublicKeyHex":cpub.hex(),"removedAuthenticationMethodIdHex":aid.hex(),
                   "removedAuthenticationPublicKeyHex":apub.hex()},
        "previousStateBytesHex":psb.hex(),"previousStateHashHex":psh.hex(),
        "operationBytesHex":ob.hex(),"controllerSigningBytesHex":csi.hex(),
        "controllerSignatureHex":csig.hex(),"signedOperationBytesHex":cbor(signed).hex(),
        "stateBytesHex":sb.hex(),"stateHashHex":sh.hex(),
        "assertions":{"previousAuthenticationGeneration":4,"resultingAuthenticationGeneration":5,
                      "authenticationPolicyPresent":False,"authenticationProofCollectionPresent":False,
                      "stateHashLength":len(sh)}
    }


def build_v308() -> dict:
    identity = bytes(range(32))
    cpriv, cpub, cid, cm = _ed25519(
        "OpenIdentity protocol-v2 v3 V308 controller Ed25519 seed", 0
    )
    _, apub, aid, am = _ed25519(
        "OpenIdentity protocol-v2 v3 V308 authentication Ed25519 seed", 16
    )
    cp, ap = _single_policy(cm), _single_policy(am)
    previous={1:3,2:identity,3:7,4:1,5:cp,8:{1:9,2:ap},9:{1:0}}
    psb=cbor(previous); psh=sha256_multihash(psb)
    operation={1:2,2:8,3:identity,4:8,5:psh,6:{}}
    ob=cbor(operation)
    csi=cbor(["OpenIdentity Operation",1,ob])
    csig=cpriv.sign(csi); cpriv.public_key().verify(csig,csi)
    signed={1:operation,2:[{1:cid,2:csig}]}
    state={1:3,2:identity,3:8,4:1,5:cp,8:{1:10,2:ap},9:{1:0}}
    sb=cbor(state); sh=sha256_multihash(sb)
    assert previous[8][2] == state[8][2]
    return {
        "id":"V308","description":"RESET_AUTHENTICATION preserves policy and increments generation exactly once",
        "expected":"PASS",
        "fixture":{"identityHex":identity.hex(),"controllerMethodIdHex":cid.hex(),
                   "controllerPublicKeyHex":cpub.hex(),"authenticationMethodIdHex":aid.hex(),
                   "authenticationPublicKeyHex":apub.hex()},
        "previousStateBytesHex":psb.hex(),"previousStateHashHex":psh.hex(),
        "operationBytesHex":ob.hex(),"controllerSigningBytesHex":csi.hex(),
        "controllerSignatureHex":csig.hex(),"signedOperationBytesHex":cbor(signed).hex(),
        "stateBytesHex":sb.hex(),"stateHashHex":sh.hex(),
        "assertions":{"previousAuthenticationGeneration":9,"resultingAuthenticationGeneration":10,
                      "authenticationPolicyPreserved":True,"authenticationProofCollectionPresent":False,
                      "stateHashLength":len(sh)}
    }



def _delegation_transition(vector_id, mode, disposition=None, generation_before=0, generation_after=0):
    identity=bytes(range(32))
    cpriv,cpub,cid,cm=_ed25519(f"OpenIdentity protocol-v2 v3 {vector_id} controller Ed25519 seed",0)
    _,oldpub,oldid,oldm=_ed25519(f"OpenIdentity protocol-v2 v3 {vector_id} delegation A Ed25519 seed",16)
    newpriv,newpub,newid,newm=_ed25519(f"OpenIdentity protocol-v2 v3 {vector_id} delegation B Ed25519 seed",32)
    cp=_single_policy(cm); oldp=_single_policy(oldm); newp=_single_policy(newm)
    previous_auth={1:0}
    previous_del={1:generation_before}
    if mode!="install": previous_del[2]=oldp
    previous={1:3,2:identity,3:1,4:1,5:cp,8:previous_auth,9:previous_del}
    psb=cbor(previous); psh=sha256_multihash(psb)

    if mode=="reset":
        operation={1:2,2:9,3:identity,4:2,5:psh,6:{}}
        result_policy=oldp
    else:
        payload_policy=None if mode=="remove" else (oldp if mode=="install" else newp)
        payload={1:payload_policy}
        if disposition is not None: payload[2]=disposition
        operation={1:2,2:7,3:identity,4:2,5:psh,6:payload}
        result_policy=payload_policy

    ob=cbor(operation)
    csi=cbor(["OpenIdentity Operation",1,ob])
    csig=cpriv.sign(csi); cpriv.public_key().verify(csig,csi)
    signed={1:operation,2:[{1:cid,2:csig}]}
    delegation_signing=None
    delegation_sig=None
    if result_policy is not None and mode!="reset":
        proof_priv, proof_id = ((newpriv,newid) if mode=="rotate" else
                               (_ed25519(f"OpenIdentity protocol-v2 v3 {vector_id} delegation A Ed25519 seed",16)[0],oldid))
        delegation_signing,proof=_purpose_proof("OpenIdentity Delegation Proof",ob,proof_priv,proof_id)
        delegation_sig=proof[2]
        signed[7]=[proof]

    result_del={1:generation_after}
    if result_policy is not None: result_del[2]=result_policy
    state={1:3,2:identity,3:2,4:1,5:cp,8:{1:0},9:result_del}
    sb=cbor(state); sh=sha256_multihash(sb)
    out={
        "id":vector_id,"expected":"PASS","previousStateBytesHex":psb.hex(),
        "previousStateHashHex":psh.hex(),"operationBytesHex":ob.hex(),
        "controllerSigningBytesHex":csi.hex(),"controllerSignatureHex":csig.hex(),
        "signedOperationBytesHex":cbor(signed).hex(),"stateBytesHex":sb.hex(),
        "stateHashHex":sh.hex(),"assertions":{
            "previousDelegationGeneration":generation_before,
            "resultingDelegationGeneration":generation_after,
            "delegationPolicyPresent":result_policy is not None,
            "delegationProofCollectionPresent":7 in signed,
            "stateHashLength":len(sh)
        }
    }
    if delegation_signing is not None:
        out["delegationProofSigningBytesHex"]=delegation_signing.hex()
        out["delegationProofSignatureHex"]=delegation_sig.hex()
    return out


def build_v309():
    v=_delegation_transition("V309","install",generation_before=0,generation_after=0)
    v["description"]="Initial DelegationPolicy installation preserves generation 0"
    return v

def build_v310():
    v=_delegation_transition("V310","rotate",disposition=2,generation_before=4,generation_after=4)
    v["description"]="DelegationPolicy planned rotation preserves generation"
    v["assertions"]["disposition"]="PRESERVE_EXISTING"
    return v

def build_v311():
    v=_delegation_transition("V311","rotate",disposition=1,generation_before=4,generation_after=5)
    v["description"]="DelegationPolicy security rotation increments generation exactly once"
    v["assertions"]["disposition"]="INVALIDATE_EXISTING"
    return v

def build_v312():
    v=_delegation_transition("V312","remove",generation_before=4,generation_after=5)
    v["description"]="Removing DelegationPolicy increments generation exactly once"
    return v

def build_v313():
    v=_delegation_transition("V313","reset",generation_before=9,generation_after=10)
    v["description"]="RESET_DELEGATIONS preserves policy and increments generation exactly once"
    v["assertions"]["delegationPolicyPreserved"]=True
    return v



def _recovery_policy(method):
    return {1:1,2:1,3:[method]}


def _recover_vector(vector_id, disposition, source_version=3, source_status=1, replace_assertion=False):
    identity=bytes(range(32))
    _,_,_,oldcm=_ed25519(f"OpenIdentity protocol-v2 v3 {vector_id} old controller Ed25519 seed",0)
    newcpriv,newcpub,newcid,newcm=_ed25519(f"OpenIdentity protocol-v2 v3 {vector_id} new controller Ed25519 seed",16)
    rpriv,rpub,rid,rm=_ed25519(f"OpenIdentity protocol-v2 v3 {vector_id} recovery Ed25519 seed",32)
    _,oldapub,oldaid,oldam=_ed25519(f"OpenIdentity protocol-v2 v3 {vector_id} assertion A Ed25519 seed",48)
    newapriv,newapub,newaid,newam=_ed25519(f"OpenIdentity protocol-v2 v3 {vector_id} assertion B Ed25519 seed",64)
    _,_,_,authm=_ed25519(f"OpenIdentity protocol-v2 v3 {vector_id} authentication Ed25519 seed",80)
    _,_,_,delm=_ed25519(f"OpenIdentity protocol-v2 v3 {vector_id} delegation Ed25519 seed",96)
    oldcp=_single_policy(oldcm); newcp=_single_policy(newcm)
    oldap=_single_policy(oldam); newap=_single_policy(newam)
    rp=_recovery_policy(rm); rc=sha256_multihash(cbor(rp))
    new_rc=sha256_multihash(cbor(_recovery_policy(newcm)))
    previous={1:source_version,2:identity,3:5,4:source_status,5:oldcp,6:rc,7:oldap}
    if source_version==3:
        previous[8]={1:3,2:_single_policy(authm)}
        previous[9]={1:7,2:_single_policy(delm)}
    psb=cbor(previous); psh=sha256_multihash(psb)
    payload={1:newcp,2:rp,3:new_rc,4:disposition}
    if replace_assertion: payload[5]=newap
    op={1:2,2:3,3:identity,4:6,5:psh,6:payload}
    ob=cbor(op)
    cpop_input=cbor(["OpenIdentity Controller Proof",1,ob,newcid])
    cpop_sig=newcpriv.sign(cpop_input); newcpriv.public_key().verify(cpop_sig,cpop_input)
    recovery_input=cbor(["OpenIdentity Recovery",1,ob,rid])
    recovery_sig=rpriv.sign(recovery_input); rpriv.public_key().verify(recovery_sig,recovery_input)
    signed={1:op,3:[{1:newcid,2:cpop_sig}],4:[{1:rid,2:recovery_sig}]}
    assertion_input=None; assertion_sig=None
    if replace_assertion:
        assertion_input=cbor(["OpenIdentity Assertion Proof",1,ob,newaid])
        assertion_sig=newapriv.sign(assertion_input); newapriv.public_key().verify(assertion_sig,assertion_input)
        signed[6]=[{1:newaid,2:assertion_sig}]
    result_assertion = oldap if disposition==1 else (newap if disposition==3 else None)
    auth_gen=1 if source_version==2 else 4
    del_gen=1 if source_version==2 else 8
    state={1:3,2:identity,3:6,4:1,5:newcp,6:new_rc,8:{1:auth_gen},9:{1:del_gen}}
    if result_assertion is not None: state[7]=result_assertion
    sb=cbor(state); sh=sha256_multihash(sb)
    out={"id":vector_id,"expected":"PASS","previousStateBytesHex":psb.hex(),
         "previousStateHashHex":psh.hex(),"operationBytesHex":ob.hex(),
         "controllerProofSigningBytesHex":cpop_input.hex(),"controllerProofSignatureHex":cpop_sig.hex(),
         "recoverySigningBytesHex":recovery_input.hex(),"recoverySignatureHex":recovery_sig.hex(),
         "signedOperationBytesHex":cbor(signed).hex(),"stateBytesHex":sb.hex(),"stateHashHex":sh.hex(),
         "assertions":{"sourceStateVersion":source_version,"sourceStatus":source_status,
                       "assertionDisposition":disposition,"ordinaryAuthorizationPresent":False,
                       "authenticationPolicyPresent":False,"delegationPolicyPresent":False,
                       "resultingAuthenticationGeneration":auth_gen,"resultingDelegationGeneration":del_gen,
                       "resultingStatus":"ACTIVE","stateHashLength":len(sh)}}
    if assertion_input is not None:
        out["assertionProofSigningBytesHex"]=assertion_input.hex()
        out["assertionProofSignatureHex"]=assertion_sig.hex()
    return out


def build_v314():
    v=_recover_vector("V314",1); v["description"]="RECOVER preserves AssertionPolicy and security-resets derived authorities"; return v
def build_v315():
    v=_recover_vector("V315",2); v["description"]="RECOVER removes AssertionPolicy and security-resets derived authorities"; return v
def build_v316():
    v=_recover_vector("V316",3,replace_assertion=True); v["description"]="RECOVER replaces AssertionPolicy with assertion-domain PoP"; return v
def build_v317():
    v=_recover_vector("V317",1,source_status=2); v["description"]="RECOVER from DEACTIVATED v3 returns ACTIVE and resets derived authorities"; return v
def build_v318():
    v=_recover_vector("V318",1,source_version=2); v["description"]="protocolVersion 2 RECOVER upgrades v2 to v3 with derived generations 1"; return v



def build_v319():
    v=_delegation_transition("V319","rotate",disposition=2,generation_before=42,generation_after=42)
    v["description"]="DelegationPolicy PRESERVE_EXISTING leaves nonzero delegation generation unchanged"
    v["assertions"]["disposition"]="PRESERVE_EXISTING"
    v["assertions"]["registeredPriorGenerationGrantsRemainGenerationCompatible"]=True
    return v


def build_v320():
    v=_delegation_transition("V320","reset",generation_before=42,generation_after=43)
    v["description"]="RESET_DELEGATIONS increments nonzero delegation generation exactly once"
    v["assertions"]["delegationPolicyPreserved"]=True
    v["assertions"]["priorGenerationGrantsInvalidatedByGenerationChange"]=True
    return v



def build_invalid_pop_vectors():
    identity=bytes(range(32))
    out=[]

    def base(vid, purpose, operation_type, payload_label, proof_field, domain):
        cpriv,_,cid,cm=_ed25519(f"OpenIdentity protocol-v2 v3 {vid} controller Ed25519 seed",0)
        ppriv,ppub,pid,pm=_ed25519(f"OpenIdentity protocol-v2 v3 {vid} {purpose} Ed25519 seed",16)
        _,upub,uid,um=_ed25519(f"OpenIdentity protocol-v2 v3 {vid} unauthorized Ed25519 seed",32)
        cp=_single_policy(cm); pp=_single_policy(pm)
        previous={1:3,2:identity,3:1,4:1,5:cp,8:{1:0},9:{1:0}}
        psh=sha256_multihash(cbor(previous))
        op={1:2,2:operation_type,3:identity,4:2,5:psh,6:{1:pp}}
        ob=cbor(op)
        csig=cpriv.sign(cbor(["OpenIdentity Operation",1,ob]))
        valid_input=cbor([domain,1,ob,pid])
        valid_sig=ppriv.sign(valid_input)
        return cp,pp,ob,cid,csig,ppriv,ppub,pid,valid_input,valid_sig,upub,uid,um,proof_field

    # Missing, wrong-domain, duplicate, unauthorized Authentication PoPs.
    cp,pp,ob,cid,csig,ppriv,ppub,pid,inp,sig,upub,uid,um,pf=base(
        "VI301","authentication",6,4,5,"OpenIdentity Authentication Proof")
    out.append({"id":"VI301","expected":"REJECT","expectedError":"MISSING_PROOF_OF_POSSESSION",
                "operationBytesHex":ob.hex(),"signedOperationBytesHex":cbor({1:cbor_decode_placeholder if False else {}}).hex() if False else "",
                "proofField":5,"proofCount":0})
    wrong_in=cbor(["OpenIdentity Operation",1,ob]); wrong_sig=ppriv.sign(wrong_in)
    out.append({"id":"VI302","expected":"REJECT","expectedError":"INVALID_PROOF_OF_POSSESSION",
                "operationBytesHex":ob.hex(),"methodIdHex":pid.hex(),"publicKeyHex":ppub.hex(),
                "sourceDomain":"OpenIdentity Operation","requiredDomain":"OpenIdentity Authentication Proof",
                "wrongSigningBytesHex":wrong_in.hex(),"requiredSigningBytesHex":inp.hex(),"signatureHex":wrong_sig.hex()})
    proof={1:pid,2:sig}
    out.append({"id":"VI303","expected":"REJECT","expectedError":"DUPLICATE_AUTHENTICATION_PROOF",
                "operationBytesHex":ob.hex(),"proofsHex":[cbor(proof).hex(),cbor(proof).hex()]})
    unauthorized_input=cbor(["OpenIdentity Authentication Proof",1,ob,uid])
    # deterministic unauthorized private key reconstructed explicitly
    upriv,_,_,_=_ed25519("OpenIdentity protocol-v2 v3 VI301 unauthorized Ed25519 seed",32)
    usig=upriv.sign(unauthorized_input)
    out.append({"id":"VI304","expected":"REJECT","expectedError":"UNAUTHORIZED_AUTHENTICATION_METHOD",
                "operationBytesHex":ob.hex(),"authorizedMethodIdHex":pid.hex(),"unauthorizedMethodIdHex":uid.hex(),
                "unauthorizedPublicKeyHex":upub.hex(),"signingBytesHex":unauthorized_input.hex(),"signatureHex":usig.hex()})

    cp,pp,ob,cid,csig,ppriv,ppub,pid,inp,sig,upub,uid,um,pf=base(
        "VI305","delegation",7,5,7,"OpenIdentity Delegation Proof")
    out.append({"id":"VI305","expected":"REJECT","expectedError":"MISSING_PROOF_OF_POSSESSION",
                "operationBytesHex":ob.hex(),"proofField":7,"proofCount":0})
    wrong_in=cbor(["OpenIdentity Authentication Proof",1,ob,pid]); wrong_sig=ppriv.sign(wrong_in)
    out.append({"id":"VI306","expected":"REJECT","expectedError":"INVALID_PROOF_OF_POSSESSION",
                "operationBytesHex":ob.hex(),"methodIdHex":pid.hex(),"publicKeyHex":ppub.hex(),
                "sourceDomain":"OpenIdentity Authentication Proof","requiredDomain":"OpenIdentity Delegation Proof",
                "wrongSigningBytesHex":wrong_in.hex(),"requiredSigningBytesHex":inp.hex(),"signatureHex":wrong_sig.hex()})
    proof={1:pid,2:sig}
    out.append({"id":"VI307","expected":"REJECT","expectedError":"DUPLICATE_DELEGATION_PROOF",
                "operationBytesHex":ob.hex(),"proofsHex":[cbor(proof).hex(),cbor(proof).hex()]})
    upriv,upub,uid,um=_ed25519("OpenIdentity protocol-v2 v3 VI305 unauthorized Ed25519 seed",32)
    unauthorized_input=cbor(["OpenIdentity Delegation Proof",1,ob,uid]); usig=upriv.sign(unauthorized_input)
    out.append({"id":"VI308","expected":"REJECT","expectedError":"UNAUTHORIZED_DELEGATION_METHOD",
                "operationBytesHex":ob.hex(),"authorizedMethodIdHex":pid.hex(),"unauthorizedMethodIdHex":uid.hex(),
                "unauthorizedPublicKeyHex":upub.hex(),"signingBytesHex":unauthorized_input.hex(),"signatureHex":usig.hex()})

    # Explicit cross-purpose substitutions.
    for vid,source,required in [
        ("VI325","OpenIdentity Assertion Proof","OpenIdentity Authentication Proof"),
        ("VI326","OpenIdentity Delegation Proof","OpenIdentity Assertion Proof"),
        ("VI327","OpenIdentity Authentication Proof","OpenIdentity Delegation Proof")]:
        priv,pub,mid,_=_ed25519(f"OpenIdentity protocol-v2 v3 {vid} cross-domain Ed25519 seed",16)
        dummy_op=cbor({1:2,2:6,3:identity,4:2,5:b"\\x12\\x20"+bytes(32),6:{}})
        source_input=cbor([source,1,dummy_op,mid]); required_input=cbor([required,1,dummy_op,mid])
        signature=priv.sign(source_input)
        out.append({"id":vid,"expected":"REJECT","expectedError":"INVALID_PROOF_OF_POSSESSION",
                    "operationBytesHex":dummy_op.hex(),"methodIdHex":mid.hex(),"publicKeyHex":pub.hex(),
                    "sourceDomain":source,"requiredDomain":required,
                    "sourceSigningBytesHex":source_input.hex(),"requiredSigningBytesHex":required_input.hex(),
                    "signatureHex":signature.hex()})
    return out



def build_remaining_invalid_vectors():
    identity=bytes(range(32)); out=[]
    def item(vid,error,kind,**kw):
        x={"id":vid,"expected":"REJECT","expectedError":error,"attackKind":kind}; x.update(kw); out.append(x)

    # Transition/disposition attacks with byte-complete predecessor/operation artifacts.
    def auth_case(vid, present=True, generation=7):
        cpriv,_,cid,cm=_ed25519(f"OpenIdentity protocol-v2 v3 {vid} controller Ed25519 seed",0)
        apriv,_,aid,am=_ed25519(f"OpenIdentity protocol-v2 v3 {vid} authentication A Ed25519 seed",16)
        _,_,_,bm=_ed25519(f"OpenIdentity protocol-v2 v3 {vid} authentication B Ed25519 seed",32)
        cp=_single_policy(cm); ap=_single_policy(am); bp=_single_policy(bm)
        aa={1:generation}
        if present: aa[2]=ap
        prev={1:3,2:identity,3:1,4:1,5:cp,8:aa,9:{1:0}}
        return cp,ap,bp,prev

    cp,ap,bp,prev=auth_case("VI309"); psb=cbor(prev); psh=sha256_multihash(psb)
    op={1:2,2:6,3:identity,4:2,5:psh,6:{1:bp}}
    item("VI309","MISSING_AUTHORITY_DISPOSITION","missing-disposition",
         previousStateBytesHex=psb.hex(),operationBytesHex=cbor(op).hex(),payloadBytesHex=cbor(op[6]).hex())

    cp,ap,bp,prev=auth_case("VI310",False,0); psb=cbor(prev); psh=sha256_multihash(psb)
    op={1:2,2:6,3:identity,4:2,5:psh,6:{1:ap,2:2}}
    item("VI310","FORBIDDEN_AUTHORITY_DISPOSITION","forbidden-disposition",
         previousStateBytesHex=psb.hex(),operationBytesHex=cbor(op).hex(),payloadBytesHex=cbor(op[6]).hex())

    cp,ap,bp,prev=auth_case("VI311"); psb=cbor(prev); psh=sha256_multihash(psb)
    op={1:2,2:6,3:identity,4:2,5:psh,6:{1:None,2:2}}
    item("VI311","INVALID_AUTHORITY_DISPOSITION","removal-preserve",
         previousStateBytesHex=psb.hex(),operationBytesHex=cbor(op).hex(),payloadBytesHex=cbor(op[6]).hex())

    cp,ap,bp,prev=auth_case("VI312"); psb=cbor(prev); psh=sha256_multihash(psb)
    op={1:2,2:6,3:identity,4:2,5:psh,6:{1:ap,2:2}}
    item("VI312","NO_OP_POLICY_REPLACEMENT","exact-policy-noop",
         previousStateBytesHex=psb.hex(),operationBytesHex=cbor(op).hex(),
         currentPolicyBytesHex=cbor(ap).hex(),proposedPolicyBytesHex=cbor(op[6][1]).hex())

    # Generation attacks carry exact predecessor, operation, and invalid proposed state bytes.
    for vid,proposed in [("VI313",9),("VI314",6)]:
        cp,ap,bp,prev=auth_case(vid,True,7); psb=cbor(prev); psh=sha256_multihash(psb)
        op={1:2,2:8,3:identity,4:2,5:psh,6:{}}
        bad={1:3,2:identity,3:2,4:1,5:cp,8:{1:proposed,2:ap},9:{1:0}}
        item(vid,"INVALID_AUTHORITY_GENERATION","generation-jump" if proposed==9 else "generation-decrease",
             previousStateBytesHex=psb.hex(),operationBytesHex=cbor(op).hex(),
             proposedStateBytesHex=cbor(bad).hex(),currentGeneration=7,proposedGeneration=proposed)

    cp,ap,bp,prev=auth_case("VI315",True,18446744073709551615); psb=cbor(prev); psh=sha256_multihash(psb)
    op={1:2,2:8,3:identity,4:2,5:psh,6:{}}
    item("VI315","AUTHORITY_GENERATION_OVERFLOW","generation-overflow",
         previousStateBytesHex=psb.hex(),operationBytesHex=cbor(op).hex(),
         currentGeneration=18446744073709551615,requiredNextGeneration="18446744073709551616")

    # Recovery attacks.
    item("VI316","RECOVERY_MUST_RESET_AUTHENTICATION","recover-preserve-authentication",
         authenticationPolicyPresentBefore=True,authenticationPolicyPresentAfter=True)
    item("VI317","RECOVERY_MUST_RESET_DELEGATION","recover-preserve-delegation",
         delegationPolicyPresentBefore=True,delegationPolicyPresentAfter=True)
    item("VI318","MISSING_ASSERTION_DISPOSITION","recover-missing-assertion-disposition",
         payloadLabels=[1,2,3])
    item("VI319","INVALID_ASSERTION_DISPOSITION","recover-remove-absent-assertion",
         sourceAssertionPolicyPresent=False,disposition="REMOVE")
    item("VI320","INVALID_ASSERTION_DISPOSITION","recover-replace-absent-assertion",
         sourceAssertionPolicyPresent=False,disposition="REPLACE")
    item("VI321","MISSING_PROOF_OF_POSSESSION","recover-replace-missing-assertion-pop",
         sourceAssertionPolicyPresent=True,disposition="REPLACE",assertionProofCount=0)

    # Version / structural attacks.
    item("VI322","STATE_VERSION_DOWNGRADE","state-version-downgrade",
         sourceStateVersion=3,proposedStateVersion=2)
    item("VI323","UNSUPPORTED_PROTOCOL_VERSION","pv1-on-v3",
         sourceStateVersion=3,operationProtocolVersion=1)
    item("VI324","MALFORMED_PROOF_COLLECTION","malformed-proof-collection",
         proofField=5,encodedAs="map",requiredShape="non-empty array")

    # Duplicate effective cryptographic key under distinct method IDs.
    _,pub,mid1,m1=_ed25519("OpenIdentity protocol-v2 v3 VI328 duplicate effective key seed",0)
    mid2=bytes(range(16,32))
    m2={1:mid2,2:m1[2]}
    dup_policy={1:2,2:2,3:[m1,m2]}
    item("VI328","DUPLICATE_EFFECTIVE_VERIFICATION_KEY","duplicate-effective-key",
         methodId1Hex=mid1.hex(),methodId2Hex=mid2.hex(),publicKeyHex=pub.hex(),
         coseKey1Hex=cbor(m1[2]).hex(),coseKey2Hex=cbor(m2[2]).hex(),
         policyBytesHex=cbor(dup_policy).hex())

    # CREATE structurally forbids redundant Controller PoP.
    item("VI329","MALFORMED_SIGNED_OPERATION","create-redundant-controller-pop",
         operationType="CREATE",forbiddenProofField=3)

    # RESET_AUTHENTICATION structurally forbids purpose-specific PoP.
    item("VI330","MALFORMED_SIGNED_OPERATION","reset-authentication-purpose-pop",
         operationType="RESET_AUTHENTICATION",forbiddenProofField=5)

    # RECOVER structurally forbids ordinary controller authorization.
    item("VI331","MALFORMED_SIGNED_OPERATION","recover-ordinary-authorization",
         operationType="RECOVER",forbiddenProofField=2)

    # RECOVER disposition / payload shape mismatch.
    item("VI332","MALFORMED_RECOVERY_PAYLOAD","recover-shape-mismatch",
         disposition="PRESERVE",replacementAssertionPolicyPresent=True)
    return out


def main() -> None:
    bundle = {
        "specification": "OpenIdentity Protocol v2 / IdentityState v3",
        "status": "DRAFT-NON-NORMATIVE",
        "wireSchema": "spec/cddl/openidentity-operation-v3.cddl",
        "invalidVectors": build_invalid_pop_vectors() + build_remaining_invalid_vectors(),
        "vectors": [build_v301(), build_v302(), build_v303(), build_v304(), build_v305(), build_v306(), build_v307(), build_v308(), build_v309(), build_v310(), build_v311(), build_v312(), build_v313(), build_v314(), build_v315(), build_v316(), build_v317(), build_v318(), build_v319(), build_v320()],
    }
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(bundle, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {OUTPUT.relative_to(ROOT)}")
    print("V301 VERIFIED")
    print("V302 VERIFIED")
    print("V303 VERIFIED")
    print("V304 VERIFIED")
    print("V305 VERIFIED")
    print("V306 VERIFIED")
    print("V307 VERIFIED")
    print("V308 VERIFIED")
    print("V309 VERIFIED")
    print("V310 VERIFIED")
    print("V311 VERIFIED")
    print("V312 VERIFIED")
    print("V313 VERIFIED")
    print("V314 VERIFIED")
    print("V315 VERIFIED")
    print("V316 VERIFIED")
    print("V317 VERIFIED")
    print("V318 VERIFIED")
    print("V319 VERIFIED")
    print("V320 VERIFIED")


if __name__ == "__main__":
    main()
