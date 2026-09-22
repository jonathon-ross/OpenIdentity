"""Independent verifier for OpenIdentity OI-002 V04 ROTATE_CONTROLLER."""

import argparse, hashlib, json, sys
from pathlib import Path
import cbor2
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PublicKey

SPEC="OpenIdentity Cryptographic Agility"; VERSION="0.1"
OP_CTX="OpenIdentity Operation"; POP_CTX="OpenIdentity Controller Proof"
ED_PK=32; ED_SIG=64; ML_PK=1952; ML_SIG=3309

def fail(m): print("\nFAILED\n------\n"+m+"\n"); sys.exit(1)
def passed(m): print("  "+m+": PASS")
def hx(v,n):
    if not isinstance(v,str): fail(n+" must be hex")
    try:return bytes.fromhex(v)
    except ValueError as e:fail(f"{n} invalid hex: {e}")
def req(v,n):
    if n not in v: fail("Missing field: "+n)
    return v[n]
def enc(v): return cbor2.dumps(v,canonical=True)
def dec(n,b):
    try:return cbor2.loads(b)
    except Exception as e:fail(f"{n} invalid CBOR: {e}")
def eq(n,a,b):
    if a!=b: fail(f"{n} mismatch")
    passed(n)
def beq(n,a,b):
    if a!=b: fail(f"{n} byte mismatch\nExpected: {b.hex()}\nActual:   {a.hex()}")
    passed(n)
def multihash(state): return b"\x12\x20"+hashlib.sha256(state).digest()

def load(path):
    try:d=json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:fail(f"Unable to load {path}: {e}")
    if d.get("specification")!=SPEC or d.get("version")!=VERSION: fail("Unexpected specification/version")
    v=d.get("vector")
    if not isinstance(v,dict) or v.get("id")!="V04": fail("Expected V04 vector")
    return v

def verify(v):
    print("\nOpenIdentity OI-002\nV04 Independent Verification\n"+"="*48+"\n")

    identity=hx(req(v,"identityHex"),"identityHex")
    prev_state=hx(req(v,"previousIdentityStateHex"),"previousIdentityStateHex")
    prev_hash=hx(req(v,"previousStateHashHex"),"previousStateHashHex")
    old_eid=hx(req(v,"oldEd25519MethodIdHex"),"oldEd25519MethodIdHex")
    old_mid=hx(req(v,"oldMlDsa65MethodIdHex"),"oldMlDsa65MethodIdHex")
    old_epk=hx(req(v,"oldEd25519PublicKeyHex"),"oldEd25519PublicKeyHex")
    old_mpk=hx(req(v,"oldMlDsa65PublicKeyHex"),"oldMlDsa65PublicKeyHex")
    new_eid=hx(req(v,"newEd25519MethodIdHex"),"newEd25519MethodIdHex")
    new_mid=hx(req(v,"newMlDsa65MethodIdHex"),"newMlDsa65MethodIdHex")
    new_epk=hx(req(v,"newEd25519PublicKeyHex"),"newEd25519PublicKeyHex")
    new_mpk=hx(req(v,"newMlDsa65PublicKeyHex"),"newMlDsa65PublicKeyHex")
    new_ecose=hx(req(v,"newEd25519CoseKeyHex"),"newEd25519CoseKeyHex")
    new_mcose=hx(req(v,"newMlDsa65CoseKeyHex"),"newMlDsa65CoseKeyHex")
    new_evm=hx(req(v,"newEd25519VerificationMethodHex"),"newEd25519VerificationMethodHex")
    new_mvm=hx(req(v,"newMlDsa65VerificationMethodHex"),"newMlDsa65VerificationMethodHex")
    new_policy_b=hx(req(v,"newControllerPolicyHex"),"newControllerPolicyHex")
    op_b=hx(req(v,"operationBytesHex"),"operationBytesHex")
    auth_in=hx(req(v,"authorizationSigningInputHex"),"authorizationSigningInputHex")
    old_esig=hx(req(v,"oldEd25519AuthorizationSignatureHex"),"oldEd25519AuthorizationSignatureHex")
    old_msig=hx(req(v,"oldMlDsa65AuthorizationSignatureHex"),"oldMlDsa65AuthorizationSignatureHex")
    old_eproof=hx(req(v,"oldEd25519AuthorizationProofHex"),"oldEd25519AuthorizationProofHex")
    old_mproof=hx(req(v,"oldMlDsa65AuthorizationProofHex"),"oldMlDsa65AuthorizationProofHex")
    new_ein=hx(req(v,"newEd25519PopSigningInputHex"),"newEd25519PopSigningInputHex")
    new_esig=hx(req(v,"newEd25519PopSignatureHex"),"newEd25519PopSignatureHex")
    new_eproof=hx(req(v,"newEd25519ControllerProofHex"),"newEd25519ControllerProofHex")
    new_min=hx(req(v,"newMlDsa65PopSigningInputHex"),"newMlDsa65PopSigningInputHex")
    new_msig=hx(req(v,"newMlDsa65PopSignatureHex"),"newMlDsa65PopSignatureHex")
    new_mproof=hx(req(v,"newMlDsa65ControllerProofHex"),"newMlDsa65ControllerProofHex")
    signed_b=hx(req(v,"signedOperationHex"),"signedOperationHex")
    result_state=hx(req(v,"resultingIdentityStateHex"),"resultingIdentityStateHex")
    result_hash=hx(req(v,"resultingStateHashHex"),"resultingStateHashHex")

    for n,a,e in [("identity length",len(identity),32),("old Ed25519 key",len(old_epk),ED_PK),
                  ("old ML-DSA key",len(old_mpk),ML_PK),("new Ed25519 key",len(new_epk),ED_PK),
                  ("new ML-DSA key",len(new_mpk),ML_PK),("old Ed25519 signature",len(old_esig),ED_SIG),
                  ("old ML-DSA signature",len(old_msig),ML_SIG),("new Ed25519 PoP",len(new_esig),ED_SIG),
                  ("new ML-DSA PoP",len(new_msig),ML_SIG),("previous StateHash",len(prev_hash),34),
                  ("resulting StateHash",len(result_hash),34)]:
        eq(n,a,e)

    # Previous state and chain linkage.
    beq("previous StateHash recomputation",prev_hash,multihash(prev_state))
    prev_obj=dec("previous IdentityState",prev_state)
    beq("previous IdentityState canonical CBOR",prev_state,enc(prev_obj))
    eq("previous state identity",prev_obj[2],identity)
    eq("previous state sequence",prev_obj[3],1)
    eq("previous state ACTIVE",prev_obj[4],1)

    # New COSE keys and methods.
    ec={1:1,3:-8,-1:6,-2:new_epk}; mc={1:7,3:-49,-1:new_mpk}
    eq("new Ed25519 COSE_Key",dec("new Ed COSE",new_ecose),ec); beq("new Ed25519 COSE canonical",new_ecose,enc(ec))
    eq("new ML-DSA COSE_Key",dec("new ML COSE",new_mcose),mc); beq("new ML-DSA COSE canonical",new_mcose,enc(mc))
    evm={1:new_eid,2:ec}; mvm={1:new_mid,2:mc}
    eq("new Ed25519 VerificationMethod",dec("new Ed VM",new_evm),evm); beq("new Ed VM canonical",new_evm,enc(evm))
    eq("new ML-DSA VerificationMethod",dec("new ML VM",new_mvm),mvm); beq("new ML VM canonical",new_mvm,enc(mvm))
    methods=sorted([(new_eid,evm),(new_mid,mvm)],key=lambda x:x[0])
    policy={1:2,2:2,3:[x[1] for x in methods]}
    eq("new 2-of-2 policy",dec("new policy",new_policy_b),policy); beq("new policy canonical",new_policy_b,enc(policy))

    # ROTATE operation. Payload contains policy only, no proofs.
    operation={1:1,2:2,3:identity,4:2,5:prev_hash,6:{1:policy}}
    eq("ROTATE_CONTROLLER structure",dec("operation",op_b),operation)
    beq("OperationBytes canonical CBOR",op_b,enc(operation))
    if 2 in operation[6]: fail("ROTATE payload unexpectedly contains controller proofs")
    passed("ROTATE payload contains no proofs")

    # Old-controller authorization domain.
    expected_auth=enc([OP_CTX,1,op_b])
    beq("authorization SigningInput",auth_in,expected_auth)
    try: Ed25519PublicKey.from_public_bytes(old_epk).verify(old_esig,auth_in)
    except Exception as e: fail("Old Ed25519 authorization failed: "+str(e))
    passed("independent old Ed25519 authorization")
    try: MLDSA65PublicKey.from_public_bytes(old_mpk).verify(old_msig,auth_in)
    except Exception as e: fail("Old ML-DSA authorization failed: "+str(e))
    passed("independent old ML-DSA authorization")

    oe={1:old_eid,2:old_esig}; om={1:old_mid,2:old_msig}
    eq("old Ed authorization proof",dec("old Ed proof",old_eproof),oe)
    eq("old ML authorization proof",dec("old ML proof",old_mproof),om)

    # New-controller PoP domains are method-specific.
    beq("new Ed25519 PoP SigningInput",new_ein,enc([POP_CTX,1,op_b,new_eid]))
    beq("new ML-DSA PoP SigningInput",new_min,enc([POP_CTX,1,op_b,new_mid]))
    if new_ein==new_min: fail("PoP signing inputs must differ by method ID")
    passed("PoP domain binds Verification Method ID")
    if new_ein==auth_in or new_min==auth_in: fail("PoP input must differ from authorization input")
    passed("authorization and PoP domains separated")

    try: Ed25519PublicKey.from_public_bytes(new_epk).verify(new_esig,new_ein)
    except Exception as e: fail("New Ed25519 PoP failed: "+str(e))
    passed("independent new Ed25519 proof of possession")
    try: MLDSA65PublicKey.from_public_bytes(new_mpk).verify(new_msig,new_min)
    except Exception as e: fail("New ML-DSA PoP failed: "+str(e))
    passed("independent new ML-DSA proof of possession")

    ne={1:new_eid,2:new_esig}; nm={1:new_mid,2:new_msig}
    eq("new Ed controller proof",dec("new Ed proof",new_eproof),ne)
    eq("new ML controller proof",dec("new ML proof",new_mproof),nm)

    # Envelope canonical ordering: old authorization in field 2, new PoP in field 3.
    auth_proofs=[x[1] for x in sorted([(old_eid,oe),(old_mid,om)],key=lambda x:x[0])]
    pop_proofs=[x[1] for x in sorted([(new_eid,ne),(new_mid,nm)],key=lambda x:x[0])]
    signed={1:operation,2:auth_proofs,3:pop_proofs}
    eq("SignedOperation structure",dec("SignedOperation",signed_b),signed)
    beq("SignedOperation canonical CBOR",signed_b,enc(signed))
    passed("authorization proofs outside OperationBytes")
    passed("controller proofs outside OperationBytes")

    # Resulting state and hash.
    resulting={1:1,2:identity,3:2,4:1,5:policy}
    eq("resulting IdentityState",dec("resulting state",result_state),resulting)
    beq("resulting IdentityState canonical CBOR",result_state,enc(resulting))
    beq("resulting StateHash",result_hash,multihash(result_state))
    if result_hash==prev_hash: fail("Resulting StateHash must differ from previous StateHash")
    passed("state transition changes StateHash")

    # Metadata.
    for f,e in [("sequence",2),("oldControllerThreshold",2),("newControllerThreshold",2),
                ("authorizationProofCount",2),("controllerProofCount",2),
                ("oldEd25519SignatureLength",64),("oldMlDsa65SignatureLength",3309),
                ("newEd25519PopSignatureLength",64),("newMlDsa65PopSignatureLength",3309)]:
        eq("metadata "+f,req(v,f),e)

    print("\n"+"="*48)
    print("V04 INDEPENDENT VERIFICATION PASSED")
    print("ROTATION + AUTHORIZATION + PROOF OF POSSESSION")
    print("="*48+"\n")

def main():
    p=argparse.ArgumentParser(description="Verify OpenIdentity OI-002 V04")
    p.add_argument("vector_file",type=Path)
    a=p.parse_args(); verify(load(a.vector_file))

if __name__=="__main__": main()
