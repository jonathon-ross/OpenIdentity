#!/usr/bin/env python3
import hashlib, json, sys
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

_ml_verify = None
for _name in ("ml_dsa_65", "dilithium3"):
    try:
        if _name == "ml_dsa_65":
            from pqcrypto.sign import ml_dsa_65 as _ml
        else:
            from pqcrypto.sign import dilithium3 as _ml
        _ml_verify = _ml.verify
        break
    except ImportError:
        pass

def hx(s): return bytes.fromhex(s)
def head(m,n):
    if n<24:return bytes([(m<<5)|n])
    if n<=255:return bytes([(m<<5)|24,n])
    if n<=65535:return bytes([(m<<5)|25])+n.to_bytes(2,"big")
    if n<=4294967295:return bytes([(m<<5)|26])+n.to_bytes(4,"big")
    return bytes([(m<<5)|27])+n.to_bytes(8,"big")
def integer(n): return head(0,n) if n>=0 else head(1,-1-n)
def bstr(b): return head(2,len(b))+b
def tstr(x):
    b=x.encode(); return head(3,len(b))+b
def arr(xs): return head(4,len(xs))+b"".join(xs)
def det_map(es):
    es=[(integer(k),v) for k,v in es]; es.sort(key=lambda x:(len(x[0]),x[0]))
    return head(5,len(es))+b"".join(k+v for k,v in es)
def mh(b): return b"\x12\x20"+hashlib.sha256(b).digest()
def cose_ed(pk): return det_map([(1,integer(1)),(3,integer(-8)),(-1,integer(6)),(-2,bstr(pk))])
def cose_ml(pk): return det_map([(1,integer(7)),(3,integer(-49)),(-1,bstr(pk))])
def vm(mid,key): return det_map([(1,bstr(mid)),(2,key)])
def single(m): return det_map([(1,integer(1)),(2,arr([m]))])
def r_single(m): return det_map([(1,integer(1)),(2,integer(1)),(3,arr([m]))])
def r_threshold(t,ms):
    ms=sorted(ms,key=lambda x:x[0])
    return det_map([(1,integer(1)),(2,integer(2)),(3,integer(t)),(4,arr([m for _,m in ms]))])
def state(ver,i,seq,status,cp,rc=None,ap=None):
    e=[(1,integer(ver)),(2,bstr(i)),(3,integer(seq)),(4,integer(status)),(5,cp)]
    if rc is not None:e.append((6,bstr(rc)))
    if ap is not None:e.append((7,ap))
    return det_map(e)
def recover(i,seq,prev,cp,rp,nrc):
    p=det_map([(1,cp),(2,rp),(3,bstr(nrc))])
    return det_map([(1,integer(1)),(2,integer(3)),(3,bstr(i)),(4,integer(seq)),(5,bstr(prev)),(6,p)])
def rin(op,mid): return arr([tstr("OpenIdentity Recovery"),integer(1),bstr(op),bstr(mid)])
def oin(op): return arr([tstr("OpenIdentity Operation"),integer(1),bstr(op)])
def cin(op,mid): return arr([tstr("OpenIdentity Controller Proof"),integer(1),bstr(op),bstr(mid)])
def proof(mid,sig): return det_map([(1,bstr(mid)),(2,bstr(sig))])
def signed(op,pops,rps):
    pops=sorted(pops,key=lambda x:x[0]); rps=sorted(rps,key=lambda x:x[0])
    return det_map([(1,op),(3,arr([p for _,p in pops])),(4,arr([p for _,p in rps]))])
def check(n,x):
    print("  "+n+": "+("PASS" if x else "FAIL"))
    if not x: raise AssertionError(n)
def edv(pk,sig,msg):
    try: Ed25519PublicKey.from_public_bytes(pk).verify(sig,msg); return True
    except Exception:return False
def mlv(pk,sig,msg):
    if _ml_verify is None: raise RuntimeError("pqcrypto ML-DSA-65 support required")
    for a in ((msg,sig,pk),(pk,msg,sig)):
        try:
            r=_ml_verify(*a); return True if r is None else bool(r)
        except Exception: pass
    return False

def verify_r01():
    root=Path(__file__).resolve().parents[2]
    p=Path(sys.argv[1]) if len(sys.argv)>1 else root/"test-vectors"/"generated"/"recovery-r01-java.json"
    d=json.loads(p.read_text()); v=d["vector"]
    print("\nOpenIdentity Recovery R01\nIndependent Verification\n--------------------------------------------")
    check("R01 specification",d["specification"]=="OpenIdentity Recovery")
    check("R01 suite version",d["version"]=="0.1"); check("R01 vector ID",v["id"]=="R01")
    i=hx(v["identityHex"]); ps=hx(v["previousIdentityStateHex"]); ph=hx(v["previousStateHashHex"]); oc=hx(v["previousControllerPolicyHex"])
    em=hx(v["currentRecoveryEd25519MethodIdHex"]); mm=hx(v["currentRecoveryMlDsa65MethodIdHex"])
    ep=hx(v["currentRecoveryEd25519PublicKeyHex"]); mp=hx(v["currentRecoveryMlDsa65PublicKeyHex"])
    ev=vm(em,cose_ed(ep)); mv=vm(mm,cose_ml(mp)); rp=r_threshold(2,[(mm,mv),(em,ev)])
    check("R01 RecoveryPolicy independently reconstructed",rp==hx(v["currentRecoveryPolicyHex"]))
    rc=mh(rp); check("R01 current recovery commitment independently recomputed",rc==hx(v["currentRecoveryCommitmentHex"]))
    check("R01 previous IdentityState independently reconstructed",state(1,i,1,1,oc,rc)==ps)
    check("R01 previous StateHash independently recomputed",mh(ps)==ph)
    nm=hx(v["newControllerMethodIdHex"]); np=hx(v["newControllerPublicKeyHex"]); nc=single(vm(nm,cose_ed(np)))
    check("R01 replacement ControllerPolicy independently reconstructed",nc==hx(v["newControllerPolicyHex"]))
    nrp=hx(v["nextRecoveryPolicyHex"]); nrc=mh(nrp)
    check("R01 new recovery commitment independently recomputed",nrc==hx(v["newRecoveryCommitmentHex"]))
    check("R01 recovery commitment rotated",nrc!=rc)
    op=recover(i,2,ph,nc,rp,nrc); check("R01 RECOVER OperationBytes independently reconstructed",op==hx(v["operationBytesHex"]))
    ei=rin(op,em); mi=rin(op,mm)
    check("R01 Ed25519 recovery signing input reconstructed",ei==hx(v["recoveryEd25519SigningInputHex"]))
    check("R01 ML-DSA-65 recovery signing input reconstructed",mi==hx(v["recoveryMlDsa65SigningInputHex"]))
    es=hx(v["recoveryEd25519SignatureHex"]); ms=hx(v["recoveryMlDsa65SignatureHex"])
    check("R01 Ed25519 recovery signature cryptographically verifies",edv(ep,es,ei))
    check("R01 ML-DSA-65 recovery signature cryptographically verifies",mlv(mp,ms,mi))
    check("R01 recovery signature rejected in ordinary operation domain",not edv(ep,es,oin(op)))
    check("R01 recovery signature rejected in controller-proof domain",not edv(ep,es,cin(op,em)))
    er=proof(em,es); mr=proof(mm,ms)
    check("R01 Ed25519 recovery proof encoding",er==hx(v["recoveryEd25519ProofHex"]))
    check("R01 ML-DSA-65 recovery proof encoding",mr==hx(v["recoveryMlDsa65ProofHex"]))
    pi=cin(op,nm); psig=hx(v["newControllerPopSignatureHex"])
    check("R01 new-controller PoP signing input reconstructed",pi==hx(v["newControllerPopSigningInputHex"]))
    check("R01 new-controller PoP cryptographically verifies",edv(np,psig,pi))
    pp=proof(nm,psig); check("R01 new-controller proof encoding",pp==hx(v["newControllerProofHex"]))
    so=signed(op,[(nm,pp)],[(mm,mr),(em,er)])
    check("R01 SignedOperation independently reconstructed",so==hx(v["signedOperationHex"]))
    rs=state(1,i,2,1,nc,nrc); check("R01 resulting IdentityState independently reconstructed",rs==hx(v["resultingIdentityStateHex"]))
    rh=mh(rs); check("R01 resulting StateHash independently recomputed",rh==hx(v["resultingStateHashHex"]))
    check("R01 resulting state differs from predecessor",rh!=ph)
    print("\nR01 VERIFIED\n\n============================================\nOI-007 RECOVERY R01 VERIFIED\n============================================")
    return 0
# __main__ is defined after the RI01-RI10 verifier below.


# ---------------------------------------------------------------------------
# RI01-RI10 independent invalid/security verification
# ---------------------------------------------------------------------------

def read_uint(data, pos, ai):
    if ai < 24: return ai, pos
    if ai == 24: return data[pos], pos + 1
    if ai == 25: return int.from_bytes(data[pos:pos+2], "big"), pos + 2
    if ai == 26: return int.from_bytes(data[pos:pos+4], "big"), pos + 4
    if ai == 27: return int.from_bytes(data[pos:pos+8], "big"), pos + 8
    raise ValueError("indefinite/reserved CBOR length unsupported")

def decode_one(data, pos=0):
    ib = data[pos]; pos += 1
    major, ai = ib >> 5, ib & 31
    if major in (0,1):
        n,pos = read_uint(data,pos,ai)
        return (n if major == 0 else -1-n), pos
    if major in (2,3):
        n,pos = read_uint(data,pos,ai); raw=data[pos:pos+n]; pos += n
        return (raw if major == 2 else raw.decode("utf-8")), pos
    if major == 4:
        n,pos = read_uint(data,pos,ai); out=[]
        for _ in range(n):
            v,pos=decode_one(data,pos); out.append(v)
        return out,pos
    if major == 5:
        n,pos = read_uint(data,pos,ai); out={}
        for _ in range(n):
            k,pos=decode_one(data,pos); v,pos=decode_one(data,pos); out[k]=v
        return out,pos
    if major == 7 and ai == 22: return None,pos
    raise ValueError(f"unsupported CBOR major={major} ai={ai}")

def dec(data):
    obj,pos=decode_one(data,0)
    if pos != len(data): raise ValueError("trailing CBOR")
    return obj

def policy_methods(policy):
    # RecoveryPolicy: label 2 is type; SINGLE methods at 3, THRESHOLD methods at 4.
    typ=policy[2]
    return policy[3] if typ == 1 else policy[4]

def policy_threshold(policy):
    return 1 if policy[2] == 1 else policy[3]

def verify_recovery_invalid():
    root=Path(__file__).resolve().parents[2]
    p=root/"test-vectors"/"generated"/"recovery-invalid-java.json"
    if not p.exists():
        raise FileNotFoundError(p)
    d=json.loads(p.read_text(encoding="utf-8"))
    vs=d["vectors"]

    print("\nRI01-RI10 Invalid/Security Verification")
    print("--------------------------------------------")
    check("Invalid suite specification", d["specification"]=="OpenIdentity Recovery")
    check("Invalid suite version", d["version"]=="0.1")
    check("Invalid suite type", d["type"]=="invalid-conformance-vectors")
    check("Invalid suite wire protocol version", d["wireProtocolVersion"]==1)
    check("Invalid suite contains exactly 10 vectors", len(vs)==10)
    check("Invalid suite IDs RI01-RI10",
          [v["id"] for v in vs] == [f"RI{i:02d}" for i in range(1,11)])

    expected = [
        "RECOVERY_NOT_CONFIGURED",
        "INVALID_RECOVERY_POLICY",
        "INVALID_RECOVERY_THRESHOLD",
        "RECOVERY_THRESHOLD_NOT_SATISFIED",
        "DUPLICATE_RECOVERY_PROOF",
        "UNAUTHORIZED_RECOVERY_METHOD",
        "INVALID_RECOVERY_SIGNATURE",
        "MISSING_PROOF_OF_POSSESSION",
        "INVALID_RECOVERY_COMMITMENT",
        "INVALID_RECOVERY_SIGNATURE",
    ]
    for i,(v,e) in enumerate(zip(vs,expected),1):
        check(f"RI{i:02d} expected error label", v["expectedError"]==e)

    # RI01: predecessor state has no label 6 recoveryCommitment.
    v=vs[0]; st=dec(hx(v["previousIdentityStateHex"]))
    check("RI01 source IdentityState has no recoveryCommitment", 6 not in st)
    check("RI01 predecessor StateHash is authoritative",
          mh(hx(v["previousIdentityStateHex"])) == hx(v["previousStateHashHex"]))
    print("  RI01 REJECTED: RECOVERY_NOT_CONFIGURED")

    # RI02: operation reveals a valid policy whose commitment differs from state.
    v=vs[1]; st=dec(hx(v["previousIdentityStateHex"])); op=dec(hx(v["operationBytesHex"]))
    revealed=op[6][2]; committed=st[6]
    # Re-encode using raw operation slice source by deriving semantic policy from decoded form.
    methods=policy_methods(revealed)
    if revealed[2] != 1:
        raise AssertionError("RI02 expected SINGLE revealed policy")
    revealed_bytes = encode_cbor_value(revealed)
    check("RI02 revealed RecoveryPolicy commitment mismatches authoritative commitment",
          mh(revealed_bytes) != committed)
    print("  RI02 REJECTED: INVALID_RECOVERY_POLICY")

    # RI03: malformed threshold 3-of-2.
    v=vs[2]; op=dec(hx(v["operationBytesHex"])); rp=op[6][2]
    check("RI03 RecoveryPolicy type is THRESHOLD", rp[2]==2)
    check("RI03 threshold is 3", rp[3]==3)
    check("RI03 contains two RecoveryMethods", len(rp[4])==2)
    check("RI03 threshold exceeds method count", rp[3] > len(rp[4]))
    print("  RI03 REJECTED: INVALID_RECOVERY_THRESHOLD")

    # Common helper from valid-shaped invalid operations.
    def signed_parts(v):
        return dec(hx(v["signedOperationHex"]))
    def current_policy(v):
        st=dec(hx(v["previousIdentityStateHex"]))
        op=dec(hx(v["operationBytesHex"]))
        return st,op,op[6][2]

    # RI04: exactly one recovery proof for committed 2-of-2 policy.
    v=vs[3]; st,op,rp=current_policy(v); so=signed_parts(v)
    check("RI04 revealed policy matches authoritative commitment",
          mh(hx_policy(rp)) == st[6])
    check("RI04 historical recovery threshold is 2", policy_threshold(rp)==2)
    check("RI04 contains exactly one recovery proof", len(so[4])==1)
    check("RI04 one proof is below threshold", len({p[1] for p in so[4]}) < 2)
    print("  RI04 REJECTED: RECOVERY_THRESHOLD_NOT_SATISFIED")

    # RI05: duplicate proof method IDs.
    v=vs[4]; so=signed_parts(v); mids=[p[1] for p in so[4]]
    check("RI05 contains duplicate recovery proof method IDs", len(mids)!=len(set(mids)))
    print("  RI05 REJECTED: DUPLICATE_RECOVERY_PROOF")

    # RI06: at least one proof method absent from committed policy.
    v=vs[5]; st,op,rp=current_policy(v); so=signed_parts(v)
    authorized={m[1] for m in policy_methods(rp)}
    supplied={p[1] for p in so[4]}
    check("RI06 supplied recovery proof set contains unauthorized method",
          bool(supplied-authorized))
    check("RI06 declared unauthorized method is absent from RecoveryPolicy",
          hx(v["unauthorizedRecoveryMethodIdHex"]) not in authorized)
    print("  RI06 REJECTED: UNAUTHORIZED_RECOVERY_METHOD")

    # RI07: identify Ed proof and prove corrupted signature fails required domain.
    v=vs[6]; st,op,rp=current_policy(v); so=signed_parts(v)
    opb=hx(v["operationBytesHex"])
    methods={m[1]:m for m in policy_methods(rp)}
    edmid=next(mid for mid,m in methods.items() if m[2].get(3)==-8)
    edpk=methods[edmid][2][-2]
    edproof=next(p for p in so[4] if p[1]==edmid)
    check("RI07 corrupted authorized Ed25519 recovery signature is rejected",
          not edv(edpk,edproof[2],rin(opb,edmid)))
    print("  RI07 REJECTED: INVALID_RECOVERY_SIGNATURE")

    # RI08: field 3 is absent.
    v=vs[7]; so=signed_parts(v)
    check("RI08 recovery proof collection is present", 4 in so and len(so[4])==2)
    check("RI08 replacement-controller proof field is absent", 3 not in so)
    print("  RI08 REJECTED: MISSING_PROOF_OF_POSSESSION")

    # RI09: proposed next commitment exactly equals current state commitment.
    v=vs[8]; st,op,rp=current_policy(v)
    check("RI09 new recovery commitment equals current commitment",
          op[6][3] == st[6])
    print("  RI09 REJECTED: INVALID_RECOVERY_COMMITMENT")

    # RI10: signatures valid over ordinary domain, invalid over recovery domain.
    v=vs[9]; st,op,rp=current_policy(v); so=signed_parts(v)
    opb=hx(v["operationBytesHex"]); ordinary=oin(opb)
    methods={m[1]:m for m in policy_methods(rp)}
    edmid=next(mid for mid,m in methods.items() if m[2].get(3)==-8)
    mlmid=next(mid for mid,m in methods.items() if m[2].get(3)==-49)
    edpk=methods[edmid][2][-2]; mlpk=methods[mlmid][2][-1]
    proofs={p[1]:p[2] for p in so[4]}
    check("RI10 Ed25519 signature verifies over wrong ordinary-operation domain",
          edv(edpk,proofs[edmid],ordinary))
    check("RI10 ML-DSA-65 signature verifies over wrong ordinary-operation domain",
          mlv(mlpk,proofs[mlmid],ordinary))
    check("RI10 Ed25519 signature fails required recovery domain",
          not edv(edpk,proofs[edmid],rin(opb,edmid)))
    check("RI10 ML-DSA-65 signature fails required recovery domain",
          not mlv(mlpk,proofs[mlmid],rin(opb,mlmid)))
    print("  RI10 REJECTED: INVALID_RECOVERY_SIGNATURE")

    print("\nRI01-RI10 VERIFIED")
    print("\n============================================")
    print("OI-007 RECOVERY R01 + RI01-RI10 VERIFIED")
    print("============================================")


# Generic deterministic CBOR re-encoder used only to reconstruct decoded
# RecoveryPolicy objects independently.
def encode_cbor_value(v):
    if v is None: return b"\\xf6"
    if isinstance(v, int): return integer(v)
    if isinstance(v, bytes): return bstr(v)
    if isinstance(v, str): return tstr(v)
    if isinstance(v, list): return arr([encode_cbor_value(x) for x in v])
    if isinstance(v, dict):
        return det_map([(k,encode_cbor_value(val)) for k,val in v.items()])
    raise TypeError(type(v))

def hx_policy(decoded_policy):
    return encode_cbor_value(decoded_policy)



def verify_r02():
    root=Path(__file__).resolve().parents[2]
    p=root/"test-vectors"/"generated"/"recovery-r02-java.json"
    d=json.loads(p.read_text(encoding="utf-8"))
    v=d["vector"]

    print("\nR02 DEACTIVATED v2 Recovery")
    print("--------------------------------------------")
    check("R02 specification", d["specification"]=="OpenIdentity Recovery")
    check("R02 suite version", d["version"]=="0.1")
    check("R02 vector ID", v["id"]=="R02")
    check("R02 source state version is v2", v["sourceIdentityStateVersion"]==2)
    check("R02 resulting state version is v2", v["resultingIdentityStateVersion"]==2)
    check("R02 source status is DEACTIVATED", v["sourceStatus"]=="DEACTIVATED")
    check("R02 resulting status is ACTIVE", v["resultingStatus"]=="ACTIVE")
    check("R02 sequence increments 6 -> 7",
          v["sourceSequence"]==6 and v["sequence"]==7)

    identity=hx(v["identityHex"])
    old_controller=hx(v["previousControllerPolicyHex"])
    assertion=hx(v["preservedAssertionPolicyHex"])

    em=hx(v["currentRecoveryEd25519MethodIdHex"])
    mm=hx(v["currentRecoveryMlDsa65MethodIdHex"])
    ep=hx(v["currentRecoveryEd25519PublicKeyHex"])
    mp=hx(v["currentRecoveryMlDsa65PublicKeyHex"])

    ev=vm(em,cose_ed(ep))
    mv=vm(mm,cose_ml(mp))
    rp=r_threshold(2,[(mm,mv),(em,ev)])
    check("R02 RecoveryPolicy independently reconstructed",
          rp==hx(v["currentRecoveryPolicyHex"]))

    rc=mh(rp)
    check("R02 current recovery commitment independently recomputed",
          rc==hx(v["currentRecoveryCommitmentHex"]))

    predecessor=state(
        2, identity, 6, 2, old_controller, rc, assertion)
    check("R02 DEACTIVATED v2 predecessor independently reconstructed",
          predecessor==hx(v["previousIdentityStateHex"]))

    predecessor_hash=mh(predecessor)
    check("R02 predecessor StateHash independently recomputed",
          predecessor_hash==hx(v["previousStateHashHex"]))

    nm=hx(v["newControllerMethodIdHex"])
    np=hx(v["newControllerPublicKeyHex"])
    new_controller=single(vm(nm,cose_ed(np)))
    check("R02 replacement ControllerPolicy independently reconstructed",
          new_controller==hx(v["newControllerPolicyHex"]))

    next_policy=hx(v["nextRecoveryPolicyHex"])
    new_rc=mh(next_policy)
    check("R02 new recovery commitment independently recomputed",
          new_rc==hx(v["newRecoveryCommitmentHex"]))
    check("R02 recovery commitment rotated", new_rc!=rc)

    op=recover(identity,7,predecessor_hash,new_controller,rp,new_rc)
    check("R02 RECOVER OperationBytes independently reconstructed",
          op==hx(v["operationBytesHex"]))

    ei=rin(op,em); mi=rin(op,mm)
    check("R02 Ed25519 recovery signing input reconstructed",
          ei==hx(v["recoveryEd25519SigningInputHex"]))
    check("R02 ML-DSA-65 recovery signing input reconstructed",
          mi==hx(v["recoveryMlDsa65SigningInputHex"]))

    es=hx(v["recoveryEd25519SignatureHex"])
    ms=hx(v["recoveryMlDsa65SignatureHex"])
    check("R02 Ed25519 recovery signature cryptographically verifies",
          edv(ep,es,ei))
    check("R02 ML-DSA-65 recovery signature cryptographically verifies",
          mlv(mp,ms,mi))

    er=proof(em,es); mr=proof(mm,ms)
    check("R02 Ed25519 recovery proof encoding",
          er==hx(v["recoveryEd25519ProofHex"]))
    check("R02 ML-DSA-65 recovery proof encoding",
          mr==hx(v["recoveryMlDsa65ProofHex"]))

    pi=cin(op,nm); psig=hx(v["newControllerPopSignatureHex"])
    check("R02 replacement-controller PoP input reconstructed",
          pi==hx(v["newControllerPopSigningInputHex"]))
    check("R02 replacement-controller PoP cryptographically verifies",
          edv(np,psig,pi))
    pp=proof(nm,psig)
    check("R02 replacement-controller proof encoding",
          pp==hx(v["newControllerProofHex"]))

    so=signed(op,[(nm,pp)],[(mm,mr),(em,er)])
    check("R02 SignedOperation independently reconstructed",
          so==hx(v["signedOperationHex"]))
    check("R02 ordinary authorization proofs absent",
          v["ordinaryAuthorizationProofCount"]==0)

    result=state(
        2,identity,7,1,new_controller,new_rc,assertion)
    check("R02 resulting ACTIVE v2 state independently reconstructed",
          result==hx(v["resultingIdentityStateHex"]))

    result_hash=mh(result)
    check("R02 resulting StateHash independently recomputed",
          result_hash==hx(v["resultingStateHashHex"]))
    check("R02 resulting StateHash differs from DEACTIVATED predecessor",
          result_hash!=predecessor_hash)

    # Inspect both canonical states and prove field 7 is byte-semantically
    # identical before/after, while status changes 2 -> 1.
    before=dec(predecessor)
    after=dec(result)
    check("R02 identity preserved", before[2]==after[2]==identity)
    check("R02 state version preserved", before[1]==after[1]==2)
    check("R02 status changes DEACTIVATED -> ACTIVE",
          before[4]==2 and after[4]==1)
    check("R02 AssertionPolicy preserved exactly",
          before[7]==after[7] and encode_cbor_value(before[7])==assertion)
    check("R02 ControllerPolicy replaced", before[5]!=after[5])
    check("R02 recoveryCommitment replaced", before[6]!=after[6])

    print("\nR02 VERIFIED")
    return 0



def verify_normative_bundle():
    root = Path(__file__).resolve().parents[2]
    bundle_path = root / "test-vectors" / "recovery-v0.1.json"
    checksum_path = root / "test-vectors" / "recovery-v0.1.json.sha256"

    print("\nNormative Recovery Bundle")
    print("--------------------------------------------")

    raw = bundle_path.read_bytes()
    d = json.loads(raw.decode("utf-8"))

    check("Normative specification",
          d["specification"] == "OpenIdentity Recovery")
    check("Normative suite version", d["version"] == "0.1")
    check("Normative wire protocol version",
          d["wireProtocolVersion"] == 1)
    check("Normative RecoveryPolicy version",
          d["recoveryPolicyVersion"] == 1)
    check("Normative recovery signing domain",
          d["recoverySigningDomain"] == "OpenIdentity Recovery")
    check("Normative controller PoP signing domain",
          d["controllerProofSigningDomain"] ==
          "OpenIdentity Controller Proof")

    commitment = d["recoveryCommitment"]
    check("Normative recovery commitment algorithm",
          commitment["multihashAlgorithm"] == "sha2-256")
    check("Normative recovery commitment multihash code",
          commitment["multihashCode"] == 18)
    check("Normative recovery commitment digest length",
          commitment["digestLength"] == 32)
    check("Normative recovery commitment total length",
          commitment["multihashLength"] == 34)
    check("Normative recovery commitment object",
          commitment["committedObject"] ==
          "deterministic CBOR RecoveryPolicyBytes")

    valid = d["validVectors"]
    invalid = d["invalidVectors"]

    check("Normative bundle contains exactly 2 valid vectors",
          len(valid) == 2)
    check("Normative valid vector IDs R01-R02",
          [v["id"] for v in valid] == ["R01", "R02"])
    check("Normative bundle contains exactly 10 invalid vectors",
          len(invalid) == 10)
    check("Normative invalid vector IDs RI01-RI10",
          [v["id"] for v in invalid] ==
          [f"RI{i:02d}" for i in range(1, 11)])

    expected_errors = [
        "RECOVERY_NOT_CONFIGURED",
        "INVALID_RECOVERY_POLICY",
        "INVALID_RECOVERY_THRESHOLD",
        "RECOVERY_THRESHOLD_NOT_SATISFIED",
        "DUPLICATE_RECOVERY_PROOF",
        "UNAUTHORIZED_RECOVERY_METHOD",
        "INVALID_RECOVERY_SIGNATURE",
        "MISSING_PROOF_OF_POSSESSION",
        "INVALID_RECOVERY_COMMITMENT",
        "INVALID_RECOVERY_SIGNATURE",
    ]
    check("Normative RI01-RI10 error labels",
          [v["expectedError"] for v in invalid] == expected_errors)

    # Prove consolidation preserved the exact generated vector objects.
    gen = root / "test-vectors" / "generated"
    r01_doc = json.loads(
        (gen / "recovery-r01-java.json").read_text(encoding="utf-8"))
    r02_doc = json.loads(
        (gen / "recovery-r02-java.json").read_text(encoding="utf-8"))
    invalid_doc = json.loads(
        (gen / "recovery-invalid-java.json").read_text(encoding="utf-8"))

    check("Normative R01 exactly equals generated R01",
          valid[0] == r01_doc["vector"])
    check("Normative R02 exactly equals generated R02",
          valid[1] == r02_doc["vector"])
    check("Normative RI01-RI10 exactly equal generated invalid suite",
          invalid == invalid_doc["vectors"])

    # Independently verify the checksum file against exact normative JSON bytes.
    checksum_line = checksum_path.read_text(encoding="utf-8").strip()
    parts = checksum_line.split()
    check("Normative checksum file names recovery-v0.1.json",
          len(parts) >= 2 and parts[-1] == "recovery-v0.1.json")
    expected_digest = parts[0].lower()
    actual_digest = hashlib.sha256(raw).hexdigest()
    check("Normative SHA-256 independently verifies",
          actual_digest == expected_digest)
    check("Normative SHA-256 matches frozen candidate",
          actual_digest ==
          "9d94283d536623f26863d611e19b58cd11d16746c54e2d75df2ac5820bba2b35")

    # Independently reconstruct the positive vectors directly from the
    # consolidated objects, so verification does not rely only on equality
    # with intermediate files.
    r01 = valid[0]
    i = hx(r01["identityHex"])
    old_cp = hx(r01["previousControllerPolicyHex"])
    em = hx(r01["currentRecoveryEd25519MethodIdHex"])
    mm = hx(r01["currentRecoveryMlDsa65MethodIdHex"])
    ep = hx(r01["currentRecoveryEd25519PublicKeyHex"])
    mp = hx(r01["currentRecoveryMlDsa65PublicKeyHex"])
    rp = r_threshold(
        2,
        [(mm, vm(mm, cose_ml(mp))),
         (em, vm(em, cose_ed(ep)))])
    rc = mh(rp)
    previous = state(1, i, 1, 1, old_cp, rc)
    previous_hash = mh(previous)
    nm = hx(r01["newControllerMethodIdHex"])
    np = hx(r01["newControllerPublicKeyHex"])
    new_cp = single(vm(nm, cose_ed(np)))
    new_rc = mh(hx(r01["nextRecoveryPolicyHex"]))
    op = recover(i, 2, previous_hash, new_cp, rp, new_rc)

    check("Normative R01 predecessor independently reconstructed",
          previous == hx(r01["previousIdentityStateHex"]))
    check("Normative R01 OperationBytes independently reconstructed",
          op == hx(r01["operationBytesHex"]))
    check("Normative R01 resulting state independently reconstructed",
          state(1, i, 2, 1, new_cp, new_rc) ==
          hx(r01["resultingIdentityStateHex"]))

    r02 = valid[1]
    i2 = hx(r02["identityHex"])
    old_cp2 = hx(r02["previousControllerPolicyHex"])
    assertion = hx(r02["preservedAssertionPolicyHex"])
    em2 = hx(r02["currentRecoveryEd25519MethodIdHex"])
    mm2 = hx(r02["currentRecoveryMlDsa65MethodIdHex"])
    ep2 = hx(r02["currentRecoveryEd25519PublicKeyHex"])
    mp2 = hx(r02["currentRecoveryMlDsa65PublicKeyHex"])
    rp2 = r_threshold(
        2,
        [(mm2, vm(mm2, cose_ml(mp2))),
         (em2, vm(em2, cose_ed(ep2)))])
    rc2 = mh(rp2)
    previous2 = state(2, i2, 6, 2, old_cp2, rc2, assertion)
    ph2 = mh(previous2)
    nm2 = hx(r02["newControllerMethodIdHex"])
    np2 = hx(r02["newControllerPublicKeyHex"])
    new_cp2 = single(vm(nm2, cose_ed(np2)))
    new_rc2 = mh(hx(r02["nextRecoveryPolicyHex"]))
    op2 = recover(i2, 7, ph2, new_cp2, rp2, new_rc2)
    result2 = state(2, i2, 7, 1, new_cp2, new_rc2, assertion)

    check("Normative R02 DEACTIVATED predecessor independently reconstructed",
          previous2 == hx(r02["previousIdentityStateHex"]))
    check("Normative R02 OperationBytes independently reconstructed",
          op2 == hx(r02["operationBytesHex"]))
    check("Normative R02 ACTIVE result independently reconstructed",
          result2 == hx(r02["resultingIdentityStateHex"]))
    check("Normative R02 AssertionPolicy preserved",
          dec(previous2)[7] == dec(result2)[7])

    print("\nrecovery-v0.1.json: VERIFIED")
    print("SHA-256:", actual_digest)
    return 0


if __name__=="__main__":
    try:
        rc=verify_r01()
        if rc not in (0,None): raise SystemExit(rc)
        verify_recovery_invalid()
        rc=verify_r02()
        if rc not in (0,None): raise SystemExit(rc)
        rc=verify_normative_bundle()
        if rc not in (0,None): raise SystemExit(rc)
        print("\n============================================")
        print("OI-007 RECOVERY R01-R02 + RI01-RI10 + NORMATIVE BUNDLE VERIFIED")
        print("============================================")
        raise SystemExit(0)
    except AssertionError:
        raise SystemExit(1)
