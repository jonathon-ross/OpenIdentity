#!/usr/bin/env python3
"""Generate draft OI-014 DG01 deterministic conformance vector."""
from __future__ import annotations
import hashlib, json
from pathlib import Path
import cbor2
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT=Path(__file__).resolve().parents[2]
OUT=ROOT/"test-vectors"/"generated"/"delegation-v1.json"

def h(b): return hashlib.sha256(b).digest()
def mh(b): return b"\x12\x20"+h(b)
def enc(x): return cbor2.dumps(x,canonical=True)
def seed(label): return h(label.encode())
def key(label,method_id):
    priv=Ed25519PrivateKey.from_private_bytes(seed(label))
    pub=priv.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
    method={1:1,3:-8,4:-1,6:pub}
    return priv,method_id,method
def policy(method_id,method): return {1:1,2:[{1:method_id,2:method}]}

def main():
    registry=b"openidentity:test:oi014:dg01"
    root=bytes(range(32))
    delegate=bytes(range(32,64))
    method_id=bytes(range(16))
    priv,_,method=key("OpenIdentity OI-014 DG01 delegation Ed25519 seed",method_id)
    dp=policy(method_id,method)

    # Minimal deterministic capability profile descriptor for DG01.
    # Candidate descriptor labels are vector-local until profile descriptor CDDL freezes.
    descriptor={1:1,2:"openidentity.test.exact-capability",3:1,
                4:[b"document.read"],5:3600,6:4}
    profile_bytes=enc(descriptor); profile_hash=mh(profile_bytes)
    profile_ref={1:1,2:profile_hash}
    capability_ref={1:profile_ref,2:b"document.read"}
    delegated_cap={1:capability_ref}

    issuer={1:1,2:root}
    delegate_principal={1:1,2:delegate}
    grant={1:1,2:root,3:issuer,4:delegate_principal,5:[delegated_cap],
           7:2000003600,9:seed("OpenIdentity OI-014 DG01 nonce")}
    grant_bytes=enc(grant); grant_id=mh(grant_bytes)

    # Synthetic but exact current IdentityState v3 used only as DG01 predecessor context.
    current_state={1:3,2:root,3:7,4:1,5:dp,8:{1:0},9:{1:4,2:dp}}
    state_bytes=enc(current_state); state_hash=mh(state_bytes)
    generation=4

    signing=enc(["OpenIdentity Delegation Grant",1,registry,grant_bytes,state_hash,generation,method_id])
    sig=priv.sign(signing)
    request={1:registry,2:grant,3:state_hash,4:generation,5:[{1:method_id,2:sig}]}
    registered_at=2000000000
    record={1:registry,2:grant_id,3:1,4:None,5:1,6:state_hash,7:generation,8:registered_at}
    record_bytes=enc(record); record_hash=mh(record_bytes)

    vector={"suite":"OpenIdentity OI-014 DelegationGrant v1","status":"DRAFT-NON-NORMATIVE",
      "vectors":[{"id":"DG01","description":"Direct grant registration with single Ed25519 DelegationPolicy and OPENIDENTITY delegate","expected":"PASS",
      "profileDescriptorBytesHex":profile_bytes.hex(),"profileHashHex":profile_hash.hex(),
      "currentStateBytesHex":state_bytes.hex(),"currentStateHashHex":state_hash.hex(),
      "grantBytesHex":grant_bytes.hex(),"grantIdHex":grant_id.hex(),
      "registrationSigningBytesHex":signing.hex(),"registrationSignatureHex":sig.hex(),
      "registrationRequestBytesHex":enc(request).hex(),"registeredAt":registered_at,
      "recordBytesHex":record_bytes.hex(),"recordHashHex":record_hash.hex()}]}
    OUT.parent.mkdir(parents=True,exist_ok=True)
    OUT.write_text(json.dumps(vector,indent=2)+"\n",encoding="utf-8")
    print("Wrote",OUT.relative_to(ROOT))
    print("DG01 VERIFIED")
if __name__=="__main__": main()
