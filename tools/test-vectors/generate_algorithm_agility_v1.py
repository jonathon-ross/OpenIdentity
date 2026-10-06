#!/usr/bin/env python3
"""Generate the OpenIdentity ML-DSA-65 algorithm-agility vector manifest.

This file deliberately freezes OpenIdentity semantics before binding the suite to
one Java or Rust crypto provider.  Raw FIPS-204 public keys/signatures are filled
by the provider-independent fixture step; signing bytes are deterministic
OpenIdentity CBOR and MUST agree across implementations.
"""
from __future__ import annotations
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
OUTPUT=ROOT/"test-vectors"/"generated"/"algorithm-agility-v1.json"

VALID=[
 ("ML01","Ed25519 SINGLE controller authorization"),
 ("ML02","ML-DSA-65 SINGLE controller authorization"),
 ("ML03","mixed Ed25519 + ML-DSA-65 threshold 2-of-2"),
 ("ML04","mixed Ed25519 + ML-DSA-65 threshold 1-of-2"),
 ("ML05","ML-DSA-65 Controller proof of possession"),
 ("ML06","ML-DSA-65 Recovery authorization"),
 ("ML07","ML-DSA-65 Authentication proof of possession"),
 ("ML08","ML-DSA-65 Assertion proof of possession"),
 ("ML09","ML-DSA-65 Delegation proof of possession"),
]
INVALID=[
 ("MLI01","INVALID_SIGNATURE","wrong ML-DSA-65 signature"),
 ("MLI02","INVALID_PROOF_OF_POSSESSION","wrong signing domain"),
 ("MLI03","UNAUTHORIZED_METHOD","wrong VerificationMethod ID"),
 ("MLI04","INVALID_SIGNATURE","truncated ML-DSA-65 signature"),
 ("MLI05","MALFORMED_COSE_KEY","malformed ML-DSA-65 public key length"),
 ("MLI06","INSUFFICIENT_THRESHOLD","mixed threshold not satisfied"),
 ("MLI07","DUPLICATE_EFFECTIVE_VERIFICATION_KEY","duplicate ML-DSA-65 key under distinct IDs"),
 ("MLI08","ALGORITHM_KEY_MISMATCH","COSE algorithm/key mismatch"),
]
def main():
 data={
  "specification":"OpenIdentity cryptographic agility v1",
  "status":"DRAFT-NON-NORMATIVE",
  "normativeCrypto":"FIPS 204 ML-DSA-65",
  "mlDsa65":{"publicKeyBytes":1952,"signatureBytes":3309},
  "generationProfile":{
    "seedBytes":32,
    "seedDerivation":"SHA-256(UTF-8('OpenIdentity agility-v1 ' || vector-id || ' ' || role))",
    "privateMaterialPersisted":False,
    "note":"Provider fixture step MUST emit raw FIPS-204 public keys and raw signatures only."
  },
  "validVectors":[{"id":i,"expected":"PASS","purpose":d} for i,d in VALID],
  "invalidVectors":[{"id":i,"expected":"REJECT","expectedError":e,"attack":d} for i,e,d in INVALID],
 }
 OUTPUT.parent.mkdir(parents=True,exist_ok=True)
 OUTPUT.write_text(json.dumps(data,indent=2)+"\n",encoding="utf-8")
 print("OPENIDENTITY ALGORITHM AGILITY MANIFEST: GENERATED")
 print("Valid:",len(VALID),"Invalid:",len(INVALID))
 print(OUTPUT)
if __name__=="__main__":main()
