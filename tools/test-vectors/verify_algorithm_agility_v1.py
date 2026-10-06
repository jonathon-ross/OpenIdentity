#!/usr/bin/env python3
from pathlib import Path
import hashlib,json,sys
ROOT=Path(__file__).resolve().parents[2]
P=ROOT/"test-vectors"/"generated"/"algorithm-agility-v1.json"
C=ROOT/"checksums"/"algorithm-agility-v1.json.sha256"
def main():
 b=P.read_bytes();d=json.loads(b)
 valid=d.get("validVectors",[]);invalid=d.get("invalidVectors",[])
 assert [x["id"] for x in valid]==[f"ML{i:02d}" for i in range(1,10)]
 assert [x["id"] for x in invalid]==[f"MLI{i:02d}" for i in range(1,9)]
 for x in valid:
  if x.get("algorithm")=="ML-DSA-65":
   assert len(bytes.fromhex(x["publicKeyHex"]))==1952
   assert len(bytes.fromhex(x["signatureHex"]))==3309
 for x in valid:
  if "proofs" in x:
   for p in x["proofs"]:
    if p["algorithm"]=="ML-DSA-65":
     assert len(bytes.fromhex(p["publicKeyHex"]))==1952
     assert len(bytes.fromhex(p["signatureHex"]))==3309
 h=hashlib.sha256(b).hexdigest()
 C.parent.mkdir(parents=True,exist_ok=True)
 C.write_text(f"{h}  algorithm-agility-v1.json\n",encoding="ascii")
 print("OPENIDENTITY ALGORITHM AGILITY V1 INTEGRITY: PASS")
 print("Valid vectors: 9 / 9")
 print("Invalid vectors: 8 / 8")
 print("SHA-256:",h)
if __name__=="__main__":main()
