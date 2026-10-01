#!/usr/bin/env python3
from pathlib import Path
import hashlib,sys
ROOT=Path(__file__).resolve().parents[1]
FILES=[
"spec/cddl/openidentity-external-ad-binding-v1.cddl",
"spec/cddl/openidentity-external-ad-binding-context-v1.cddl",
"spec/external-ad-binding-v1-errors.md",
"spec/external-ad-binding-v1-pre-freeze-conformance.md",
"test-vectors/external-ad-binding-v1-pre-freeze.json",
"test-vectors/external-ad-binding-v1-crypto-pre-freeze.json",
]
manifest=ROOT/"test-vectors/external-ad-binding-v1-pre-freeze.sha256"
def lines():
 return [f"{hashlib.sha256((ROOT/p).read_bytes()).hexdigest()}  {p}" for p in FILES]
if "--generate" in sys.argv:
 manifest.write_text("\n".join(lines())+"\n");print("AD PRE-FREEZE CHECKSUMS GENERATED");raise SystemExit
if not manifest.exists():print("AD PRE-FREEZE CHECKSUMS: FAIL (manifest missing)");raise SystemExit(1)
expected=manifest.read_text().splitlines();actual=lines()
if expected!=actual:
 print("AD PRE-FREEZE CHECKSUMS: FAIL")
 for e,a in zip(expected,actual):
  if e!=a:print(" expected:",e);print(" actual:  ",a)
 raise SystemExit(1)
print("AD PRE-FREEZE CHECKSUMS VERIFIED")
