#!/usr/bin/env python3
import argparse, hashlib, pathlib, sys

ROOT=pathlib.Path(__file__).resolve().parents[1]
FILES=[
 "spec/cddl/openidentity-external-oidc-binding-v1.cddl",
 "spec/cddl/openidentity-external-oidc-binding-context-v1.cddl",
 "spec/external-oidc-binding-v1-pre-freeze-conformance.md",
 "test-vectors/external-oidc-binding-v1.json",
]
MANIFEST=ROOT/"test-vectors"/"external-oidc-binding-v1.sha256"

def digest(rel):
 p=ROOT/rel
 if not p.is_file(): raise SystemExit("missing artifact: "+rel)
 return hashlib.sha256(p.read_bytes()).hexdigest()

def expected_lines():
 return [digest(p)+"  "+p for p in FILES]

def generate():
 text="\n".join(expected_lines())+"\n"
 MANIFEST.write_text(text,encoding="ascii",newline="\n")
 print(text,end="")

def verify():
 if not MANIFEST.is_file(): raise SystemExit("missing manifest: "+str(MANIFEST.relative_to(ROOT)))
 raw=MANIFEST.read_text(encoding="ascii").splitlines()
 if len(raw)!=len(FILES): raise SystemExit("manifest entry count mismatch")
 parsed={}
 for line in raw:
  parts=line.split("  ",1)
  if len(parts)!=2 or len(parts[0])!=64: raise SystemExit("malformed manifest line: "+line)
  h,p=parts
  if p in parsed: raise SystemExit("duplicate manifest entry: "+p)
  parsed[p]=h
 if set(parsed)!=set(FILES):
  raise SystemExit("manifest file set mismatch")
 for p in FILES:
  actual=digest(p); expected=parsed[p]
  if actual!=expected: raise SystemExit("FAIL "+p+" expected="+expected+" actual="+actual)
  print("PASS",p,actual)
 print("EXTERNAL OIDC PRE-FREEZE CHECKSUMS VERIFIED")

ap=argparse.ArgumentParser()
ap.add_argument("--generate",action="store_true")
args=ap.parse_args()
if args.generate: generate()
else: verify()
