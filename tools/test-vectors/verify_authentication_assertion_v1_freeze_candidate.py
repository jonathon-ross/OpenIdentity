#!/usr/bin/env python3
"""Verify OI-015 Authentication Assertion v1 byte-freeze candidate."""
from __future__ import annotations
import hashlib,re,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
BUNDLE=ROOT/"test-vectors"/"generated"/"authentication-assertion-v1.json"
CHECKSUM=ROOT/"checksums"/"authentication-assertion-v1.json.sha256"
LINE=re.compile(r"^([0-9a-f]{64})  authentication-assertion-v1\.json\n$")
def main():
    if not CHECKSUM.is_file():raise SystemExit("OI-015 FREEZE-CANDIDATE CHECKSUM MISSING")
    m=LINE.fullmatch(CHECKSUM.read_text(encoding="ascii"))
    if not m:raise SystemExit("OI-015 FREEZE-CANDIDATE CHECKSUM FORMAT FAIL")
    p=subprocess.run([sys.executable,"tools/test-vectors/generate_authentication_assertion_v1.py"],cwd=ROOT)
    if p.returncode:raise SystemExit(p.returncode)
    data=BUNDLE.read_bytes();actual=hashlib.sha256(data).hexdigest();expected=m.group(1)
    if actual!=expected:
        print("OI-015 FREEZE-CANDIDATE CHECKSUM FAIL");print("expected",expected);print("actual  ",actual);raise SystemExit(1)
    print("OI-015 Authentication Assertion v1 freeze candidate")
    print("Exact regenerated bundle bytes: PASS");print("Checksum filename: PASS")
    print("Bytes:",len(data));print("SHA-256:",actual)
    print("OI-015 V1 BYTE-FROZEN CANDIDATE: VERIFIED")
    print("STATUS: NOT YET NORMATIVE")
if __name__=="__main__":main()
