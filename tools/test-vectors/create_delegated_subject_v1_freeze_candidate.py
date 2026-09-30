#!/usr/bin/env python3
"""Create OI-016 Delegated Subject Token v1 byte-freeze candidate checksum."""
from __future__ import annotations
import hashlib,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
BUNDLE=ROOT/"test-vectors"/"generated"/"delegated-subject-v1.json"
CHECKSUM=ROOT/"checksums"/"delegated-subject-v1.json.sha256"
def main():
    p=subprocess.run([sys.executable,"tools/test-vectors/generate_delegated_subject_v1.py"],cwd=ROOT)
    if p.returncode:raise SystemExit(p.returncode)
    data=BUNDLE.read_bytes();digest=hashlib.sha256(data).hexdigest()
    CHECKSUM.parent.mkdir(parents=True,exist_ok=True)
    CHECKSUM.write_text(f"{digest}  delegated-subject-v1.json\n",encoding="ascii",newline="\n")
    print("OI-016 Delegated Subject Token v1 freeze candidate")
    print("Bytes:",len(data));print("SHA-256:",digest)
    print("Wrote:",CHECKSUM.relative_to(ROOT))
    print("STATUS: BYTE-FROZEN CANDIDATE; NOT YET NORMATIVE")
if __name__=="__main__":main()
