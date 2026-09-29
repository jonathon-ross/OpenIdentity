#!/usr/bin/env python3
"""Create the byte-level SHA-256 freeze candidate for Protocol v2 / IdentityState v3.

This does not make the draft normative. It pins the exact generated bundle
that has passed the pre-freeze interoperability gates.
"""
from __future__ import annotations
import hashlib
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
BUNDLE=ROOT/"test-vectors"/"generated"/"protocol-v2-identity-state-v3.json"
CHECKSUM=ROOT/"test-vectors"/"generated"/"protocol-v2-identity-state-v3.json.sha256"

raw=BUNDLE.read_bytes()
digest=hashlib.sha256(raw).hexdigest()
CHECKSUM.write_text(f"{digest}  {BUNDLE.name}\n",encoding="ascii",newline="\n")
print("Protocol v2 / IdentityState v3 freeze candidate")
print(f"Bytes: {len(raw)}")
print(f"SHA-256: {digest}")
print(f"Wrote: {CHECKSUM.relative_to(ROOT)}")
print("STATUS: BYTE-FROZEN CANDIDATE; NOT YET NORMATIVE")
