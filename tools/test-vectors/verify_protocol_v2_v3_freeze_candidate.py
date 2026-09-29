#!/usr/bin/env python3
"""Verify the exact byte-frozen Protocol v2 / IdentityState v3 candidate."""
from __future__ import annotations
import hashlib
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
BUNDLE=ROOT/"test-vectors"/"generated"/"protocol-v2-identity-state-v3.json"
CHECKSUM=ROOT/"test-vectors"/"generated"/"protocol-v2-identity-state-v3.json.sha256"

if not CHECKSUM.exists():
    raise SystemExit("Missing v3 freeze-candidate checksum: "+str(CHECKSUM))

line=CHECKSUM.read_text(encoding="ascii").strip()
parts=line.split()
if len(parts)!=2 or parts[1]!=BUNDLE.name:
    raise SystemExit("Invalid v3 checksum file format or filename")

expected=parts[0].lower()
actual=hashlib.sha256(BUNDLE.read_bytes()).hexdigest()
if expected!=actual:
    raise SystemExit(f"V3 FREEZE-CANDIDATE CHECKSUM FAIL\nexpected {expected}\nactual   {actual}")

print("Protocol v2 / IdentityState v3 freeze candidate")
print("Exact bundle bytes: PASS")
print("Checksum filename: PASS")
print("SHA-256:",actual)
print("V3 BYTE-FROZEN CANDIDATE: VERIFIED")
