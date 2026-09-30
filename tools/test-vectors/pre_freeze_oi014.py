#!/usr/bin/env python3
"""Unified OI-014 pre-freeze release gate.

This gate verifies draft OI-014 vectors and independently invokes the Java
reconstruction. It does NOT freeze OI-014 or create its checksum.
"""
from __future__ import annotations
import subprocess, sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]

FROZEN_PATHS=[
 "test-vectors/assertion-authority-v0.1.json","test-vectors/assertion-authority-v0.1.json.sha256",
 "test-vectors/credential-v0.1.json","test-vectors/credential-v0.1.json.sha256",
 "test-vectors/cryptographic-agility-v0.1.json","test-vectors/cryptographic-agility-v0.1.json.sha256",
 "test-vectors/identity-id-v0.1.json","test-vectors/identity-id-v0.1.json.sha256",
 "test-vectors/recovery-v0.1.json","test-vectors/recovery-v0.1.json.sha256",
 "test-vectors/signature-envelope-v0.1.json","test-vectors/signature-envelope-v0.1.json.sha256",
 "test-vectors/state-hash-v0.1.json","test-vectors/state-hash-v0.1.json.sha256",
 "test-vectors/w3c-credential-projection-v0.1.json","test-vectors/w3c-credential-projection-v0.1.json.sha256",
 "test-vectors/w3c-projection-v0.1.json",
 "checksums/w3c-identity-projection-v0.1.sha256",
]

def run(label,cmd,cwd=ROOT):
    print(f"\n[{label}]")
    p=subprocess.run(cmd,cwd=cwd)
    if p.returncode:
        print(f"\nRELEASE GATE: FAIL ({label})")
        raise SystemExit(p.returncode)
    print(f"[PASS] {label}")

def main():
    run("Generate draft OI-014 vectors",[sys.executable,"tools/test-vectors/generate_delegation_v1.py"])
    run("Verify draft OI-014 vectors",[sys.executable,"tools/test-vectors/verify_delegation_v1.py"])
    java=ROOT/"tools"/"test-vectors-java"
    run("Independent Java OI-014 verification",
        ["mvn","-q","compile","exec:java","-Dexec.mainClass=org.openidentity.vectors.DelegationV1Vectors"],java)

    print("\n[Frozen v0.1 artifact integrity]")
    p=subprocess.run(["git","diff","--quiet","--",*FROZEN_PATHS],cwd=ROOT)
    if p.returncode!=0:
        subprocess.run(["git","diff","--","--",*FROZEN_PATHS],cwd=ROOT)
        print("\nRELEASE GATE: FAIL (frozen v0.1 artifact/checksum changed)")
        raise SystemExit(1)
    print("[PASS] No tracked frozen v0.1 artifact/checksum changed")

    print("\n============================================================")
    print("OI-014 PRE-FREEZE RELEASE GATE: PASS")
    print("============================================================")
    print("\nStatus: draft vectors verified; NOT byte-frozen.")
    print("Next: inspect git status/diff, then create a freeze candidate only if intentional.")

if __name__=="__main__":
    main()
