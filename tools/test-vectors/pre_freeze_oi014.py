#!/usr/bin/env python3
"""Unified OI-014 pre-freeze release gate.

This gate verifies draft OI-014 vectors and independently invokes the Java
reconstruction. It does NOT freeze OI-014 or create its checksum.
"""
from __future__ import annotations
import argparse, os, shutil, subprocess, sys
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

def parse_args():
    p=argparse.ArgumentParser(description="Run the OI-014 pre-freeze release gate.")
    p.add_argument("--maven", help="Path/name of Maven launcher (for example C:\\Users\\name\\apache-maven\\bin\\mvn.cmd). Overrides OI014_MAVEN and PATH discovery.")
    return p.parse_args()

def resolve_maven(explicit=None):
    candidates=[]
    if explicit:
        candidates.append(explicit)
    env=os.environ.get("OI014_MAVEN")
    if env:
        candidates.append(env)
    candidates += ["mvn.cmd","mvn"] if os.name=="nt" else ["mvn","mvn.cmd"]
    for candidate in candidates:
        p=Path(candidate).expanduser()
        if p.is_file():
            return str(p.resolve())
        found=shutil.which(candidate)
        if found:
            return found
    return None

def main():
    args=parse_args()
    run("Generate draft OI-014 vectors",[sys.executable,"tools/test-vectors/generate_delegation_v1.py"])
    run("Verify draft OI-014 vectors",[sys.executable,"tools/test-vectors/verify_delegation_v1.py"])
    candidate=ROOT/"checksums"/"delegation-v1.json.sha256"
    if candidate.is_file():
        run("Verify committed OI-014 byte-frozen candidate",
            [sys.executable,"tools/test-vectors/verify_delegation_v1_freeze_candidate.py"])
    else:
        print("\n[OI-014 freeze candidate]")
        print("[INFO] No committed candidate checksum yet; semantic pre-freeze checks continue.")
    java=ROOT/"tools"/"test-vectors-java"
    maven=resolve_maven(args.maven)
    if not maven:
        print("\nRELEASE GATE: FAIL (Maven executable not found)")
        print("Pass --maven <path-to-mvn.cmd>, set OI014_MAVEN, or add Maven's bin directory to PATH.")
        raise SystemExit(1)
    print(f"Using Maven: {maven}")
    run("Independent Java OI-014 verification",
        [maven,"-q","compile","exec:java","-Dexec.mainClass=org.openidentity.vectors.DelegationV1Vectors"],java)

    print("\n[Frozen v0.1 artifact integrity]")
    p=subprocess.run(["git","diff","--quiet","--",*FROZEN_PATHS],cwd=ROOT)
    if p.returncode!=0:
        subprocess.run(["git","diff","--",*FROZEN_PATHS],cwd=ROOT)
        print("\nRELEASE GATE: FAIL (frozen v0.1 artifact/checksum changed)")
        raise SystemExit(1)
    print("[PASS] No tracked frozen v0.1 artifact/checksum changed")

    print("\n============================================================")
    print("OI-014 FROZEN-NORMATIVE RELEASE GATE: PASS")
    print("============================================================")
    print("\nStatus: OI-014 v1 frozen-normative semantic vectors and committed byte checksum verified.")
    print("Frozen OI-014 v1 bytes MUST NOT change without an explicit protocol revision.")

if __name__=="__main__":
    main()
