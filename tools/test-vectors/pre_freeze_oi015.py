#!/usr/bin/env python3
"""Frozen-normative release gate for OI-015 Authentication Assertion v1.

Regenerates and verifies OI-015, invokes the independent Java verifier, and
protects previously frozen OpenIdentity commitments. This gate does NOT create
an OI-015 checksum or make OI-015 normative.
"""
from __future__ import annotations
import argparse, os, shutil, subprocess, sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]

PROTECTED=[
 "checksums/protocol-v2-identity-state-v3.json.sha256",
 "checksums/delegation-v1.json.sha256",
 "test-vectors/assertion-authority-v0.1.json","test-vectors/assertion-authority-v0.1.json.sha256",
 "test-vectors/credential-v0.1.json","test-vectors/credential-v0.1.json.sha256",
 "test-vectors/cryptographic-agility-v0.1.json","test-vectors/cryptographic-agility-v0.1.json.sha256",
 "test-vectors/identity-id-v0.1.json","test-vectors/identity-id-v0.1.json.sha256",
 "test-vectors/recovery-v0.1.json","test-vectors/recovery-v0.1.json.sha256",
 "test-vectors/signature-envelope-v0.1.json","test-vectors/signature-envelope-v0.1.json.sha256",
 "test-vectors/state-hash-v0.1.json","test-vectors/state-hash-v0.1.json.sha256",
 "test-vectors/w3c-credential-projection-v0.1.json","test-vectors/w3c-credential-projection-v0.1.json.sha256",
 "checksums/w3c-identity-projection-v0.1.sha256",
]

def run(label,cmd,cwd=ROOT):
    print(f"\n[{label}]")
    p=subprocess.run(cmd,cwd=cwd)
    if p.returncode:
        print(f"\nOI-015 FROZEN-NORMATIVE GATE: FAIL ({label})")
        raise SystemExit(p.returncode)
    print(f"[PASS] {label}")

def args():
    p=argparse.ArgumentParser()
    p.add_argument("--maven",help="Path/name of Maven launcher. Overrides OI015_MAVEN and PATH.")
    return p.parse_args()

def maven(explicit):
    cs=[explicit,os.environ.get("OI015_MAVEN")]
    cs += ["mvn.cmd","mvn"] if os.name=="nt" else ["mvn","mvn.cmd"]
    for c in cs:
        if not c:continue
        p=Path(c).expanduser()
        if p.is_file():return str(p.resolve())
        q=shutil.which(c)
        if q:return q
    return None

def main():
    a=args()
    run("Generate draft OI-015 vectors",[sys.executable,"tools/test-vectors/generate_authentication_assertion_v1.py"])
    run("Verify draft OI-015 vectors",[sys.executable,"tools/test-vectors/verify_authentication_assertion_v1.py"])
    candidate=ROOT/"checksums"/"authentication-assertion-v1.json.sha256"
    if not candidate.is_file():
        print("\nOI-015 PRE-FREEZE GATE: FAIL (committed byte-frozen candidate checksum missing)")
        raise SystemExit(1)
    run("Verify committed OI-015 byte-frozen candidate",
        [sys.executable,"tools/test-vectors/verify_authentication_assertion_v1_freeze_candidate.py"])
    mvn=maven(a.maven)
    if not mvn:
        print("\nOI-015 PRE-FREEZE GATE: FAIL (Maven executable not found)")
        print("Pass --maven <path-to-mvn.cmd>, set OI015_MAVEN, or add Maven to PATH.")
        raise SystemExit(1)
    print("Using Maven:",mvn)
    run("Independent Java OI-015 verification",
        [mvn,"-q","compile","exec:java","-Dexec.mainClass=org.openidentity.vectors.AuthenticationAssertionV1Vectors"],
        ROOT/"tools"/"test-vectors-java")

    print("\n[Previously frozen commitment integrity]")
    p=subprocess.run(["git","diff","--quiet","--",*PROTECTED],cwd=ROOT)
    if p.returncode:
        subprocess.run(["git","diff","--",*PROTECTED],cwd=ROOT)
        print("\nOI-015 PRE-FREEZE GATE: FAIL (previously frozen commitment/artifact changed)")
        raise SystemExit(1)
    print("[PASS] Previously frozen commitments/artifacts unchanged")

    print("\n============================================================")
    print("OI-015 FROZEN-NORMATIVE RELEASE GATE: PASS")
    print("============================================================")
    print("\nStatus: OI-015 v1 frozen-normative AA01-AA06 + AAI01-AAI31 and committed byte checksum verified.")
    print("Frozen OI-015 v1 bytes MUST NOT change without an explicit protocol revision.")

if __name__=="__main__":
    main()
