#!/usr/bin/env python3
from pathlib import Path
import subprocess, sys

ROOT=Path(__file__).resolve().parents[1]

def run(label,*cmd,cwd=ROOT):
    print(f"\n=== {label} ===",flush=True)
    r=subprocess.run(cmd,cwd=cwd)
    if r.returncode:
        print(f"OPENIDENTITY RELEASE INTEGRITY GATE: FAIL ({label})")
        sys.exit(r.returncode)

run("External OIDC frozen checksums",sys.executable,"scripts/verify-external-oidc-binding-checksums.py")
run("External OIDC executable semantic vectors",sys.executable,"scripts/verify-external-oidc-binding-v1.py")
run("Entra integration hardening",sys.executable,"scripts/verify-entra-integration-hardening.py")
run("Java conformance reactor","mvn","clean","install",cwd=ROOT/"java-sdk")

status=subprocess.run(["git","status","--porcelain"],cwd=ROOT,text=True,capture_output=True,check=True).stdout
if status.strip():
    print("\n=== Worktree ===")
    print(status,end="")
    print("OPENIDENTITY RELEASE INTEGRITY GATE: FAIL (worktree is not clean)")
    sys.exit(1)

print("\nOPENIDENTITY RELEASE INTEGRITY GATE: PASS")
