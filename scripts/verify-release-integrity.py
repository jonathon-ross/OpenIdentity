#!/usr/bin/env python3
from pathlib import Path
import argparse, os, shutil, subprocess, sys

ROOT=Path(__file__).resolve().parents[1]
parser=argparse.ArgumentParser()
parser.add_argument("--maven",help="Path to Maven executable (for example C:/apache-maven/bin/mvn.cmd)")
args=parser.parse_args()

def run(label,*cmd,cwd=ROOT):
    print(f"\n=== {label} ===",flush=True)
    r=subprocess.run(cmd,cwd=cwd)
    if r.returncode:
        print(f"OPENIDENTITY RELEASE INTEGRITY GATE: FAIL ({label})")
        sys.exit(r.returncode)

run("External OIDC frozen checksums",sys.executable,"scripts/verify-external-oidc-binding-checksums.py")
run("External OIDC executable semantic vectors",sys.executable,"scripts/verify-external-oidc-binding-v1.py")
run("Entra integration hardening",sys.executable,"scripts/verify-entra-integration-hardening.py")
maven=args.maven
if not maven:
    home=os.environ.get("MAVEN_HOME")
    if home:
        candidate=Path(home)/"bin"/("mvn.cmd" if os.name=="nt" else "mvn")
        if candidate.is_file(): maven=str(candidate)
if not maven:
    maven=shutil.which("mvn.cmd" if os.name=="nt" else "mvn") or shutil.which("mvn")
if not maven or not Path(maven).is_file():
    print("OPENIDENTITY RELEASE INTEGRITY GATE: FAIL (Maven executable not found; pass --maven PATH or set MAVEN_HOME)")
    sys.exit(1)
run("Java conformance reactor",maven,"clean","install",cwd=ROOT/"java-sdk")

status=subprocess.run(["git","status","--porcelain"],cwd=ROOT,text=True,capture_output=True,check=True).stdout
if status.strip():
    print("\n=== Worktree ===")
    print(status,end="")
    print("OPENIDENTITY RELEASE INTEGRITY GATE: FAIL (worktree is not clean)")
    sys.exit(1)

print("\nOPENIDENTITY RELEASE INTEGRITY GATE: PASS")
