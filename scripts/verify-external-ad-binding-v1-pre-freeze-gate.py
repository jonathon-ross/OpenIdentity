#!/usr/bin/env python3
from pathlib import Path
import argparse,os,shutil,subprocess,sys
ROOT=Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser();p.add_argument("--maven",help="Path to Maven executable");args=p.parse_args()
def run(label,*cmd,cwd=ROOT):
 print(f"\n=== {label} ===",flush=True);r=subprocess.run(cmd,cwd=cwd)
 if r.returncode:print(f"OPENIDENTITY AD V1 PRE-FREEZE GATE: FAIL ({label})");sys.exit(r.returncode)
run("AD objectGUID representation",sys.executable,"scripts/verify-ad-objectguid-byte-order.py")
run("AD01 cryptographic reconstruction",sys.executable,"scripts/verify-external-ad-binding-v1-crypto-pre-freeze.py")
run("AD semantic contracts",sys.executable,"scripts/verify-external-ad-binding-v1-pre-freeze.py")
run("AD candidate artifact checksums",sys.executable,"scripts/verify-external-ad-binding-checksums-pre-freeze.py")
maven=args.maven
if not maven:
 home=os.environ.get("MAVEN_HOME")
 if home:
  q=Path(home)/"bin"/("mvn.cmd" if os.name=="nt" else "mvn")
  if q.is_file():maven=str(q)
if not maven:maven=shutil.which("mvn.cmd" if os.name=="nt" else "mvn") or shutil.which("mvn")
if not maven or not Path(maven).is_file():
 print("OPENIDENTITY AD V1 PRE-FREEZE GATE: FAIL (Maven executable not found; pass --maven PATH or set MAVEN_HOME)");sys.exit(1)
run("Java cross-implementation and semantic reactor",maven,"clean","test",cwd=ROOT/"java-sdk")
status=subprocess.run(["git","status","--porcelain"],cwd=ROOT,text=True,capture_output=True,check=True).stdout
if status.strip():
 print("\n=== Worktree ===");print(status,end="");print("OPENIDENTITY AD V1 PRE-FREEZE GATE: FAIL (worktree is not clean)");sys.exit(1)
print("\nOPENIDENTITY AD V1 PRE-FREEZE GATE: PASS")
