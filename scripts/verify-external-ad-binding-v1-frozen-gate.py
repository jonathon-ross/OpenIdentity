#!/usr/bin/env python3
from pathlib import Path
import argparse,os,shutil,subprocess,sys
ROOT=Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser();p.add_argument("--maven",help="Path to Maven executable");args=p.parse_args()
def run(label,*cmd,cwd=ROOT):
 print(f"\n=== {label} ===",flush=True);r=subprocess.run(cmd,cwd=cwd)
 if r.returncode:print(f"OPENIDENTITY EXTERNAL AD V1 FROZEN GATE: FAIL ({label})");sys.exit(r.returncode)
run("Frozen AD artifact checksums",sys.executable,"scripts/verify-external-ad-binding-checksums.py")
run("AD objectGUID representation",sys.executable,"scripts/verify-ad-objectguid-byte-order.py")
run("Frozen AD01 cryptographic reconstruction",sys.executable,"scripts/verify-external-ad-binding-v1-crypto.py")
run("Frozen AD semantic contracts",sys.executable,"scripts/verify-external-ad-binding-v1.py")
maven=args.maven
if not maven:
 home=os.environ.get("MAVEN_HOME")
 if home:
  q=Path(home)/"bin"/("mvn.cmd" if os.name=="nt" else "mvn")
  if q.is_file():maven=str(q)
if not maven:maven=shutil.which("mvn.cmd" if os.name=="nt" else "mvn") or shutil.which("mvn")
if not maven or not Path(maven).is_file():
 print("OPENIDENTITY EXTERNAL AD V1 FROZEN GATE: FAIL (Maven executable not found; pass --maven PATH or set MAVEN_HOME)");sys.exit(1)
run("Java frozen-vector and semantic reactor",maven,"clean","test",cwd=ROOT/"java-sdk")
status=subprocess.run(["git","status","--porcelain"],cwd=ROOT,text=True,capture_output=True,check=True).stdout
if status.strip():
 print("\n=== Worktree ===");print(status,end="");print("OPENIDENTITY EXTERNAL AD V1 FROZEN GATE: FAIL (worktree is not clean)");sys.exit(1)
print("\nOPENIDENTITY EXTERNAL AD V1 FROZEN GATE: PASS")
