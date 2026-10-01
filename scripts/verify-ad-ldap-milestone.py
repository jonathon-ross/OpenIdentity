#!/usr/bin/env python3
from pathlib import Path
import argparse,os,shutil,subprocess,sys
ROOT=Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser();p.add_argument("--maven",help="Path to Maven executable");args=p.parse_args()
def run(label,*cmd,cwd=ROOT):
 print(f"\n=== {label} ===",flush=True);r=subprocess.run(cmd,cwd=cwd)
 if r.returncode:print(f"OPENIDENTITY AD LDAP MILESTONE GATE: FAIL ({label})");sys.exit(r.returncode)
run("Frozen External AD v1 checksums",sys.executable,"scripts/verify-external-ad-binding-checksums.py")
run("Frozen AD objectGUID representation",sys.executable,"scripts/verify-ad-objectguid-byte-order.py")
run("Frozen AD01 cryptographic reconstruction",sys.executable,"scripts/verify-external-ad-binding-v1-crypto.py")
run("Frozen AD semantic contracts",sys.executable,"scripts/verify-external-ad-binding-v1.py")
for rel in ("dev/openidentity-ad-bindings.store","dev/openidentity-ad-ldap-bindings.store"):
 q=ROOT/rel
 if q.exists():
  if subprocess.run(["git","check-ignore","-q",str(q)],cwd=ROOT).returncode!=0:
   print(f"OPENIDENTITY AD LDAP MILESTONE GATE: FAIL ({rel} is not gitignored)");sys.exit(1)
  if subprocess.run(["git","ls-files","--error-unmatch",rel],cwd=ROOT,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0:
   print(f"OPENIDENTITY AD LDAP MILESTONE GATE: FAIL ({rel} is tracked)");sys.exit(1)
maven=args.maven
if not maven:
 home=os.environ.get("MAVEN_HOME")
 if home:
  q=Path(home)/"bin"/("mvn.cmd" if os.name=="nt" else "mvn")
  if q.is_file():maven=str(q)
if not maven:maven=shutil.which("mvn.cmd" if os.name=="nt" else "mvn") or shutil.which("mvn")
if not maven or not Path(maven).is_file():
 print("OPENIDENTITY AD LDAP MILESTONE GATE: FAIL (Maven not found; pass --maven PATH or set MAVEN_HOME)");sys.exit(1)
run("Java AD + LDAP integration reactor",maven,"clean","test",cwd=ROOT/"java-sdk")
status=subprocess.run(["git","status","--porcelain"],cwd=ROOT,text=True,capture_output=True,check=True).stdout
if status.strip():
 print("\n=== Worktree ===");print(status,end="");print("OPENIDENTITY AD LDAP MILESTONE GATE: FAIL (worktree is not clean)");sys.exit(1)
print("\nOPENIDENTITY AD LDAP MILESTONE GATE: PASS")
