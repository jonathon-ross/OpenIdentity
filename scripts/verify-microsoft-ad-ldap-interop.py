#!/usr/bin/env python3
from pathlib import Path
import argparse,os,shutil,subprocess,sys
ROOT=Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser();p.add_argument("--maven");p.add_argument("--host",default="DC01.oi-test.internal");p.add_argument("--port",default="636");p.add_argument("--base-dn",default="DC=oi-test,DC=internal");p.add_argument("--bind-dn",default="oi-ldap@oi-test.internal");p.add_argument("--principal",default="alice@oi-test.internal");p.add_argument("--directory-id",default="d0d1d2d3d4d5d6d7d8d9dadbdcdddedf");a=p.parse_args()
def run(label,*cmd,cwd=ROOT,env=None):
 print(f"\n=== {label} ===",flush=True);r=subprocess.run(cmd,cwd=cwd,env=env)
 if r.returncode:print(f"OPENIDENTITY MICROSOFT AD LDAP INTEROP GATE: FAIL ({label})");sys.exit(r.returncode)
for n in ("OPENIDENTITY_LDAP_BIND_PASSWORD","OPENIDENTITY_EXPECTED_OBJECTGUID_HEX"):
 if not os.environ.get(n):print(f"OPENIDENTITY MICROSOFT AD LDAP INTEROP GATE: FAIL (missing {n})");sys.exit(1)
expected=os.environ["OPENIDENTITY_EXPECTED_OBJECTGUID_HEX"]
if len(expected)!=32:
 print("OPENIDENTITY MICROSOFT AD LDAP INTEROP GATE: FAIL (expected objectGUID must be 16-byte hex)");sys.exit(1)
try:bytes.fromhex(expected)
except ValueError:print("OPENIDENTITY MICROSOFT AD LDAP INTEROP GATE: FAIL (expected objectGUID is not hex)");sys.exit(1)
run("Frozen External AD v1 checksums",sys.executable,"scripts/verify-external-ad-binding-checksums.py")
run("Frozen AD01 crypto",sys.executable,"scripts/verify-external-ad-binding-v1-crypto.py")
maven=a.maven
if not maven:
 home=os.environ.get("MAVEN_HOME")
 if home:
  q=Path(home)/"bin"/("mvn.cmd" if os.name=="nt" else "mvn")
  if q.is_file():maven=str(q)
if not maven:maven=shutil.which("mvn.cmd" if os.name=="nt" else "mvn") or shutil.which("mvn")
if not maven or not Path(maven).is_file():print("OPENIDENTITY MICROSOFT AD LDAP INTEROP GATE: FAIL (Maven not found)");sys.exit(1)
run("Java reactor",maven,"clean","test",cwd=ROOT/"java-sdk")
args=f'--host {a.host} --tls true --port {a.port} --base-dn {a.base_dn} --bind-dn {a.bind_dn} --directory-id {a.directory_id} --principal {a.principal}'
run("Live Microsoft AD certificate-validated LDAPS",maven,"exec:java","-Dexec.mainClass=org.openidentity.ad.ldap.MicrosoftAdInteropProbe",f"-Dexec.args={args}",cwd=ROOT/"java-sdk/openidentity-external-ad-ldap",env=os.environ.copy())
status=subprocess.run(["git","status","--porcelain"],cwd=ROOT,text=True,capture_output=True,check=True).stdout
if status.strip():
 print(status,end="");print("OPENIDENTITY MICROSOFT AD LDAP INTEROP GATE: FAIL (worktree not clean)");sys.exit(1)
print("\nOPENIDENTITY MICROSOFT AD LDAP INTEROP GATE: PASS")
