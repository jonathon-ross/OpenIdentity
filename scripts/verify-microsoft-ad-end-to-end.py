#!/usr/bin/env python3
from pathlib import Path
import argparse,os,shutil,subprocess,sys
ROOT=Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser();p.add_argument("--maven");p.add_argument("--live",action="store_true");a=p.parse_args()
def run(label,*cmd,cwd=ROOT,env=None):
 print(f"\n=== {label} ===",flush=True);r=subprocess.run(cmd,cwd=cwd,env=env)
 if r.returncode:print(f"OPENIDENTITY MICROSOFT AD END-TO-END GATE: FAIL ({label})");sys.exit(r.returncode)
run("Frozen External AD checksums",sys.executable,"scripts/verify-external-ad-binding-checksums.py")
run("Frozen External AD crypto",sys.executable,"scripts/verify-external-ad-binding-v1-crypto.py")
maven=a.maven
if not maven:
 home=os.environ.get("MAVEN_HOME")
 if home:
  q=Path(home)/"bin"/("mvn.cmd" if os.name=="nt" else "mvn")
  if q.is_file():maven=str(q)
if not maven:maven=shutil.which("mvn.cmd" if os.name=="nt" else "mvn") or shutil.which("mvn")
if not maven or not Path(maven).is_file():print("OPENIDENTITY MICROSOFT AD END-TO-END GATE: FAIL (Maven not found)");sys.exit(1)
run("Java reactor including LDAP, SPNEGO, and Spring AD",maven,"clean","test",cwd=ROOT/"java-sdk")
run("Reusable Microsoft AD Spring sample",maven,"clean","package",cwd=ROOT/"samples/spring-ad-microsoft")
run("Minimal Spring AD reference consumer",maven,"clean","package",cwd=ROOT/"samples/spring-ad-reference")
for pat in ("*.keytab","*.pfx","*.p12","*.jks"):
 tracked=subprocess.run(["git","ls-files",pat],cwd=ROOT,text=True,capture_output=True,check=True).stdout.strip()
 if tracked:print(tracked);print(f"OPENIDENTITY MICROSOFT AD END-TO-END GATE: FAIL (tracked secret artifact {pat})");sys.exit(1)
if a.live:
 for n in ("OPENIDENTITY_LDAP_BIND_PASSWORD","OPENIDENTITY_EXPECTED_OBJECTGUID_HEX"):
  if not os.environ.get(n):print(f"OPENIDENTITY MICROSOFT AD END-TO-END GATE: FAIL (missing {n})");sys.exit(1)
 run("Live Microsoft AD validated LDAPS",maven,"exec:java","-Dexec.mainClass=org.openidentity.ad.ldap.MicrosoftAdInteropProbe","-Dexec.args=--host DC01.oi-test.internal --tls true --port 636 --base-dn DC=oi-test,DC=internal --bind-dn oi-ldap@oi-test.internal --directory-id d0d1d2d3d4d5d6d7d8d9dadbdcdddedf --principal alice@oi-test.internal",cwd=ROOT/"java-sdk/openidentity-external-ad-ldap",env=os.environ.copy())
status=subprocess.run(["git","status","--porcelain"],cwd=ROOT,text=True,capture_output=True,check=True).stdout
if status.strip():print(status,end="");print("OPENIDENTITY MICROSOFT AD END-TO-END GATE: FAIL (worktree not clean)");sys.exit(1)
print("\nOPENIDENTITY MICROSOFT AD END-TO-END GATE: PASS"+(" (LIVE AD VERIFIED)" if a.live else ""))
