#!/usr/bin/env python3
"""OpenIdentity Java reference implementation release gate."""
from __future__ import annotations
import argparse,os,shutil,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]

def run(label,cmd,cwd=ROOT):
 print(f"\n[{label}]");p=subprocess.run(cmd,cwd=cwd)
 if p.returncode:
  print(f"\nJAVA REFERENCE IMPLEMENTATION RELEASE GATE: FAIL ({label})");raise SystemExit(p.returncode)
 print(f"[PASS] {label}")

def find_maven(explicit):
 for c in [explicit,os.environ.get("OPENIDENTITY_MAVEN"),"mvn.cmd","mvn"]:
  if not c:continue
  p=Path(c).expanduser()
  if p.is_file():return str(p.resolve())
  q=shutil.which(c)
  if q:return q
 return None

def main():
 ap=argparse.ArgumentParser();ap.add_argument("--maven");a=ap.parse_args();mvn=find_maven(a.maven)
 if not mvn:raise SystemExit("Maven executable not found")
 run("Java SDK reactor",[mvn,"clean","install"],ROOT/"java-sdk")
 run("Spring Authorization Server black-box sample",[mvn,"clean","test"],ROOT/"samples"/"spring-authorization-server")
 run("Frozen Delegated Agent Profile conformance",
     [sys.executable,"tools/test-vectors/pre_freeze_oauth_delegated_agent_profile_v1.py","--maven",mvn],ROOT)
 print("\n============================================================")
 print("OPENIDENTITY JAVA REFERENCE IMPLEMENTATION RELEASE GATE: PASS")
 print("============================================================")
 print("\nSDK modules: PASS")
 print("Spring Authorization Server exact-token black-box exchange: PASS")
 print("Frozen Delegated Agent Profile v1 conformance: PASS")
 print("Replay rejection and no-refresh-token behavior: covered by integration tests.")
if __name__=="__main__":main()
