#!/usr/bin/env python3
"""Unified pre-freeze gate for OpenIdentity OAuth Delegated Agent Profile v1."""
from __future__ import annotations
import argparse,os,shutil,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
PROTECTED=[
 "checksums/protocol-v2-identity-state-v3.json.sha256",
 "checksums/delegation-v1.json.sha256",
 "checksums/authentication-assertion-v1.json.sha256",
 "checksums/delegated-subject-v1.json.sha256",
 "checksums/oauth-token-exchange-context-v1.json.sha256",
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
    print(f"\n[{label}]");p=subprocess.run(cmd,cwd=cwd)
    if p.returncode:
        print(f"\nDELEGATED AGENT PROFILE v1 PRE-FREEZE GATE: FAIL ({label})");raise SystemExit(p.returncode)
    print(f"[PASS] {label}")
def args():
    p=argparse.ArgumentParser();p.add_argument("--maven",help="Path/name of Maven launcher. Overrides DELEGATED_AGENT_MAVEN and PATH.");return p.parse_args()
def maven(explicit):
    cs=[explicit,os.environ.get("DELEGATED_AGENT_MAVEN")]+(["mvn.cmd","mvn"] if os.name=="nt" else ["mvn","mvn.cmd"])
    for c in cs:
        if not c:continue
        p=Path(c).expanduser()
        if p.is_file():return str(p.resolve())
        q=shutil.which(c)
        if q:return q
    return None
def main():
    a=args()
    run("Generate draft delegated-agent profile vectors",[sys.executable,"tools/test-vectors/generate_oauth_delegated_agent_profile_v1.py"])
    run("Verify draft delegated-agent profile vectors",[sys.executable,"tools/test-vectors/verify_oauth_delegated_agent_profile_v1.py"])
    mvn=maven(a.maven)
    if not mvn:
        print("\nDELEGATED AGENT PROFILE v1 PRE-FREEZE GATE: FAIL (Maven executable not found)");raise SystemExit(1)
    print("Using Maven:",mvn)
    run("Independent Java delegated-agent profile verification",
        [mvn,"-q","compile","exec:java","-Dexec.mainClass=org.openidentity.vectors.OAuthDelegatedAgentProfileV1Vectors"],
        ROOT/"tools"/"test-vectors-java")
    print("\n[Previously frozen commitment integrity]")
    p=subprocess.run(["git","diff","--quiet","--",*PROTECTED],cwd=ROOT)
    if p.returncode:
        subprocess.run(["git","diff","--",*PROTECTED],cwd=ROOT)
        print("\nDELEGATED AGENT PROFILE v1 PRE-FREEZE GATE: FAIL (previously frozen commitment/artifact changed)");raise SystemExit(1)
    print("[PASS] Previously frozen commitments/artifacts unchanged")
    print("\n============================================================")
    print("OAUTH DELEGATED AGENT PROFILE v1 PRE-FREEZE RELEASE GATE: PASS")
    print("============================================================")
    print("\nStatus: PX01-PX03 + PXI01-PXI37 verified in Python and Java; NOT BYTE-FROZEN; NOT NORMATIVE.")
    print("Frozen OI-014/OI-015/OI-016/context dependencies remain unchanged.")
if __name__=="__main__":main()
