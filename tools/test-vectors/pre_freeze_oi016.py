#!/usr/bin/env python3
"""Unified pre-freeze gate for draft OI-016 Delegated Subject Token v1."""
from __future__ import annotations
import argparse,os,shutil,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]

PROTECTED=[
 "checksums/protocol-v2-identity-state-v3.json.sha256",
 "checksums/delegation-v1.json.sha256",
 "checksums/authentication-assertion-v1.json.sha256",
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
        print(f"\nOI-016 PRE-FREEZE GATE: FAIL ({label})");raise SystemExit(p.returncode)
    print(f"[PASS] {label}")
def parse():
    p=argparse.ArgumentParser();p.add_argument("--maven",help="Path/name of Maven launcher. Overrides OI016_MAVEN and PATH.");return p.parse_args()
def maven(explicit):
    cs=[explicit,os.environ.get("OI016_MAVEN")]+(["mvn.cmd","mvn"] if os.name=="nt" else ["mvn","mvn.cmd"])
    for c in cs:
        if not c:continue
        p=Path(c).expanduser()
        if p.is_file():return str(p.resolve())
        q=shutil.which(c)
        if q:return q
    return None
def main():
    a=parse()
    run("Generate draft OI-016 vectors",[sys.executable,"tools/test-vectors/generate_delegated_subject_v1.py"])
    run("Verify draft OI-016 vectors",[sys.executable,"tools/test-vectors/verify_delegated_subject_v1.py"])
    candidate=ROOT/"checksums"/"delegated-subject-v1.json.sha256"
    if candidate.is_file():
        run("Verify OI-016 byte-frozen candidate",
            [sys.executable,"tools/test-vectors/verify_delegated_subject_v1_freeze_candidate.py"])
    else:
        print("\n[OI-016 freeze candidate]")
        print("[INFO] No candidate checksum present; semantic pre-freeze checks continue.")
    mvn=maven(a.maven)
    if not mvn:
        print("\nOI-016 PRE-FREEZE GATE: FAIL (Maven executable not found)")
        print("Pass --maven <path-to-mvn.cmd>, set OI016_MAVEN, or add Maven to PATH.");raise SystemExit(1)
    print("Using Maven:",mvn)
    run("Independent Java OI-016 verification",
        [mvn,"-q","compile","exec:java","-Dexec.mainClass=org.openidentity.vectors.DelegatedSubjectV1Vectors"],
        ROOT/"tools"/"test-vectors-java")
    print("\n[Previously frozen commitment integrity]")
    p=subprocess.run(["git","diff","--quiet","--",*PROTECTED],cwd=ROOT)
    if p.returncode:
        subprocess.run(["git","diff","--",*PROTECTED],cwd=ROOT)
        print("\nOI-016 PRE-FREEZE GATE: FAIL (previously frozen commitment/artifact changed)");raise SystemExit(1)
    print("[PASS] Previously frozen commitments/artifacts unchanged")
    print("\n============================================================")
    print("OI-016 PRE-FREEZE RELEASE GATE: PASS")
    print("============================================================")
    print("\nStatus: DS01-DS06 + DSI01-DSI28 verified in Python and Java; NOT BYTE-FROZEN; NOT NORMATIVE.")
    print("Next: final design/CDDL review, clean-worktree check, then create a freeze candidate only if intentional.")
if __name__=="__main__":main()
