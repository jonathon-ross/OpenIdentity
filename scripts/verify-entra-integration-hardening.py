#!/usr/bin/env python3
from pathlib import Path
import re, sys

ROOT=Path(__file__).resolve().parents[1]
errors=[]

tracked_forbidden=[
    ROOT/"dev/openidentity-bindings.store",
]
for p in tracked_forbidden:
    if p.exists():
        errors.append(f"local runtime artifact exists in repository working tree: {p.relative_to(ROOT)}")

for base in (ROOT/"dev",):
    if base.exists():
        for p in base.rglob("*"):
            if p.is_file() and (p.name.endswith(".controller.key") or p.name.endswith(".authentication.key")):
                # Local files are allowed only when ignored; git check-ignore verifies protection.
                import subprocess
                r=subprocess.run(["git","check-ignore","-q",str(p)],cwd=ROOT)
                if r.returncode != 0: errors.append(f"private authenticator is not gitignored: {p.relative_to(ROOT)}")

gi=(ROOT/".gitignore").read_text()
for required in ("/dev/openidentity-secrets/","*.controller.key","*.authentication.key","/dev/openidentity-bindings.store"):
    if required not in gi: errors.append(f"missing .gitignore protection: {required}")

sample=(ROOT/"samples/spring-entra-oidc/src/main/java/org/openidentity/samples/entra/EntraOidcSampleApplication.java").read_text()
for forbidden in ("ed25519Seed","getIdToken().getTokenValue","getAccessToken"):
    if forbidden in sample: errors.append(f"sample exposes/handles forbidden secret material: {forbidden}")

if errors:
    print("OPENIDENTITY ENTRA HARDENING GATE: FAIL")
    for e in errors: print(" -",e)
    sys.exit(1)
print("OPENIDENTITY ENTRA HARDENING GATE: PASS")
