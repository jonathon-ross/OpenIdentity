#!/usr/bin/env python3
from pathlib import Path
import re, sys

ROOT=Path(__file__).resolve().parents[1]
errors=[]

import subprocess
local_artifacts=[]
binding_store=ROOT/"dev/openidentity-bindings.store"
if binding_store.exists(): local_artifacts.append(binding_store)
base=ROOT/"dev"
if base.exists():
    local_artifacts.extend(p for p in base.rglob("*") if p.is_file() and (p.name.endswith(".controller.key") or p.name.endswith(".authentication.key")))
for p in local_artifacts:
    ignored=subprocess.run(["git","check-ignore","-q",str(p)],cwd=ROOT).returncode == 0
    tracked=subprocess.run(["git","ls-files","--error-unmatch",str(p.relative_to(ROOT))],cwd=ROOT,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode == 0
    if tracked: errors.append(f"local secret/runtime artifact is tracked by Git: {p.relative_to(ROOT)}")
    elif not ignored: errors.append(f"local secret/runtime artifact is not gitignored: {p.relative_to(ROOT)}")

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
