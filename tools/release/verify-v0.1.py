#!/usr/bin/env python3
"""OpenIdentity Protocol v0.1 release gate.

Run from anywhere inside a clean OpenIdentity checkout:

    python tools/release/verify-v0.1.py

The gate is intentionally platform-neutral (Windows/macOS/Linux) and uses
Python for integrity verification rather than requiring sha256sum.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PYTHON = sys.executable

REQUIRED = [
    "README.md", "AGENTS.md", "LICENSE", "NOTICE", "LICENSING.md",
    "TRADEMARKS.md",
    "docs/identity-id.md", "docs/cryptographic-agility.md",
    "docs/credential.md", "docs/w3c-identity-projection.md",
    "spec/cddl/openidentity-operation-v1.cddl",
    "spec/cddl/openidentity-operation-v2.cddl",
    "spec/cddl/openidentity-credential-v1.cddl",
    "spec/create-operation.md", "spec/rotate-controller.md",
    "spec/deactivate.md", "spec/recover.md",
    "spec/sequence-and-replay.md", "spec/canonical-serialization.md",
    "spec/signature-envelope.md", "spec/state-hash.md",
    "spec/w3c-credential-projection.md",
    "spec/credential-profiles/basic-v1.md",
]

NORMATIVE_BUNDLES = [
    "test-vectors/identity-id-v0.1.json",
    "test-vectors/cryptographic-agility-v0.1.json",
    "test-vectors/assertion-authority-v0.1.json",
    "test-vectors/credential-v0.1.json",
    "test-vectors/w3c-projection-v0.1.json",
    "test-vectors/w3c-credential-projection-v0.1.json",
    "test-vectors/recovery-v0.1.json",
    "test-vectors/signature-envelope-v0.1.json",
    "test-vectors/state-hash-v0.1.json",
]

CHECKSUM_FILES = [
    "test-vectors/identity-id-v0.1.sha256",
    "test-vectors/cryptographic-agility-v0.1.sha256",
    "test-vectors/assertion-authority-v0.1.json.sha256",
    "test-vectors/credential-v0.1.json.sha256",
    "test-vectors/w3c-credential-projection-v0.1.json.sha256",
    "test-vectors/recovery-v0.1.json.sha256",
    "test-vectors/signature-envelope-v0.1.json.sha256",
    "test-vectors/state-hash-v0.1.json.sha256",
    "checksums/w3c-identity-projection-v0.1.sha256",
    "contexts/openidentity-v1.sha256",
    "contexts/openidentity-v2.sha256",
    "public/ns/v1.sha256",
    "public/ns/v2.sha256",
    "public/test/credentials/basic/v1/context.sha256",
]

VERIFIERS = [
    "tools/test-vectors/verify_identity_vectors.py",
    "tools/test-vectors/verify_cryptographic_agility.py",
    "tools/test-vectors/verify_assertion_authority.py",
    "tools/test-vectors/verify_credential.py",
    "tools/test-vectors/verify_w3c_projection.py",
    "tools/test-vectors/verify_w3c_credential_projection.py",
    "tools/test-vectors/verify_recovery.py",
    "tools/test-vectors/verify_signature_envelope.py",
    "tools/test-vectors/verify_state_hash.py",
]

# These are immutable/published inputs whose exact bytes must survive the Java
# generator. Include specs/verifiers covered by the W3C projection manifest too.
FROZEN = NORMATIVE_BUNDLES + CHECKSUM_FILES + [
    "contexts/openidentity-v1.jsonld",
    "contexts/openidentity-v2.jsonld",
    "public/ns/v1.jsonld",
    "public/ns/v2.jsonld",
    "public/test/credentials/basic/v1/context",
    "docs/w3c-identity-projection.md",
    "tools/test-vectors/verify_w3c_projection.py",
]

RELEASE_TEXT_FILES = [
    "README.md",
    "docs/identity-id.md",
    "docs/cryptographic-agility.md",
    "docs/credential.md",
    "spec/create-operation.md",
    "spec/rotate-controller.md",
    "spec/deactivate.md",
    "spec/recover.md",
    "spec/sequence-and-replay.md",
    "spec/canonical-serialization.md",
    "spec/signature-envelope.md",
    "spec/state-hash.md",
    "spec/w3c-credential-projection.md",
]

FORBIDDEN_RELEASE_MARKERS = [
    re.compile(r"\bDraft v0\.1\b", re.I),
    re.compile(r"\bTODO\b"),
    re.compile(r"\bTBD\b"),
    re.compile(r"\bSHOULD publish\b", re.I),
    re.compile(r"\bplanned cases\b", re.I),
    re.compile(r"RECOVER\s+[—-]\s+allocated but unsupported", re.I),
    re.compile(r"license (?:has not yet been selected|is .*pending)", re.I),
]


class GateFailure(RuntimeError):
    pass


def ok(msg: str) -> None:
    print(f"      [OK] {msg}")


def section(title: str) -> None:
    print()
    print("=" * 72)
    print(title)
    print("=" * 72)


def fail(msg: str) -> None:
    raise GateFailure(msg)


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def require_files() -> None:
    section("1. REQUIRED RELEASE ARTIFACTS")
    for rel in REQUIRED + NORMATIVE_BUNDLES + CHECKSUM_FILES + VERIFIERS:
        p = ROOT / rel
        if not p.is_file():
            fail(f"Missing required file: {rel}")
    ok("all required specifications, schemas, vectors, checksums, and verifiers exist")


def parse_checksum_line(line: str):
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    m = re.match(r"^([0-9A-Fa-f]{64})\s+[* ]?(.+?)\s*$", line)
    if not m:
        fail(f"Invalid SHA-256 manifest line: {line!r}")
    return m.group(1).lower(), m.group(2)


def resolve_manifest_target(manifest_rel: str, target: str) -> Path:
    manifest = ROOT / manifest_rel

    # The W3C identity projection manifest deliberately uses repository-root
    # paths. Other .sha256 files use filenames relative to their own directory.
    if manifest_rel.startswith("checksums/"):
        return ROOT / target

    return manifest.parent / target


def verify_checksums() -> None:
    section("2. NORMATIVE AND PUBLIC SHA-256 INTEGRITY")
    for manifest_rel in CHECKSUM_FILES:
        manifest = ROOT / manifest_rel
        entries = 0
        for line in manifest.read_text(encoding="utf-8").splitlines():
            parsed = parse_checksum_line(line)
            if parsed is None:
                continue
            expected, target_name = parsed
            target = resolve_manifest_target(manifest_rel, target_name)
            if not target.is_file():
                fail(f"{manifest_rel}: target does not exist: {target_name}")
            actual = sha256(target)
            if actual != expected:
                fail(
                    f"{manifest_rel}: checksum mismatch for {target_name}\n"
                    f"expected {expected}\nactual   {actual}"
                )
            entries += 1
        if entries == 0:
            fail(f"{manifest_rel}: no checksum entries")
        ok(f"{manifest_rel} ({entries} entr{'y' if entries == 1 else 'ies'})")


def check_release_text() -> None:
    section("3. RELEASE TEXT / CURRENT-SCHEMA SANITY")
    for rel in RELEASE_TEXT_FILES:
        text = (ROOT / rel).read_text(encoding="utf-8")
        for pattern in FORBIDDEN_RELEASE_MARKERS:
            if pattern.search(text):
                fail(f"{rel}: stale release marker matched {pattern.pattern!r}")

    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
    if "spec/cddl/openidentity-operation-v2.cddl" not in readme:
        fail("README.md does not identify openidentity-operation-v2.cddl")
    if "Apache License, Version 2.0" not in readme:
        fail("README.md does not identify Apache License 2.0")
    if "openidentity-operation-v2.cddl" not in agents:
        fail("AGENTS.md does not identify current operation-v2 CDDL")
    if "historical/frozen" not in agents:
        fail("AGENTS.md does not mark operation-v1 as historical/frozen")
    ok("no stale Draft/TODO/TBD/planned/license markers")
    ok("README and AGENTS identify current v2 schema and release licensing")


def verify_apache_license() -> None:
    section("4. LICENSE SANITY")
    text = (ROOT / "LICENSE").read_text(encoding="utf-8", errors="replace")
    required = [
        "Apache License",
        "Version 2.0, January 2004",
        "TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION",
        "3. Grant of Patent License.",
        "6. Trademarks.",
        "END OF TERMS AND CONDITIONS",
    ]
    for token in required:
        if token not in text:
            fail(f"LICENSE is missing expected Apache-2.0 text: {token}")
    licensing = (ROOT / "LICENSING.md").read_text(encoding="utf-8")
    if "Apache License, Version 2.0" not in licensing:
        fail("LICENSING.md does not state Apache-2.0 repository-wide licensing")
    ok("Apache-2.0 license structure detected")
    ok("LICENSING.md identifies repository-wide Apache-2.0")


def run(cmd, cwd=ROOT, label=None) -> None:
    shown = label or " ".join(str(x) for x in cmd)
    print()
    print(f">>> {shown}")
    proc = subprocess.run(
        [str(x) for x in cmd],
        cwd=str(cwd),
        text=True,
    )
    if proc.returncode != 0:
        fail(f"Command failed ({proc.returncode}): {shown}")
    ok(shown)


def run_verifiers(round_name: str) -> None:
    section(round_name)
    for rel in VERIFIERS:
        run([PYTHON, ROOT / rel], label=rel)


def frozen_snapshot():
    snap = {}
    for rel in FROZEN:
        p = ROOT / rel
        if not p.is_file():
            fail(f"Frozen artifact missing: {rel}")
        snap[rel] = sha256(p)
    return snap


def compare_snapshot(before) -> None:
    changed = []
    for rel, digest in before.items():
        p = ROOT / rel
        if not p.is_file():
            changed.append(f"{rel} (deleted)")
        elif sha256(p) != digest:
            changed.append(rel)
    if changed:
        fail(
            "Java generation changed frozen release artifacts:\n  " +
            "\n  ".join(changed)
        )
    ok(f"all {len(before)} frozen artifacts unchanged after Java generation")


def run_java_generator() -> None:
    section("6. JAVA REFERENCE GENERATOR")
    mvn = shutil.which("mvn") or shutil.which("mvn.cmd")
    if not mvn:
        fail("Maven not found on PATH (expected mvn or mvn.cmd)")
    java_dir = ROOT / "tools" / "test-vectors-java"
    run([mvn, "clean", "compile"], cwd=java_dir, label="mvn clean compile")
    run(
        [mvn, "exec:java", "-Dexec.mainClass=org.openidentity.vectors.GenerateVectors"],
        cwd=java_dir,
        label="mvn exec:java -Dexec.mainClass=org.openidentity.vectors.GenerateVectors",
    )


def check_git_clean_if_available() -> None:
    section("8. WORKTREE SANITY")
    git = shutil.which("git")
    if not git or not (ROOT / ".git").exists():
        print("      [SKIP] git worktree check unavailable")
        return
    proc = subprocess.run(
        [git, "status", "--porcelain"],
        cwd=str(ROOT),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if proc.returncode != 0:
        fail("git status failed: " + proc.stderr.strip())
    # Generated output may be intentionally ignored. Anything reported by Git
    # after the gate indicates tracked/unignored release-tree mutation.
    if proc.stdout.strip():
        fail("worktree is not clean after release gate:\n" + proc.stdout)
    ok("git worktree clean")


def main() -> int:
    print()
    print("OPENIDENTITY PROTOCOL v0.1 RELEASE GATE")
    print(f"Repository: {ROOT}")
    print(f"Python:     {sys.version.split()[0]}")

    require_files()
    verify_checksums()
    check_release_text()
    verify_apache_license()

    run_verifiers("5. INDEPENDENT CONFORMANCE — PRE-GENERATION")

    before = frozen_snapshot()
    run_java_generator()
    compare_snapshot(before)

    run_verifiers("7. INDEPENDENT CONFORMANCE — POST-GENERATION")
    verify_checksums()
    check_git_clean_if_available()

    print()
    print("=" * 72)
    print("OPENIDENTITY PROTOCOL v0.1 RELEASE GATE: PASS")
    print("=" * 72)
    print("All required artifacts, integrity manifests, independent verifiers,")
    print("Java reference generation, frozen-artifact checks, and release sanity")
    print("checks passed.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except GateFailure as exc:
        print()
        print("=" * 72)
        print("OPENIDENTITY PROTOCOL v0.1 RELEASE GATE: FAIL")
        print("=" * 72)
        print(exc)
        raise SystemExit(1)
    except KeyboardInterrupt:
        print("\nRelease gate interrupted.")
        raise SystemExit(130)
