#!/usr/bin/env python3
"""Frozen-normative release gate for OpenIdentity Protocol v2 / IdentityState v3.

Runs the draft v3 generator/verifier and every existing independent Python
conformance verifier. Java remains an explicit separate Maven gate because
this script must not hide or weaken cross-language independence.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PY = sys.executable

CHECKS = [
    ("Verify committed v3 byte-frozen candidate", "verify_protocol_v2_v3_freeze_candidate.py"),
    ("Generate draft Protocol v2/v3 vectors", "generate_protocol_v2_v3.py"),
    ("Verify regenerated v3 byte identity", "verify_protocol_v2_v3_freeze_candidate.py"),
    ("Verify draft Protocol v2/v3 vectors", "verify_protocol_v2_v3.py"),
    ("Frozen OI-002 cryptographic agility", "verify_cryptographic_agility.py", "test-vectors/cryptographic-agility-v0.1.json"),
    ("Frozen identity vectors", "verify_identity_vectors.py"),
    ("Frozen assertion authority", "verify_assertion_authority.py"),
    ("Frozen credential vectors", "verify_credential.py"),
    ("Frozen recovery vectors", "verify_recovery.py"),
    ("Frozen signature envelope", "verify_signature_envelope.py"),
    ("Frozen StateHash", "verify_state_hash.py"),
    ("Frozen W3C identity projection", "verify_w3c_projection.py"),
    ("Frozen W3C credential projection", "verify_w3c_credential_projection.py"),
]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--refresh-candidate",
        action="store_true",
        help="Run semantic and frozen regressions while intentionally skipping the superseded candidate checksum checks.",
    )
    args = parser.parse_args()
    tools = ROOT / "tools" / "test-vectors"
    print("OpenIdentity Protocol v2 / IdentityState v3")
    print("Frozen-Normative Python Release Gate")
    print("=" * 60)
    for check in CHECKS:
        label, filename, *check_args = check
        if args.refresh_candidate and filename == "verify_protocol_v2_v3_freeze_candidate.py":
            print(f"\n[SKIP] {label} (candidate refresh explicitly requested)")
            continue
        print(f"\n[{label}]")
        result = subprocess.run([PY, str(tools / filename), *check_args], cwd=ROOT)
        if result.returncode != 0:
            print(f"\nRELEASE GATE: FAIL ({label})")
            raise SystemExit(result.returncode)
        print(f"[PASS] {label}")

    print("\n" + "=" * 60)
    print("PYTHON CANDIDATE-REFRESH REGRESSION GATE: PASS" if args.refresh_candidate
          else "PROTOCOL V2 / IDENTITYSTATE V3 FROZEN-NORMATIVE PYTHON GATE: PASS")
    print("=" * 60)
    print()
    print("Required independent Java gates:")
    print("  cd tools/test-vectors-java")
    print("  mvn clean compile exec:java")
    print("  mvn clean compile exec:java -Dexec.mainClass=org.openidentity.vectors.ProtocolV2V3Vectors")
    print()
    if args.refresh_candidate:
        print("Candidate checksum verification was intentionally skipped.")
        print("Do not treat this run as a byte-freeze. Establish and commit a new checksum only after")
        print("both Java commands pass and frozen v0.1 artifacts remain unchanged.")
    print("Do not freeze until both Java commands pass and git diff confirms")
    print("that no frozen v0.1 artifact/checksum changed.")


if __name__ == "__main__":
    main()
