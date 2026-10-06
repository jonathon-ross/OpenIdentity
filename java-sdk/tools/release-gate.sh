#!/usr/bin/env bash
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

echo "========================================================================"
echo "OPENIDENTITY JAVA SDK RELEASE GATE"
echo "========================================================================"

find_maven() {
  if command -v mvn >/dev/null 2>&1; then
    command -v mvn
    return 0
  fi

  # Git Bash / MSYS on Windows. Maven installations commonly live directly
  # under the Windows user home, e.g. C:\Users\name\apache-maven-3.9.16.
  if [[ -n "${USERPROFILE:-}" ]]; then
    local win_home
    win_home="$(cygpath -u "$USERPROFILE" 2>/dev/null || true)"
    if [[ -n "$win_home" ]]; then
      local candidate
      for candidate in "$win_home"/apache-maven-*/bin/mvn "$win_home"/maven/apache-maven-*/bin/mvn; do
        if [[ -x "$candidate" ]]; then
          printf '%s\n' "$candidate"
          return 0
        fi
      done
    fi
  fi

  # HOME is also useful when Git Bash maps it directly to the Windows profile.
  local candidate
  for candidate in "$HOME"/apache-maven-*/bin/mvn "$HOME"/maven/apache-maven-*/bin/mvn; do
    if [[ -x "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done

  return 1
}

if ! MVN="$(find_maven)"; then
  echo "Release gate failed: Maven was not found." >&2
  echo "Install Maven or add its bin directory to PATH." >&2
  echo "Git Bash example: export PATH=\"/c/Users/<user>/apache-maven-3.9.16/bin:\$PATH\"" >&2
  exit 127
fi

echo "Maven: $MVN"
"$MVN" clean verify

git diff --exit-code

if [[ -n "$(git status --porcelain)" ]]; then
  echo "Release gate failed: git worktree is not clean." >&2
  git status --short
  exit 1
fi

echo "========================================================================"
echo "OPENIDENTITY JAVA SDK RELEASE GATE: PASS"
echo "========================================================================"
