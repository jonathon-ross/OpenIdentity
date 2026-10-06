$ErrorActionPreference = "Stop"

$root = git rev-parse --show-toplevel
if ($LASTEXITCODE -ne 0) { throw "Not inside a Git repository." }
Set-Location $root

Write-Host "========================================================================"
Write-Host "OPENIDENTITY JAVA SDK RELEASE GATE"
Write-Host "========================================================================"

mvn clean verify
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

git diff --exit-code
if ($LASTEXITCODE -ne 0) {
    Write-Error "Release gate failed: tracked files changed during verification."
    exit 1
}

$status = git status --porcelain
if ($status) {
    Write-Host "Release gate failed: git worktree is not clean." -ForegroundColor Red
    git status --short
    exit 1
}

Write-Host "========================================================================"
Write-Host "OPENIDENTITY JAVA SDK RELEASE GATE: PASS"
Write-Host "========================================================================"
