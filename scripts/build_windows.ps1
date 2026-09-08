param(
    [string]$Python = "python",
    [switch]$SkipInstall
)
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$RepositoryRoot = Split-Path -Parent $PSScriptRoot
Push-Location -LiteralPath $RepositoryRoot
try {
    if (-not $SkipInstall) {
        & $Python -m pip install --require-hashes --only-binary=:all: -r requirements-windows.lock
        if ($LASTEXITCODE -ne 0) { throw "Dependency installation failed." }
    }
    & $Python scripts/run_tests.py
    if ($LASTEXITCODE -ne 0) { throw "Tests failed; no release was built." }
    & $Python scripts/build_release.py
    if ($LASTEXITCODE -ne 0) { throw "Executable build failed." }
} finally {
    Pop-Location
}
