# test.ps1 — Run all Catch2 unit tests on Windows
$ErrorActionPreference = "Stop"

$ScriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectDir = Split-Path -Parent $ScriptDir
$BuildDir   = Join-Path $ProjectDir "build\windows-release"

if (-not (Test-Path "$BuildDir\Release\test_rsatool.exe")) {
    Write-Error "test_rsatool.exe not found. Run build.ps1 first."
    exit 1
}

Write-Host "`n=== Running unit tests ===" -ForegroundColor Cyan
Push-Location $BuildDir
try {
    & ctest --output-on-failure -C Release
    if ($LASTEXITCODE -ne 0) { throw "Some tests failed" }
} finally {
    Pop-Location
}

Write-Host "`n=== All tests passed ===" -ForegroundColor Green

