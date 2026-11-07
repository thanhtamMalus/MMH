# build.ps1 — Build rsatool on Windows (MSVC 2022)
# Usage: .\scripts\build.ps1 [-OpenSSLRoot D:\path\to\openssl4]
# OPENSSL_ROOT_DIR can also be set as an environment variable before running.
#
# Windows OpenSSL location example: D:\cryptolibrary\openssl403
param(
    [string]$OpenSSLRoot = $env:OPENSSL_ROOT_DIR
)
$ErrorActionPreference = "Stop"

$ScriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectDir = Split-Path -Parent $ScriptDir
$BuildDir   = Join-Path $ProjectDir "build\windows-release"

if ($OpenSSLRoot) {
    $env:OPENSSL_ROOT_DIR = $OpenSSLRoot
    Write-Host "Using OPENSSL_ROOT_DIR = $OpenSSLRoot"
} else {
    Write-Warning "OPENSSL_ROOT_DIR not set. CMake will search the default path."
    Write-Warning "If OpenSSL 3.x is found, the build will FAIL (requires >= 4.0)."
    Write-Warning "Set -OpenSSLRoot or the OPENSSL_ROOT_DIR environment variable."
}

Write-Host "`n=== Configuring (Visual Studio 17 2022, x64, Release) ===" -ForegroundColor Cyan

$cmakeArgs = @(
    "-S", $ProjectDir,
    "-B", $BuildDir,
    "-G", "Visual Studio 17 2022",
    "-A", "x64",
    "-DCMAKE_BUILD_TYPE=Release"
)
if ($env:OPENSSL_ROOT_DIR) {
    $cmakeArgs += "-DOPENSSL_ROOT_DIR=$($env:OPENSSL_ROOT_DIR -replace '\\', '/')"
}

& cmake @cmakeArgs
if ($LASTEXITCODE -ne 0) { throw "CMake configure failed" }

Write-Host "`n=== Building ===" -ForegroundColor Cyan
& cmake --build $BuildDir --config Release --parallel
if ($LASTEXITCODE -ne 0) { throw "CMake build failed" }

Write-Host "`n=== Done ===" -ForegroundColor Green
Write-Host "Executable : $BuildDir\Release\rsatool.exe"
Write-Host ""
Write-Host "Run the demo:  .\scripts\demo.ps1"
Write-Host "Run tests  :   .\scripts\test.ps1"

