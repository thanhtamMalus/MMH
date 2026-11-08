# build.ps1 — Build rsatool trên Windows, tự động tìm OpenSSL >= 4.0
#
# Dùng:
#   .\scripts\build.ps1                                   # tự dò OpenSSL (khuyến nghị)
#   .\scripts\build.ps1 -OpenSSLRoot "D:/duong/dan/openssl4"  # chỉ định thủ công
#   .\scripts\build.ps1 -AutoBuildOpenSSL                 # chưa có -> tự tải & build
#                                                         #   (chạy trong "x64 Native Tools Command Prompt")
#   .\scripts\build.ps1 -Static                           # liên kết tĩnh libcrypto
#   .\scripts\build.ps1 -Clean                            # xoá build cũ trước
#
# $env:OPENSSL_ROOT_DIR cũng được hỗ trợ nhưng KHÔNG bắt buộc.
param(
    [string]$OpenSSLRoot = "",
    [string]$Generator   = "",
    [switch]$AutoBuildOpenSSL,
    [switch]$Static,
    [switch]$Clean,
    [switch]$VerboseSearch
)
$ErrorActionPreference = "Stop"

$ScriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectDir = Split-Path -Parent $ScriptDir
$BuildDir   = Join-Path $ProjectDir "build\windows-release"

if (-not (Get-Command cmake -ErrorAction SilentlyContinue)) {
    throw "Chưa cài cmake (>= 3.20) hoặc chưa có trong PATH."
}

# ── Chọn generator Visual Studio theo bản đang cài (không ép VS 2022) ────────
if (-not $Generator) {
    $Generator = "Visual Studio 18 2026"
    $vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $vswhere) {
        $major = & $vswhere -latest -products * -property installationVersion 2>$null
        if ($major) { $major = ($major -split '\.')[0] }
        switch ($major) {
            "18" { $Generator = "Visual Studio 18 2026" }
            "17" { $Generator = "Visual Studio 17 2022" }
            "16" { $Generator = "Visual Studio 16 2019" }
        }
    }
}

# ── Build cũ copy từ máy khác -> xoá để configure sạch ───────────────────────
$Cache = Join-Path $BuildDir "CMakeCache.txt"
if (Test-Path $Cache) {
    $src = (Select-String -Path $Cache -Pattern '^CMAKE_HOME_DIRECTORY:INTERNAL=(.*)$').Matches.Groups[1].Value
    $bin = (Select-String -Path $Cache -Pattern '^CMAKE_CACHEFILE_DIR:INTERNAL=(.*)$').Matches.Groups[1].Value
    $norm = { param($p) ($p -replace '\\','/').TrimEnd('/').ToLowerInvariant() }
    if ((& $norm $src) -ne (& $norm $ProjectDir) -or (& $norm $bin) -ne (& $norm $BuildDir)) {
        Write-Host "INFO: build cũ được tạo ở đường dẫn khác ($src) -> xoá và configure lại."
        $Clean = $true
    }
} elseif (Test-Path $BuildDir) {
    $Clean = $true   # thư mục build dở dang
}
if ($Clean -and (Test-Path $BuildDir)) { Remove-Item -Recurse -Force $BuildDir }

Write-Host "`n=== Configuring ($Generator, x64, Release; tự dò OpenSSL >= 4.0) ===" -ForegroundColor Cyan

$cmakeArgs = @(
    "-S", $ProjectDir,
    "-B", $BuildDir,
    "-G", $Generator,
    "-A", "x64",
    "-DCMAKE_BUILD_TYPE=Release"
)
if ($OpenSSLRoot)       { $cmakeArgs += "-DOPENSSL_ROOT_DIR=$($OpenSSLRoot -replace '\\', '/')" }
if ($AutoBuildOpenSSL)  { $cmakeArgs += "-DRSATOOL_AUTO_BUILD_OPENSSL=ON" }
if ($Static)            { $cmakeArgs += "-DRSATOOL_OPENSSL_STATIC=ON" }
if ($VerboseSearch)     { $cmakeArgs += "-DRSATOOL_OPENSSL_VERBOSE=ON" }

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
