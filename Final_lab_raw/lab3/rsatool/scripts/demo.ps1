# demo.ps1 — End-to-end demo trên Windows: keygen -> encrypt -> decrypt -> fc /b
$ErrorActionPreference = "Stop"

$ScriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectDir = Split-Path -Parent $ScriptDir
$BuildDir   = Join-Path $ProjectDir "build\windows-release\Release"
$Tool       = Join-Path $BuildDir "rsatool.exe"
$TmpDir     = Join-Path $env:TEMP ("rsatool_demo_" + [System.IO.Path]::GetRandomFileName())

# Cleanup on exit
function Remove-TmpDir { if (Test-Path $TmpDir) { Remove-Item -Recurse -Force $TmpDir } }
Register-EngineEvent PowerShell.Exiting -Action { Remove-TmpDir } | Out-Null

New-Item -ItemType Directory -Path $TmpDir | Out-Null

if (-not (Test-Path $Tool)) {
    Write-Error "rsatool.exe not found at $Tool. Run build.ps1 first."
    exit 1
}

Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "  rsatool End-to-End Demo (Windows)"
Write-Host "  Temp directory: $TmpDir"
Write-Host "========================================================`n"

# ── Step 1: keygen ────────────────────────────────────────────────────────────
Write-Host "--- Step 1: Key generation (RSA-3072) ---" -ForegroundColor Yellow
& $Tool keygen `
    --bits 3072 `
    --pub  "$TmpDir\pub.pem" `
    --priv "$TmpDir\priv.pem"
Write-Host ""

# ── Step 2: Direct OAEP encrypt ───────────────────────────────────────────────
Write-Host "--- Step 2: Direct RSA-OAEP encrypt (small message) ---" -ForegroundColor Yellow
$SmallMsg = [System.Text.Encoding]::ASCII.GetBytes("Hello RSA-OAEP World! This is 32b")
[System.IO.File]::WriteAllBytes("$TmpDir\small.bin", $SmallMsg)

& $Tool encrypt `
    --in    "$TmpDir\small.bin" `
    --pub   "$TmpDir\pub.pem" `
    --out   "$TmpDir\small.enc" `
    --mode  direct `
    --encode base64
Write-Host ""

# ── Step 3: Decrypt ───────────────────────────────────────────────────────────
Write-Host "--- Step 3: Decrypt ---" -ForegroundColor Yellow
& $Tool decrypt `
    --in    "$TmpDir\small.enc" `
    --priv  "$TmpDir\priv.pem" `
    --out   "$TmpDir\small.dec" `
    --encode base64
Write-Host ""

# ── Step 4: Verify ────────────────────────────────────────────────────────────
Write-Host "--- Step 4: Verify (fc /b) ---" -ForegroundColor Yellow
$fcResult = & fc /b "$TmpDir\small.bin" "$TmpDir\small.dec" 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-Host "PASS: Decrypted file is byte-identical to original." -ForegroundColor Green
} else {
    Write-Error "FAIL: Files differ!`n$fcResult"
    exit 1
}
Write-Host ""

# ── Step 5: Hybrid encrypt ────────────────────────────────────────────────────
Write-Host "--- Step 5: Hybrid encrypt (1 KiB random data) ---" -ForegroundColor Yellow
$randBytes = New-Object byte[] 1024
[System.Security.Cryptography.RandomNumberGenerator]::Fill($randBytes)
[System.IO.File]::WriteAllBytes("$TmpDir\large.bin", $randBytes)

& $Tool encrypt `
    --in    "$TmpDir\large.bin" `
    --pub   "$TmpDir\pub.pem" `
    --out   "$TmpDir\large.enc" `
    --mode  hybrid `
    --encode hex
Write-Host ""

# ── Step 6: Decrypt hybrid ────────────────────────────────────────────────────
Write-Host "--- Step 6: Decrypt hybrid ---" -ForegroundColor Yellow
& $Tool decrypt `
    --in    "$TmpDir\large.enc" `
    --priv  "$TmpDir\priv.pem" `
    --out   "$TmpDir\large.dec" `
    --encode hex
Write-Host ""

# ── Step 7: Verify hybrid ─────────────────────────────────────────────────────
Write-Host "--- Step 7: Verify hybrid (fc /b) ---" -ForegroundColor Yellow
$fcResult2 = & fc /b "$TmpDir\large.bin" "$TmpDir\large.dec" 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-Host "PASS: Hybrid decrypted file is byte-identical." -ForegroundColor Green
} else {
    Write-Error "FAIL: Hybrid files differ!`n$fcResult2"
    exit 1
}
Write-Host ""

# ── Step 8: Wrong label ────────────────────────────────────────────────────────
Write-Host "--- Step 8: Wrong label test (must fail) ---" -ForegroundColor Yellow
& $Tool encrypt `
    --in    "$TmpDir\small.bin" `
    --pub   "$TmpDir\pub.pem" `
    --out   "$TmpDir\labeled.enc" `
    --label "correct-label" `
    --mode  direct

$decFailed = $false
try {
    & $Tool decrypt `
        --in    "$TmpDir\labeled.enc" `
        --priv  "$TmpDir\priv.pem" `
        --out   "$TmpDir\labeled.dec" `
        --label "wrong-label"
} catch {
    $decFailed = $true
}
if ($LASTEXITCODE -ne 0 -or $decFailed) {
    Write-Host "PASS: Wrong label correctly rejected." -ForegroundColor Green
} else {
    Write-Error "FAIL: Wrong label should have failed!"
    exit 1
}
Write-Host ""

Remove-TmpDir
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "  All demo steps PASSED" -ForegroundColor Green
Write-Host "========================================================"

