# bench.ps1 — Run benchmarks and generate plots on Windows
$ErrorActionPreference = "Stop"

$ScriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectDir = Split-Path -Parent $ScriptDir
$BuildDir   = Join-Path $ProjectDir "build\windows-release\Release"
$Bench      = Join-Path $BuildDir "bench_rsatool.exe"

if (-not (Test-Path $Bench)) {
    Write-Error "bench_rsatool.exe not found. Run build.ps1 first."
    exit 1
}

Write-Host "=== Running benchmarks ===" -ForegroundColor Cyan
Push-Location $ProjectDir
try {
    & $Bench
    if ($LASTEXITCODE -ne 0) { throw "Benchmark failed" }

    Write-Host "`n=== Generating plots ===" -ForegroundColor Cyan
    $py = Get-Command python -ErrorAction SilentlyContinue
    if ($py) {
        & python bench\plot.py
    } else {
        Write-Warning "python not found. Skipping plots."
        Write-Warning "Install: pip install pandas numpy scipy matplotlib"
    }
} finally {
    Pop-Location
}

Write-Host "`n=== Done. Results in bench\results\ ===" -ForegroundColor Green

