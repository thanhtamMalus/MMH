#requires -Version 5.1
# run_all.ps1 - Lab 4: Hashing tool (Windows PowerShell)
# Build -> Test (KAT) -> Benchmark (SHA-2, SHA-3, SHAKE) -> X.509 -> Collect logs
# LUU Y: file nay phai luu dang UTF-8 with BOM (hoac chay bang pwsh 7).

$ErrorActionPreference = "Continue"

# scripts\ nam trong lab root -> lay thu muc cha
$LabDir   = Split-Path -Parent $PSScriptRoot
$BuildDir = Join-Path $LabDir "build"
$DataDir  = Join-Path $LabDir "data"
$ResDir   = Join-Path $LabDir "results"
$LogDir   = Join-Path $LabDir "logs"
$CertDir  = Join-Path $LabDir "certs"

foreach ($d in @($BuildDir, $DataDir, $ResDir, $LogDir, $CertDir)) {
    New-Item -ItemType Directory -Path $d -Force | Out-Null
}

function Find-HashTool {
    $candidates = @(
        (Join-Path $LabDir "bin\hashtool.exe"),
        (Join-Path $LabDir "bin\hashtool"),
        (Join-Path $BuildDir "Release\hashtool.exe"),
        (Join-Path $BuildDir "hashtool.exe")
    )
    foreach ($c in $candidates) { if (Test-Path $c) { return $c } }
    return $null
}

function New-RandomFile([string]$Path, [int]$MiB) {
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $buf = New-Object byte[] (1MB)
    $fs  = [System.IO.File]::Create($Path)
    try {
        for ($i = 0; $i -lt $MiB; $i++) {
            $rng.GetBytes($buf)
            $fs.Write($buf, 0, $buf.Length)
        }
    } finally { $fs.Close(); $rng.Dispose() }
}

Write-Host "=== LAB 4 RUN ALL ===" -ForegroundColor Cyan
Write-Host "Thu muc lam viec: $LabDir"

# ---- Buoc 0: Kiem tra OpenSSL ----
Write-Host "`n--- Buoc 0: Kiem tra OpenSSL version ---" -ForegroundColor Cyan
$OpenSslVer = (& openssl version -a 2>&1) -join "`n"
Write-Host "OpenSSL: $OpenSslVer"
if ($OpenSslVer -match "OpenSSL [34]\.") {
    Write-Host "OK OpenSSL version hop le (>= 3.0)" -ForegroundColor Green
} else {
    Write-Host "! Canh bao: OpenSSL khong phai la 4.0.3 hoac 3.x." -ForegroundColor Yellow
    Write-Host "  Hay dat bien moi truong OPENSSL_ROOT_DIR tro toi thu muc OpenSSL cua ban."
}

# ---- Buoc 1: Build ----
Write-Host "`n--- Buoc 1: Build ---" -ForegroundColor Cyan
Push-Location $BuildDir
$cmakeArgs = @("..", "-DCMAKE_BUILD_TYPE=Release")
if ($env:OPENSSL_ROOT_DIR) { $cmakeArgs += "-DOPENSSL_ROOT_DIR=$($env:OPENSSL_ROOT_DIR)" }
& cmake @cmakeArgs 2>&1
& cmake --build . --config Release 2>&1
Pop-Location
Write-Host "Build hoan tat." -ForegroundColor Green

$Bin = Find-HashTool
if (-not $Bin) {
    Write-Host "! Khong tim thay hashtool. Vui long kiem tra loi build." -ForegroundColor Red
    return
}
Write-Host "Su dung binary: $Bin"

# ---- Buoc 2: KAT ----
Write-Host "`n--- Buoc 2: Chay KAT ---" -ForegroundColor Cyan
Set-Location $LabDir
& $Bin --kat (Join-Path $LabDir "vectors\vectors.json") *> (Join-Path $LogDir "kat_run.log")
Write-Host "Log KAT duoc luu tai: $LogDir\kat_run.log" -ForegroundColor Green

# ---- Buoc 3: Benchmark ----
Write-Host "`n--- Buoc 3: Benchmark ---" -ForegroundColor Cyan
$f1m   = Join-Path $DataDir "test_1m.bin"
$f100m = Join-Path $DataDir "test_100m.iso"
$f1g   = Join-Path $DataDir "test_1g.iso"
if (-not (Test-Path $f1m))   { Write-Host "Tao file 1 MiB...";   New-RandomFile $f1m 1 }
if (-not (Test-Path $f100m)) { Write-Host "Tao file 100 MiB..."; New-RandomFile $f100m 100 }
if (-not (Test-Path $f1g))   { Write-Host "Tao file 1 GiB...";   New-RandomFile $f1g 1024 }

# BO SUNG: Them toan bo cac thuat toan trong yeu cau cua Lab 4
$benchmarks = @(
    # SHA-2 Family
    @{ Name="SHA-224 (1 MiB)";            Args=@("--algo","sha224","--in",$f1m,"--bench","100");                 Out="sha224_1m.csv" },
    @{ Name="SHA-256 (1 MiB)";            Args=@("--algo","sha256","--in",$f1m,"--bench","100");                 Out="sha256_1m.csv" },
    @{ Name="SHA-384 (1 MiB)";            Args=@("--algo","sha384","--in",$f1m,"--bench","100");                 Out="sha384_1m.csv" },
    @{ Name="SHA-512 (1 MiB)";            Args=@("--algo","sha512","--in",$f1m,"--bench","100");                 Out="sha512_1m.csv" },
    
    # SHA-3 Family
    @{ Name="SHA3-224 (1 MiB)";           Args=@("--algo","sha3-224","--in",$f1m,"--bench","100");               Out="sha3-224_1m.csv" },
    @{ Name="SHA3-256 (1 MiB)";           Args=@("--algo","sha3-256","--in",$f1m,"--bench","100");               Out="sha3-256_1m.csv" },
    @{ Name="SHA3-384 (1 MiB)";           Args=@("--algo","sha3-384","--in",$f1m,"--bench","100");               Out="sha3-384_1m.csv" },
    @{ Name="SHA3-512 (1 MiB)";           Args=@("--algo","sha3-512","--in",$f1m,"--bench","100");               Out="sha3-512_1m.csv" },
    
    # SHAKE Family (Kiem tra chuc nang Extendable-Output bang flag --outlen)
    @{ Name="SHAKE128 (1 MiB - outlen 64)"; Args=@("--algo","shake128","--outlen","64","--in",$f1m,"--bench","100"); Out="shake128_1m.csv" },
    @{ Name="SHAKE256 (1 MiB - outlen 128)";Args=@("--algo","shake256","--outlen","128","--in",$f1m,"--bench","100"); Out="shake256_1m.csv" },
    
    # Large Files & Streaming 
    @{ Name="SHA-256 (100 MiB stream)";   Args=@("--algo","sha256","--in",$f100m,"--stream","--bench","100");    Out="sha256_100m_stream.csv" },
    @{ Name="SHA-512 (1 GiB stream)";     Args=@("--algo","sha512","--in",$f1g,"--stream","--bench","100");      Out="sha512_1g_stream.csv" },
    @{ Name="SHA-256 (1 GiB mmap)";       Args=@("--algo","sha256","--in",$f1g,"--mmap","--bench","100");        Out="sha256_1g_mmap.csv" }
)

foreach ($b in $benchmarks) {
    Write-Host "Dang chay Benchmark $($b.Name), 100 vong..."
    & $Bin @($b.Args) *> (Join-Path $ResDir $b.Out)
}
Write-Host "Hoan thanh Benchmark. Ket qua nam trong thu muc $ResDir" -ForegroundColor Green

# ---- Buoc 4: X.509 ----
Write-Host "`n--- Buoc 4: Kiem tra chung chi X.509 ---" -ForegroundColor Cyan
$valid = Join-Path $CertDir "cert.pem"
if (-not (Test-Path $valid)) { $valid = Join-Path $CertDir "valid.crt" }
if (Test-Path $valid) {
    Write-Host "Trich xuat thong tin Subject/Issuer tu cert hop le..."
    & $Bin --algo x509 --in $valid --out (Join-Path $ResDir "valid_cert_info.txt") 2>&1

    Write-Host "Chay negative test: tampered cert (chung chi bi chinh sua)..."
    $tampered = Join-Path $CertDir "tampered.crt"
    # decode PEM -> DER, flip the last byte (inside the signature value), re-encode as PEM
    $b64 = ((Get-Content $valid) | Where-Object { $_ -notmatch "-----" }) -join ""
    $der = [Convert]::FromBase64String($b64)
    $der[$der.Length - 1] = $der[$der.Length - 1] -bxor 0xFF
    $lines = [Convert]::ToBase64String($der, [Base64FormattingOptions]::InsertLineBreaks)
    Set-Content -Path $tampered -Value ("-----BEGIN CERTIFICATE-----`n" + $lines + "`n-----END CERTIFICATE-----") -Encoding ASCII
    & $Bin --algo x509 --in $tampered --out (Join-Path $ResDir "tampered_info.txt") 2>&1

    $expired = Join-Path $CertDir "expired.crt"
    if (Test-Path $expired) {
        Write-Host "Chay negative test: expired cert (chung chi het han)..."
        & $Bin --algo x509 --in $expired --out (Join-Path $ResDir "expired_info.txt") 2>&1
    }
} else {
    Write-Host "! Khong tim thay $valid, bo qua buoc test X.509." -ForegroundColor Yellow
}

# ---- Buoc 5: Tom tat ----
Write-Host "`n=== KET QUA TONG HOP ===" -ForegroundColor Cyan
Write-Host "Log KAT: $LogDir\kat_run.log"
Write-Host "File Benchmark CSV:"
$csv = Get-ChildItem "$ResDir\*.csv" -ErrorAction SilentlyContinue
if ($csv) { $csv | ForEach-Object { Write-Host "  $($_.Name)" } } else { Write-Host "  (Khong co file CSV)" -ForegroundColor Yellow }
Write-Host "Thong tin X.509 txt:"
$txt = Get-ChildItem "$ResDir\*.txt" -ErrorAction SilentlyContinue
if ($txt) { $txt | ForEach-Object { Write-Host "  $($_.Name)" } } else { Write-Host "  (Khong co file txt)" -ForegroundColor Yellow }

Write-Host "`n=== HOAN THANH run_all.ps1 ===" -ForegroundColor Cyan