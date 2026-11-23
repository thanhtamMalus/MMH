# Hướng dẫn Sử dụng RSATool

## Mục lục
1. [Tổng quan subcommands](#tổng-quan-subcommands)
2. [Subcommand: `keygen`](#subcommand-keygen)
3. [Subcommand: `encrypt`](#subcommand-encrypt)
4. [Subcommand: `decrypt`](#subcommand-decrypt)
5. [Ví dụ có output mẫu](#ví-dụ-có-output-mẫu)
6. [Exit Codes](#exit-codes)
7. [File Formats](#file-formats)

---

## Tổng quan subcommands

```
rsatool <subcommand> [options]

Subcommands:
  keygen    Sinh cặp khóa RSA (private + public)
  encrypt   Mã hóa dữ liệu (direct RSA-OAEP hoặc hybrid AES-GCM)
  decrypt   Giải mã dữ liệu
```

---

## Subcommand: `keygen`

Sinh cặp khóa RSA và lưu ra file PEM.

### Cú pháp
```
rsatool keygen [options]
```

### Options

| Option | Kiểu | Mặc định | Mô tả |
|--------|------|----------|-------|
| `--bits <n>` | int | `4096` | Độ dài khóa RSA (khuyến nghị: 2048, 3072, 4096) |
| `--out <dir>` | path | `.` | Thư mục lưu file khóa |
| `--name <prefix>` | string | `rsa` | Tiền tố tên file (sinh ra `<prefix>_private.pem` và `<prefix>_public.pem`) |
| `--format <fmt>` | string | `PEM` | Định dạng output: `PEM` hoặc `DER` |
| `--help` | flag | — | In hướng dẫn và thoát |

### Output
- `<out>/<name>_private.pem` — Khóa riêng tư (PKCS#8, PEM)
- `<out>/<name>_public.pem` — Khóa công khai (SubjectPublicKeyInfo, PEM)

> **Linux:** File private key tự động được `chmod 0600`.  
> **Windows:** In cảnh báo nếu file permissions không thể restrict.

---

## Subcommand: `encrypt`

Mã hóa dữ liệu từ stdin hoặc file đầu vào.

### Cú pháp
```
rsatool encrypt [options]
```

### Options

| Option | Kiểu | Mặc định | Mô tả |
|--------|------|----------|-------|
| `--pubkey <path>` | path | — | **[Bắt buộc]** Đường dẫn file public key (PEM hoặc DER) |
| `--in <path>` | path | stdin | File plaintext đầu vào |
| `--out <path>` | path | stdout | File ciphertext đầu ra |
| `--mode <mode>` | string | `auto` | Chế độ: `direct` (RSA-OAEP) hoặc `hybrid` (RSA-OAEP-AES-GCM). `auto` chọn tự động theo kích thước. |
| `--label <str>` | string | `""` | OAEP label (AAD). Phải khớp khi giải mã. |
| `--hash <alg>` | string | `SHA256` | Hash cho OAEP: `SHA256`, `SHA384`, `SHA512` |
| `--help` | flag | — | In hướng dẫn và thoát |

---

## Subcommand: `decrypt`

Giải mã dữ liệu từ file envelope.

### Cú pháp
```
rsatool decrypt [options]
```

### Options

| Option | Kiểu | Mặc định | Mô tả |
|--------|------|----------|-------|
| `--privkey <path>` | path | — | **[Bắt buộc]** Đường dẫn file private key (PEM hoặc DER) |
| `--in <path>` | path | stdin | File ciphertext đầu vào (envelope) |
| `--out <path>` | path | stdout | File plaintext đầu ra |
| `--label <str>` | string | `""` | OAEP label — phải khớp với lúc mã hóa |
| `--help` | flag | — | In hướng dẫn và thoát |

---

## Ví dụ có output mẫu

### Ví dụ 1 — Tin nhắn nhỏ, direct RSA-OAEP

**Linux (bash)**
```bash
# 1. Sinh khóa
./build/rsatool keygen --bits 4096 --out ./keys --name mykey

# 2. Mã hóa
echo -n "Hello RSA!" | ./build/rsatool encrypt \
    --pubkey ./keys/mykey_public.pem \
    --mode direct \
    --label "greeting" \
    --out cipher_direct.bin
```

**Windows (PowerShell)**
```powershell
# 1. Sinh khóa
.\build\Release\rsatool.exe keygen --bits 4096 --out .\keys --name mykey

# 2. Mã hóa
[System.Text.Encoding]::UTF8.GetBytes("Hello RSA!") | `
    .\build\Release\rsatool.exe encrypt `
        --pubkey .\keys\mykey_public.pem `
        --mode direct `
        --label "greeting" `
        --out cipher_direct.bin
```

**Output mẫu (keygen):**
```
[INFO] Generating RSA-4096 key pair...
[INFO] Private key saved: ./keys/mykey_private.pem (chmod 0600 applied)
[INFO] Public  key saved: ./keys/mykey_public.pem
[INFO] Done.
```

**Output mẫu (encrypt):**
```
[INFO] Mode: direct (RSA-OAEP)
[INFO] Plaintext size: 10 bytes
[INFO] OAEP label: "greeting"
[INFO] Ciphertext written: cipher_direct.bin (512 bytes)
[INFO] Envelope type: RSA-OAEP
```

**Giải mã:**

**Linux**
```bash
./build/rsatool decrypt \
    --privkey ./keys/mykey_private.pem \
    --in cipher_direct.bin \
    --label "greeting"
```

**Windows**
```powershell
.\build\Release\rsatool.exe decrypt `
    --privkey .\keys\mykey_private.pem `
    --in cipher_direct.bin `
    --label "greeting"
```

**Output mẫu:**
```
[INFO] Envelope type detected: RSA-OAEP
[INFO] Decrypting with RSA-OAEP (label: "greeting")...
Hello RSA!
[INFO] Plaintext: 10 bytes written to stdout.
```

---

### Ví dụ 2 — File lớn, hybrid RSA-OAEP-AES-GCM

**Linux (bash)**
```bash
# Tạo file test 10MB
dd if=/dev/urandom of=bigfile.dat bs=1M count=10

# Mã hóa hybrid
./build/rsatool encrypt \
    --pubkey ./keys/mykey_public.pem \
    --mode hybrid \
    --in bigfile.dat \
    --out bigfile.enc

# Giải mã
./build/rsatool decrypt \
    --privkey ./keys/mykey_private.pem \
    --in bigfile.enc \
    --out bigfile_dec.dat

# Kiểm tra tính toàn vẹn
sha256sum bigfile.dat bigfile_dec.dat
```

**Windows (PowerShell)**
```powershell
# Tạo file test 10MB
$bytes = New-Object byte[] (10MB)
(New-Object Random).NextBytes($bytes)
[System.IO.File]::WriteAllBytes("bigfile.dat", $bytes)

# Mã hóa hybrid
.\build\Release\rsatool.exe encrypt `
    --pubkey .\keys\mykey_public.pem `
    --mode hybrid `
    --in bigfile.dat `
    --out bigfile.enc

# Giải mã
.\build\Release\rsatool.exe decrypt `
    --privkey .\keys\mykey_private.pem `
    --in bigfile.enc `
    --out bigfile_dec.dat

# Kiểm tra
Get-FileHash bigfile.dat, bigfile_dec.dat -Algorithm SHA256
```

**Output mẫu (encrypt hybrid):**
```
[INFO] Mode: hybrid (RSA-OAEP-AES-GCM)
[INFO] Plaintext size: 10485760 bytes (10.00 MB)
[INFO] Generated AES-256-GCM session key (random).
[INFO] Session key wrapped with RSA-OAEP.
[INFO] AES-GCM IV: a3f1c2...  (12 bytes)
[INFO] Ciphertext written: bigfile.enc (10485876 bytes)
[INFO] Envelope type: RSA-OAEP-AES-GCM
```

**Output mẫu (decrypt hybrid):**
```
[INFO] Envelope type detected: RSA-OAEP-AES-GCM
[INFO] Unwrapping session key with RSA-OAEP...
[INFO] Decrypting with AES-256-GCM...
[INFO] GCM authentication tag: OK
[INFO] Plaintext: 10485760 bytes written to bigfile_dec.dat.
```

---

### Ví dụ 3 — Label sai → thất bại (expected failure)

**Linux (bash)**
```bash
# Mã hóa với label "correct_label"
echo -n "Secret" | ./build/rsatool encrypt \
    --pubkey ./keys/mykey_public.pem \
    --mode direct \
    --label "correct_label" \
    --out secret.bin

# Giải mã với label sai
./build/rsatool decrypt \
    --privkey ./keys/mykey_private.pem \
    --in secret.bin \
    --label "wrong_label"
echo "Exit code: $?"
```

**Windows (PowerShell)**
```powershell
# Mã hóa với label "correct_label"
[System.Text.Encoding]::UTF8.GetBytes("Secret") | `
    .\build\Release\rsatool.exe encrypt `
        --pubkey .\keys\mykey_public.pem `
        --mode direct `
        --label "correct_label" `
        --out secret.bin

# Giải mã với label sai
.\build\Release\rsatool.exe decrypt `
    --privkey .\keys\mykey_private.pem `
    --in secret.bin `
    --label "wrong_label"
Write-Host "Exit code: $LASTEXITCODE"
```

**Output mẫu (expected):**
```
[INFO] Envelope type detected: RSA-OAEP
[INFO] Decrypting with RSA-OAEP (label: "wrong_label")...
[ERROR] RSA-OAEP decryption failed: EVP_PKEY_decrypt() error — decryption error (incorrect label or corrupted ciphertext).
[ERROR] OpenSSL error: error:04000068:...
Exit code: 1
```

> OAEP label không khớp sẽ luôn trả về lỗi xác thực — không có thông tin nào về plaintext bị rò rỉ.

---

## Exit Codes

| Code | Ý nghĩa |
|------|---------|
| `0` | Thành công |
| `1` | Bất kỳ lỗi nào (lỗi file, lỗi mã hóa/giải mã, options không hợp lệ, v.v.) |

---

## File Formats

### PEM / DER Keys

| File | Nội dung |
|------|---------|
| `*_private.pem` | PKCS#8 EncryptedPrivateKeyInfo (PEM, header `-----BEGIN PRIVATE KEY-----`) |
| `*_public.pem` | SubjectPublicKeyInfo (PEM, header `-----BEGIN PUBLIC KEY-----`) |
| `*.der` | Định dạng binary tương đương |

### Envelope Format

#### Direct Mode — `RSA-OAEP`

```
Offset  Length   Field
------  ------   -----
0       4        Magic: "ROAEP" (5 bytes, null-terminated)
5       1        Version: 0x01
6       2        Header length (little-endian uint16)
8       N        JSON header: {"mode":"RSA-OAEP","hash":"SHA256","label_len":5}
8+N     2        Ciphertext length (little-endian uint16)
10+N    M        RSA-OAEP ciphertext (M = key_bits/8 bytes)
```

#### Hybrid Mode — `RSA-OAEP-AES-GCM`

```
Offset  Length   Field
------  ------   -----
0       8        Magic: "ROAEPGCM" (null-terminated)
8       1        Version: 0x01
9       2        Header length (little-endian uint16)
11      N        JSON header: {"mode":"RSA-OAEP-AES-GCM","hash":"SHA256","aes_bits":256}
11+N    2        Wrapped key length (uint16)
13+N    K        RSA-OAEP wrapped AES key
13+N+K  12       AES-GCM IV / Nonce
25+N+K  16       AES-GCM authentication tag (128-bit)
41+N+K  ...      AES-GCM ciphertext (same length as plaintext)
```

### meta.json (optional, sinh kèm nếu dùng `--meta`)

```json
{
  "mode": "RSA-OAEP-AES-GCM",
  "rsa_bits": 4096,
  "aes_bits": 256,
  "hash": "SHA256",
  "label": "",
  "plaintext_size": 10485760,
  "created_at": "2026-11-06T10:00:00Z"
}
```
