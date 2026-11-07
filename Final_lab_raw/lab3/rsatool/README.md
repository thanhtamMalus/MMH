# RSATool — Công cụ mã hóa RSA-OAEP & Hybrid Encryption CLI

RSATool là công cụ dòng lệnh (CLI) viết bằng C++17, sử dụng OpenSSL ≥ 4.0, hỗ trợ hai chế độ mã hóa:

| Chế độ | Tên Envelope | Mô tả |
|--------|-------------|-------|
| **Direct** | `RSA-OAEP` | Mã hóa trực tiếp bằng khóa công khai RSA-OAEP. Phù hợp cho dữ liệu nhỏ (≤ giới hạn OAEP). |
| **Hybrid** | `RSA-OAEP-AES-GCM` | Sinh AES-256-GCM key ngẫu nhiên, mã hóa dữ liệu bằng AES-GCM, bọc key bằng RSA-OAEP. Phù hợp cho file lớn tùy ý. |

---

## Yêu cầu hệ thống

| Thành phần | Yêu cầu tối thiểu |
|------------|-------------------|
| C++ Standard | C++17 |
| CMake | ≥ 3.20 |
| OpenSSL | ≥ 4.0 (xem [INSTALL_OPENSSL.md](docs/INSTALL_OPENSSL.md)) |
| **Windows** | MSVC 2022 (Visual Studio 2022), x64 |
| **Linux** | GCC ≥ 11, Ubuntu 22.04+ |

> **Vị trí OpenSSL mặc định:**
> - Windows: `D:/cryptolibrary/openssl403`
> - Linux: `/opt/openssl4`

---

## Cấu trúc thư mục

```
rsatool/
├── CMakeLists.txt          # Build script chính
├── README.md               # Tài liệu này
├── src/
│   ├── main.cpp            # Entry point, CLI parsing
│   ├── keygen.cpp/.h       # Sinh cặp khóa RSA
│   ├── encrypt.cpp/.h      # Mã hóa (direct + hybrid)
│   ├── decrypt.cpp/.h      # Giải mã (direct + hybrid)
│   ├── envelope.cpp/.h     # Đọc/ghi envelope format
│   └── utils.cpp/.h        # Tiện ích chung
├── docs/
│   ├── INSTALL_OPENSSL.md  # Hướng dẫn cài đặt OpenSSL 4.x
│   ├── USAGE.md            # Hướng dẫn sử dụng chi tiết
│   └── TROUBLESHOOTING.md  # Xử lý sự cố
└── tests/
    └── ...                 # Unit tests & integration tests
```

---

## Quick Start

### Bước 1 — Clone repository

**Linux (bash)**
```bash
git clone <repo-url> rsatool
cd rsatool
```

**Windows (PowerShell)**
```powershell
git clone <repo-url> rsatool
cd rsatool
```

---

### Bước 2 — Chỉ định đường dẫn OpenSSL

**Linux (bash)**
```bash
export OPENSSL_ROOT_DIR=/opt/openssl4
```

**Windows (PowerShell)**
```powershell
$env:OPENSSL_ROOT_DIR = "D:/cryptolibrary/openssl403"
```

---

### Bước 3 — Configure và Build

**Linux (bash)**
```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
```

**Windows (PowerShell — chạy trong "x64 Native Tools Command Prompt for VS 2022")**
```powershell
cmake -B build -G "Visual Studio 17 2022" -A x64 -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
```

---

### Bước 4 — Demo nhanh

#### 4a. Sinh cặp khóa RSA-4096

**Linux**
```bash
./build/rsatool keygen --bits 4096 --out keys/
```

**Windows**
```powershell
.\build\Release\rsatool.exe keygen --bits 4096 --out keys\
```

#### 4b. Mã hóa tin nhắn nhỏ (direct RSA-OAEP)

**Linux**
```bash
echo "Hello RSA!" | ./build/rsatool encrypt \
    --pubkey keys/public.pem \
    --mode direct \
    --label "demo" \
    --out cipher.bin
```

**Windows**
```powershell
"Hello RSA!" | .\build\Release\rsatool.exe encrypt `
    --pubkey keys\public.pem `
    --mode direct `
    --label "demo" `
    --out cipher.bin
```

#### 4c. Giải mã

**Linux**
```bash
./build/rsatool decrypt \
    --privkey keys/private.pem \
    --in cipher.bin \
    --label "demo"
```

**Windows**
```powershell
.\build\Release\rsatool.exe decrypt `
    --privkey keys\private.pem `
    --in cipher.bin `
    --label "demo"
```

#### 4d. Mã hóa file lớn (hybrid AES-GCM)

**Linux**
```bash
./build/rsatool encrypt \
    --pubkey keys/public.pem \
    --mode hybrid \
    --in bigfile.dat \
    --out bigfile.enc
```

**Windows**
```powershell
.\build\Release\rsatool.exe encrypt `
    --pubkey keys\public.pem `
    --mode hybrid `
    --in bigfile.dat `
    --out bigfile.enc
```

---

## Tài liệu

| File | Nội dung |
|------|---------|
| [docs/INSTALL_OPENSSL.md](docs/INSTALL_OPENSSL.md) | Cách build và cài OpenSSL ≥ 4.0 trên Linux & Windows |
| [docs/USAGE.md](docs/USAGE.md) | Toàn bộ subcommand, options, ví dụ có output mẫu |
| [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) | Xử lý các lỗi build và runtime thường gặp |

---

## Envelope Format

- **Direct mode** (`RSA-OAEP`): file output chứa header nhận dạng `RSA-OAEP`, theo sau là ciphertext RSA trực tiếp.
- **Hybrid mode** (`RSA-OAEP-AES-GCM`): file output chứa header nhận dạng `RSA-OAEP-AES-GCM`, wrapped AES key (mã hóa bằng RSA-OAEP), AES-GCM IV/nonce, GCM authentication tag, và ciphertext AES-GCM.

Chi tiết format xem tại [docs/USAGE.md — File Formats](docs/USAGE.md#file-formats).

---

## Tính tương thích

> **Verified on:** Windows 10/11 x64 (MSVC 2022).
>
> **Written to be portable, not verified on:** Linux (Ubuntu 22.04+ expected to work).

---

## License

Dự án này thuộc phạm vi học thuật (Lab 3 — Môn Mật mã học).
