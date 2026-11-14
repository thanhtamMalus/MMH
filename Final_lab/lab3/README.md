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
| OpenSSL | ≥ 4.0 — **CMake tự tìm**, không cần đặt đường dẫn (xem [INSTALL_OPENSSL.md](docs/INSTALL_OPENSSL.md)) |
| **Windows** | MSVC 2022 (Visual Studio 2022), x64 |
| **Linux** | GCC ≥ 11, Ubuntu 22.04+ |

> **OpenSSL được tự động tìm trên mọi máy** (`cmake/RsatoolOpenSSL.cmake`).
> Không cần sửa `CMakeLists.txt`, không cần đường dẫn cố định. Thứ tự tìm:
> `-DOPENSSL_ROOT_DIR` → biến môi trường `OPENSSL_ROOT_DIR` → thư mục trong `PATH` / `LD_LIBRARY_PATH`
> → các thư mục cài đặt quen thuộc (`/opt/openssl*`, `~/openssl*`, `D:/cryptolibrary/openssl*`,
> `C:/Program Files/OpenSSL*`, vcpkg, Homebrew…) → (tuỳ chọn) tự tải & build.
> OpenSSL 3.x / 1.1.x trên hệ thống bị **bỏ qua**, không bao giờ bị chọn nhầm.

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

### Bước 2 — (Không bắt buộc) Chỉ định đường dẫn OpenSSL

Thường **bỏ qua bước này**: CMake tự tìm. Chỉ cần khi OpenSSL 4 nằm ở thư mục "lạ":

**Linux (bash)**
```bash
export OPENSSL_ROOT_DIR=/duong/dan/openssl4      # hoặc truyền: ./scripts/build.sh /duong/dan/openssl4
```

**Windows (PowerShell)**
```powershell
$env:OPENSSL_ROOT_DIR = "D:/duong/dan/openssl4"  # hoặc: .\scripts\build.ps1 -OpenSSLRoot "D:/duong/dan/openssl4"
```

Máy chưa có OpenSSL 4 và có internet + git + perl? Để CMake tự tải & build (vài phút, chỉ lần đầu,
kết quả lưu ở `.deps/` và được dùng lại):

```bash
./scripts/build.sh --auto-openssl                 # Linux
```
```powershell
.\scripts\build.ps1 -AutoBuildOpenSSL             # Windows — chạy trong "x64 Native Tools Command Prompt for VS"
```

---

### Bước 3 — Configure và Build

**Linux (bash)**
```bash
./scripts/build.sh
# hoặc thủ công:
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
```

**Windows (PowerShell)**
```powershell
.\scripts\build.ps1
# hoặc thủ công:
cmake -B build -G "Visual Studio 17 2022" -A x64 -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
```

CMake in ra OpenSSL nào được chọn, ví dụ:
```
-- RSATool: tự tìm thấy OpenSSL 4.0.3 tại /opt/openssl4
-- OpenSSL version : 4.0.3
-- OpenSSL root    : /opt/openssl4
```
(thêm `--verbose` / `-VerboseSearch` để xem các bản bị bỏ qua)

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
