# Hướng dẫn Cài đặt OpenSSL ≥ 4.0

## Mục lục
1. [Tại sao cần OpenSSL ≥ 4.0?](#tại-sao-cần-openssl--40)
2. [Kiểm tra phiên bản hiện tại](#kiểm-tra-phiên-bản-hiện-tại)
3. [Build từ source trên Linux](#build-từ-source-trên-linux)
4. [Build từ source trên Windows](#build-từ-source-trên-windows)
5. [CMake tự tìm OpenSSL như thế nào](#cmake-tự-tìm-openssl-như-thế-nào)
6. [Xác nhận DLL / shared library được load đúng](#xác-nhận-dll--shared-library-được-load-đúng)

---

## Tại sao cần OpenSSL ≥ 4.0?

RSATool sử dụng các API hiện đại của OpenSSL yêu cầu ít nhất phiên bản 4.0:

| Lý do | Chi tiết |
|-------|---------|
| **EVP_PKEY API** | OpenSSL 4.x chuẩn hóa toàn bộ thao tác khóa qua `EVP_PKEY_CTX`. Các API cũ (`RSA_public_encrypt`, v.v.) đã bị loại bỏ. |
| **ENGINE API bị xóa** | OpenSSL 3.x deprecated ENGINE; OpenSSL 4.x xóa hoàn toàn. RSATool không dùng ENGINE, nhưng build với header 3.x sẽ gây cảnh báo/lỗi không tương thích. |
| **Opaque ASN1 structures** | Các struct nội bộ như `RSA`, `EC_KEY` đã hoàn toàn opaque từ 4.x — không thể truy cập trực tiếp trường nội bộ, bắt buộc dùng accessor functions. |
| **OSSL_PARAM API** | OAEP label và các tham số EVP truyền qua `OSSL_PARAM` array — cú pháp chỉ ổn định từ 4.x. |

> **Lưu ý:** OpenSSL 1.1.x và 3.x **không tương thích** với RSATool.

---

## Kiểm tra phiên bản hiện tại

```bash
openssl version
```

Kết quả mong đợi:
```
OpenSSL 4.0.0 ... (Library: OpenSSL 4.0.0 ...)
```

Nếu ra `1.1.x` hoặc `3.x`, hãy build từ source theo hướng dẫn bên dưới.

---

## Build từ source trên Linux

### Yêu cầu
- `git`, `gcc` ≥ 11, `make`, `perl` ≥ 5.10

### Các bước

```bash
# 1. Clone repository OpenSSL
git clone https://github.com/openssl/openssl.git
cd openssl

# 2. Checkout branch/tag 4.0.0
git checkout openssl-4.0.0

# 3. Configure với prefix /opt/openssl4
./Configure --prefix=/opt/openssl4 --libdir=lib

# 4. Build (sử dụng tất cả CPU cores)
make -j$(nproc)

# 5. Cài đặt (cần quyền sudo)
sudo make install
```

### Thiết lập biến môi trường (KHÔNG bắt buộc — CMake tự tìm; chỉ cần nếu cài ở thư mục lạ)

Thêm vào `~/.bashrc` hoặc `~/.zshrc`:

```bash
export OPENSSL_ROOT_DIR=/opt/openssl4
export PATH=/opt/openssl4/bin:$PATH
export LD_LIBRARY_PATH=/opt/openssl4/lib:$LD_LIBRARY_PATH
```

Nạp lại shell:
```bash
source ~/.bashrc
```

Kiểm tra:
```bash
openssl version
# → OpenSSL 4.0.0 ...
```

---

## Build từ source trên Windows

### Yêu cầu
- **Visual Studio 2022** với workload "Desktop development with C++"
- **Perl** (khuyến nghị: [Strawberry Perl](https://strawberryperl.com/))
- **NASM** ([https://www.nasm.us/](https://www.nasm.us/)) — thêm vào PATH

### Các bước (chạy trong "x64 Native Tools Command Prompt for VS 2022")

```cmd
:: 1. Clone và checkout
git clone https://github.com/openssl/openssl.git
cd openssl
git checkout openssl-4.0.0

:: 2. Configure cho Windows x64
perl Configure VC-WIN64A ^
    --prefix=D:\cryptolibrary\openssl403 ^
    --openssldir=D:\cryptolibrary\openssl403\ssl

:: 3. Build
nmake

:: 4. Cài đặt
nmake install
```

### Thiết lập biến môi trường (PowerShell, KHÔNG bắt buộc)

Tạm thời (cho session hiện tại):
```powershell
$env:OPENSSL_ROOT_DIR = "D:/cryptolibrary/openssl403"
$env:PATH = "D:\cryptolibrary\openssl403\bin;" + $env:PATH
```

Vĩnh viễn (System Environment Variables):
```powershell
[System.Environment]::SetEnvironmentVariable(
    "OPENSSL_ROOT_DIR",
    "D:/cryptolibrary/openssl403",
    [System.EnvironmentVariableTarget]::User
)
```

> **Quan trọng:** Dùng **forward slashes** (`D:/cryptolibrary/openssl403`) khi truyền cho CMake, dù đây là Windows. Backslash trong CMake string gây lỗi escaping.

Kiểm tra:
```powershell
& "D:\cryptolibrary\openssl403\bin\openssl.exe" version
# → OpenSSL 4.0.0 ...
```

---

## CMake tự tìm OpenSSL như thế nào

RSATool dùng module `cmake/RsatoolOpenSSL.cmake`. Nó **đọc `opensslv.h`** của từng ứng viên (không chạy
chương trình nào) và chỉ chọn bản >= 4.0 có đủ `libcrypto`, theo thứ tự ưu tiên:

| # | Nguồn | Ghi chú |
|---|-------|---------|
| 1 | `-DOPENSSL_ROOT_DIR=...` | Chỉ định rõ; sai thì **dừng và báo lỗi** |
| 2 | Biến môi trường `OPENSSL_ROOT_DIR`, `OPENSSL_DIR`, `OPENSSL_HOME`, `OPENSSL4_ROOT_DIR` | Sai/cũ thì cảnh báo rồi tự dò tiếp |
| 3 | Lần tìm trước (cache) và `.deps/openssl-*` (do auto-build) | |
| 4 | Thư mục trong `PATH`, `LD_LIBRARY_PATH`, `CMAKE_PREFIX_PATH` (và thư mục cha) | Ví dụ `D:\x\openssl\bin` trong PATH → root là `D:\x\openssl` |
| 5 | Vị trí quen thuộc | `/opt/openssl*`, `/usr/local/openssl*`, `~/openssl*`, Homebrew `openssl@4`, vcpkg, `C:..H:/cryptolibrary/openssl*`, `X:/openssl*`, `X:/Program Files/OpenSSL*` |
| 6 | `/usr/local`, `/usr` | Thường là 3.x → bị loại |
| 7 | Tự tải & build (chỉ khi `-DRSATOOL_AUTO_BUILD_OPENSSL=ON`) | Cần git, perl, make (Windows: nmake) |

Sau khi chọn, CMake kiểm tra chéo rằng `include` và `libcrypto` mà `FindOpenSSL` trả về nằm đúng trong thư mục
đã chọn (tránh lẫn header 4.x với `libcrypto.so.3` hệ thống).

**Các tuỳ chọn:**

| Option | Mặc định | Ý nghĩa |
|--------|----------|---------|
| `RSATOOL_AUTO_BUILD_OPENSSL` | OFF | Không tìm thấy → tải & build OpenSSL ngay lúc configure |
| `RSATOOL_OPENSSL_BUILD_TAG` | `openssl-4.0.3` | Tag git dùng cho auto-build |
| `RSATOOL_OPENSSL_STATIC` | OFF | Liên kết tĩnh `libcrypto` (không cần `.so`/`.dll` khi chạy) |
| `RSATOOL_OPENSSL_VERBOSE` | OFF | In các ứng viên bị bỏ qua |
| `RSATOOL_OPENSSL_MIN_VERSION` | `4.0` | Phiên bản tối thiểu |

**Ví dụ:**

```bash
# Linux — để CMake tự tìm
cmake -B build -DCMAKE_BUILD_TYPE=Release

# Linux — chỉ đường dẫn
cmake -B build -DOPENSSL_ROOT_DIR=/duong/dan/openssl4 -DCMAKE_BUILD_TYPE=Release
```
```powershell
# Windows — để CMake tự tìm
cmake -B build -G "Visual Studio 17 2022" -A x64

# Windows — chỉ đường dẫn (dùng dấu / )
cmake -B build -G "Visual Studio 17 2022" -A x64 -DOPENSSL_ROOT_DIR="D:/duong/dan/openssl4"
```

CMake in ra bản được chọn:
```
-- RSATool: tự tìm thấy OpenSSL 4.0.3 tại /opt/openssl4
-- Found OpenSSL: /opt/openssl4/lib/libcrypto.so (found suitable version "4.0.3", minimum required is "4.0")
-- OpenSSL root    : /opt/openssl4
```

Nếu in ra `3.x` hoặc `1.1.x` → xem [TROUBLESHOOTING.md](TROUBLESHOOTING.md).

---

## Xác nhận DLL / Shared Library được load đúng

### Linux — kiểm tra `ldd`

```bash
ldd ./build/rsatool | grep ssl
# → libssl.so.4 => /opt/openssl4/lib/libssl.so.4 (0x...)
# → libcrypto.so.4 => /opt/openssl4/lib/libcrypto.so.4 (0x...)
```

### Windows — kiểm tra DLL trong thư mục executable

Sau khi build, CMake sẽ tự copy (post-build step):
```
build\Release\
    rsatool.exe
    libssl-4.dll
    libcrypto-4.dll
```

Chạy thử:
```powershell
.\build\Release\rsatool.exe --version
```

Nếu báo lỗi `libcrypto-4.dll not found`, xem [TROUBLESHOOTING.md — DLL Missing](TROUBLESHOOTING.md#2-cannot-find-libcrypto--missing-dll-trên-windows).
