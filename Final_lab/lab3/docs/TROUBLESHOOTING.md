# Xử lý Sự cố (Troubleshooting)

Tài liệu này liệt kê các vấn đề thường gặp khi build và chạy RSATool, kèm nguyên nhân và cách khắc phục.

---

## Mục lục

1. [CMake báo "Không tìm thấy OpenSSL >= 4.0"](#1-cmake-báo-không-tìm-thấy-openssl--40)
2. [`cannot find libcrypto` / Missing DLL trên Windows](#2-cannot-find-libcrypto--missing-dll-trên-windows)
3. [LNK2019 / Library mismatch (Windows)](#3-lnk2019--library-mismatch-windows)
4. [OPENSSL_ROOT_DIR dùng backslash trên Windows](#4-openssl_root_dir-dùng-backslash-trên-windows)
5. [Thiếu thư viện Python cho plot](#5-thiếu-thư-viện-python-cho-plot)
6. [Lỗi phân quyền file khóa (Permission errors)](#6-lỗi-phân-quyền-file-khóa-permission-errors)
7. [Output bị lỗi encoding / garbled (Text-mode I/O)](#7-output-bị-lỗi-encoding--garbled-text-mode-io)

---

## 1. CMake báo "Không tìm thấy OpenSSL >= 4.0"

### Triệu chứng

```
CMake Error at cmake/RsatoolOpenSSL.cmake:...
  Không tìm thấy OpenSSL >= 4.0 trên máy này.
  Đã thấy nhưng BỎ QUA (quá cũ / thiếu thư viện):
      - /usr  (OpenSSL 3.0.13 < 4.0)
```

### Nguyên nhân

Từ phiên bản này CMake **tự dò** OpenSSL (xem `cmake/RsatoolOpenSSL.cmake`) và chỉ chấp nhận bản
>= 4.0 có đủ header + `libcrypto`. OpenSSL 3.x của hệ điều hành bị bỏ qua có chủ đích, nên nếu máy
chưa có OpenSSL 4 ở nơi nào CMake nhìn thấy, build dừng và báo như trên.

### Khắc phục (chọn 1)

**A) Đã cài OpenSSL 4 ở thư mục lạ → chỉ đường dẫn**
```bash
# Linux
cmake -B build -DOPENSSL_ROOT_DIR=/duong/dan/openssl4 -DCMAKE_BUILD_TYPE=Release
```
```powershell
# Windows (dùng dấu / )
cmake -B build -DOPENSSL_ROOT_DIR="D:/duong/dan/openssl4"
```
Thư mục phải chứa `include/openssl/opensslv.h` (bản 4.x) và `lib/libcrypto*`.

**B) Chưa cài → tự tải & build** (cần git, perl, make/nmake, internet; chỉ lần đầu)
```bash
cmake -B build -DRSATOOL_AUTO_BUILD_OPENSSL=ON      # hoặc: ./scripts/build.sh --auto-openssl
```
Kết quả lưu ở `.deps/openssl-<ver>/`, các lần sau tự dùng lại. Trên Windows phải chạy trong
"x64 Native Tools Command Prompt for VS" (cần `nmake`, `cl`).

**C) Tự cài** theo [INSTALL_OPENSSL.md](INSTALL_OPENSSL.md).

### Muốn biết CMake đã xem những đâu?

```bash
cmake -B build -DRSATOOL_OPENSSL_VERBOSE=ON
```

### Lỗi `OPENSSL_ROOT_DIR='...' không dùng được`

Bạn đã chỉ định `-DOPENSSL_ROOT_DIR` nhưng thư mục đó không phải OpenSSL >= 4.0 (thường là trỏ nhầm vào
OpenSSL 3.x, hoặc trỏ vào thư mục `bin/`/`lib/` thay vì thư mục gốc). Biến môi trường `OPENSSL_ROOT_DIR`
sai/cũ thì chỉ bị cảnh báo rồi CMake tự dò tiếp.

### Lỗi `CMakeCache.txt directory ... is different than the directory ...`

Thư mục `build/` được copy từ máy/đường dẫn khác. `scripts/build.sh` và `build.ps1` tự phát hiện và xoá
build cũ; nếu chạy `cmake` thủ công thì `rm -rf build` (Windows: `Remove-Item -Recurse -Force build`).

---

## 2. `cannot find libcrypto` / Missing DLL trên Windows

### Triệu chứng

```
The code execution cannot proceed because libcrypto-4.dll was not found.
```
Hoặc:
```
error while loading shared libraries: libcrypto.so.4: cannot open shared object file
```

### Nguyên nhân (Windows)

Trên Windows, `.exe` tìm DLL trong thư mục của nó trước, sau đó trong `PATH`. Nếu `libcrypto-4.dll` và `libssl-4.dll` không nằm cùng thư mục với `rsatool.exe`, chương trình sẽ không khởi động được.

### Khắc phục (Windows)

**Cách 1 — Post-build copy (tự động):**

Module `cmake/RsatoolOpenSSL.cmake` tự tìm `libcrypto*.dll` trong `<OpenSSL root>/bin` và copy cạnh
`rsatool.exe`, `test_rsatool.exe`, `bench_rsatool.exe`. CMake in dòng `OpenSSL DLL : ...` khi configure.
Nếu thấy cảnh báo "Không thấy libcrypto*.dll", hãy dùng Cách 2 hoặc 3.

**Cách 2 — Copy thủ công:**
```powershell
Copy-Item "D:\cryptolibrary\openssl403\bin\libssl-4.dll"   .\build\Release\
Copy-Item "D:\cryptolibrary\openssl403\bin\libcrypto-4.dll" .\build\Release\
```

**Cách 3 — Thêm vào PATH:**
```powershell
$env:PATH = "D:\cryptolibrary\openssl403\bin;" + $env:PATH
```

### Khắc phục (Linux)

File chạy đã được gắn `RUNPATH` = `$ORIGIN` + thư mục `lib` của OpenSSL lúc build (kiểm tra:
`readelf -d build/linux-release/rsatool | grep RUNPATH`), nên thường không cần `LD_LIBRARY_PATH`.
Nếu copy file chạy sang máy khác, hoặc OpenSSL bị di chuyển, dùng một trong các cách sau, hoặc
build với `--static` (`-DRSATOOL_OPENSSL_STATIC=ON`) để không phụ thuộc `libcrypto.so`:

```bash
export LD_LIBRARY_PATH=/duong/dan/openssl4/lib:$LD_LIBRARY_PATH
```

Hoặc cấu hình `ldconfig`:
```bash
echo "/duong/dan/openssl4/lib" | sudo tee /etc/ld.so.conf.d/openssl4.conf
sudo ldconfig
```

---

## 3. LNK2019 / Library mismatch (Windows)

### Triệu chứng

```
error LNK2019: unresolved external symbol EVP_PKEY_CTX_new_from_name referenced in ...
LINK : fatal error LNK1120: 1 unresolved externals
```

Hoặc:
```
LINK : warning LNK4098: defaultlib 'LIBCMT' conflicts with use of other libs
```

### Nguyên nhân

Linker đang link với `libcrypto.lib` của OpenSSL 3.x (hoặc 1.1.x) thay vì 4.x. Các symbol như `EVP_PKEY_CTX_new_from_name` chỉ có trong OpenSSL ≥ 3.x/4.x, nhưng cũng có thể bị thiếu nếu link nhầm phiên bản.

### Khắc phục

1. Xóa cache CMake:
   ```powershell
   Remove-Item -Recurse -Force build\
   ```

2. Kiểm tra `OPENSSL_ROOT_DIR` trỏ đúng vào OpenSSL 4.x:
   ```powershell
   $env:OPENSSL_ROOT_DIR = "D:/cryptolibrary/openssl403"
   Get-ChildItem "D:\cryptolibrary\openssl403\lib\libcrypto.lib"  # phải tồn tại
   ```

3. Configure lại:
   ```powershell
   cmake -B build -G "Visual Studio 17 2022" -A x64 `
         -DOPENSSL_ROOT_DIR="D:/cryptolibrary/openssl403"
   ```

4. Kiểm tra output CMake:
   ```
   -- Found OpenSSL: D:/cryptolibrary/openssl403/lib/libssl.lib (found version "4.0.0")
   ```

---

## 4. OPENSSL_ROOT_DIR dùng backslash trên Windows

### Triệu chứng

```
CMake Error: The source directory "D:\cryptolibrary\openssl403" does not exist.
```
Hoặc CMake không tìm được OpenSSL dù đường dẫn trông đúng.

### Nguyên nhân

CMake trên Windows xử lý backslash (`\`) trong string có thể bị interpret là escape character, dẫn đến đường dẫn sai.

### Khắc phục

**Luôn dùng forward slashes** khi truyền path cho CMake hoặc biến môi trường liên quan đến CMake:

```powershell
# ✅ Đúng
$env:OPENSSL_ROOT_DIR = "D:/cryptolibrary/openssl403"

# ❌ Sai (có thể gây lỗi)
$env:OPENSSL_ROOT_DIR = "D:\cryptolibrary\openssl403"
```

Tương tự khi dùng `-D` flag:
```powershell
# ✅ Đúng
cmake -B build -DOPENSSL_ROOT_DIR="D:/cryptolibrary/openssl403"
```

---

## 5. Thiếu thư viện Python cho plot

### Triệu chứng

```
ModuleNotFoundError: No module named 'pandas'
ModuleNotFoundError: No module named 'matplotlib'
```

Khi chạy script benchmark hoặc visualization.

### Nguyên nhân

Các script Python để vẽ đồ thị benchmark yêu cầu các thư viện bên ngoài chưa được cài.

### Khắc phục

```bash
pip install pandas numpy scipy matplotlib
```

Nếu dùng virtual environment:
```bash
python -m venv venv
source venv/bin/activate        # Linux
.\venv\Scripts\Activate.ps1    # Windows

pip install pandas numpy scipy matplotlib
```

Kiểm tra sau cài đặt:
```bash
python -c "import pandas, numpy, scipy, matplotlib; print('OK')"
```

---

## 6. Lỗi phân quyền file khóa (Permission errors)

### Triệu chứng

**Linux:**
```
[WARNING] Cannot set permissions on private key file. Manual chmod recommended.
```
Hoặc khi đọc key của người khác:
```
[ERROR] Permission denied: ./keys/other_private.pem
```

**Windows:**
```
[WARNING] Cannot restrict permissions on private key: keys\mykey_private.pem.
         Consider restricting access manually via file Properties > Security.
```

### Nguyên nhân & Hành vi mặc định

| Hệ điều hành | Hành vi |
|-------------|---------|
| **Linux** | RSATool tự động gọi `chmod(path, 0600)` sau khi ghi private key. Nếu gọi thất bại (ví dụ: filesystem FAT32), in cảnh báo. |
| **Windows** | Windows không có API `chmod` POSIX tương đương đơn giản. RSATool in cảnh báo và khuyến nghị user tự restrict quyền. |

### Khắc phục thủ công

**Linux:**
```bash
chmod 0600 ./keys/mykey_private.pem
ls -la ./keys/mykey_private.pem
# → -rw------- 1 user user ... mykey_private.pem
```

**Windows (PowerShell — restrict quyền):**
```powershell
$path = ".\keys\mykey_private.pem"
$acl = Get-Acl $path
$acl.SetAccessRuleProtection($true, $false)   # Xóa inherited rules
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    $env:USERNAME, "FullControl", "Allow")
$acl.SetAccessRule($rule)
Set-Acl $path $acl
```

---

## 7. Output bị lỗi encoding / garbled (Text-mode I/O)

### Triệu chứng

File giải mã ra bị thiếu bytes, hoặc dữ liệu binary bị hỏng khi đọc/ghi qua stdin/stdout/file trên Windows:

```
[ERROR] Decrypted data integrity check failed.
```

Hoặc file output nhỏ hơn plaintext gốc không rõ lý do.

### Nguyên nhân

Trên Windows, nếu file hoặc stream được mở ở chế độ **text mode** (mặc định), các byte `0x0D 0x0A` (CRLF) bị convert thành `0x0A` (LF) khi đọc, và ngược lại khi ghi. Điều này làm hỏng dữ liệu binary (ciphertext, keys).

### Khắc phục

RSATool mở **tất cả** file và stream trong binary mode (`std::ios::binary`):

```cpp
// ✅ Đúng — binary mode
std::ifstream fin(path, std::ios::in | std::ios::binary);
std::ofstream fout(path, std::ios::out | std::ios::binary);

// ❌ Sai — text mode (mặc định)
std::ifstream fin(path);
std::ofstream fout(path);
```

Nếu bạn fork và tự sửa code, **luôn thêm `std::ios::binary`** khi mở bất kỳ file nào xử lý dữ liệu mã hóa.

Với stdin/stdout trên Windows (khi dùng pipe):
```cpp
// Chuyển stdin/stdout sang binary mode (Windows only)
#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
_setmode(_fileno(stdin),  _O_BINARY);
_setmode(_fileno(stdout), _O_BINARY);
#endif
```

Đoạn code trên đã được áp dụng trong [`src/main.cpp`](../src/main.cpp).
