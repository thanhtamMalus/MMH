# RUN (Windows) – Hướng dẫn build, test và chạy aestool

Tài liệu này dành cho Windows 10/11. Có hai cách build, chọn **một** trong hai:

- **Cách A: MSVC + vcpkg** (PowerShell). Dễ cài DLL, khuyên dùng nếu đã có Visual Studio.
- **Cách B: MinGW64 (MSYS2)**. Nhẹ hơn, không cần Visual Studio.

Tất cả lệnh chạy từ thư mục gốc của dự án (`lab1\`).

> Lưu ý quan trọng: thư mục `build\` không dùng chung giữa Windows và Linux. Nếu có `build\` được copy từ máy khác sang, xóa đi trước khi build:
> PowerShell: `Remove-Item -Recurse -Force build`

---

## Cách A: MSVC + vcpkg

### A1. Cài công cụ (một lần)

1. Cài **Visual Studio 2019/2022** (hoặc *Build Tools*) với workload **Desktop development with C++**.
2. Cài **Git** và **CMake** (CMake có sẵn trong Visual Studio, hoặc cài riêng từ cmake.org).
3. Cài **Python 3** từ python.org (tick *Add Python to PATH*), nếu muốn dùng GUI và vẽ đồ thị.

Mở **Developer PowerShell for VS 2022** (hoặc 2019), rồi cài Crypto++ và Catch2 bằng vcpkg:

```powershell
git clone https://github.com/microsoft/vcpkg C:\vcpkg
C:\vcpkg\bootstrap-vcpkg.bat
C:\vcpkg\vcpkg install cryptopp:x64-windows catch2:x64-windows
```

Nếu không muốn cài vcpkg, có thể bỏ qua bước này: để `AESTOOL_FETCH_DEPS=ON` (mặc định), CMake sẽ tự tải Crypto++ và Catch2 khi có mạng (build lâu hơn lần đầu).

### A2. Build và test

```powershell
git clone <repo-url>
cd lab1
cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

Nếu không dùng vcpkg, bỏ tham số `-DCMAKE_TOOLCHAIN_FILE=...`.

Các file sau khi build:

| File | Mô tả |
|---|---|
| `build\bin\Release\aestool.exe` | Chương trình dòng lệnh chính |
| `build\bin\Release\aescore_tests.exe` | File test Catch2 |
| `build\bin\Release\aescore.dll` | Thư viện chia sẻ (GUI gọi qua `ctypes`) |
| `build\lib\Release\aescore_static.lib` | Thư viện tĩnh |

### A3. Đặt alias cho gõ ngắn

```powershell
Set-Alias aestool .\build\bin\Release\aestool.exe
aestool help
```

Alias chỉ có hiệu lực trong cửa sổ PowerShell hiện tại.

---

## Cách B: MinGW64 (MSYS2)

### B1. Cài công cụ (một lần)

1. Cài **MSYS2** từ msys2.org.
2. Mở shell **MSYS2 MINGW64** (không phải MSYS hay UCRT64), rồi chạy:

```bash
pacman -S --needed mingw-w64-x86_64-gcc mingw-w64-x86_64-cmake mingw-w64-x86_64-ninja \
                   mingw-w64-x86_64-crypto++ mingw-w64-x86_64-catch git
```

Muốn chạy file `.exe` ngoài MSYS2 (ví dụ từ PowerShell hoặc GUI), thêm `C:\msys64\mingw64\bin` vào biến môi trường `PATH`.

### B2. Build và test

```bash
git clone <repo-url>
cd lab1
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
```

Các file sau khi build:

| File | Mô tả |
|---|---|
| `build/bin/aestool.exe` | Chương trình dòng lệnh chính |
| `build/bin/aescore_tests.exe` | File test Catch2 (link tĩnh với MinGW) |
| `build/bin/aescore.dll` | Thư viện chia sẻ |

### B3. Alias

```bash
alias aestool=./build/bin/aestool.exe
aestool help
```

---

## Kết quả test mong đợi

```
1/2 Test #1: nist_kat .... Passed
2/2 Test #2: unit_tests .. Passed
100% tests passed, 0 tests failed out of 2
```

Từ đây trở xuống, lệnh viết cho **PowerShell** (cách A). Với MinGW (cách B) dùng cú pháp bash tương tự, chỉ khác đường dẫn file chạy.

---

## 1. Thử nhanh các chức năng (PowerShell)

```powershell
# Sinh khóa AES-256 (nhị phân 32 byte) và dạng hex
aestool keygen --bits 256 --out key.bin
aestool keygen --bits 256 --format hex --out key.hex

# Tạo file thử
"Xin chào, đây là thông điệp bí mật" | Out-File -Encoding utf8 msg.txt

# Mã hóa / giải mã GCM (IV tự sinh, lưu trong header)
aestool encrypt --mode gcm --key key.bin --in msg.txt --out ct.bin
aestool decrypt --mode gcm --key key.bin --in ct.bin --out out.txt
type out.txt

# Dùng --text, AAD, hiển thị Base64
aestool encrypt --mode gcm --key key.bin --text "hello" --aad-text "v1" --out ct.bin --encode base64
aestool decrypt --mode gcm --key key.bin --in ct.bin

# Không có --out: in hex ra màn hình, rồi giải mã lại từ chuỗi hex
aestool encrypt --mode ctr --key key.bin --text "abc" > ct.hex
aestool decrypt --key key.bin --text (Get-Content ct.hex)

# Thử các mode
foreach ($m in "ecb","cbc","ofb","cfb","ctr","ccm","gcm") {
  aestool encrypt --mode $m --key key.bin --in msg.txt --out "ct.$m"
}
aestool keygen --bits 512 --out xts.key
aestool encrypt --mode xts --key xts.key --in msg.txt --out ct.xts

# Sidecar JSON
aestool encrypt --mode gcm --key key.bin --in msg.txt --out ct.raw --sidecar ct.json
aestool decrypt --key key.bin --in ct.raw --sidecar ct.json --out out.txt
```

Lưu ý:

- ECB bị từ chối với dữ liệu lớn hơn 16 KiB, phải thêm `--allow-ecb`.
- Dùng `>` trong PowerShell 5.1 có thể ghi file UTF-16. Nếu `ct.hex` bị lỗi khi đọc lại, dùng: `aestool encrypt ... | Out-File -Encoding ascii ct.hex`.

## 2. Kiểm tra vector NIST (KAT)

```powershell
aestool --kat vectors\nist_vectors.json
```

Mỗi case in `[PASS]` hoặc `[FAIL]`, cuối cùng có bảng tổng kết theo từng mode.

## 3. Negative test (chứng minh từ chối dữ liệu sai)

```powershell
aestool keygen --bits 256 --out key2.bin
aestool encrypt --mode gcm --key key.bin --in msg.txt --out ct.bin

# Sai key -> AUTHENTICATION FAILED, mã thoát 3, không tạo file bad.txt
aestool decrypt --key key2.bin --in ct.bin --out bad.txt ; "exit=$LASTEXITCODE"

# Sai IV
aestool decrypt --key key.bin --in ct.bin --iv-hex 000000000000000000000000 --out bad.txt

# Sửa 1 byte ciphertext -> bị từ chối
Copy-Item ct.bin tampered.bin
$b = [System.IO.File]::ReadAllBytes("tampered.bin")
$b[$b.Length - 1] = $b[$b.Length - 1] -bxor 0xFF
[System.IO.File]::WriteAllBytes("tampered.bin", $b)
aestool decrypt --key key.bin --in tampered.bin --out bad.txt

# IV sai độ dài -> mã thoát 2
aestool encrypt --mode gcm --key key.bin --in msg.txt --out x.bin --iv-hex 0011223344

# Dùng lại nonce -> lần thứ hai bị REFUSED
aestool encrypt --mode gcm --key key.bin --in msg.txt --out n.bin --nonce-hex 000102030405060708090a0b
aestool encrypt --mode gcm --key key.bin --in msg.txt --out n.bin --nonce-hex 000102030405060708090a0b

# ECB file lớn
$r = New-Object byte[] 20000
(New-Object System.Random).NextBytes($r)
[System.IO.File]::WriteAllBytes("big.bin", $r)
aestool encrypt --mode ecb --key key.bin --in big.bin --out e.bin               # REFUSED
aestool encrypt --mode ecb --key key.bin --in big.bin --out e.bin --allow-ecb   # cho phép
```

Các negative test này cũng nằm trong `aescore_tests`, nên `ctest` đã chạy chúng.

## 4. Benchmark và vẽ đồ thị

Trước khi đo: vào **Power Options** và chọn **High performance** (hoặc *Ultimate Performance*), cắm sạc nếu dùng laptop.

```powershell
aestool bench --quick                       # chạy thử vài chục giây
aestool bench --csv bench_windows.csv       # đầy đủ: 8 mode x 6 kích thước, 30 lần lặp
aestool bench --runs 100 --warmup 2 --csv bench_100.csv
aestool bench --op decrypt --csv bench_dec.csv
aestool bench --with-io --csv bench_io.csv
aestool bench --modes gcm,ctr --sizes 1k,1m --runs 50

pip install matplotlib
python scripts\plot_bench.py bench_windows.csv --out plots
```

- Phải build **Release**. Bản Debug chậm hơn nhiều và được cảnh báo ở đầu kết quả.
- So sánh Windows/Linux: chạy cùng lệnh trên cả hai hệ điều hành rồi đưa cả hai CSV vào script:

  ```powershell
  python scripts\plot_bench.py bench_linux.csv bench_windows.csv --out plots
  ```

## 5. Chạy GUI

```powershell
python aestool_gui.py
```

GUI cần `aescore.dll`. Nếu chưa có, script sẽ tự build lần đầu (cần CMake và compiler trong `PATH`, nên chạy từ Developer PowerShell hoặc MSYS2 MINGW64). Nếu không tìm thấy thư viện, chỉ đường dẫn tay:

```powershell
$env:AESCORE_LIB = "$PWD\build\bin\Release\aescore.dll"
python aestool_gui.py
```

Với MinGW: `$env:AESCORE_LIB = "$PWD\build\bin\aescore.dll"`.

Tkinter có sẵn trong bản Python cài từ python.org. GUI chỉ gọi thư viện đã biên dịch (qua `ctypes`), không cài lại thuật toán mật mã.

Lưu ý: Python và `aescore.dll` phải cùng kiến trúc (cùng 64-bit). Nếu báo `OSError: ... is not a valid Win32 application`, kiểm tra lại cả hai đều là x64.

## 6. Chạy riêng test Catch2

```powershell
.\build\bin\Release\aescore_tests.exe              # chạy tất cả
.\build\bin\Release\aescore_tests.exe -s           # in cả assertion thành công
.\build\bin\Release\aescore_tests.exe --list-tests # liệt kê test case

ctest --test-dir build -C Release -R unit_tests -V
ctest --test-dir build -C Release -R nist_kat -V
```

Với MinGW: bỏ `Release\` và `-C Release`.

## 7. Cấu hình CMake

| Option | Mặc định | Ý nghĩa |
|---|---|---|
| `AESTOOL_BUILD_TESTS` | ON | Build test Catch2 và đăng ký ctest |
| `AESTOOL_BUILD_SHARED` | ON | Build `aescore.dll` có C API |
| `AESTOOL_FETCH_DEPS` | ON | Tự tải Crypto++ / Catch2 nếu máy chưa có (cần git và internet) |
| `AESTOOL_USE_LOCAL_CRYPTOPP` | ON | Chỉ áp dụng cho Linux/macOS, Windows bỏ qua `crypto_libs/` |

## 8. Xử lý sự cố

| Triệu chứng | Cách xử lý |
|---|---|
| `CMakeCache.txt directory is different` | Xóa `build\` rồi build lại |
| `Crypto++ was not found` | Cài qua vcpkg/pacman, hoặc để `AESTOOL_FETCH_DEPS=ON` và có mạng |
| Lỗi `cryptopp/xts.h` / `XTS_Mode` không tồn tại | Crypto++ quá cũ, cần >= 8.2 |
| `Catch2 v3 not found` | Chỉ là cảnh báo, `nist_kat` vẫn chạy. Cài `catch2` qua vcpkg/pacman hoặc có mạng để tự tải |
| `ctest` báo "Test not available" (MSVC) | Thêm `-C Release` |
| Chạy `.exe` báo thiếu `cryptopp-dll.dll` | Dùng toolchain vcpkg (tự sao chép DLL), hoặc cài `cryptopp:x64-windows-static` |
| Chạy file MinGW báo thiếu `libstdc++-6.dll`, `libgcc_s_seh-1.dll`... | Thêm `C:\msys64\mingw64\bin` vào `PATH`, hoặc chạy từ shell MSYS2 MINGW64 |
| Console hiện sai tiếng Việt | Dùng Windows Terminal; tool tự đặt code page UTF-8 |
| PowerShell chặn script (`running scripts is disabled`) | `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` |
| GUI báo `aescore library not found` | Build trước, hoặc đặt `$env:AESCORE_LIB` |
| `AUTHENTICATION FAILED` (mã thoát 3) | Đúng thiết kế: sai khóa, nonce, AAD hoặc dữ liệu bị sửa; không tạo file đầu ra |

## 9. Lưu ý khi commit lên Git

- Thêm vào `.gitignore`: `build/`, `__pycache__/`, `*.pyc`.
- Nếu từng commit `build/`: `git rm -r --cached build`.
- Phải commit: `vectors/nist_vectors.json` (test `nist_kat` đọc file này).
- Windows có thể tự đổi xuống dòng (CRLF). Nếu file vector hoặc script bị lỗi, chạy `git config core.autocrlf input` trước khi clone.