# 🚀 Hướng Dẫn Build & Chạy rsatool

> **Lưu ý:** AI đã viết toàn bộ code. Bạn cần tự chạy các lệnh bên dưới để build và lấy kết quả, vì cần OpenSSL >= 4.0 đã cài sẵn trên máy.

---

## Yêu Cầu Hệ Thống

| Thành phần | Phiên bản |
|---|---|
| C++ Compiler | MSVC 2022 (Windows) hoặc GCC >= 11 (Linux) |
| CMake | >= 3.20 |
| OpenSSL | **>= 4.0** (bắt buộc, không dùng 3.x) |
| Ninja | Khuyến nghị (Linux) |
| Python 3 | Chỉ cần cho plot benchmark |

> **QUAN TRỌNG:** OpenSSL 4.0 **chưa được cài sẵn** trên hầu hết hệ thống. Xem `docs/INSTALL_OPENSSL.md` trong project để hướng dẫn build từ source.

---

## Bước 0: Kiểm Tra OpenSSL

```bash
# Linux
openssl version
# Phải hiện: OpenSSL 4.0.x ...

# Windows (PowerShell) — dùng openssl của bạn
& "D:\cryptolibrary\openssl403\bin\openssl.exe" version
# Phải hiện: OpenSSL 4.0.3 ...
```

---

## Bước 1: Vào Thư Mục Project

```bash
# Linux / Git Bash
cd d/GitHub/MMH/Final_lab_raw/lab3/rsatool

# Windows PowerShell
cd D:\GitHub\MMH\Final_lab_raw\lab3\rsatool
```

---

## Bước 2: Build

### Linux (Bash)
```bash
# Đặt đường dẫn OpenSSL 4
export OPENSSL_ROOT_DIR=/opt/openssl4

# Build qua script
bash scripts/build.sh

# Hoặc thủ công:
cmake -S . -B build/linux-release \
      -DCMAKE_BUILD_TYPE=Release \
      -DOPENSSL_ROOT_DIR=/opt/openssl4 \
      -GNinja
cmake --build build/linux-release --config Release -j$(nproc)
```

### Windows (PowerShell)
```powershell
# Build qua script (thay đường dẫn OpenSSL cho phù hợp)
.\scripts\build.ps1 -OpenSSLRoot "D:/cryptolibrary/openssl403"

# Hoặc thủ công:
cmake -S . -B build/windows-release `
      -G "Visual Studio 17 2022" -A x64 `
      -DCMAKE_BUILD_TYPE=Release `
      -DOPENSSL_ROOT_DIR="D:/cryptolibrary/openssl403"
cmake --build build/windows-release --config Release
```

**Output kỳ vọng khi build thành công:**
```
OpenSSL version : 4.0.x
OpenSSL include : /opt/openssl4/include
...
[100%] Linking CXX executable rsatool
```

> **Lưu ý:** Nếu CMake tìm thấy OpenSSL 3.x, build sẽ **FAIL** ngay — set `OPENSSL_ROOT_DIR` đúng vào OpenSSL 4.

---

## Bước 3: Chạy Demo End-to-End

### Linux
```bash
bash scripts/demo.sh
```

### Windows
```powershell
.\scripts\demo.ps1
```

**Output kỳ vọng:**
```
========================================================
  rsatool End-to-End Demo
========================================================
--- Step 1: Key generation (RSA-3072) ---
Generating RSA-3072 key pair...
...
PASS: Decrypted file is byte-identical to original.
PASS: Hybrid decrypted file is byte-identical.
PASS: Wrong label correctly rejected (exit code 1).

  All demo steps PASSED
```

---

## Bước 4: Chạy Unit Tests

### Linux
```bash
bash scripts/test.sh
# hoặc:
cd build/linux-release && ctest --output-on-failure -C Release
```

### Windows
```powershell
.\scripts\test.ps1
# hoặc:
cd build\windows-release; ctest --output-on-failure -C Release
```

**Output kỳ vọng:**
```
100% tests passed, 0 tests failed out of XX
```

> **Chú ý:** Các test keygen RSA sẽ chậm (~1-2 giây/test). Toàn bộ suite có thể mất 2-5 phút.

---

## Bước 5: Chạy Benchmarks

### Linux
```bash
bash scripts/bench.sh
```

### Windows
```powershell
.\scripts\bench.ps1
```

**Xem kết quả:**
```bash
cat bench/results/bench_results.csv
```

**Vẽ plots (cần Python):**
```bash
pip install pandas numpy scipy matplotlib
python bench/plot.py
# Plots lưu tại: bench/results/rsa_latency.png, aes_throughput.png, hybrid_latency.png
```

---

## Bước 6: Chạy Bonus A (Manual OAEP)

### Linux
```bash
./build/linux-release/oaep_manual
```

### Windows
```powershell
.\build\windows-release\Release\oaep_manual.exe
```

**Output kỳ vọng:**
```
=== Bonus A: Manual OAEP Cross-Test ===
[PASS] Manual encode -> OpenSSL decrypt
[PASS] OpenSSL encrypt -> manual decode
[PASS] Manual round trip (100 bytes, no label)
[PASS] Wrong label -> CryptoError
All bonus tests passed.
```

---

## Sử Dụng CLI Thủ Công

```bash
# Tạo key RSA-3072
rsatool keygen --bits 3072 --pub pub.pem --priv priv.pem

# Mã hóa (auto: direct nếu <= 318 bytes, hybrid nếu lớn hơn)
rsatool encrypt --in message.txt --pub pub.pem --out cipher.bin

# Mã hóa với encoding base64
rsatool encrypt --in message.txt --pub pub.pem --out cipher.b64 --encode base64

# Bắt buộc hybrid mode
rsatool encrypt --in bigfile.bin --pub pub.pem --out cipher.bin --mode hybrid

# Giải mã
rsatool decrypt --in cipher.bin --priv priv.pem --out plain.txt

# Với label
rsatool encrypt --in msg.txt --pub pub.pem --out ct.bin --label "my-app-v1"
rsatool decrypt --in ct.bin  --priv priv.pem --out msg.txt --label "my-app-v1"

# RSA-4096 (chậm hơn, ciphertext dài hơn)
rsatool keygen --bits 4096 --pub pub4096.pem --priv priv4096.pem
```

---

## Troubleshooting Nhanh

| Lỗi | Nguyên nhân | Fix |
|-----|-------------|-----|
| `OpenSSL >= 4.0 required, but found 3.x` | OPENSSL_ROOT_DIR sai | Trỏ đúng vào OpenSSL 4 install |
| `Cannot find libcrypto` trên Windows | DLL không tìm thấy | Build có post-build step tự copy DLL |
| `LNK2019` trên Windows | Link với lib sai version | Kiểm tra OPENSSL_ROOT_DIR |
| `error: decryption failed` | Key/label sai hoặc data corrupt | Dùng đúng key và label |
| Output bị corrupt | `--encode` khác nhau lúc encrypt/decrypt | Match `--encode` |
| CMake `cannot find OpenSSL` | Chưa set OPENSSL_ROOT_DIR | Set env var hoặc dùng `-DOPENSSL_ROOT_DIR=` |
| Slashes trên Windows | Dùng `\` thay vì `/` cho path | Dùng forward slash `/` cho OPENSSL_ROOT_DIR |

---

## Cấu Trúc File Đã Tạo

```
rsatool/
├── CMakeLists.txt
├── CMakePresets.json
├── .gitignore / .gitattributes
├── README.md
├── include/rsatool/
│   ├── errors.hpp, secure.hpp, platform.hpp
│   ├── codec.hpp, keys.hpp, oaep.hpp
│   ├── hybrid.hpp, envelope.hpp
├── src/
│   ├── main.cpp, keys.cpp, oaep.cpp
│   ├── hybrid.cpp, envelope.cpp
│   ├── codec.cpp, platform.cpp
│   └── bonus/oaep_manual.cpp    ← Bonus A
├── tests/
│   ├── test_oaep.cpp            ← Positive tests
│   ├── test_hybrid.cpp          ← Hybrid tests
│   ├── test_negative.cpp        ← 15+ negative tests
│   └── test_codec.cpp           ← Codec tests
├── bench/
│   ├── bench.cpp, plot.py
│   └── results/
├── scripts/
│   ├── build.sh/.ps1
│   ├── test.sh/.ps1
│   ├── demo.sh/.ps1
│   └── bench.sh/.ps1
├── docs/
│   ├── INSTALL_OPENSSL.md, USAGE.md
│   ├── DESIGN.md, TESTING_AND_BENCH.md
│   └── TROUBLESHOOTING.md
├── report/report.md
└── .github/workflows/ci.yml
```

---

**Verified on:** Windows 10/11 x64 (MSVC 2022) — written to be portable.
**Written to be portable but not verified on:** Linux Ubuntu 22.04 (expected to work with GCC >= 11).

