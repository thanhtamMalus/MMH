# rsatool - RSA-OAEP & Hybrid Encryption Tool

## 1. Giới thiệu & Tính năng

**rsatool** là công cụ CLI để thực hiện mã hóa RSA-OAEP và mã hóa lai (hybrid) với AES-256-GCM.

### Đặc điểm chính:
- **RSA-OAEP** với SHA-256 và MGF1-SHA-256 (bắt buộc 3072-bit, thêm 4096-bit)
- **Giới hạn plaintext**: RSA-3072: 318 byte max; RSA-4096: 446 byte max
- **Tự động chuyển mode**: Dữ liệu nhỏ → RSA-OAEP Direct; Dữ liệu lớn → Hybrid (AES-256-GCM + RSA-OAEP)
- **Envelope format**: Container format self-describing (magic "RSAE", version, JSON header, payload)
- **Auto mode**: Kiểm tra kích thước và chuyển đổi giữa Direct/Hybrid tự động
- **Fail-closed**: Các lỗi giải mã/xác thực → thông báo chung `"Error: decryption failed."`, exit code 3, không tạo file output

### Thuật toán:
- **RSA-OAEP**: SHA-256 hash, MGF1-SHA-256, label hỗ trợ
- **Hybrid**: RSA-OAEP bọc khóa AES-256 → AES-256-GCM (IV 96-bit, tag 128-bit)
- **AAD**: `"RSAE-AAD-v1|" + mode + "|" + rsa_modulus + "|" + hash + "|" + wrapped_key_b64 + "|" + iv_b64`

## 2. Yêu cầu hệ thống & Thư viện

### Yêu cầu:
- **OpenSSL ≥ 4.0** (chỉ `libcrypto`; Ubuntu LTS thường có 3.x → cần build OpenSSL 4.x từ source)
- **nlohmann_json** (v3.x)
- **Catch2** (v3.x) - cho unit tests
- **Python 3** + pandas, numpy, scipy, matplotlib - cho script benchmark & análise
- **CMake** ≥ 3.16
- **C++17** compiler (GCC, Clang, MSVC, MinGW64)

### Hướng dẫn cài thư viện:

#### Ubuntu:
1. **Build OpenSSL 4.x từ source** (không nên dùng `apt` có chỉ 3.x):
   ```bash
   # Tải tarball từ trang chính thức OpenSSL 4.x
   ./Configure --prefix=/opt/openssl-4 --openssldir=/opt/openssl-4/ssl --libdir=lib
   make -j$(nproc)
   make install
   ```
   Kiểm tra: `/opt/openssl-4/bin/openssl version` (phải hiện 4.x)

2. Build lab:
   ```bash
   cmake -S . -B build -DOPENSSL_ROOT_DIR=/opt/openssl-4
   cmake --build build --config Release
   ```

#### Windows (MSVC + vcpkg):
1. Cài vcpkg và OpenSSL 4.x:
   ```powershell
   git clone https://github.com/microsoft/vcpkg C:\vcpkg
   C:\vcpkg\bootstrap-vcpkg.bat
   C:\vcpkg\vcpkg install openssl --triplet x64-windows
   ```
2. Build lab:
   ```powershell
   cmake -S . -B build-msvc -G "Visual Studio 17 2022" -A x64 `
     -DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake
   cmake --build build-msvc --config Release
   ```

#### Windows (MinGW64 / MSYS2):
```bash
pacman -S --needed mingw-w64-x86_64-toolchain mingw-w64-x86_64-cmake \
    mingw-w64-x86_64-ninja
cmake -S . -B build-mingw -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build-mingw
```

### Cảnh báo:
- **Không** ghi đè OpenSSL của hệ thống trên Ubuntu
- Trên Windows, đảm bảo runtime MD/MT khớp với bản OpenSSL được cài
- Nếu CMake báo tìm thấy OpenSSL 3.x → sai đường dẫn `-DOPENSSL_ROOT_DIR`

## 3. Build (Out-of-source, bắt buộc)

### Linux:
```bash
mkdir -p results report/figures testdata
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DOPENSSL_ROOT_DIR=/opt/openssl-4
cmake --build build --config Release
```

### Windows (MSVC):
```powershell
cmake -S . -B build-msvc -G "Visual Studio 17 2022" -A x64 `
  -DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake
cmake --build build-msvc --config Release
```

### Windows (MinGW64):
```bash
cmake -S . -B build-mingw -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build-mingw
```

### Biến đổi:
- `-DOPENSSL_ROOT_DIR=<đường dẫn>`: Khi OpenSSL không ở đường dẫn mặc định
- `-DOPENSSL_USE_STATIC_LIBS=ON`: Link OpenSSL tĩnh (tránh vấn đề DLL trên Windows)
- `-DCRYPTOPP_ENABLE_STATIC_INLINE=OFF`: (nếu cần)

## 4. Sử dụng CLI

### Sinh khóa:
```bash
rsatool keygen --bits 3072 --pub keys/pub3072.pem --priv keys/priv3072.pem
rsatool keygen --bits 4096 --pub keys/pub4096.pem --priv keys/priv4096.pem
```

### Mã hóa (Direct - dữ liệu ≤ 318 byte với RSA-3072):
```bash
rsatool encrypt --in msg.bin --pub pub3072.pem --out ct.bin
rsatool encrypt --in msg.bin --pub pub3072.pem --out ct.bin --label "lab3-demo"
rsatool encrypt --in msg.bin --pub pub3072.pem --out ct.bin --encode hex
rsatool encrypt --in msg.bin --pub pub3072.pem --out ct.bin --encode base64
```

### Giải mã:
```bash
rsatool decrypt --in ct.bin --priv priv3072.pem --out msg.bin
rsatool decrypt --in ct.bin --priv priv3072.pem --out msg.bin --label "lab3-demo" --encode base64
```

### Auto mode (mặc định):
- Nếu plaintext ≤ max → RSA-OAEP Direct
- Nếu plaintext > max → Hybrid (AES-256-GCM envelope)

### Force hybrid:
```bash
rsatool encrypt --in msg.bin --pub pub3072.pem --out ct.bin --force-hybrid
```

### Xem header envelope:
```bash
python3 -c "
import struct, json
b = open('ct_1KiB.bin','rb').read()
assert b[:4]==b'RSAE'
n = struct.unpack('>I', b[5:9])[0]
print(json.dumps(json.loads(b[9:9+n]), indent=2))
"
```

### Cờ toàn cục:
- `--label TEXT`: OAEP label (UTF-8); phải khớp giữa encrypt/decrypt
- `--encode raw|hex|base64`: Định dạng file output
- `--force-hybrid`: Efp Hybrid mode
- `--impl lib|manual`: Chọn implement RSA-OAEP (mặc định `lib`)
- `--verbose`: In thông tin chi tiết (kích thước, mode, phiên bản OpenSSL)

## 5. Định dạng file

### Khóa (Keygen tạo ra):

| File | Nội dung |
|------|----------|
| `pub.pem` | Public key, SPKI (`-----BEGIN PUBLIC KEY-----`) |
| `priv.pem` | Private key, PKCS#8 (`-----BEGIN PRIVATE KEY-----`) |
| `pub.der` | DER format (tự suy từ pub.pem) |
| `priv.der` | DER format (tự suy từ priv.pem) |
| `<tên priv>.meta.json` | Metadata JSON |

### Metadata schema:
```json
{
  "creation_time": "2024-01-15T10:30:00Z",
  "modulus_bits": 3072,
  "hash": "SHA-256"
}
```
- `creation_time`: UTC, ISO-8601 kết thúc với `Z`
- `public_exponent`: 65537 (không bắt buộc, thêm nếu muốn)

### Envelope container format:
```
+--------+---------+----------------+------------------+-----------------+
| "RSAE" | ver=0x01| header_len u32 | header JSON      | payload bytes   |
| 4 byte | 1 byte  | big-endian     | (UTF-8, ≤ 64KiB)  | (xem dưới)      |
+--------+---------+----------------+------------------+-----------------+
```

#### Direct mode:
- `header.mode = "RSA-OAEP"`
- `payload` = RSA ciphertext (k byte = modulus bytes)

#### Hybrid mode:
- `header.mode = "RSA-OAEP-AES-GCM"`
- `payload` = AES-256-GCM ciphertext (không gồm tag)
- Header JSON chứa: wrapped_key (base64), iv (base64 12 byte), tag (base64 16 byte)

### AAD (Additional Authenticated Data):
```
"RSAE-AAD-v1|" + mode + "|" + rsa_modulus + "|" + hash + "|" + wrapped_key_b64 + "|" + iv_b64
```

## 6. Chạy test (ctest)

```bash
ctest --test-dir build -C Release --output-on-failure -V
```

Kết quả mong muốn: `100% tests passed, 0 tests failed out of N`

Danh sách test chi tiết:
```bash
rsatool --list-tests > results/test_list.txt
```

### Test bao gồm:
- **Round-trip Direct**: msg rỗng, 1 byte, mLen_max (318 với 3072), vẫn Direct
- **mLen_max + 1** → tự chuyển Hybrid, round-trip đúng
- **Hybrid**: 1 KiB, 1 MiB (100 MiB không đưa vào unit test)
- **RSA-3072 và RSA-4096** (4096 có thể đánh dấu `[slow]`)
- **Label khớp** → OK; label rỗng ↔ rỗng → OK
- **Encoding**: raw/hex/base64 round-trip
- **Negative tests**: đủ 5 kịch bản đề + biến thể, lỗi chung `"decryption failed."`
- **Bonus A**: cross-check manual OAEP ↔ library OAEP

## 7. Benchmark & Thống kê

### Chạy benchmark:
```bash
rsabench --out results/bench_raw.csv --env-out results/bench_env.txt
```

### Chạy nhanh (kiểm tra không lỗi):
```bash
rsabench --out results/bench_raw.csv --env-out results/bench_env.txt --quick
```

### Phân tích & vẽ đồ thị:
```bash
python scripts/analyze_bench.py --in results/bench_raw.csv --out-dir results --fig-dir report/figures
```

### Kết quả thu thập:
- `results/bench_summary.csv`: Bảng mean/std/95% CI
- `results/bench_summary.md`: Markdown bảng dán vào báo cáo
- `report/figures/*.png`: 4 đồ thị (keygen, enc/dec, AES-GCM, hybrid total)
- `results/bench_env.txt`: Môi trường đo (phiên bản OpenSSL, CPU, OS, compiler)

## 8. Mã thoát & Thông báo lỗi

| Mã | Ý nghĩa |
|----|---------|
| `0` | OK |
| `1` | Sai tham số/cú pháp |
| `2` | Lỗi I/O/khóa không đọc được |
| `3` | Giải mã/xác thực thất bại |

### Thông báo lỗi (mọi lỗi crypto/giải mã):
```
Error: decryption failed.
```
- **Không** in "padding sai", "tag sai", "label sai", độ dài, chi tiết ERR_*
- **Không** in nội dung hàng đợi lỗi OpenSSL
- Luôn `ERR_clear_error()` trước khi trả lỗi

### `--verbose` chỉ in:
- Kích thước file
- Mode đã chọn (Direct/Hybrid)
- Phiên bản OpenSSL (`OpenSSL_version(OPENSSL_VERSION)`)

## 9. Cấu trúc thư mục & Rubric

```
lab3-rsatool/
├── CMakeLists.txt
├── AGENT.md (chỉ thị cho bot)
├── RUN_GUIDE.md (hướng dẫn chạy)
├── include/rsalab/ (các header)
│   ├── errors.hpp
│   ├── ossl_raii.hpp
│   ├── encoding.hpp
│   ├── keyio.hpp
│   ├── rsa_oaep.hpp
│   ├── envelope.hpp
│   ├── hybrid.hpp
│   ├── oaep_manual.hpp (Bonus A)
│   └── util.hpp
├── src/ (nguồn C++)
│   ├── main.cpp
│   ├── cli.cpp / cli.hpp
│   ├── encoding.cpp
│   ├── keyio.cpp
│   ├── rsa_oaep.cpp
│   ├── envelope.cpp
│   ├── hybrid.cpp
│   └── util.cpp
├── tests/ (test Catch2)
│   ├── test_main_or_catch.cpp
│   ├── test_rsa_oaep.cpp
│   ├── test_keyio.cpp
│   ├── test_hybrid.cpp
│   ├── test_negative.cpp
│   └── test_oaep_manual.cpp (Bonus A)
├── bench/ (benchmark)
│   └── bench_main.cpp
├── scripts/ (Python scripts)
│   ├── analyze_bench.py
│   ├── tamper.py
│   └── make_testfiles.py
├── docs/ (tài liệu)
│   ├── COMPILE_RISKS.md
│   ├── DESIGN.md (bảng ánh xạ API)
│   └── BONUS_B_hybrid_analysis.md (Bonus B)
├── report/ (báo cáo)
│   └── REPORT_OUTLINE.md (dàn ý + lý thuyết)
└── results/ (log/CSV/hình sau chạy)
```

### Đánh giá rubric (điểm):
| Hạng mục | Điểm | Vị trí trong repo |
|----------|------|-------------------|
| RSA-OAEP SHA-256 | 20 | `rsa_oaep.*` (EVP, MGF1=SHA-256 tường minh), label, giới hạn mLen |
| Hybrid Envelope | 20 | AES-256-GCM (EVP), IV 96-bit, wrap OAEP, header JSON đúng trường, AAD |
| Khóa & định dạng | 15 | PEM + DER + metadata JSON đúng schema, PKCS#8/SPKI (OSSL_ENCODER/DECODER) |
| Negative test | 15 | Đủ 5 kịch bản đề + biến thể, lỗi chung, không rò rỉ |
| Benchmark | 15 | `rsabench` + CSV mẫu riêng lẻ + `analyze_bench.py` (95% CI, 4 đồ thị) |
| CMake + README | 5 | Build out-of-source Win/Linux, yêu cầu OpenSSL ≥ 4.0 có kiểm tra |
| Báo cáo | 10 | `REPORT_OUTLINE.md` có sẵn lý thuyết bắt buộc |
| Bonus A (+5) | | `oaep_manual.*` constant-time + test cross-check |
| Bonus B (+10) | | `BONUS_B_hybrid_analysis.md` đủ 4 mục + mục mở rộng |

## 10. Ghi chú bảo mật

- **RNG**: Sử DRBG của OpenSSL qua `RAND_bytes` (CSPRNG); không dùng `rand()`, `random_device`, `mt19937`
- **Fail-closed**: Mọi lỗi giải mã → `"Error: decryption failed."`, exit 3, không leave file output
- **Giới hạn constant-time**: Decode OAEP phải constant-time để ngăn Manger attack (xem Bonus A)
- **Khóa private**: Không mã hóa bằng passphrase; không dùng cho sản xuất thực tế
- **Tag GCM**: Luôn dùng `EVP_DecryptFinal_ex` để xác thực; **không** dùng `memcmp`/`==` trực tiếp
- **Label**: Giữ label đồng nhất giữa encrypt/decrypt; label rỗng = chuẩn OAEP (L = chuỗi rỗng)
- **AAD**: Luôn bao bọc header vào GCM để sửa header → xác thực thất bại

## 11. Vấn đề đã biết / Giới hạn

- Phụ thuộc OpenSSL 4.x; API OpenSSL 4.0 có thể khác 3.x ở các hàm đã gỡ
- Nếu CMake báo tìm thấy OpenSSL 3.x → truyền `-DOPENSSL_ROOT_DIR=<đường OpenSSL 4.x>`
- API `OSSL_ENCODER`/`OSSL_DECODER` chỉ có sẵn OpenSSL 4.x trở lên
- Windows DLL runtime: cần khớp MD/MT với bản OpenSSL hoặc dùng static linking
- Hybrid mode đòi hỏi plaintext > max_plaintext_len (318 byte cho 3072-bit, 446 byte cho 4096-bit)
- Test 100 MiB đưa vào benchmark chứ không đưa vào unit test (quá lớn)
- API `EVP_PKEY_CTX_set0_rsa_oaep_label` chuyển ownership buffer; phải careful không free đôi khi
- OpenSSL 4.x có thể chưa có sẵn trong package manager hệ thống cần build từ source