# Lab 4 — Hashing, PKI, Practical Attacks (hashtool)

## 1. Overview
**Mục tiêu**: Xây dựng công cụ `hashtool` sử dụng OpenSSL 4.0.3 API cấp cao `EVP_*` để:
- Băm đa dạng: SHA-224/256/384/512, SHA3-224/256/384/512, SHAKE128/256.
- Phân tích X.509: trích thông tin chứng thư, verify chữ ký.
- Demo va chạm MD5 (hashclash) và length-extension attack.
- Đo benchmark hiệu suất trên các thuật toán hash.

**Thư viện**: OpenSSL 4.0.3 (bắt buộc). Không dùng Crypto++ ở Lab 4.

**CLI thống nhất** (theo đề mục 6.1):
```
mytool <command>
  [--in INFILE | --text "…"]   [--out OUTFILE]
  [--key KEYFILE | --key-hex HEX]
  [--iv IV-hex] [--nonce NONCE-hex] [--mode MODE] [--aead]
  [--encode hex|base64|raw] [--threads N]
  [--kat path/to/vectors.json] [--verbose]
```

## 2. Cách build (Windows + Linux)

### Linux (bash)
```bash
cd lab4
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -DOPENSSL_ROOT_DIR="[Thư viện openssl]  # hoặc thư mục cài OpenSSL 4.0.3
cmake --build . --config Release
ctest -C Release --output-on-failure
```

### Windows (PowerShell)
```powershell
cd lab4
mkdir build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -DOPENSSL_ROOT_DIR=C:\vcpkg\installed\x64-windows\openssl  # hoặc thư mục cài OpenSSL 4.0.3
cmake --build . --config Release
ctest -C Release --output-on-failure
```

**Quan trọng**: `-DOPENSSL_ROOT_DIR` phải trỏ tới OpenSSL 4.0.3. Nếu không chỉ định, CMake sẽ link vào OpenSSL hệ thống (thường là 3.x) và build sẽ thất bại vì static_assert.

## 3. Các lệnh chạy chính (RUN_GUIDE chi tiết ở file riêng)

### a) Hash file (đếnh/dạng cố định)
```bash
# SHA-256
./bin/hashtool --algo sha256 --in data/file.bin --out results/sha256_hash.txt

# SHA-512
./bin/hashtool --algo sha512 --in data/large.iso --out results/sha512_hash.txt

# SHA3-256
./bin/hashtool --algo sha3-256 --in data/file.bin --out results/sha3-256_hash.txt

# SHAKE128 với độ dài 64 byte
./bin/hashtool --algo shake128 --outlen 64 --in data/file.bin --out results/shake128_64.txt

# SHAKE256 với độ dài 128 byte
./bin/hashtool --algo shake256 --outlen 128 --in data/file.bin --out results/shake256_128.txt
```

### b) Streaming I/O (file lớn, RAM không tăng)
```bash
./bin/hashtool --algo sha512 --in data/large.iso --stream --out results/sha512_stream.txt
```
*Chế độ `--stream` đọc file theo từng phần, không tải toàn bộ vào RAM.*

### c) X.509 parsing
```bash
./bin/hashtool --algo x509 --in certs/server.crt --out results/x509_info.txt
```
*In Subject, Issuer, Validité, Key Usage, SANs, Algorithm.*

### d) KAT (Known Answer Test)
```bash
./bin/hashtool --kat vectors.json
```
*In PASS/FAIL cho từng test vector.*

## 4. Phần bonus
- **Length-extension**: triển khai SHA-256 thuần C++ (custom), dùng `hashpump` hoặc script của bản thân.
- **MD5 collision**: hướng dẫn cài hashclash, tạo va chạm, verify qua OpenSSL.

## 5. Kết quả mong đợi sau khi chạy
- `results/sha256_counters.csv`, `results/sha512_stats.csv` v.v. (tùy benchmark).
- `figures/hash_benchmark.png` (đồ thị throughput với error bars).
- `logs/kat_run.log` (KAT result log).

*Nếu chưa có dữ liệu thực, các con số trong báo cáo giữ là placeholder dạng ⟦CHƯA CÓ DỮ LIỆU: chạy scripts/run_all.* rồi dán results/xxx.csv⟧.*