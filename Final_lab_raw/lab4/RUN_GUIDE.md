# Lab 4 — RUN GUIDE

**Mục đích**: Hướng dẫn người dùng từng bước để build, test, benchmark và thu thập kết quả cho Lab 4.

> **Quan trọng**: Tôi (AI) KHÔNG chạy lệnh terminalใด. Bạn sẽ chạy các lệnh sau và dán log/CSV kết quả về. Tôi sẽ cập nhật báo cáo và placeholder với dữ liệu thực.

---

## Bước 0: Kiểm tra môi trường (tắt tự động nếu đã chạy ENV_CHECK.md)

Chạy lệnh sau và dán kết quả:

```bash
openssl version -a
```

**Kết quả mong đợi**: Phải là `OpenSSL 4.0.3 ...`.

- Nếu khác → cài OpenSSL 4.0.3, chỉ định `-DOPENSSL_ROOT_DIR=<path>` khi chạy cmake, sau đó chạy lại lệnh này.
- Nếu là OpenSSL 3.x hệ thống → rất có thể build sẽ fail do static_assert, hãy chỉ định đường dẫn đúng.

**Linux**: Đặt governor performance (tùy nhưng khuyến nghị cho benchmark):
```bash
sudo cpupower frequency-set -g performance
```

**Windows**: Chế độ High Performance trong Power Options, đóng các ứng dụng nặng (browser, IDE).

---

## Bước 1: Build

### Linux (bash)
```bash
cd lab4
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -DOPENSSL_ROOT_DIR=/usr/local/opt/openssl@4  # sửa đường dẫn nếu cần
cmake --build . --config Release
ctest -C Release --output-on-failure
```

### Windows (PowerShell)
```powershell
cd lab4
mkdir build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -DOPENSSL_ROOT_DIR=C:\vcpkg\installed\x64-windows\openssl@4  # sửa đường dẫn
cmake --build . --config Release
ctest -C Release --output-on-failure
```

**Kiểm tra binary có build xong chưa**:
```bash
./bin/hashtool --version
# hoặc
./bin/hashtool --help
```
Nó in phiên bản OpenSSL runtime và danh sách lệnh hỗ trợ. Nếu in lỗi → kiểm tra lại OPENSSL_ROOT_DIR.

---

## Bước 2: Chạy KAT (Known Answer Test)

### Sử dụng vector chuẩn (NIST CAVP / FIPS 180-4 / FIPS 202)
```bash
./bin/hashtool --kat 
```

**Kết quả mong đợi**: In ra các dòng PASS/FAIL và thống kê. Ví dụ:
```
=== KAT RESULTS ===
sha256_test: PASS
sha3_256_test: PASS
shake128_test: PASS
shake256_test: PASS
x509_test: PASS
Total: 4/4 passed
```

**Nếu KAT thất bại**: Kiểm tra:
- Vector có đúng nguồn NIST/ACVP không.
- OpenSSL version có phải 4.0.3 không.
- File vector có bị corrupt không.

Kết quả KAT sẽ được ghi vào `logs/kat_run.log`. Nếu chưa chạy → placeholder trong báo cáo: ⟦CHƯA CHẠY KAT: chạy `./bin/hashtool --kat vectors.json` rồi dán logs/kat_run.log⟧.

---

## Bước 3: Chạy benchmark hash

Harness đo throughput (MB/s) và latency cho các thuật toán hash. Kết quả thuần CSV được lưu vào `results/`.

### a) Benchmark cơ bản (không mmap, không streaming)
Chạy các lệnh sau và dán kết quả:

```bash
# SHA-256 trên 1 MiB
./bin/hashtool --algo sha256 --in data/test_1m.bin --bench 30

# SHA-512 trên 1 MiB
./bin/hashtool --algo sha512 --in data/test_1m.bin --bench 30

# SHA3-256 trên 1 MiB
./bin/hashtool --algo sha3-256 --in data/test_1m.bin --bench 30

# SHA3-512 trên 1 MiB
./bin/hashtool --algo sha3-512 --in data/test_1m.bin --bench 30
```

**Kết quả mong đợi (ví dụ CSV format, bạn dán toàn bộ output)**:
```
=== BENCHMARK RESULTS (sha256, 1 MiB, 30 runs) ===
Throughput (MB/s): mean=523.4, median=521.1, stddev=12.3, 95% CI=[518.2, 528.6]
Latency per op (ns): mean=19.1, median=18.9, stddev=0.5, 95% CI=[18.8, 19.4]
===
```

```bash
# SHA-256 trên 100 MiB (streaming)
./bin/hashtool --algo sha256 --in data/test_100m.iso --stream --bench 30
```

```bash
# SHA-512 trên 1 GiB (streaming)
./bin/hashtool --algo sha512 --in data/test_1g.iso --stream --bench 30
```

### b) Benchmark với mmap (Linux chỉ)
```bash
./bin/hashtool --algo sha256 --in data/test_1g.iso --mmap --bench 30
```
*Chế độ `--mmap` dùng `mmap` trên Linux để đọc file. Windows dùng `MapViewOfFile` (đã hỗ trợ trong code, nhưng benchmark có thể ghi chú khác).*

---

## Bước 4: X.509 parsing và verify chữ ký

### a) Trích thông tin chứng thư
```bash
./bin/hashtool --algo x509 --in certs/valid.crt --out results/valid_cert_info.txt
```

**Kết quả mong đợi**: File `results/valid_cert_info.txt` chứa:
```
Subject: /O=Test Organization/CN=Test Certificate
Issuer: /O=Test Authority/CN=Test CA
Validity Not Before: 2024-01-01 00:00:00 UTC
Validity Not After: 2025-01-01 00:00:00 UTC
Key Usage: Digital Signature, Key Encipherment
Signature Algorithm: sha256WithRSAEncryption
SANs: DNS:test.example.com, IP Address:192.168.1.1
```

### b) Verify chữ ký X.509 (nếu có chứng thư kèm khóa CA)
```bash
# Giả sử có cert và khóa CA
./bin/hashtool --algo verify --in msg.bin --cert cert.crt --key ca_key.pem --out results/verify_log.txt
```

### c) Negative tests (test fail-closed)
```bash
# Thay đổi 1 byte trong file cert (sửa TBS)
cp certs/valid.crt certs/tampered.crt
xxd -s 100 -l 1 certs/tampered.crt  # xem byte cũ
# Sửa byte (ví dụ byte thứ 100 từ 0x00 thành 0xFF)
./bin/hashtool --algo x509 --in certs/tampered.crt --out results/tampered_info.txt
# Kết quả: tool nên fail-closed (không báo cert hợp lệ)
```

```bash
# Test cert hết hạn
./bin/hashtool --algo x509 --in certs/expired.crt --out results/expired_info.txt
# Kết quả: in ra thông báo cert đã hết hạn (sử dụng X509_check_certificate_times() API 4.0).
```

---

## Bước 5: MD5 collision guide (appendix, không bắt buộc làm cho điểm chính)

Nếu muốn làm phần bonus MD5 collision:
```bash
# Xem script hướng dẫn: scripts/hashclash_guide.md
```
*Tôi không tự chạy hashclash. Script và file va chạm do người dùng tạo.*

---

## Bước 6: Thu thập kết quả và format dán

Sau khi chạy xong các bước trên, dán kết quả dưới đây:

### a) KQ KAT
```
=== KAT RESULTS ===
<copy-paste output từ `./bin/hashtool --kat vectors.json`>
===
```

### b) KQ Benchmark (CSV ví dụ)
```
=== BENCHMARK RESULTS ===
sha256_1m: mean=523.4 MB/s, median=521.1, stddev=12.3, 95% CI=[518.2, 528.6]
sha512_1m: mean=315.2 MB/s, median=312.0, stddev=8.7, 95% CI=[309.5, 320.9]
sha3_256_1m: mean=489.7 MB/s, median=487.2, stddev=15.1, 95% CI=[482.3, 497.1]
sha3_512_1m: mean=298.4 MB/s, median=295.1, stddev=6.3, 95% CI=[293.1, 301.7]
===
```

### c) KQ X.509
```
=== X.509 INFO ===
<copy-paste output từ `./bin/hashtool --algo x509 --in certs/valid.crt --out results/valid_cert_info.txt`>
===
```

### d) KQ Negative test
```
=== NEGATIVE TEST RESULTS ===
tampered_cert: FAIL (expected - fail-closed)
expired_cert: FAIL (expected - fail-closed)
===
```

---

## Bước 7: Next steps (sau khi dán kết quả)

Bạn dán kết quả ở phần Bước 6 về, tôi sẽ:
1. Kiểm tra dữ liệu KAT, benchmark, X.509.
2. Cập nhật `lab4/report_lab4.md` với con số thực (điềnplaceholder → con số thật).
3. Tạo bảng `results/summary.csv` và `figures/hash_benchmark.png` (qua script `scripts/make_tables.py` sau này).
4. Tự chấm rubric dựa trên dữ liệu thực.
5. Chuyển sang Lab 5 hoặc dừng chờ bạn.

*File này sẽ được cập nhật nếu có thay đổi môi trường hoặc yêu cầu mới.*