# Lab 4 — Report (Hashing, PKI, Practical Attacks)

> **Lưu ý**: Các phần đánh dấu ⟦⟧ là placeholder chờ dữ liệu thực từ người dùng dán log/CSV.
> Khi có dữ liệu thật, hãy thay placeholder bằng con số thực và xóa chú thích.

## 1. Objective & outcomes
- Xây dựng `hashtool` sử dụng OpenSSL 4.0.3 API `EVP_*` cho hash và X.509.
- Đo throughput hash trên các thuật toán SHA-2, SHA-3, XOF.
- Phân tích X.509: trích thông tin chứng thư, verify chữ ký, negative tests.
- Demo các khái niệm: Merkle–Damgård vs sponge, collision resistance, length-extension.
- **Kết quả thực (chờ dán)**: ⟦⟧ (sau khi có benchmark CSV và KAT result, điền vào đây: số lượng test PASS, throughput MB/s mean/median/stddev, v.v.)

## 2. Design & security
- **Tham số**: Sử dụng OpenSSL 4.0.3 EVP_MD* cho hash, EVP_PKEY* cho X.509.
- **Kiểm tra misuse**: Fail-closed behavior: input sai/tham số không hỗ trợ → exit code 2, không xuất kết quả một phần.
- **Thiết kế**: CLI thống nhất theo đề mục 6.1: `mytool --algo sha256 --in file.bin --out results.txt`.
- **Known attacks**:
  - Length-extension trên Merkle–Damgård (SHA-256, SHA-512): có thể tấn công nếu dùng `H(k‖m)` mà không dùng HMAC.
  - MD5 collision: MD5 đã bị broke (va chạm dễ tạo), không dùng cho ký số.
  - SHA-1/MD5 trong X.509: cấm dùng,CA/B Baseline Requirements cấm.
- **Secure defaults**: `--encode hex` mặc định in hex trên màn hình; file raw binary trừ khi `--encode raw`.
- **Limitations**: Chưa hỗ trợ `--mmap` trên Windows (chế độ đọc file khác); chưa tích hợp hashclash để tạo va chạm MD5 tự động; Chưa implement custom SHA-256 C++ từ scratch cho length-extension demo (chưa chạy bonus).

> **Thay đổi API OpenSSL 4.0 đã xử lý**:
> - Không dùng `X509_cmp_time()` (đã deprecated), dùng `X509_check_certificate_times()`.
> - `ASN1_STRING` là opaque: dùng accessor hàm.
> - Static_assert kiểm tra version OpenSSL >= 4.0 tại compile time.

## 3. Test methodology
- **Vector (KAT)**: Sử dụng vector NIST CAVP/FIPS 180-4/FIPS 202. Mô tả nguồn trong `vectors/SOURCES.md`.
  ⟦⟧ (sau khi chạy `./bin/hashtool --kat vectors.json`: số test PASS/FAIL cho từng thuật toán).
- **Negative tests**: 
  - Input file không tồn thị → exit 3 (I/O error).
  - Tham số `--algo` không hỗ trợ → exit 1 (error parameters).
  - Certificate tampered (sửa 1 byte TBS) → fail-closed, exit 2.
  - Certificate hết hạn → fail-closed.
- **Unit tests**: Catch2 tests (nếu có) test case cơ bản: hash đúng, x509 parse, base64 encode/decode.

> ⟦⟧ (chi tiết từng test case PASS/FAIL sẽ điền sau khi có log thực).
=== KAT RESULTS (vectors/vectors.json) ===
[PASS] sha224 | Empty input
[PASS] sha224 | abc (FIPS 180-4)
[PASS] sha224 | NIST 448-bit message
[PASS] sha224 | NIST 896-bit message
[PASS] sha224 | The quick brown fox jumps over the lazy dog
[PASS] sha224 | One million 'a' characters
[PASS] sha256 | Empty input
[PASS] sha256 | abc (FIPS 180-4)
[PASS] sha256 | NIST 448-bit message
[PASS] sha256 | NIST 896-bit message
[PASS] sha256 | The quick brown fox jumps over the lazy dog
[PASS] sha256 | One million 'a' characters
[PASS] sha384 | Empty input
[PASS] sha384 | abc (FIPS 180-4)
[PASS] sha384 | NIST 448-bit message
[PASS] sha384 | NIST 896-bit message
[PASS] sha384 | The quick brown fox jumps over the lazy dog
[PASS] sha384 | One million 'a' characters
[PASS] sha512 | Empty input
[PASS] sha512 | abc (FIPS 180-4)
[PASS] sha512 | NIST 448-bit message
[PASS] sha512 | NIST 896-bit message
[PASS] sha512 | The quick brown fox jumps over the lazy dog
[PASS] sha512 | One million 'a' characters
[PASS] sha3-224 | Empty input
[PASS] sha3-224 | abc (FIPS 180-4)
[PASS] sha3-224 | NIST 448-bit message
[PASS] sha3-224 | NIST 896-bit message
[PASS] sha3-224 | The quick brown fox jumps over the lazy dog
[PASS] sha3-224 | One million 'a' characters
[PASS] sha3-256 | Empty input
[PASS] sha3-256 | abc (FIPS 180-4)
[PASS] sha3-256 | NIST 448-bit message
[PASS] sha3-256 | NIST 896-bit message
[PASS] sha3-256 | The quick brown fox jumps over the lazy dog
[PASS] sha3-256 | One million 'a' characters
[PASS] sha3-384 | Empty input
[PASS] sha3-384 | abc (FIPS 180-4)
[PASS] sha3-384 | NIST 448-bit message
[PASS] sha3-384 | NIST 896-bit message
[PASS] sha3-384 | The quick brown fox jumps over the lazy dog
[PASS] sha3-384 | One million 'a' characters
[PASS] sha3-512 | Empty input
[PASS] sha3-512 | abc (FIPS 180-4)
[PASS] sha3-512 | NIST 448-bit message
[PASS] sha3-512 | NIST 896-bit message
[PASS] sha3-512 | The quick brown fox jumps over the lazy dog
[PASS] sha3-512 | One million 'a' characters
[PASS] shake128 | Empty input (outlen 32)
[PASS] shake128 | abc (FIPS 180-4) (outlen 32)
[PASS] shake128 | NIST 448-bit message (outlen 32)
[PASS] shake128 | NIST 896-bit message (outlen 32)
[PASS] shake128 | The quick brown fox jumps over the lazy dog (outlen 32)
[PASS] shake128 | One million 'a' characters (outlen 32)
[PASS] shake128 | Empty input (outlen 64)
[PASS] shake128 | abc (FIPS 180-4) (outlen 64)
[PASS] shake128 | NIST 448-bit message (outlen 64)
[PASS] shake128 | NIST 896-bit message (outlen 64)
[PASS] shake128 | The quick brown fox jumps over the lazy dog (outlen 64)
[PASS] shake128 | One million 'a' characters (outlen 64)
[PASS] shake256 | Empty input (outlen 64)
[PASS] shake256 | abc (FIPS 180-4) (outlen 64)
[PASS] shake256 | NIST 448-bit message (outlen 64)
[PASS] shake256 | NIST 896-bit message (outlen 64)
[PASS] shake256 | The quick brown fox jumps over the lazy dog (outlen 64)
[PASS] shake256 | One million 'a' characters (outlen 64)
[PASS] shake256 | Empty input (outlen 128)
[PASS] shake256 | abc (FIPS 180-4) (outlen 128)
[PASS] shake256 | NIST 448-bit message (outlen 128)
[PASS] shake256 | NIST 896-bit message (outlen 128)
[PASS] shake256 | The quick brown fox jumps over the lazy dog (outlen 128)
[PASS] shake256 | One million 'a' characters (outlen 128)
Total: 72/72 passed
## 4. Performance
- **Phần cứng/OS** (chờ dán từ ENV_CHECK.md):
  - CPU: ⟦⟧
  - Cores/threads: ⟦⟧
  - RAM: ⟦⟧
  - OS: ⟦⟧
  - Compiler + flags: ⟦⟧
  - OpenSSL version: ⟦⟧

- **Protocol**: Đo throughput (MB/s) cho SHA-256, SHA-512, SHA3-256, SHA3-512 trên kích thước dữ liệu: 1 MiB, 100 MiB, 1 GiB. Sử dụng `std::chrono::steady_clock`, 30 lần đo mỗi case, tính Mean/Median/StdDev/95% CI (Student-t).

- **Kết quả thực (chờ dán)**:
  ⟦⟧

  **Bảng kết quả (sau khi `make_tables.py` chạy)**:
  ⟦⟧

  ✦ Đồ thị `figures/hash_benchmark.png` (throughput với error bars 95% CI):
  ✦ Diễn giải: so sánh SHA-2 vs SHA-3, hiệu ứng cache ở kích thước lớn, streaming vs mmap.

## 5. Discussion
- So sánh throughput giữa các thuật toán: SHA-3 nhanh/hash 1 GiB hay chậm hơn SHA-2 do cấu trúc sponge?
- Streaming I/O có giảm RAM peak không? (Kết quả đo: ⟦⟧).
- X.509 parsing với API 4.0: khó khăn gặp phải gì khi dùng `X509_check_certificate_times` so với các hàm deprecated cũ?
- Length-extension vulnerability: tại sao HMAC hoặc prefix-free constructions (prefix-free) mới an toàn? Có thể giải thích sơ đồ padding SHA-256 không?
- Nếu có thực hiện bonus length-extension custom SHA-256: kết quả đạt được gì, khó khăn nào?

## 6. Conclusion
- Tóm tắt bài học: OpenSSL 4.0.3 API EVP dễ dùng và an toàn hơn các API cấp thấp; fail-closed quan trọng cho bảo mật; SHA-3 khác SHA-2 về cấu trúc nhưng throughput phụ thuộc bài toán.
- Hướng phát triển: Thêm tích hợp length-extension demo (bonus), hỗ trợ mmap trên Windows, mở rộng KAT vector cho SHAKE/XOF.

## 7. Appendix
### Appendix A — Academic Integrity & Ethics (dán nguyên văn từ đề)
Work is your own; cite libraries, KAT sources, and references.
Attack demonstrations are limited to your own test artifacts in an offline sandbox.
No testing against third-party data, networks, or services.
Keys and secrets included in the repo are test keys only.
You understand the difference between vulnerability demonstration and malicious exploitation and commit to the former strictly for learning.
Thêm dòng khai báo việc dùng AI/công cụ hỗ trợ (đề yêu cầu disclosure); để người dùng tự đọc, xác nhận, ký.

### Appendix B — Rubric Table
| Criterion | Points | Self-score | TA score |
|-----------|--------|------------|----------|
| Hash suite & KATs | 25 | ✗ (chờ dữ liệu) | ✗ |
| Streaming & large-file performance | 10 | ✗ (chờ dữ liệu) | ✗ |
| X.509 parsing & signature verification | 25 | ✗ (chờ dữ liệu) | ✗ |
| MD5 collision demo & explanation | 20 | ✗ (chờ dữ liệu) | ✗ |
| Length-extension demo & mitigation | 20 | ✗ (chờ dữ liệu) | ✗ |
| Bonus custom length-extension +5 | +5 | ✗ (chờ dữ liệu) | ✗ |
| **Tổng** | **100 + 15** | | |

### Appendix C — CLI examples with real output
⟦⟧ (sau khi có kết quả thực, điền ví dụ: `./bin/hashtool --algo sha256 --in data/file.bin --out results/sha256_hash.txt`)

### Appendix D — KAT coverage
⟦⟧ (sau khi chạy KAT, liệt kê các test vector đã test và kết quả).

### Appendix E — Performance data CSV
⟦⟧ (sau khi có results/*.csv, điền tóm tắt thống kê).

### Reference
- FIPS 180-4, FIPS 202, FIPS 199, FIPS 180-4
- RFC 5280 (X.509)
- RFC 6979 (Deterministic ECDSA - though Lab 4 is hash-focused)
- OpenSSL 4.0 release notes
- NIST SP 800-185 (cSHAKE, XOF)
- Tài liệu hashclash cho collision MD5