# Lab 4 — SELF_GRADE.md

**Checklist nộp bài** (đánh dấu ✓ khi hoàn thành hoặc ghi lý do chưa làm).

## 1. Code & Build
- [ ] `lab4/CMakeLists.txt` viết đúng API OpenSSL 4.0 (EVP_*), có `static_assert(OPENSSL_VERSION_MAJOR >= 4)`.
- [ ] Build chạy thành công: `cmake .. && cmake --build . --config Release`.
- [ ] Binary `bin/hashtool` hoạt động: `--help`, `--version` in OpenSSL 4.0.3.
- [ ] Code comment, tên biến tiếng Anh. Không có `rand()`, không hardcode khóa thực.
- [ ] `common/common.hpp` chứa: hex/base64, timer, stats, X.509 helper, secure_cleanse.

## 2. KAT (Known Answer Test)
- [ ] `lab4/vectors/vectors.json` chứa vector test (sources ghi rõ).
- [ ] Chạy `./bin/hashtool --kat vectors.json` → in PASS/FAIL.
- [ ] KAT coverage: SHA-256, SHA-512, SHA3-256, SHA3-512, SHAKE128, SHAKE256, X.509.
- [ ] File `logs/kat_run.log` có kết quả KAT.

## 3. Negative tests & UX
- [ ] Test input malformed → fail.
- [ ] Test file không tồn tại → fail với message rõ ràng.
- [ ] Test cert không hợp lệ (tampered, expired) → fail-closed (không báo hợp lệ).
- [ ] `--encode hex|base64|raw` hoạt đúng.
- [ ] Mã thoát: 0 OK, 1 lỗi tham số, 2 lỗi xác thực/fail-closed, 3 lỗi I/O.

## 4. Benchmark & Performance
- [ ] Đã chạy benchmark: SHA-256/512, SHA3-256/512, XOF (SHAKE) trên 1 MiB, 100 MiB, 1 GiB.
- [ ] Kết quả CSV nằm trong `results/*.csv`.
- [ ] Đã chạy `--stream` và (nếu được) `--mmap`.
- [ ] Đã tạo `results/benchmark_table.md` qua `scripts/make_tables.py`.
- [ ] Đã tạo `figures/hash_benchmark.png` với error bars (95% CI).

## 5. X.509 parsing
- [ ] `--algo x509 --in cert.crt` trích Subject, Issuer, validity, SANs, algorithm.
- [ ] Negative test cert tampered/sửa 1 byte → fail.
- [ ] Negative test cert hết hạn → fail.
- [ ] Sử dụng `X509_check_certificate_times()` cho kiểm tra thời gian (API 4.0).

## 6. Documentation
- [ ] `lab4/README.md` có: mục overview, build instruction (Win + Linux), CLI ví dụ, known limitations.
- [ ] `lab4/RUN_GUIDE.md` có đầy đủ bước 0→5, format dán kết quả, next steps.
- [ ] `lab4/ENV_CHECK.md` (root) đã chạy và kết quả dán.

## 7. Báo cáo (report_lab4.md) - Placeholder chờ dữ liệu thực
- [ ] Mục Objective & outcomes: ✓ (đã viết lý thuyết).
- [ ] Mục Design & security: ✓ (đã tham số, fail-closed, limitations).
- [ ] Mục Test methodology: placeholder → sẽ điền khi có KAT result, CSV.
- [ ] Mục Performance: placeholder → sẽ điền khi có benchmark CSV, bảng Table, đồ thị PNG.
- [ ] Mục Discussion: chờ dữ liệu thực để trả lời các câu hỏi.
- [ ] Mục Conclusion: chờ dữ liệu thực.
- [ ] Appendix A: Academic Integrity & Ethics (dán nguyên văn từ đề).
- [ ] Appendix B: Rubric Table (chưa điền điểm, chờ dữ liệu).
- [ ] Reference: FIPS 180-4, 202, 203, 204; RFC 5280, 6979; OpenSSL 4.0 release notes.

## 8. Output files check list (sau khi chạy run_all)
- [ ] `logs/kat_run.log`
- [ ] `results/sha256_1m.csv`, `results/sha512_1m.csv`, `results/sha3-256_1m.csv`, `results/sha3-512_1m.csv`
- [ ] `results/sha256_100m_stream.csv`, `results/sha512_1g_stream.csv`, `results/sha256_1g_mmap.csv`
- [ ] `results/valid_cert_info.txt`, `results/tampered_info.txt` (nếu có cert)
- [ ] `results/expired_info.txt` (nếu có cert hết hạn)
- [ ] `results/benchmark_table.md`
- [ ] `figures/hash_benchmark.png`

---
*Self-score chỉ điền sau khi có dữ liệu thực. TA score để trống cho đến khi cô giáo chấm.*