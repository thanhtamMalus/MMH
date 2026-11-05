# REPORT_OUTLINE.md — Đàn ý báo cáo kỹ thuật

## 1. Giới thiệu & Mục tiêu
- Mô tả về lab 3: RSA-OAEP & Hybrid Encryption
- Mục tiêu thực hiện: công cụ CLI `rsatool` với RSA-OAEP SHA-256, envelope hybrid
- Mô tả ngắn về kiến trúc: OpenSSL 4.x, EVP API, OSSL_ENCODER/DECODER

## 2. Lý thuyết RSA-OAEP
- Sơ đồ OAEP: lhash, PS, 0x01, M, seed, MGF1
- Tại sao IND-CCA2: mô hình ngẫu nhiên, ràng buộc plaintext-awareness
- Chứng minh sơ lược: Fujisaki-Okamoto-Shoup-Pointcheval
- Sự khác biệt so với PKCS#1 v1.5

## 3. Vì sao PKCS#1 v1.5 không an toàn
- Bleichenbacher 1998: padding oracle attack
- Lỗi ROBOT (Return Of Bleichenbacher's Oracle Threat)
- So sánh với OAEP: OAEP bảo vệ tegen adaptive chosen ciphertext attack

## 4. Giới hạn plaintext `mLen ≤ k − 2·hLen − 2`
- Suy ra công thức: k = byte của modulus, hLen = 32 (SHA-256)
- Ví dụ: RSA-3072: k = 384 → mLen tối đa 318 byte
- RSA-4096: k = 512 → mLen tối đa 446 byte
- Lý do RSA không dùng trực tiếp cho file lớn: giới hạn kích thước, tốc độ chậm, không xác thực, chi phí bộ nhớ

## 5. Mã hóa lai/Envelope
- Sơ đồ khối: Direct vs Hybrid
- Định dạng envelope: magic "RSAE", version, header_len u32, header JSON, payload
- AAD: `"RSAE-AAD-v1|" + mode + "|" + rsa_modulus + "|" + hash + "|" + wrapped_key_b64 + "|" + iv_b64`
- Tại sao GCM yêu cầu IV duy nhất: mỗi lần mã hóa sinh khóa AES mới

### 5.1. Direct mode
- header.mode = "RSA-OAEP"
- payload = RSA ciphertext (k byte)
- Giới hạn: mLen ≤ 318 (3072) hoặc 446 (4096)

### 5.2. Hybrid mode
- header.mode = "RSA-OAEP-AES-GCM"
- payload = AES-256-GCM ciphertext (không gồm tag)
- Header JSON: mode, rsa_modulus, hash, wrapped_key (base64 32 byte), iv (base64 12 byte), tag (base64 16 byte)

## 6. Thiết kế & triển khai
- Kiến trúc module: errors → ossl_raii → util → rsa_oaep → envelope → hybrid → keyio → cli → main
- Lựa chọn OpenSSL 4.x và API EVP/OSSL_ENCODER
- Định dạng khóa: PEM (SPKI/PKCS#8), DER, metadata JSON
- Quyết định thiết kế: auto mode Direct↔Hybrid dựa trên size threshold
- Xử lý lỗi fail-closed: tiêu chuẩn lỗi chung, ERR_clear_error(), không leak chi tiết

### 6.1. Lựa chọn thư viện
- Chỉ `libcrypto` (không `libssl`)
- Không Crypto++ hay thư viện mật mã nào khác
- OpenSSL 4.x (≥ 4.0) bắt buộc
- Define `OPENSSL_NO_DEPRECATED` cho mọi target

### 6.2. Xử lý lỗi
- `rsalab::UsageError`, `rsalab::IoError`, `rsalab::CryptoFailure`
- Mã thoát: 0 OK, 1 sai tham số, 2 I/O/khóa, 3 giải mã thất bại
- `--verbose` chỉ in kích thước, mode, phiên bản OpenSSL

## 7. Kiểm thử
### 7.1. Test tự động (Catch2, chạy qua ctest)
- Kiểm tra round-trip Direct với các kích thước: empty, 1 byte, mLen_max (318), mLen_max+1 → Hybrid
- Test Hybrid: 1 KiB, 1 MiB (100 MiB không đưa vào test)
- Test cả RSA-3072 và RSA-4096 (4096 có thể đánh dấu [slow])
- Test label khớp/rỗng
- Kiểm tra max_plaintext_len(3072)==318, max_plaintext_len(4096)==446
- Test encoding: raw/hex/base64 round-trip
- Test phiên bản: OPENSSL_VERSION_MAJOR >= 4

### 7.2. Test tiêu cực / Fail-closed
Mỗi test kiểm tra: ném CryptoFailure (hoặc trả mã 3), thông điệp `"decryption failed"` (không rò rỉ), và file output không tồn tại / plaintext rỗng:
1. Lật 1 bit trong RSA ciphertext (Direct) → thất bại
2. Lật 1 bit trong payload AES-GCM (Hybrid) → thất bại (lỗi xác thực tag)
3. Lật 1 bit trong tag → thất bại
4. Giải mã bằng private key khác → thất bại (cả Direct và Hybrid)
5. Giải mã với label sai (và label thiếu) → thất bại (cả Direct và Hybrid)
6. Sửa header JSON: đổi iv, đổi wrapped_key, đổi rsa_modulus, đổi mode, thêm khoảng trắng/field lạ → thất bại
7. Cắt cụt envelope (thiếu payload/tag), thêm byte thừa vào cuối → thất bại
8. Magic/version sai → thất bại
9. Test thông điệp lỗi: chuỗi lỗi không chứa các từ padding, tag, label, OAEP, mac, và không chứa chuỗi đặc trưng của OpenSSL như error:, routines, evp, rsa_
10. Hàng đợi lỗi OpenSSL không "rò" sang thao tác kế tiếp: sau một lần giải mã thất bại, một lần giải mã đúng ngay sau đó vẫn thành công (ERR_clear_error hoạt động đúng)

### 7.3. Kết quả test (placeholder)
- `{{TODO: dán kết quả ctest}}` - điền sau chạy ctest
- Danh sách test: `{{TODO: dán danh sách test từ results/test_list.txt}}`

## 8. Hiệu năng
### 8.1. Phương pháp đo
- Đồng hồ: `std::chrono::steady_clock`, đơn vị micro/nano giây
- Warm-up ≥ 3 lần bỏ ra ngoài
- Chống tối ưu hóa bỏ code: dùng kết quả: cộng vào biến `volatile`/in checksum
- Tách chi phí khởi tạo ra khỏi vùng đo: `EVP_MD_fetch`/`EVP_CIPHER_fetch` và nạp khóa thực hiện một lần ngoài vòng lặp

### 8.2. Môi trường đo (placeholder)
- `{{TODO: dán số liệu từ results/bench_env.txt}}` - điền sau chạy bench
- Phiên bản OpenSSL: `{{TODO}}`
- CPU/tăng tốc phần cứng: `{{TODO}}` (OpenSSL_version(OPENSSL_CPU_INFO))
- OS, compiler, loại build

### 8.3. Bảng/ đồ thị (placeholder)
- `{{TODO: chèn từ report/figures}}`
- 4 đồ thị:
  1. `latency_rsa_keygen.png` — keygen 3072 vs 4096 (log-scale nếu cần)
  2. `latency_rsa_encdec.png` — encrypt vs decrypt, 3072 vs 4096 (nhóm cột)
  3. `throughput_aesgcm.png` — MiB/s theo cỡ dữ liệu
  4. `latency_hybrid_total.png` — tổng thời gian hybrid theo 1 KiB / 1 MiB / 100 MiB (log-log), 3072 vs 4096

### 8.4. Phân tích bắt buộc
- **chi phí giải mã RSA (d lớn)** vs **mã hóa RSA (e=65537 nhỏ)**: số phép nhân modulo ~ log₂d vs 17 (e = 2¹⁶+1), CRT tăng tốc ~4×
- **đánh đổi kích thước khóa ↔ hiệu năng** (3072 vs 4096: độ phức tạp ~O(k³) cho decrypt)
- ưu thế của Hybrid so với RSA thuần: mô phỏng băng thông (AES-NI, CLMUL/GHASH, xử lý theo luồng)
- Mẹo: throughput AES áp đảo hơn so với RSA mã hóa/giải mã

## 9. Bonus A (+5)
- Tự cài OAEP thủ công (MGF1, XOR mask, unpad constant-time)
- Thêm tuỳ chọn CLI `--impl lib|manual` cho `encrypt`/`decrypt` để minh hoạ
- Giải thích tại sao decode phải constant-time: tấn công Manger: oracle phân biệt lỗ‌ "byte đầu ≠ 0x00" với lỗi khác → khôi phục plaintext từng bit/byte; nên mọi lỗi phải không phân biệt được cả về thông điệp lẫn thời gian
- Test cross-check: `manual_encrypt` ↔ `library_decrypt` và `library_encrypt` ↔ `manual_decrypt` đều round-trip

## 10. Bonus B (+10)
- Phân tích bảo mật lai (TLS handshake, forward secrecy, ML-KEM)
- 4 mục chính:
  1. So sánh Envelope vs RSA trực tiếp
  2. TLS handshake như một thiết kế lai
  3. Forward secrecy: RSA key transport thuần không có FS
  4. Lộ trình nâng cấp: ECDHE + HKDF + AEAD; sau đó ML-KEM (FIPS 203) lai X25519+ML-KEM
- Có thể nêu OpenSSL 4.x đã hỗ trợ ML-KEM/hybrid group ở tầng provider/TLS
- Cách dùng `EVP_PKEY_encapsulate`/`EVP_PKEY_decapsulate` cho KEM (chỉ nêu hướng, không bắt buộc cài)

## 11. Kết luận, hạn chế, hướng phát triển
- Tóm tắt kết quả lab 3
- Giới hạn: phụ thuộc OpenSSL 4.x; API có thể khác 3.x; không chạy trên nền tindows test môi trường
- Hướng phát triển: ECDHE, ML-KEM, mở rộng thêm AES-CTR+HMAC

## 12. Tài liệu tham khảo
- RFC 8017: PKCS #1 v2.2 (OAEP)
- NIST SP 800-38D: Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC
- Bleichenbacher 1998: "A Summative Attack on Based-Encryption
- Manger 2001: A Chosen-Ciphertext Attack on RSA OAEP
- FIPS 203: ML-KEM
- RFC 8446: TLS 1.3
- docs.openssl.org/4.0/

## 13. Phụ lục: Lệnh đã chạy, log
- `{{TODO: dán log build}}`
- `{{TODO: dán log ctest}}`
- `{{TODO: dán log demo}}`
- `{{TODO: dán log benchmark}}`
- `{{TODO: dán figures}}`

### Checklist số liệu/hình/log cần điền:
| # | Mục | File/Hình | Trạng thái |
|---|-----|-----------|------------|
| 1 | Log build Linux / MSVC / MinGW | `results/build_*.log` | Chưa thu |
| 2 | Kết quả ctest | `results/ctest_*.log` + ảnh chụp | Chưa thu |
| 3 | Danh sách test | `results/test_list.txt` | Chưa thu |
| 4 | Demo keygen & metadata | `results/demo_linux.log`, ảnh `ls keys/` | Chưa thu |
| 5 | Demo Direct + biên 318/319 | `results/demo_linux.log` | Chưa thu |
| 6 | Demo Hybrid 1KiB/1MiB/100MiB + hash khớp | `results/demo_hybrid_*.log` | Chưa thu |
| 7 | Header JSON của envelope | ảnh chụp lệnh Python | Chưa thu |
| 8 | Negative tests | `results/negative_tests.log` | Chưa thu |
| 9 | Bảng thống kê | `results/bench_summary.md` | Chưa thu |
| 10 | 4 đồ thị | `report/figures/*.png` | Chưa thu |
| 11 | Môi trường đo | `results/bench_env.txt` | Chưa thu |