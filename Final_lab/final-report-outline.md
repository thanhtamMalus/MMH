# BÁO CÁO KỸ THUẬT TỔNG HỢP: CHUỖI THỰC HÀNH MẬT MÃ VÀ ỨNG DỤNG (LABS 1 – 6)

**Học phần**: Mật mã và Ứng dụng  
**Mã SV / Nhóm**: [Điền Mã Sinh Viên / Tên Nhóm]  
**Họ và tên**: [Điền Họ và Tên Sinh Viên]  
**Hệ điều hành thử nghiệm**: Windows 11 (MSVC / MinGW64) & Ubuntu LTS (GCC / Clang)  
**Ngày nộp**: [Điền Ngày Nộp Báo Cáo]  

---

## BẢNG THÔNG TIN MÔI TRƯỜNG VÀ CẤU HÌNH PHẦN CỨNG

| Thành phần | Môi trường Windows | Môi trường Linux (Ubuntu) |
| :--- | :--- | :--- |
| **CPU** | [Ví dụ: Intel Core i7-12700H @ 2.30GHz (14 cores, 20 threads)] | [Ví dụ: Intel Core i7-12700H @ 2.30GHz] |
| **RAM** | [Ví dụ: 16 GB DDR5 4800 MHz] | [Ví dụ: 16 GB DDR5 4800 MHz] |
| **Ổ cứng** | [Ví dụ: NVMe SSD 512 GB] | [Ví dụ: NVMe SSD 512 GB] |
| **Hệ điều hành** | Windows 11 Pro 64-bit | Ubuntu 22.04.4 LTS (Linux kernel 5.15) |
| **Trình biên dịch & Cờ** | MSVC `cl.exe` (VS 2022) / `/O2 /std:c++17` | GCC `g++ 11.4` / `-O3 -std=c++17` |
| **Phiên bản Thư viện** | Crypto++ 8.9.0 / OpenSSL 3.0.13 | Crypto++ 8.9.0 / OpenSSL 3.0.13 |

---

## MỤC LỤC

1. [Chương I: Tổng quan Kiến trúc Hệ thống & Quy chuẩn Kỹ thuật](#chuong-i-tong-quan-kien-truc-he-thong--quy-chuan-ky-thuat)
2. [Chương II: Lab 1 — Symmetric Encryption with Crypto++](#chuong-ii-lab-1--symmetric-encryption-with-cryptopp)
3. [Chương III: Lab 2 — AES-128 Implementation in Pure C++ (CTR Mode)](#chuong-iii-lab-2--aes-128-implementation-in-pure-c-ctr-mode)
4. [Chương IV: Lab 3 — RSA-OAEP & Hybrid Encryption (Crypto++ / OpenSSL)](#chuong-iv-lab-3--rsa-oaep--hybrid-encryption-cryptopp--openssl)
5. [Chương V: Lab 4 — Hashing, PKI, and Practical Attacks](#chuong-v-lab-4--hashing-pki-and-practical-attacks)
6. [Chương VI: Lab 5 — Classical Digital Signatures (ECDSA, RSA-PSS)](#chuong-vi-lab-5--classical-digital-signatures-ecdsa-rsa-pss)
7. [Chương VII: Lab 6 — Post-Quantum Signatures & Certificates (ML-DSA, ML-KEM)](#chuong-vii-lab-6--post-quantum-signatures--certificates-ml-dsa-ml-kem)
8. [Chương VIII: Tổng hợp Thực nghiệm Hiệu năng & So sánh Đa Nền tảng](#chuong-viii-tong-hop-thuc-nghiem-hieu-nang--so-sanh-da-nen-tang)
9. [Phụ lục A: Cam kết Liêm chính Học thuật & Đạo đức](#phu-luc-a-cam-ket-liem-chinh-hoc-thuat--dao-duc)
10. [Phụ lục B: Bảng Tự Đánh giá Kết quả (Self-Grade Rubric)](#phu-luc-b-bang-tu-danh-gia-ket-qua-self-grade-rubric)
11. [Phụ lục C: Hướng dẫn Biên dịch & Danh mục Lệnh CLI](#phu-luc-c-huong-dan-bien-dich--danh-muc-lenh-cli)

---

## CHƯƠNG I: TỔNG QUAN KIẾN TRÚC HỆ THỐNG & QUY CHUẨN KỸ THUẬT

### 1.1 Mục tiêu Chuỗi Bài Thực hành
- Trình bày tóm tắt mục tiêu tích hợp giữa lý thuyết mật mã và kỹ năng lập trình an toàn C++17.
- Hệ thống hóa các kỹ thuật phát triển CLI, kiểm thử tiêu cực (Negative Testing), KAT (Known Answer Tests), và phương pháp đo đạc hiệu năng chuẩn thống kê.

### 1.2 Kiến trúc Hệ thống Biên dịch Đa Nền tảng (CMake Cross-Platform Build)
- Mô tả cấu trúc file `CMakeLists.txt` tổng quát cho phép biên dịch linh hoạt out-of-source trên Windows (MSVC/MinGW64) và Linux (GCC/Clang).
- Nguyên tắc sử dụng đường dẫn tương đối qua `${CMAKE_CURRENT_SOURCE_DIR}` và cấm hardcode đường dẫn tuyệt đối.

### 1.3 Quy chuẩn An toàn & Quản lý Bộ nhớ (Security Hygiene & Memory Management)
- **Sinh số ngẫu nhiên an toàn**: Bắt buộc dùng `AutoSeededRandomPool` (Crypto++) hoặc `RAND_bytes` (OpenSSL), cấm dùng `rand()`, `std::mt19937`.
- **Dọn dẹp bộ nhớ nhạy cảm**: Áp dụng `OPENSSL_cleanse()` hoặc `memset_s()` bóc tách khóa và IV khỏi RAM trước khi giải phóng.
- **Xử lý lỗi an toàn (Fail-Closed Paradigm)**: Khi phát hiện lỗi định dạng, sai tag AEAD hay sai IV, chương trình dừng ngay lập tức mà không rò rỉ thông tin qua thông báo lỗi.

---

## CHƯƠNG II: LAB 1 — SYMMETRIC ENCRYPTION WITH CRYPTO++

### 2.1 Mục tiêu & Phạm vi Thiết kế
- Triển khai công cụ dòng lệnh mã hóa đối xứng hỗ trợ 8 chế độ hoạt động: ECB, CBC, OFB, CFB, CTR, XTS, CCM (AEAD), GCM (AEAD).
- Sử dụng duy nhất thư viện **Crypto++** và **C++ STL** (cấm sử dụng OpenSSL ở Lab 1).

### 2.2 Thiết kế Kỹ thuật & Cơ chế Phòng ngừa Lỗi Mật mã (Misuse Prevention)
- **Cảnh báo và Giới hạn ECB**: Xuất thông báo cảnh báo an ninh, chặn file $> 16\text{ KiB}$ ngoại trừ khi có cờ `--allow-ecb`.
- **Cấu trúc Sidecar Header JSON**:
  ```json
  {
    "alg": "AES-256-GCM",
    "iv": "4a5b6c...",
    "aad": "7d8e9f...",
    "tag": "1a2b3c..."
  }
  ```

### 2.3 Phương pháp Kiểm thử & Kết quả Xác minh (KATs & Negative Tests)
- Bảng thống kê chạy runner `--kat vectors.json` đối chiếu với NIST SP 800-38A, GCM, CCM vectors.
- Kết quả kịch bản Negative Testing: Sai khóa, sai IV, lật bit Ciphertext, lật bit Tag AEAD $\rightarrow$ Xác nhận dừng an toàn.

### 2.4 Báo cáo Thực nghiệm Hiệu năng (Performance Evaluation)
- Đo Throughput (MB/s) và Latency trên các payload: 1 KB, 4 KB, 16 KB, 256 KB, 1 MB, 8 MB.
- Quy chuẩn lấy mẫu thống kê ($N \ge 30$ đợt chạy độc lập, warm-up 1–2s):

| Chế độ mã hóa | Dung lượng File | Throughput Trung bình (MB/s) | Trung vị (Median) | Độ lệch chuẩn (Std Dev) | Khoảng tin cậy 95% (95% CI) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **AES-256-CBC** | 1 MB | ... | ... | ... | $[\mu - \delta, \mu + \delta]$ |
| **AES-256-CTR** | 1 MB | ... | ... | ... | $[\mu - \delta, \mu + \delta]$ |
| **AES-256-GCM** | 1 MB | ... | ... | ... | $[\mu - \delta, \mu + \delta]$ |

- *[Chèn Biểu đồ Cột/Đường biểu diễn Băng thông có Thanh Sai số Error Bars 95% CI]*

### 2.5 Phân tích An toàn Mật mã (Security Discussion)
- Phân tích rủi ro của ECB (lộ cấu trúc hình ảnh), CBC Padding Oracle, thảm họa tái sử dụng Nonce trong CTR/GCM.

---

## CHƯƠNG III: LAB 2 — AES-128 IMPLEMENTATION IN PURE C++ (CTR MODE)

### 3.1 Mục tiêu & Ràng buộc Kỹ thuật (Strict Constraints)
- Bắt buộc lập trình thủ công thuật toán AES-128 (FIPS-197) và CTR mode (NIST SP 800-38A) bằng **C++ thuần**.
- Cấm sử dụng bất kỳ thư viện mật mã bên ngoài nào (Crypto++, OpenSSL) trong mã nguồn chính.

### 3.2 Kiến trúc Lõi AES-128 & CTR Mode
- Chi tiết 5 hàm biến đổi vòng: `AddRoundKey`, `SubBytes` (S-box), `ShiftRows`, `MixColumns`, `KeyExpansion`.
- Công thức dòng mã hóa/giải mã CTR mode:
  $$S_i = \text{AES}(K, \text{Nonce} \parallel \text{Counter}_i), \quad C_i = P_i \oplus S_i, \quad P_i = C_i \oplus S_i$$
- Tài liệu hóa quy định Endianness của Counter và xử lý tràn bộ đếm (Counter Overflow).

### 3.3 Kiểm thử Xác minh & Cross-Validation
- Kết quả chạy KATs FIPS-197 và NIST SP 800-38A.
- Bằng chứng đối chiếu Ciphertext giữa mã C++ tự viết và OpenSSL/Crypto++ (khớp 100% bit-exact).
- Kết quả Negative Tests: Chèn file bị lật bit $\rightarrow$ CTR giải mã ra dữ liệu hỏng nhưng không báo lỗi do CTR không có tính năng xác thực toàn vẹn (Authenticity).

### 3.4 Thực nghiệm & Phân tích Hiệu năng
- Đánh giá băng thông trên các file **1 MiB, 100 MiB, 1 GiB**:

| Phiên bản triển khai | File 1 MiB (MB/s) | File 100 MiB (MB/s) | File 1 GiB (MB/s) | 95% Confidence Interval |
| :--- | :--- | :--- | :--- | :--- |
| **Table-based S-box** | ... | ... | ... | ... |
| **Computed S-box** | ... | ... | ... | ... |
| **Crypto++ AES-128-CTR (Đối chứng)** | ... | ... | ... | ... |

- Phân tích hiện tượng Timing Leakage từ S-box dạng bảng tra, ảnh hưởng bộ nhớ đệm Cache (T-table leakage), và tác động của tập lệnh phần cứng AES-NI.

---

## CHƯƠNG IV: LAB 3 — RSA-OAEP & HYBRID ENCRYPTION (CRYPTO++ / OPENSSL)

### 4.1 Mục tiêu & Thuật toán Cấu hình
- Triển khai mã hóa bất đối xứng **RSA-3072 / RSA-4096** kết hợp đệm **OAEP (SHA-256, MGF1 SHA-256)**.
- Triển khai cơ chế **Mã hóa Lai (Hybrid Envelope Encryption)** khi kích thước file vượt quá giới hạn $mLen$:
  $$mLen \le k - 2 \cdot hLen - 2$$

### 4.2 Cấu trúc Gói Bao thư (Hybrid Envelope Format v1)
- Đặc tả JSON Header và Payload AES-256-GCM:
  ```json
  {
    "mode": "RSA-OAEP-AES-GCM",
    "rsa_modulus": 3072,
    "hash": "SHA-256",
    "wrapped_key": "<base64-encoded wrapped AES key>",
    "iv": "<base64-encoded 96-bit IV>",
    "tag": "<base64-encoded 128-bit authentication tag>"
  }
  ```

### 4.3 Kiểm thử Tiêu cực & Xử lý Lỗi an toàn (Fail-Closed)
- Bảng kịch bản unit test tự động (Catch2 / GoogleTest) chạy qua `ctest`:

| Kịch bản thử nghiệm | Thao tác can thiệp | Kết quả mong đợi | Trạng thái |
| :--- | :--- | :--- | :--- |
| **Altered RSA Ciphertext** | Lật 1 bit khóa AES đã bọc | Giải mã RSA-OAEP thất bại | PASS / Fail-Closed |
| **Altered AES Ciphertext** | Lật 1 bit dữ liệu mã hóa GCM | Tag Verification Failed | PASS / Fail-Closed |
| **Wrong Private Key** | Dùng RSA Private Key khác cặp | Decryption Failed | PASS / Fail-Closed |
| **Altered JSON Header** | Sửa giá trị AAD trong Header | GCM Tag Mismatch | PASS / Fail-Closed |

### 4.4 Thực nghiệm Hiệu năng RSA vs Hybrid Mode
- Đo độ trễ Sinh khóa, Mã hóa, Giải mã RSA-3072 vs RSA-4096.
- Đo băng thông Mã hóa Lai trên các tập tin 1 KiB, 1 MiB, 100 MiB.
- Phân tích sự chênh lệch chi phí tính toán giữa số mũ công khai $e=65537$ và số mũ riêng $d$.

---

## CHƯƠNG V: LAB 4 — HASHING, PKI, AND PRACTICAL ATTACKS

### 5.1 Bộ Trình Mã hóa Băm (`hashtool`)
- Trình bày chi tiết triển khai họ SHA-2 (SHA-224/256/384/512), SHA-3 (SHA3-224/256/384/512) và SHAKE128/SHAKE256 (XOFs).
- Cơ chế xử lý luồng (Streaming I/O) cho file dung lượng lớn ($> 1\text{ GiB}$).

### 5.2 Phân tích Chứng thư số X.509 & Triển khai HTTPS/TLS
- Kết quả trích xuất Subject, Issuer, Validity, Public Key Info, Signature Algorithm từ file X.509.
- Báo cáo bài thực hành TLS Deployment (cấu hình Apache/Nginx HTTPS với ZeroSSL/ECDSA cert, ảnh chụp màn hình log và sơ đồ Chuỗi tin cậy Chain of Trust).

### 5.3 Thử nghiệm Va chạm MD5 (Controlled MD5 Collision)
- Báo cáo kết quả chạy `hashclash` tạo 2 file ảnh PNG (hoặc 2 chương trình C++) có cùng mã băm MD5.
- Phân tích sự khác biệt giữa Tấn công Va chạm (Collision) và Tấn công Tiền ảnh (Preimage).

### 5.4 Tấn công Mở rộng Độ dài (Length-Extension Attack on Naïve MAC)
- Thực nghiệm tấn công trên cấu trúc $\text{MAC} = H(k \parallel m)$ không cần biết khóa $k$.
- Sơ đồ minh họa cấu trúc đệm Merkle–Damgård và lý giải vì sao HMAC triệt tiêu hoàn toàn lỗ hổng này.

---

## CHƯƠNG VI: LAB 5 — CLASSICAL DIGITAL SIGNATURES (ECDSA, RSA-PSS)

### 6.1 Thuật toán & Tham số Chữ ký Số
- ECDSA-P256 (bổ sung ECDSA-P384) tuân thủ RFC 6979 (Deterministic Nonce Generation).
- RSA-PSS-3072 (SHA-256, Salt length = 32 bytes).

### 6.2 Giao diện CLI (`sigtool`) & Xác thực Chữ ký Tách rời (Detached Signatures)
- Trình bày định dạng lưu trữ file chữ ký (.sig nhị phân / Base64) và quy trình xác thực.

### 6.3 Đánh giá Hiệu năng Chữ ký Số
- Bảng so sánh độ trễ Sinh khóa, Ký (Sign), và Xác thực (Verify) giữa ECDSA vs RSA-PSS trên các kích thước dữ liệu (1 KiB, 16 KiB, 1 MiB, 8 MiB).
- Phân tích ưu thế kích thước chữ ký nhỏ của ECDSA so với tốc độ xác thực cực nhanh của RSA-PSS.

---

## CHƯƠNG VII: LAB 6 — POST-QUANTUM SIGNATURES & CERTIFICATES (ML-DSA, ML-KEM)

### 7.1 Mật mã Hậu Lượng tử (Post-Quantum Cryptography Primitives)
- Triển khai Chữ ký số hậu lượng tử **ML-DSA-44** (tương đương NIST Security Level 2).
- Triển khai Cơ chế Đóng gói Khóa hậu lượng tử **ML-KEM-512** (Encapsulation / Decapsulation).

### 7.2 Mini-Project: Cấu trúc Chứng thư Hậu Lượng tử (PQ Certificate Structure)
- Trình bày đoạn mã JSON chứng thư tự tạo được ký bởi CA dùng ML-DSA:
  ```json
  {
    "subject": "Student PQ Identity",
    "public_key": "<ML-DSA public key base64>",
    "issuer": "PQ-CA-Root",
    "signature": "<ML-DSA signature base64>"
  }
  ```

### 7.3 Phân tích So sánh PQC vs Mật mã Kinh điển (ECDSA / RSA)
- Bảng so sánh kích thước Khóa, Chữ ký / Ciphertext, và Độ trễ thực thi giữa ML-DSA / ML-KEM so với RSA-3072 và ECDSA-P256.

---

## CHƯƠNG VIII: TỔNG HỢP THỰC NGHIỆM HIỆU NĂNG & SO SÁNH ĐA NỀN TẢNG

### 8.1 Bảng Tổng hợp Hiệu năng Toàn bộ Chuỗi Bài Lab (Labs 1–6)

| Bài Lab | Thuật toán cốt lõi | Băng thông / Độ trễ (Windows) | Băng thông / Độ trễ (Linux Ubuntu) | Chênh lệch (%) |
| :--- | :--- | :--- | :--- | :--- |
| **Lab 1** | AES-256-GCM | ... MB/s | ... MB/s | $\pm ...\%$ |
| **Lab 2** | AES-128-CTR (C++ thuần) | ... MB/s | ... MB/s | $\pm ...\%$ |
| **Lab 3** | RSA-3072 Decryption | ... ms/op | ... ms/op | $\pm ...\%$ |
| **Lab 4** | SHA3-256 Streaming | ... MB/s | ... MB/s | $\pm ...\%$ |
| **Lab 5** | ECDSA-P256 Verify | ... ops/sec | ... ops/sec | $\pm ...\%$ |
| **Lab 6** | ML-KEM-512 Encaps | ... ops/sec | ... ops/sec | $\pm ...\%$ |

### 8.2 Biểu đồ So sánh Đa Nền tảng (Windows vs Linux)
- *[Chèn Biểu đồ Đồ thị So sánh Băng thông & Độ trễ có Thanh Sai số Error Bars 95% CI]*
- Phân tích nguyên nhân chênh lệch hiệu năng: OS Scheduler, System Call Overhead, Cờ tối ưu trình biên dịch MSVC (`/O2`) vs GCC (`-O3`), cơ chế cấp phát bộ nhớ RAM.

---

## PHỤ LỤC A: CAM KẾT LIÊM CHÍNH HỌC THUẬT & ĐẠO ĐỨC

1. **Tuyên bố Nguyên bản (Statement of Originality)**: Tôi/Nhóm chúng tôi cam kết toàn bộ mã nguồn C++ và nội dung báo cáo kỹ thuật này là sản phẩm tự làm của cá nhân/nhóm. Các thư viện mật mã cho phép (Crypto++, OpenSSL) và tài liệu tham khảo đều được trích dẫn đầy đủ.
2. **Khai báo Trợ giúp Công cụ / AI**: [Khai báo chi tiết các công cụ đã sử dụng để hỗ trợ tìm hiểu tài liệu, kiểm thử hoặc viết báo cáo, nếu có].
3. **Tuyên bố An toàn & Đạo đức Mật mã (Ethics Notice)**: Mọi thao tác thử nghiệm tấn công (MD5 Collision, Length-Extension Attack) đều được thực hiện hoàn toàn trong môi trường sandbox cách ly, trên các tập tin thử nghiệm offline do chúng tôi sở hữu. Chúng tôi cam kết tuyệt đối không tấn công vào các hệ thống thực tế hay dịch vụ trực tuyến.

---

## PHỤ LỤC B: BẢNG TỰ ĐÁNH GIÁ KẾT QUẢ (SELF-GRADE RUBRIC)

| Tiêu chí Đánh giá (Rubric Criterion) | Điểm Tối đa | Điểm Tự chấm (Self-Score) | Ghi chú minh chứng của Sinh viên |
| :--- | :---: | :---: | :--- |
| **Tính Đúng đắn Mật mã & KATs** | **35 - 40** | [Ví dụ: 38/40] | Vượt qua 100% test vectors FIPS-197, NIST SP 800-38A/38D, SHA-3 KATs. |
| **An toàn Mật mã & Kiểm thử Tiêu cực** | **10 - 20** | [Ví dụ: 18/20] | Đã xử lý fail-closed cho toàn bộ lỗi sai key, sai IV, sai tag AEAD. |
| **Biên dịch Đa nền tảng & CMake/UX** | **10** | [Ví dụ: 10/10] | Build out-of-source thành công trên cả Windows (MSVC) và Ubuntu (GCC). |
| **Thực nghiệm Hiệu năng & Thống kê** | **10 - 20** | [Ví dụ: 18/20] | Thu thập đủ $N \ge 30$ đợt chạy, tính Mean, Median, 95% CI, vẽ đồ thị error bars. |
| **Chất lượng Báo cáo Kỹ thuật** | **5 - 10** | [Ví dụ: 9/10] | Trình bày bài bản, phân tích chuyên sâu các nguy cơ an ninh mật mã. |
| **Phần Điểm thưởng (Bonuses)** | **+15** | [Ví dụ: +10/15] | Tự triển khai đệm OAEP bằng tay (+5) và demo Length-Extension (+5). |
| **TỔNG ĐIỂM DỰ KIẾN** | **100 (+Bonus)** | **[Ví dụ: 103/100]** | |

---

## PHỤ LỤC C: HƯỚNG DẪN BIÊN DỊCH & DANH MỤC LỆNH CLI

### C.1 Cấu trúc Thư mục Nộp bài (`MSV.All6labs.zip`)
```text
MSV.All6labs/
├── CMakeLists.txt
├── README.md
├── Report_Final.pdf (hoặc .docx)
├── bin/
│   ├── win64/
│   └── linux64/
├── lab1/
├── lab2/
├── lab3/
├── lab4/
├── lab5/
└── lab6/
```

### C.2 Lệnh Biên dịch Out-of-Source Chuẩn
```bash
# Trên Linux (Ubuntu)
mkdir build && cd build
cmake ..
cmake --build .
ctest --output-on-failure

# Trên Windows (Developer Command Prompt for VS 2022)
mkdir build && cd build
cmake -G "Visual Studio 17 2022" -A x64 ..
cmake --build . --config Release
ctest -C Release --output-on-failure
```

### C.3 Danh mục Lệnh CLI Mẫu đại diện các Bài Lab
```bash
# Lab 1: Mã hóa AES-256-GCM với AAD
./mytool encrypt --mode gcm --key key.bin --iv iv.bin --aad-text "header-info" --in msg.bin --out ct.bin

# Lab 2: AES-128-CTR tự viết & KATs
./aestool encrypt --mode ctr --key key.bin --iv iv.bin --in msg.bin --out ct.bin
./aestool --kat vectors.json

# Lab 3: RSA-OAEP & Hybrid Envelope
./rsatool keygen --bits 3072 --pub pub.pem --priv priv.pem
./rsatool encrypt --in largefile.iso --pub pub.pem --out envelope.json

# Lab 4: Hashing Stream & Certificate Parsing
./hashtool --algo sha3-256 --in large.iso --stream
./hashtool parse-cert --in cert.pem

# Lab 5: Ký chữ ký số tách rời ECDSA
./sigtool sign --algo ecdsa-p256 --priv priv.pem --in doc.pdf --out doc.pdf.sig

# Lab 6: Post-Quantum KEM & Signature
./pqtool encaps --algo mlkem-512 --pub pub.pem --ct ct.bin --ss ss.bin
```
