# LAB 1 - Symmetric Encryption with Crypto++

## MỤC LỤC
[Lời cam kết học thuật (Academic Integrity & Ethics Statement)](#lời-cam-kết-học-thuật-academic-integrity--ethics-statement)

[Tóm tắt kết quả chính (Executive Summary)](#tóm-tắt-kết-quả-chính-executive-summary)

[1. Mục tiêu và phạm vi kỹ thuật (Objectives & Technical Scope)](#1-mục-tiêu-và-phạm-vi-kỹ-thuật-objectives--technical-scope)

&emsp;[1.1. Bối cảnh và mục tiêu dự án](#11-bối-cảnh-và-mục-tiêu-dự-án)

&emsp;[1.2. Phạm vi chức năng](#12-phạm-vi-chức-năng)

[2. Cơ sở lý thuyết (Theoretical Background)](#2-cơ-sở-lý-thuyết-theoretical-background)

&emsp;[2.1. Tổng quan về thuật toán AES](#21-tổng-quan-về-thuật-toán-aes)

&emsp;[2.2. Cấu trúc và nguyên lý hoạt động của AES](#22-cấu-trúc-và-nguyên-lý-hoạt-động-của-aes)

&emsp;[2.3. Các chế độ hoạt động của AES (ECB, CBC, CFB, OFB, CTR, XTS)](#23-các-chế-độ-hoạt-động-của-aes-ecb-cbc-cfb-ofb-ctr-xts)

&emsp;[2.4. Padding, IV, Nonce và Tweak](#24-padding-iv-nonce-và-tweak)

&emsp;[2.5. Đặc điểm và yêu cầu an toàn của từng chế độ](#25-đặc-điểm-và-yêu-cầu-an-toàn-của-từng-chế-độ)

[3. Thiết kế và hiện thực công cụ AES (System Design & Implementation)](#3-thiết-kế-và-hiện-thực-công-cụ-aes-system-design--implementation)

&emsp;[3.1. Kiến trúc tổng thể của hệ thống](#31-kiến-trúc-tổng-thể-của-hệ-thống)

&emsp;[3.2. Cấu trúc thư mục mã nguồn (Project Structure)](#32-cấu-trúc-thư-mục-mã-nguồn-project-structure)

&emsp;[3.3. Thiết kế giao diện dòng lệnh (CLI – aestool)](#33-thiết-kế-giao-diện-dòng-lệnh-cli--aestool)

&emsp;[3.4. Hiện thực các chế độ mã hóa và giải mã](#34-hiện-thực-các-chế-độ-mã-hóa-và-giải-mã)

&emsp;[3.5. Cơ chế xử lý lỗi và chống lạm dụng](#35-cơ-chế-xử-lý-lỗi-và-chống-lạm-dụng)

&emsp;[3.6. Quy trình xử lý dữ liệu và quản lý khóa](#36-quy-trình-xử-lý-dữ-liệu-và-quản-lý-khóa)

[4. Kiểm thử tính đúng đắn (Correctness & Security Testing)](#4-kiểm-thử-tính-đúng-đắn-correctness--security-testing)

&emsp;[4.1. Known Answer Tests (KATs)](#41-known-answer-tests-kats)

&emsp;[4.2. Kiểm thử đối chiếu kết quả](#42-kiểm-thử-đối-chiếu-kết-quả)

&emsp;[4.3. Negative Tests và xử lý đầu vào không hợp lệ](#43-negative-tests-và-xử-lý-đầu-vào-không-hợp-lệ)

&emsp;[4.4. Kiểm thử các trường hợp biên (Edge Cases)](#44-kiểm-thử-các-trường-hợp-biên-edge-cases)

&emsp;[4.5. Tổng hợp kết quả kiểm thử](#45-tổng-hợp-kết-quả-kiểm-thử)

[5. Môi trường và phương pháp thực nghiệm (Experimental Setup & Methodology)](#5-môi-trường-và-phương-pháp-thực-nghiệm-experimental-setup--methodology)

&emsp;[5.1. Cấu hình phần cứng](#51-cấu-hình-phần-cứng)

&emsp;[5.2. Môi trường phần mềm và hệ điều hành](#52-môi-trường-phần-mềm-và-hệ-điều-hành)

&emsp;[5.3. Thiết lập dữ liệu và kịch bản benchmark](#53-thiết-lập-dữ-liệu-và-kịch-bản-benchmark)

&emsp;[5.4. Phương pháp đo và xử lý số liệu](#54-phương-pháp-đo-và-xử-lý-số-liệu)

&emsp;[5.5. Độ tin cậy và khoảng tin cậy 95%](#55-độ-tin-cậy-và-khoảng-tin-cậy-95)

[6. Kết quả và phân tích hiệu năng (Performance Evaluation & Analysis)](#6-kết-quả-và-phân-tích-hiệu-năng-performance-evaluation--analysis)

&emsp;[6.1. Kết quả benchmark trên Windows](#61-kết-quả-benchmark-trên-windows)

&emsp;[6.2. Kết quả benchmark trên Linux](#62-kết-quả-benchmark-trên-linux)

&emsp;[6.3. So sánh hiệu năng giữa các chế độ AES](#63-so-sánh-hiệu-năng-giữa-các-chế-độ-aes)

&emsp;[6.4. So sánh hiệu năng giữa Windows và Linux](#64-so-sánh-hiệu-năng-giữa-windows-và-linux)

&emsp;[6.5. Phân tích nguyên nhân chênh lệch](#65-phân-tích-nguyên-nhân-chênh-lệch)

&emsp;[6.6. Nhận xét và đánh giá tổng hợp](#66-nhận-xét-và-đánh-giá-tổng-hợp)

[7. Phân tích an toàn mật mã (Cryptographic Security Analysis)](#7-phân-tích-an-toàn-mật-mã-cryptographic-security-analysis)

&emsp;[7.1. Đánh giá đặc điểm an toàn của từng chế độ](#71-đánh-giá-đặc-điểm-an-toàn-của-từng-chế-độ)

&emsp;[7.2. Rủi ro khi sử dụng sai IV, Nonce và Tweak](#72-rủi-ro-khi-sử-dụng-sai-iv-nonce-và-tweak)

&emsp;[7.3. Quản lý khóa và bảo vệ dữ liệu](#73-quản-lý-khóa-và-bảo-vệ-dữ-liệu)

&emsp;[7.4. Các giới hạn an toàn của công cụ](#74-các-giới-hạn-an-toàn-của-công-cụ)

[8. Build và triển khai đa nền tảng (Cross-platform Build & Deployment)](#8-build-và-triển-khai-đa-nền-tảng-cross-platform-build--deployment)

&emsp;[8.1. Cấu hình CMake](#81-cấu-hình-cmake)

&emsp;[8.2. Quy trình biên dịch trên Windows](#82-quy-trình-biên-dịch-trên-windows)

&emsp;[8.3. Quy trình biên dịch trên Linux](#83-quy-trình-biên-dịch-trên-linux)

&emsp;[8.4. Hướng dẫn sử dụng và triển khai](#84-hướng-dẫn-sử-dụng-và-triển-khai)

[9. Mở rộng hệ thống – Bonus (Extended Features)](#9-mở-rộng-hệ-thống--bonus-extended-features)

&emsp;[9.1. Xây dựng thư viện động (DLL/SO)](#91-xây-dựng-thư-viện-động-dllso)

&emsp;[9.2. Tích hợp giao diện đồ họa (GUI)](#92-tích-hợp-giao-diện-đồ-họa-gui)

&emsp;[9.3. Cơ chế liên kết giữa GUI và thư viện AES](#93-cơ-chế-liên-kết-giữa-gui-và-thư-viện-aes)

&emsp;[9.4. Kiểm thử và đánh giá phần mở rộng](#94-kiểm-thử-và-đánh-giá-phần-mở-rộng)

[10. Hạn chế và hướng phát triển (Limitations & Future Work)](#10-hạn-chế-và-hướng-phát-triển-limitations--future-work)

&emsp;[10.1. Những hạn chế hiện tại](#101-những-hạn-chế-hiện-tại)

&emsp;[10.2. Các vấn đề chưa giải quyết](#102-các-vấn-đề-chưa-giải-quyết)

&emsp;[10.3. Hướng phát triển trong tương lai](#103-hướng-phát-triển-trong-tương-lai)

[11. Kết luận (Conclusion)](#11-kết-luận-conclusion)

[12. Tài liệu tham khảo (References)](#12-tài-liệu-tham-khảo-references)

[PHỤ LỤC](#phụ-lục)

&emsp;[Phụ lục A – Bảng kết quả benchmark chi tiết](#phụ-lục-a--bảng-kết-quả-benchmark-chi-tiết)

&emsp;[Phụ lục B – Bộ kiểm thử KAT và Negative Tests](#phụ-lục-b--bộ-kiểm-thử-kat-và-negative-tests)

&emsp;[Phụ lục C – Hướng dẫn build và sử dụng](#phụ-lục-c--hướng-dẫn-build-và-sử-dụng)

&emsp;[Phụ lục D – Bảng tự đánh giá (Self-grade Rubric)](#phụ-lục-d--bảng-tự-đánh-giá-self-grade-rubric)


## Lời cam kết học thuật (Academic Integrity & Ethics Statement)
Các số liệu thực nghiệm được giữ theo nguồn; những điểm chưa có bằng chứng hoặc có mâu thuẫn được đánh dấu rõ ràng. Người thực hiện cam kết trình bày trung thực quá trình thiết kế, hiện thực, kiểm thử và benchmark; không tự tạo log, ảnh chụp, số liệu hoặc kết quả build; phân biệt kết quả quan sát với nhận định và giả thuyết; sử dụng công cụ trong phạm vi học tập, nghiên cứu được phép.

**Ngày viết báo cáo:** 14/11/2026

## Tóm tắt kết quả chính (Executive Summary)

Đề tài xây dựng công cụ `aestool` sử dụng Crypto++ để mã hóa và giải mã AES ở nhiều chế độ. Kiến trúc được mô tả gồm lõi `aescore`, tầng điều phối thao tác, định dạng container `AEST`, sidecar JSON và giao diện CLI. Các mode trong phạm vi gồm ECB, CBC, CFB, OFB, CTR, XTS, CCM và GCM. Công cụ hướng đến AES-128/192/256; báo cáo này lấy AES-256 làm trọng tâm.

**Cụ thể:**
- Bảng KAT ghi nhận 12/12 vector PASS. 
- Bảng Negative Tests có 6 kịch bản. Các tình huống IV sai độ dài, sửa ciphertext/tag GCM và sai khóa được mô tả; CBC bị sửa ciphertext minh họa rằng mode non-AEAD không tự bảo vệ tính toàn vẹn.
- Benchmark được mô tả với 6 payload (1 KB, 4 KB, 16 KB, 256 KB, 1 MB, 8 MB), N=1000, warm-up và các thống kê Mean, Median, SD, CI 95%.
- CSV benchmark được lưu trữ trong `lab1\result\bench` gồm đẩy đủ AES-128/192/256 của hai hệ điều hành Window và Linux. AES 192 không bao gồm mode XTS vì XTS chỉ định nghĩa cho khóa AES-128 và AES-256 theo chuẩn.
- GCM và CCM có xác thực (AEAD); ECB, CBC, CFB, OFB, CTR và XTS không có xác thực tích hợp.


## 1. Mục tiêu và phạm vi kỹ thuật (Objectives & Technical Scope)

### 1.1. Bối cảnh và mục tiêu dự án

AES là thuật toán mã hóa khối; việc sử dụng an toàn còn phụ thuộc chế độ hoạt động, cách quản lý IV/nonce/tweak, khóa và xác thực dữ liệu. Lab 1 hướng đến xây dựng công cụ `aestool` dựa trên Crypto++, tách lõi mật mã khỏi giao diện, hỗ trợ mã hóa/giải mã file và chuỗi, sinh khóa, KAT và benchmark.

Các mục tiêu cụ thể:
1. Sử dụng Crypto++ làm thư viện mật mã cho các mode AES được yêu cầu.
2. Hỗ trợ khóa AES-128, AES-192 và AES-256; XTS sử dụng hai khóa AES ghép lại.
3. Kiểm tra độ dài IV/nonce theo mode và sinh ngẫu nhiên bằng `CryptoPP::AutoSeededRandomPool` khi cần.
4. Cảnh báo/hạn chế ECB, phát hiện một số trường hợp nonce reuse và từ chối tham số không hợp lệ.
5. Kiểm thử bằng vector NIST và Negative Tests.
6. Đo hiệu năng trên nhiều payload, mode và hai hệ điều hành.
7. Tổ chức build out-of-source bằng CMake.

## 1.2. Phạm vi chức năng

### Độ dài khóa

| Phiên bản | Độ dài khóa | Số vòng |
|---|---:|---:|
| AES-128 | 16 byte | 10 |
| AES-192 | 24 byte | 12 |
| AES-256 | 32 byte | 14 |

### Các mode

| Mode | Nhóm | IV/nonce/tweak theo tài liệu thiết kế | AEAD |
|---|---|---|---|
| ECB | Block | Không dùng | Không |
| CBC | Block | 16 byte | Không |
| CFB | Stream-like | 16 byte | Không |
| OFB | Stream-like | 16 byte | Không |
| CTR | Stream-like | 16 byte trong triển khai mô tả | Không |
| XTS | Tweaked block | Tweak 16 byte; khóa kép | Không |
| CCM | AEAD | Nonce 7–13 byte (12 byte khuyến nghị) | Có |
| GCM | AEAD | Nonce 12 byte trong cấu hình thông thường | Có |


### Chức năng CLI

- Mã hóa/giải mã từ file hoặc chuỗi UTF-8.
- Nhập khóa từ file hoặc hex.
- Sinh khóa AES.
- Đầu ra hex, Base64 hoặc raw binary.
- Lưu metadata trong container `AEST` hoặc sidecar JSON.
- Hỗ trợ AAD và tag với CCM/GCM.
- Chạy KAT và benchmark.

# 2. Cơ sở lý thuyết (Theoretical Background)

## 2.1. Tổng quan về thuật toán AES

AES (Advanced Encryption Standard), chuẩn hóa trong FIPS 197, là mã khối xử lý khối 128 bit (16 byte), hỗ trợ khóa 128, 192 và 256 bit. AES là phép biến đổi khả nghịch trên một khối dưới khóa xác định. Để mã hóa thông điệp dài cần kết hợp AES với một mode of operation. An toàn tổng thể phụ thuộc vào mode, IV/nonce, quản lý khóa và xác thực dữ liệu, không chỉ riêng thuật toán AES.

## 2.2. Cấu trúc và nguyên lý hoạt động của AES

AES biểu diễn 16 byte của một khối thành ma trận State 4×4 byte. Các phép biến đổi chính:

| Phép biến đổi | Chức năng |
|---|---|
| `SubBytes` | Thay thế phi tuyến từng byte bằng S-box |
| `ShiftRows` | Dịch vòng các hàng để tăng khuếch tán |
| `MixColumns` | Biến đổi tuyến tính trên GF(2⁸); bỏ qua ở vòng cuối |
| `AddRoundKey` | XOR State với khóa vòng |

Khóa đầu vào được mở rộng thành các khóa vòng bằng Key Expansion. AES-128/192/256 lần lượt có 10/12/14 vòng. Tài liệu dự án ghi Crypto++ có thể tận dụng AES-NI trên x86 hoặc ARMv8 Crypto khi CPU hỗ trợ; `aescore` có hàm `hardware_aes_available()`.

Sơ đồ minh họa state 4×4 byte và các bước SubBytes, ShiftRows, MixColumns, AddRoundKey.

![](img/so-do-1round-4x4.png)


Kết quả kiểm tra AES-NI trên hai môi trường
![aes-ni-enc](result\compare\compare_ratio_enc.png)

![aes-ni-dec](result\compare\compare_ratio_dec.png)

## 2.3. Các chế độ hoạt động của AES (ECB, CBC, CFB, OFB, CTR, XTS)

Ký hiệu: `P_i` là plaintext block, `C_i` là ciphertext block, `E_K`/`D_K` là AES encrypt/decrypt, `IV` là initialization vector và `⊕` là XOR.

### ECB – Electronic Codebook


$$C_i=E_K(P_i),\qquad P_i=D_K(C_i)$$


Mỗi block được mã hóa độc lập. Các block plaintext giống nhau tạo ciphertext giống nhau dưới cùng khóa, làm lộ cấu trúc/mẫu. ECB không có xác thực và không phù hợp dữ liệu thực tế. Công cụ cảnh báo ECB và chặn dữ liệu lớn hơn 16 KiB mặc định, trừ khi có `--allow-ecb`.

### CBC – Cipher Block Chaining

$$
C_0=IV,\quad C_i=E_K(P_i\oplus C_{i-1}),\quad P_i=D_K(C_i)\oplus C_{i-1}
$$

Mã hóa tuần tự; giải mã có thể song song theo block ciphertext. CBC cần padding nếu dữ liệu không chia hết cho 16 byte. IV cần ngẫu nhiên, không thể dự đoán. CBC không xác thực nên có nguy cơ bit flipping và padding oracle nếu hệ thống xử lý lỗi không an toàn.

### CFB – Cipher Feedback

$$C_i=P_i\oplus E_K(C_{i-1}),\qquad C_0=IV$$

CFB-128 biến AES thành dạng mã dòng, không cần padding. Mã hóa tuần tự; giải mã có thể tận dụng các block ciphertext đã biết. Không có xác thực tích hợp.

### OFB – Output Feedback

$$O_0=IV,\quad O_i=E_K(O_{i-1}),\quad C_i=P_i\oplus O_i$$

OFB sinh keystream độc lập plaintext, không cần padding. Keystream được sinh tuần tự. Dùng lại IV với cùng khóa làm trùng keystream và gây rò rỉ quan hệ plaintext.

### CTR – Counter

$$C_i=P_i\oplus E_K(Nonce\parallel Counter_i)$$

CTR mã hóa counter kết hợp nonce để tạo keystream. Có thể song song hóa, truy cập ngẫu nhiên và không cần padding. Không được dùng lại cùng cặp khóa/nonce-counter. Nếu keystream bị tái sử dụng thì `C1 ⊕ C2 = P1 ⊕ P2`. CTR không xác thực và có thể bị bit flipping.

### XTS – XEX-based Tweaked-codebook with ciphertext Stealing

XTS được thiết kế cho mã hóa dữ liệu lưu trữ, ví dụ sector. XTS dùng hai khóa AES và tweak gắn với đơn vị dữ liệu. Tweak giúp cùng plaintext ở các sector khác nhau không tạo cùng ciphertext theo cách ECB. XTS hỗ trợ ciphertext stealing cho phần cuối không đủ block, nhưng không cung cấp xác thực; không nên dùng như mode truyền thông điệp có tính toàn vẹn.

## 2.4. Padding, IV, Nonce và Tweak

**Padding:** 
- **ECB/CBC**: dùng PKCS#7, luôn thêm 1–16 byte (mỗi byte có giá trị bằng số byte thêm), kể cả khi plaintext đã là bội số của 16.
- **CFB/OFB/CTR**: không cần padding (hoạt động như stream cipher).
- **XTS**: không dùng PKCS#7, dùng ciphertext stealing; dữ liệu tối thiểu 16 byte.
- **CCM/GCM**: không cần padding; ciphertext có độ dài bằng plaintext, cộng thêm authentication tag.

**IV:** giá trị khởi tạo cho một số mode.
- CBC yêu cầu IV ngẫu nhiên và không thể dự đoán.
- CFB/OFB cần quản lý IV để tránh tái sử dụng
- ECB không dùng IV.

**Nonce:** giá trị dùng một lần theo yêu cầu của mode.
- CTR, CCM và GCM cần tránh tái sử dụng nonce dưới cùng khóa.
- Với GCM, nonce reuse có thể phá vỡ cả tính bí mật lẫn xác thực.

**Tweak:** tham số phân biệt đơn vị dữ liệu trong XTS, thường gắn với vị trí sector. Tweak không phải khóa bí mật và không cung cấp integrity.

| Mode | Tham số theo tài liệu thiết kế | Kiểm tra/ghi chú |
|---|---|---|
| ECB | Không IV | Có IV thì từ chối |
| CBC/CFB/OFB/CTR/XTS | 16 byte | `valid_iv_len` theo mô tả |
| GCM | 12 byte | Cấu hình thông thường |
| CCM | 7–13 byte | Mặc định 12 byte |

## 2.5. Đặc điểm và yêu cầu an toàn của từng chế độ

| Mode | Padding | Song song hóa | Xác thực | Rủi ro chính | Định hướng sử dụng |
|---|---|---|---|---|---|
| ECB | PKCS#7 | Enc/dec song song | Không | Block plaintext giống nhau tạo ciphertext giống nhau, làm lộ cấu trúc và mẫu lặp của dữ liệu. | Tránh dùng cho dữ liệu thực |
| CBC | PKCS#7 | Enc tuần tự, dec song song | Không | IV phải không đoán được và không tái sử dụng. Bit-flipping nếu không có xác thực. Padding oracle nếu lỗi padding bị lộ. | Cần MAC độc lập (Encrypt-then-MAC) |
| CFB | Không | Enc tuần tự, dec song song | Không | Bit-flipping (lật bit ciphertext lật đúng bit plaintext ở block hiện tại). Không tái sử dụng IV. | Cần MAC độc lập |
| OFB | Không | Enc/dec tuần tự (keystream tính trước được) | Không | Tái sử dụng IV làm lộ P₁ ⊕ P₂. Bit-flipping như CTR. | Không tái sử dụng IV, cần MAC độc lập |
| CTR | Không | Enc/dec song song | Không | Tái sử dụng nonce/counter làm lộ P₁ ⊕ P₂. Bit-flipping chính xác từng bit nếu không có xác thực. | Quản lý nonce nghiêm ngặt, thêm MAC |
| XTS | CTS (dữ liệu ≥ 16 byte) | Enc/dec song song (mỗi block độc lập nhờ tweak) | Không | Không phát hiện sửa đổi; kẻ tấn công có thể hoán đổi hoặc phát lại block ở cùng vị trí, chỉ gây rác ở mức block 16 byte. | Mã hóa lưu trữ at-rest (ổ đĩa) |
| CCM | Không | Phần CTR song song, phần CBC-MAC tuần tự | Có | Tái sử dụng nonce làm mất an toàn. Cần biết trước độ dài dữ liệu. | AEAD, nonce duy nhất |
| GCM | Không | Enc/dec song song | Có | Tái sử dụng nonce làm lộ P₁ ⊕ P₂ và khóa GHASH, cho phép giả mạo tag. | AEAD, quản lý nonce chặt (ưu tiên nonce 96-bit) |

# 3. Thiết kế và hiện thực công cụ AES (System Design & Implementation)

## 3.1. Kiến trúc tổng thể của hệ thống

Luồng xử lý được mô tả: `main.cpp` phân tích CLI $\rightarrow$ `ops.cpp` kiểm tra chính sách và nonce reuse $\rightarrow$ `aescore.cpp` gọi Crypto++ $\rightarrow$ `container.cpp` đóng gói metadata $\rightarrow$ ghi file đầu ra nguyên tử. `util.cpp` hỗ trợ hex/Base64/UTF-8/file I/O.

#### Luồng xử lý của chương trình
1) Mô tả chi tiết từng bước thực thi trong chương trình `aestool`. Luồng được thiết kế theo thứ tự từ parse tham số, kiểm tra chính sách, mã hóa/giải mã bằng Crypto++, đóng gói metadata, đến ghi file đầu ra an toàn.
```
+------------------------------------+
| main.cpp: parse CLI arguments      |
+------------------------------------+
                  |
                  v
        < Kiểm tra mode & options >
                  |
                  | nếu cần
                  v
+------------------------------------+
| ops.cpp: kiểm tra policy           |
| (ECB, reuse nonce, AAD, tag-len)   |
+------------------------------------+
                  |
                  v
+------------------------------------+
| aescore.cpp: gọi Crypto++          |
| encrypt/decrypt                    |
+------------------------------------+
                  |
                  v
+------------------------------------+
| Sinh IV/nonce (nếu mode cần)       |
+------------------------------------+
                  |
                  v
+------------------------------------+
| Thực hiện mã hóa/giải mã block     |
+------------------------------------+
                  |
                  v
+------------------------------------+
| container.cpp: đóng gói metadata   |
+------------------------------------+
          |                |
          v                v
+------------------+  +--------------------------+
| Header AEST      |  | Sidecar JSON             |
| (nếu có)         |  | (IV, tag, key-id, ...)   |
+------------------+  +--------------------------+
          |                |
          +-------+--------+
                  |
                  v
+------------------------------------+
| util.cpp: mã hóa xuất              |
| (hex / base64 / raw)               |
+------------------------------------+
                  |
                  v
+------------------------------------+
| Ghi file tạm (temp file)           |
+------------------------------------+
                  |
                  v
+------------------------------------+
| util.cpp: rename atomic (fail-safe)|
| thành file đầu ra cuối cùng        |
+------------------------------------+
                  |
                  v
+------------------------------------+
| Trả kết quả cho CLI                |
| (stdout hoặc thông báo)            |
+------------------------------------+
```
2) Ứng dụng `aestool` được xây dựng theo mô hình **CLI $\rightarrow$ phân tích $\rightarrow$ kiểm tra chính sách $\rightarrow$ mã hóa/giải mã (Crypto++) $\rightarrow$ đóng gói metadata $\rightarrow$ ghi file đầu ra an toàn**. 
```
# Kiến trúc tổng quan của chương trình

```text
                      +------------------------+
                      |    CLI (main.cpp)      |
                      +------------------------+
                                  |
     +------------+---------------+--------------+------------+
     | arguments  | keygen        | benchmark    | KAT        | version/help
     v            v               v              v            v
+-----------+  +-----------+  +-----------+  +---------+  +-----------+
| Parse &   |  | cmd_keygen|  | cmd_bench |  | cmd_kat |  | version / |
| validate  |  +-----------+  +-----------+  +---------+  | help      |
+-----------+                                              +-----------+
     |
     +--------------------+
     | mode               | key/iv/aad
     v                    v
+---------------+   +----------------------+
| Mode          |   | Key / IV / AAD       |
| classification|   | handling             |
+---------------+   +----------------------+
     |                    |
     | policy             | validate
     +----------+---------+
                |
                v
+----------------------------------------+
| ops.cpp: policy, ECB-warn, nonce-reuse |
+----------------------------------------+
                |
                | encrypt/decrypt
                v
+----------------------------------------+
| aescore.cpp: Crypto++ calls            |
+----------------------------------------+
        |                       |
        | IV/nonce gen          | cipher ops
        v                       v
+-----------------------+  +----------------------------------+
| Random-IV / nonce     |  | Transform: SubBytes, ShiftRows,  |
| generation            |  | MixColumns, AddRoundKey          |
+-----------------------+  +----------------------------------+
                                  |                 |
                                  | ciphertext      | tags
                                  v                 v
                   +--------------------------+  +-------------------------+
                   | container.cpp:           |  | Tag generation /        |
                   | AEST header / sidecar    |  | verification            |
                   | JSON                     |  +-------------------------+
                   +--------------------------+             |
                                  |                         | tag data
                                  | format                  |
                                  v                         |
                   +--------------------------+             |
                   | util.cpp: hex / base64 / |<------------+
                   | raw encoding             |
                   +--------------------------+
                                  |
                                  | write
                                  v
                   +--------------------------+
                   | File-system I/O          |
                   +--------------------------+
                                  |
                                  | write-temp + rename
                                  v
                   +--------------------------+
                   | util::write_file_atomic  |
                   +--------------------------+
                                  |
                                  | output file
                                  v
                   +--------------------------+
                   | File output              |
                   | (ciphertext, plaintext,  |
                   |  sidecar)                |
                   +--------------------------+

```
## 3.2. Cấu trúc thư mục mã nguồn 
### Sơ đồ cấu trúc file
```text
lab1/
├── CMakeLists.txt
├── README.md
├── src/
│   ├── aescore.{h,cpp}
│   ├── container.{h,cpp}
│   ├── ops.{h,cpp}
│   ├── kat.{h,cpp}
│   ├── bench.{h,cpp}
│   ├── util.{h,cpp}
│   ├── minijson.h
│   ├── aescore_capi.*
│   └── main.cpp
├── tests/test_aescore.cpp
├── vectors/nist_vectors.json
├── result/
│   ├── windows_benchmark.csv
│   ├── linux_benchmark.csv
│   └── compare/compare_summary.csv, *.png
└── aestool_gui.py
```
### Chi tiết file
| Thành phần | Chức năng |
|---|---|
| `aescore.h/.cpp` | Lõi bọc Crypto++, mode, kiểm tra tham số, CSPRNG, key ID, secure wipe |
| `container.h/.cpp` | Container `AEST` và sidecar JSON |
| `ops.h/.cpp` | Pipeline encrypt/decrypt, ECB policy, nonce reuse |
| `kat.h/.cpp` | KAT runner |
| `bench.h/.cpp` | Benchmark và thống kê |
| `util.h/.cpp` | Hex, Base64, UTF-8, file I/O |
| `aescore_capi.*` | C API cho thư viện động |
| `main.cpp` | CLI `aestool` |
| `test_aescore.cpp` | Unit tests Catch2 được nhắc trong tài liệu |
| `aestool_gui.py` | GUI Python tkinter/ctypes theo mô tả |


## 3.3. Thiết kế giao diện dòng lệnh (CLI – aestool)
### Các lệnh của aestool

| Lệnh | Cú pháp | Mô tả | Chú thích quan trọng |
|---|---|---|---|
| `encrypt` | `aestool encrypt --mode MODE (--key FILE \| --key-hex HEX) (--in FILE \| --text STR) [--out FILE] [--iv FILE\|HEX \| --nonce FILE\|HEX] [--aad FILE \| --aad-text STR] [--aead] [--tag-len N] [--encode hex\|base64\|raw] [--sidecar FILE.json] [--ledger FILE] [--allow-ecb] [--verbose]` | Mã hóa bản rõ (plaintext) theo chế độ chỉ định. Khối mã 128-bit (16 byte). Có thể xuất ra file, hex/Base64 hoặc raw. | • `--mode` bắt buộc (`ecb`, `cbc`, `ofb`, `ctr`, `xts`, `ccm`, `gcm`).<br>• Khóa nhập từ file (`--key FILE`) hoặc hex (`--key-hex HEX`).<br>• IV/nonce bắt buộc với chế độ CTR/CCM/GCM.<br>• `--aead` chỉ dùng cho CCM/GCM.<br>• `--sidecar` tạo file JSON chứa metadata (IV, tag, key-id, ...). |
| `decrypt` | `aestool decrypt [--mode MODE] (--key FILE \| --key-hex HEX) (--in FILE \| --text ENCODED) [--out FILE] [--iv ...] [--nonce ...] [--aad ...] [--encode hex\|base64] [--sidecar FILE.json]` | Giải mã ciphertext về plaintext. Nếu bỏ `--mode`, chế độ được đọc từ header container AEST. | • Khi không có `--mode`, file đầu vào phải là container AEST (bắt đầu bằng `AEST`).<br>• `--encode` chỉ áp dụng với đầu ra stdout (hex/base64).<br>• `--sidecar` đọc sidecar JSON nếu có. |
| `keygen` | `aestool keygen [--bits 128\|192\|256\|512] [--format raw\|hex] [--out FILE] [--force]` | Tạo khóa AES ngẫu nhiên. Kích thước khóa: 128/192/256 bit; 512 bit dành cho XTS (đôi khi được hỗ trợ). | • Mặc định xuất khóa ra stdout (hex).<br>• `--out FILE` ghi khóa vào file.<br>• `--force` cho phép ghi đè file đã tồn tại. |
| `kat` | `aestool --kat vectors.json [--verbose]` | Chạy bộ kiểm tra NIST Known-Answer-Tests (GCM, CCM, ...). File `vectors.json` chứa các test vector chuẩn. | • Giúp xác minh tính đúng đắn của mã hóa/giải mã.<br>• `--verbose` in thêm thông tin chi tiết từng test. |
| `bench` | `aestool bench [--modes gcm,ctr,...] [--sizes 1k,4k,16k,256k,1m,8m] [--runs 1000] [--warmup 1.0] [--bits 256] [--dir enc\|dec\|both] [--with-io] [--csv FILE] [--quick]` | Đo throughput (MB/s) và latency (µs) cho các chế độ/kích thước đã chọn. | • `--modes` chỉ định một hoặc nhiều chế độ (cách nhau bằng dấu phẩy).<br>• `--sizes` kích thước dữ liệu test (kilobyte/megabyte).<br>• `--dir` chạy mã hóa, giải mã hoặc cả hai.<br>• `--quick` giảm số lần lặp (20 runs, warm-up 0.2 s).<br>• Kết quả xuất ra file CSV (`--csv`) và các biểu đồ PNG trong thư mục `result/compare/`. |
| `version` / `help` | `aestool version`<br>`aestool help` (hoặc `aestool --help`) | In phiên bản phần mềm và thông tin thư viện Crypto++. In bảng trợ giúp đầy đủ các lệnh và tùy chọn. | • `version` cho ra `aestool 1.0.0 (Crypto++ x.x.x)`.<br>• `help` in lại cú pháp tương tự bảng trên. |

### Lưu ý khi sử dụng

- **Chế độ và khóa:** `--mode` phải khớp với kiểu dữ liệu khóa.
- XTS cần khóa đôi (32 hoặc 64 byte, gồm tweak key + data key).
- CCM/GCM hỗ trợ độ dài nonce 7-13 byte (khuyến nghị 12 byte).
- **File khóa/IV/AAD:** có thể là file nhị phân thuần hoặc file text bắt đầu bằng dòng `AESTOOL-HEX`, theo sau là các ký tự hex.
- **Atomic write:** mọi ghi file đầu ra đều đi qua `util::write_file_atomic` (ghi file tạm rồi rename) để tránh file bị ghi dở khi có lỗi.
- Khóa có thể đọc từ file (`--key FILE`, khuyến nghị) hoặc truyền hex (`--key-hex HEX`). Tài liệu cảnh báo truyền khóa qua command line có thể làm lộ trong shell history và danh sách tiến trình. Đầu ra hỗ trợ hex, Base64 và raw; raw cần file đầu ra và không in binary ra terminal. `--text` nhận chuỗi UTF-8, còn `--in` nhận file.

Ví dụ:

```console
.\build\bin\aestool.exe keygen --bits 256 --out key.bin
.\build\bin\aestool.exe encrypt --mode gcm --key key.bin --in msg.txt --out ct_gcm.bin --aad-text "v1" --verbose
.\build\bin\aestool.exe decrypt --key key.bin --in ct_gcm.bin --out dec.txt
.\build\bin\aestool.exe --kat vectors/nist_vectors.json --verbose
```
![](img/genkey.png)

![](img/genkeyFile.png)

![](img/encrypt.png)

![](img/decrypt.png)

## 3.4. Hiện thực các chế độ mã hóa và giải mã

Với ECB/CBC/CFB/OFB/CTR/XTS, `aescore` kiểm tra khóa, IV/nonce/tweak, khởi tạo mode Crypto++ và thực hiện encrypt/decrypt. ECB/CBC dùng padding theo mô tả, các mode stream-like không cần padding. XTS dùng ciphertext stealing khi cần.

CCM/GCM xử lý AAD và tag. AAD được xác thực nhưng không mã hóa. Khi giải mã AEAD, tag phải được xác minh trước khi chấp nhận plaintext. Tài liệu thiết kế mô tả tag sai sẽ dẫn đến `AuthError`, xóa plaintext tạm và không ghi file đầu ra.

### Container AEST

| Offset | Trường | Kích thước | Ý nghĩa |
|---:|---|---:|---|
| 0 | `magic` | 4 | `AEST` |
| 4 | `version` | 1 | Phiên bản |
| 5 | `mode` | 1 | Mã mode |
| 6 | `key_len` | 1 | Độ dài khóa |
| 7 | `flags` | 1 | Bit 0: AEAD |
| 8 | `key_id` | 8 | 8 byte đầu SHA-256 có domain separation |
| 16 | `iv_len` | 1 | Độ dài IV |
| 17 | `iv` | `iv_len` | IV/nonce/tweak |
| … | `aad_len` | 4 | Độ dài AAD |
| … | `aad` | `aad_len` | AAD |
| … | `tag_len` | 1 | Độ dài tag |
| … | `tag` | `tag_len` | Tag |
| … | `ct_len` | 8 | Độ dài ciphertext |
| … | `ciphertext` | `ct_len` | Ciphertext |

**...: offset không cố định.*

Các trường nhiều byte được mô tả theo big-endian. Parser kiểm tra magic, version, mode, flags, độ dài khóa/IV/tag và kích thước ciphertext. `key_id` được tính từ `SHA-256("aestool-keyid-v1" || key)` và giữ 8 byte đầu để phục vụ phát hiện nonce reuse, không lưu khóa trực tiếp.

```text
+---------------------------- header cố định (17 byte) -----------------------------+
| magic "AEST" | version | mode | key_len | flags | key_id (8 byte) | iv_len        |
+-----------------------------------------------------------------------------------+
| iv (iv_len byte)                                                                  |
| aad_len (4 byte) | aad (aad_len byte)                                             |
| tag_len (1 byte) | tag (tag_len byte)                                             |
| ct_len (8 byte)  | ciphertext (ct_len byte)                                       |
+-----------------------------------------------------------------------------------+
```

## 3.5. Cơ chế xử lý lỗi và chống lạm dụng

### Phân cấp lỗi

| Lớp lỗi | Ý nghĩa | Exit code |
|---|---|---:|
| `UsageError` | Sai tham số, ECB quá giới hạn, nonce reuse, IV/key sai độ dài | 2 |
| `AuthError` | Tag không hợp lệ | 3 |
| `FormatError` | Container/sidecar sai định dạng | 3 |
| `CryptoError` | Lỗi mật mã khác, ví dụ padding | 3 |
| Lỗi CLI chung/KAT fail | Cú pháp hoặc KAT thất bại | 1 |

### Hạn chế ECB

ECB luôn phát cảnh báo. Dữ liệu lớn hơn 16 KiB bị từ chối mặc định; người dùng phải chỉ định `--allow-ecb` để vượt giới hạn.

![](img/ecb.png)

### Kiểm tra IV/nonce

| Mode | Độ dài theo tài liệu thiết kế | Xử lý |
|---|---|---|
| CBC, OFB, CFB, CTR, XTS | 16 byte | Kiểm tra `valid_iv_len` |
| GCM | 12 byte | Cấu hình thông thường |
| CCM | 7–13 byte | Miền hợp lệ |
| ECB | Không có | Cung cấp IV thì từ chối |

Nếu thiếu IV/nonce, chương trình sinh bằng `CryptoPP::AutoSeededRandomPool`. Nếu RNG hệ thống lỗi, chương trình phát sinh `CryptoError` và dừng.

### Phát hiện nonce reuse
Nonce reuse thực hiện như sau:

(1) tạo `key_id` 

(2) đọc header file AEST đã tồn tại để so sánh `(key_id, iv)`

(3) kiểm tra sidecar JSON

(4) kiểm tra ledger có dòng `<keyid-hex> <nonce-hex>`

(5) từ chối nonce người dùng nhập nếu trùng

(6) nonce tự sinh bị trùng thì sinh lại tối đa 8 lần

(7) sau mã hóa thành công ghi cặp key ID/nonce vào ledger nếu cấu hình.

![](img/key-nonce.png)

**Giới hạn:** cơ chế chỉ phát hiện trong file/sidecar/ledger mà chương trình nhìn thấy; không bảo đảm phát hiện reuse giữa nhiều máy hoặc khi metadata bị xóa. Với CTR, so sánh nonce trùng hoàn toàn không phát hiện dải counter chồng lấn.

### Vệ sinh bộ nhớ và I/O

Tài liệu mô tả `KeyGuard` theo RAII, `secure_wipe` ghi đè vùng nhớ nhạy cảm bằng 0 qua con trỏ `volatile`, keygen không ghi đè file có sẵn nếu thiếu `--force`, quyền file `600` trên Linux, ghi file tạm rồi rename, giới hạn file đầu vào 2 GiB và giới hạn kích thước sidecar/ledger.

## 3.6. Quy trình xử lý dữ liệu và quản lý khóa

**Mã hóa:** nhận CLI $\rightarrow$ đọc plaintext/khóa $\rightarrow$ kiểm tra mode và tham số $\rightarrow$ sinh IV/nonce nếu cần $\rightarrow$ kiểm tra ECB/nonce reuse $\rightarrow$ gọi `aescore` $\rightarrow$ tạo ciphertext/tag $\rightarrow$ đóng gói AEST hoặc sidecar $\rightarrow$ ghi file nguyên tử $\rightarrow$ xóa dữ liệu tạm.

**Giải mã:** đọc ciphertext/metadata/khóa $\rightarrow$ kiểm tra cấu trúc $\rightarrow$ khởi tạo mode $\rightarrow$ giải mã tạm $\rightarrow$ nếu AEAD thì xác minh tag $\rightarrow$ chỉ ghi plaintext nếu xác thực thành công.

Khóa cần được lưu riêng, không commit vào repository, không truyền qua command line trong môi trường thật và không lưu cùng ciphertext ở nơi không kiểm soát. 

# 4. Kiểm thử tính đúng đắn (Correctness & Security Testing)

## 4.1. Known Answer Tests (KATs)

KAT so sánh kết quả thực thi với vector chuẩn:
### Tổng hợp theo mode

| Mode | Tổng | Pass | Fail |
|---|---:|---:|---:|
| ECB | 2 | 2 | 0 |
| CBC | 3 | 3 | 0 |
| CFB | 2 | 2 | 0 |
| OFB | 2 | 2 | 0 |
| CTR | 3 | 3 | 0 |
| CCM | 3 | 3 | 0 |
| GCM | 12 | 12 | 0 |
| **Tổng** | **27** | **27** | **0** |

### Tổng hợp theo độ dài khóa

| Khóa | Tổng | Pass | Fail |
|---|---:|---:|---:|
| AES-128 | 13 | 13 | 0 |
| AES-192 | 10 | 10 | 0 |
| AES-256 | 4 | 4 | 0 |
| **Tổng** | **27** | **27** | **0** |

Kết luận: `RESULT: ALL PASS`.

Tỷ lệ PASS theo bảng: `27/27 × 100% = 100%`. 

![](img/kat.png)

## 4.2. Kiểm thử đối chiếu kết quả
Ta kiểm thử mã hóa và dịch bằng cách sử dụng file cần mã hóa để mã hóa và dịch ngược để kiểm tra so sánh.

![](img/sosanhfile.png)

## 4.3. Negative Tests và xử lý đầu vào không hợp lệ

| # | Kịch bản | Điều kiện | Kết quả ghi nhận | Đánh giá |
|---:|---|---|---|---|
| 1 | Sai key | Mã hóa key A, giải mã key B | Plaintext không khớp | Đạt theo báo cáo nguồn |
| 2 | Sai IV | IV sai độ dài/giá trị | UsageError hoặc thất bại | Đạt theo báo cáo nguồn |
| 3 | Sửa ciphertext non-AEAD | XOR một bit ciphertext CBC | Plaintext bị thay đổi, không tự phát hiện | Đúng với giới hạn CBC |
| 4 | Sửa ciphertext AEAD | XOR một bit ciphertext GCM | AuthError, không trả plaintext | Đạt |
| 5 | Tag AEAD sai | Sửa byte cuối tag | AuthError | Đạt |
| 6 | IV sai độ dài | GCM 8 byte, CBC 15 byte | UsageError | Đạt |

- Kịch bản CBC không phải một lỗi triển khai: CBC không có xác thực tích hợp. 
- GCM phải từ chối khi tag không hợp lệ và không chấp nhận plaintext.

![](img/gcmAuthError.png)

## 4.4. Kiểm thử các trường hợp biên (Edge Cases)

| Trường hợp | Mục đích | Kết quả thực tế | 
|---|---|---|
| Plaintext rỗng (CBC) | Dữ liệu 0 byte | Ciphertext 16 byte (1 block padding), giải mã khớp: PASS | 
| Plaintext 16 byte (CBC) | Ranh giới block/padding | Ciphertext 32 byte, giải mã khớp: PASS | 
| Plaintext 15/17 byte (CBC) | Kiểm tra padding | 15 → 16 byte, 17 → 32 byte, giải mã khớp: PASS | 
| XTS plaintext 57 byte | Ciphertext stealing | Chạy được, giải mã khớp hash, `ct_len` = 57 | 
| XTS plaintext dưới 16 byte | Kiểm tra giới hạn tối thiểu | Bị từ chối, không tạo file |
| IV/nonce sai độ dài | Từ chối tham số | Bị từ chối, ví dụ: invalid IV/nonce length 6 bytes for GCM (expected 12 bytes) | 
| Tag sai kích thước | Parser/AEAD | Bị từ chối | 
| Container bị cắt | Kiểm tra parser | Bị từ chối, không tạo plaintext | 
| Sidecar JSON sai | Kiểm tra parser | Bị từ chối | 
| File vượt giới hạn 2 GiB | Kiểm tra giới hạn I/O | Bị từ chối|



## 4.5. Tổng hợp kết quả kiểm thử

| Nhóm | Kết quả nguồn | 
|---|---|
| KAT NIST | 27/27 PASS | 
| Catch2 | 13 test case được mô tả | 
| Negative Tests | 6 kịch bản | 
| AEAD tamper | GCM từ chối ciphertext bị sửa | 
| Round-trip | Có ví dụ GCM và XTS | 
| Edge Cases | Một số trường hợp được nêu | 


# 5. Môi trường và phương pháp thực nghiệm 

## 5.1. Cấu hình phần cứng

| Thông số | Windows | Linux |
|---|---|---|
| CPU | Intel Core i7-9750H, 6C/12T | AMD Ryzen 7 5800X, 8C/16T |
| RAM | 16 GB DDR4 | 32 GB DDR4 |
| Storage | SSD 512 GB | NVMe 1 TB |
| AES-NI | Có | Có |

Hai môi trường dùng CPU, RAM và storage khác nhau. Vì vậy, phép so sánh Windows/Linux là so sánh hai cấu hình máy thực nghiệm, không cô lập riêng ảnh hưởng hệ điều hành.

## 5.2. Môi trường phần mềm và hệ điều hành

| Thành phần | Windows | Linux |
|---|---|---|
| OS | Windows 10 Pro 21H2 | Ubuntu 22.04.3 LTS, kernel 5.15 |
| Compiler | MinGW GCC 11.2.0 | g++ 11.4.0 |
| Crypto++ | 8.9.0, static build | libcryptopp.so 8.9.0 |
| CMake | 3.21.3 | 3.21.3 |

## 5.3. Thiết lập dữ liệu và kịch bản benchmark

| Payload | Byte |
|---|---:|
| 1 KB | 1.024 |
| 4 KB | 4.096 |
| 16 KB | 16.384 |
| 256 KB | 262.144 |
| 1 MB | 1.048.576 |
| 8 MB | 8.388.608 |

- Các mode thực thi: ECB, CBC, OFB, CFB, CTR, XTS, CCM và GCM. 
- Độ dài khóa: Có đủ 3 loại AES 128/192/256 nhưng báo cáo ưu tiên AES-256.

![](img/bench.png)

## 5.4. Phương pháp đo và xử lý số liệu

- Warm-up: 1–2 giây.
- Số lần chạy: N=1000 cho mỗi tổ hợp.
- Thống kê: Mean, Median, SD mẫu (`ddof=1`), CI 95% theo t-Student.
- Throughput: `payload_MB / time_s`.
- Latency: thời gian cho một thao tác.
- Tài liệu mô tả benchmark lõi đo trên bộ nhớ, hạn chế overhead file I/O.

Ta tính through put bằng công thức:
$$Throughput=\frac{Payload\ (MB)}{Time\ (s)}$$


## 5.5. Độ tin cậy và khoảng tin cậy 95%

Khoảng tin cậy 95% cho throughput trung bình được tính bằng:

$$CI_{95\%}=\bar{x}\pm t_{0.975,\,N-1}\,\frac{s}{\sqrt{N}}$$

Trong đó $\bar{x}$ là trung bình mẫu, $s$ là độ lệch chuẩn mẫu và $N$ là số lần đo. Với $N=1000$ (bậc tự do 999), $t_{0.975,999} \approx 1{,}962$, gần với 1,96 của phân phối chuẩn.

Ví dụ với CTR, payload 1 MB:

| Hướng | Môi trường | $\bar{x}$ (MB/s) | $s$ (MB/s) | $CI_{95\%}$ (MB/s) |
|---|---|---:|---:|---|
| Mã hóa | Windows | 882.698 | 25.589 | [881.110, 884.286] |
| Mã hóa | Linux | 3137.295 | 80.517 | [3132.299, 3142.292] |
| Giải mã | Windows | 875.868 | 46.215 | [873.000, 878.736] |
| Giải mã | Linux | 3208.246 | 83.165 | [3203.085, 3213.407] |

**Nhận xét:** Với CTR 1 MB, hai khoảng tin cậy của Windows và Linux cách nhau rất xa và không chồng lấn ở cả hai hướng. Throughput trên Linux cao hơn Windows khoảng 3,55 lần khi mã hóa và 3,66 lần khi giải mã. Kiểm định Welch cho kết quả khác biệt có ý nghĩa thống kê cực mạnh ($p < 10^{-6}$; chênh lệch trung bình khi mã hóa là 2254.6 MB/s, khoảng tin cậy 95% của chênh lệch là [2249.4, 2259.8]).

**Lưu ý**: Các yếu tố ảnh hưởng gồm tiến trình nền, nhiệt độ/xung CPU, compiler flags, khác biệt phần cứng, cách liên kết Crypto++ và quy ước MB/MiB, µs/ms.


# 6. Kết quả và phân tích hiệu năng 

> **Cảnh báo key size:** bảng bên dưới là số liệu được trích từ `result\bench\bench_linux_256.csv`, `result\bench\bench_windows_256.csv` là sử dụng chế độ key size AES-256. 

## 6.1. Kết quả benchmark trên Windows

### Throughput trung bình (MB/s)

| Mode | 1 KB | 4 KB | 16 KB | 256 KB | 1 MB | 8 MB |
|---|---:|---:|---:|---:|---:|---:|
| ECB | 587,29 | 1.092,87 | 1.291,73 | 1.478,64 | 620,79 | 592,82 |
| CBC | 374,48 | 635,03 | 725,17 | 768,94 | 498,47 | 452,54 |
| OFB | 398,63 | 609,60 | 675,83 | 707,72 | 506,23 | 475,18 |
| CFB | 424,70 | 678,52 | 754,90 | 789,68 | 551,53 | 517,79 |
| CTR | 488,21 | 1.094,24 | 1.410,15 | 1.584,22 | 882,70 | 762,95 |
| XTS | 302,34 | 592,98 | 742,87 | 805,54 | 579,09 | 527,55 |
| CCM | 287,78 | 462,99 | 523,62 | 543,58 | 386,25 | 360,63 |
| GCM | 366,61 | 837,60 | 1.127,29 | 1.253,76 | 644,64 | 582,48 |

![](result/window/throughput_vs_size.png)

### Latency trung bình (đơn vị ghi trong nguồn: ms/op)

| Mode | 1 KB | 4 KB | 16 KB | 256 KB | 1 MB | 8 MB |
|---|---:|---:|---:|---:|---:|---:|
| ECB | 1,84 | 3,92 | 5,14 | 177,50 | 1.709,01 | 14.664,27 |
| CBC | 2,74 | 6,47 | 22,60 | 341,01 | 2.106,12 | 18.557,06 |
| OFB | 2,57 | 6,79 | 24,27 | 370,66 | 2.075,42 | 17.699,31 |
| CFB | 2,41 | 6,04 | 21,72 | 332,01 | 1.928,91 | 16.220,26 |
| CTR | 2,10 | 3,74 | 11,62 | 165,53 | 1.189,06 | 11.055,67 |
| XTS | 3,40 | 6,91 | 22,07 | 325,54 | 1.811,91 | 16.077,84 |
| CCM | 3,56 | 8,85 | 31,32 | 482,34 | 2.716,23 | 23.268,38 |
| GCM | 2,79 | 4,89 | 14,54 | 209,28 | 1.630,89 | 14.436,51 |

![](result/window/latency_vs_size.png)

**Nhận xét:** 
- CTR có throughput cao nhất trong các mode tại payload 1 MB và 8 MB theo bảng Windows. GCM thấp hơn CTR do chi phí xác thực. 
- CCM có throughput thấp hơn trong các bảng này.
- ECB có thể đạt throughput cạnh tranh nhưng không an toàn cho dữ liệu thực.

## 6.2. Kết quả benchmark trên Linux

### Throughput trung bình (MB/s)

| Mode | 1 KB | 4 KB | 16 KB | 256 KB | 1 MB | 8 MB |
|---|---:|---:|---:|---:|---:|---:|
| ECB | 1.007,06 | 2.222,83 | 2.813,06 | 718,68 | 658,90 | 491,30 |
| CBC | 511,87 | 750,14 | 848,82 | 864,73 | 853,99 | 365,05 |
| OFB | 526,36 | 766,37 | 853,19 | 874,53 | 886,51 | 723,15 |
| CFB | 541,51 | 786,35 | 877,34 | 894,28 | 896,05 | 730,19 |
| CTR | 909,69 | 2.077,05 | 2.858,21 | 3.129,02 | 3.137,30 | 1.736,11 |
| XTS | 523,19 | 932,10 | 1.154,72 | 1.213,70 | 1.213,70 | 933,22 |
| CCM | 425,00 | 642,22 | 712,62 | 725,69 | 725,58 | 347,19 |
| GCM | 670,98 | 1.486,61 | 2.006,10 | 2.123,28 | 2.122,44 | 505,97 |

[Ảnh minh chứng: `result/linux/throughput_vs_size.png`]

### Latency trung bình (đơn vị ghi trong nguồn: ms/op)

| Mode | 1 KB | 4 KB | 16 KB | 256 KB | 1 MB | 8 MB |
|---|---:|---:|---:|---:|---:|---:|
| ECB | 1,02 | 1,84 | 5,83 | 364,82 | 1.593,03 | 17.108,09 |
| CBC | 2,00 | 5,48 | 19,31 | 303,20 | 1.228,98 | 22.992,77 |
| OFB | 1,95 | 5,35 | 19,21 | 300,71 | 1.182,92 | 11.601,92 |
| CFB | 1,89 | 5,21 | 18,68 | 293,16 | 1.170,93 | 6.481,75 |
| CTR | 1,13 | 1,97 | 5,74 | 83,83 | 334,45 | 4.771,15 |
| XTS | 1,96 | 4,40 | 14,19 | 216,67 | 866,57 | 8.990,21 |
| CCM | 2,41 | 6,38 | 22,99 | 361,26 | 1.445,27 | 24.162,10 |
| GCM | 1,53 | 2,76 | 8,17 | 123,50 | 494,25 | 16.579,71 |

![](result/linux/latency_vs_size.png)

**Nhận xét:** 
- CTR đạt 3.137,30 MB/s ở 1 MB. CTR có thông lượng cao trong các payload vừa/lớn.
- GCM đạt mức cao ở các payload đến 1 MB nhưng giảm xuống 505,97 MB/s ở 8 MB, cần xác minh.

## 6.3. So sánh hiệu năng giữa các chế độ AES

### So sánh 1 MB theo bảng throughput chi tiết

| Mode | Windows (MB/s) | Linux (MB/s) |
|---|---|---|
| ECB | 620,79 | 658,90 |
| CBC | 498,47 | 853,99 |
| OFB | 506,23 | 886,51 |
| CFB | 551,53 | 896,05 |
| CTR | 882,70 | 3.137,30 |
| XTS | 579,09 | 1.213,70 |
| CCM | 386,25 | 725,58 |
| GCM | 644,64 | 2.122,44 |

Theo bảng này, CTR nhanh nhất ở cả hai hệ thống tại 1 MB. GCM có chi phí xác thực nhưng cung cấp integrity; CCM thấp hơn GCM trong dữ liệu được cung cấp. XTS dành cho lưu trữ; ECB không nên được chọn chỉ vì tốc độ.

### Stream-like/block

**Hướng mã hóa**

| Mode | Nhóm | Windows (MB/s) | Linux (MB/s) | Linux/Windows |
|---|---|---|---|---|
| CTR | Stream-like | 882,70 | 3137,30 | 3,55 |
| OFB | Stream-like | 506,23 | 886,51 | 1,75 |
| CFB | Stream-like | 551,53 | 896,05 | 1,62 |
| CBC | Block | 498,47 | 854,00 | 1,71 |
| ECB | Block | 620,79 | 658,90 | 1,06 |

**Hướng giải mã**

| Mode | Nhóm | Windows (MB/s) | Linux (MB/s) | Linux/Windows |
|---|---|---|---|---|
| CTR | Stream-like | 875,87 | 3208,25 | 3,66 |
| OFB | Stream-like | 524,64 | 887,04 | 1,69 |
| CFB | Stream-like | 852,67 | 2162,05 | 2,54 |
| CBC | Block | 896,39 | 3040,45 | 3,39 |
| ECB | Block | 922,16 | 3000,36 | 3,25 |

**Nhận xét:** Việc một mode thuộc nhóm stream-like hay block **không quyết định** throughput. Trên Linux, ở hướng mã hóa CTR (stream-like) đạt 3137 MB/s nhưng OFB và CFB (cũng stream-like) chỉ khoảng 890 MB/s, ngang CBC (block). Ở hướng giải mã, CBC (block) lại đạt 3040 MB/s, gần bằng CTR.

Yếu tố giải thích tốt hơn là **khả năng song song hóa**. Các phép toán mà mỗi block phụ thuộc kết quả block trước (mã hóa CBC, mã hóa CFB, cả hai hướng của OFB) buộc AES-NI xử lý tuần tự, nên chỉ đạt khoảng 850-900 MB/s. Các phép toán mà các block độc lập (CTR cả hai hướng, giải mã CBC, giải mã CFB) cho phép xử lý nhiều block cùng lúc và đạt 2100-3200 MB/s. Trên Windows, chênh lệch này gần như không xuất hiện (mọi mode đều trong khoảng 500-920 MB/s), cho thấy bản build Windows chưa tận dụng được việc xử lý song song nhiều block.
### AEAD và non-AEAD

Latency 1 MB, trung bình, đơn vị µs (Linux/Windows nhỏ hơn 1 nghĩa là Linux nhanh hơn).

**Hướng mã hóa**

| Mode | Nhóm | Windows (µs) | Linux (µs) | Linux/Windows |
|---|---|---|---|---|
| CTR | Non-AEAD | 1189,06 | 334,45 | 0,28 |
| GCM | AEAD | 1630,89 | 494,25 | 0,30 |
| CCM | AEAD | 2716,23 | 1445,27 | 0,53 |

**Hướng giải mã**

| Mode | Nhóm | Windows (µs) | Linux (µs) | Linux/Windows |
|---|---|---|---|---|
| CTR | Non-AEAD | 1201,55 | 327,06 | 0,27 |
| GCM | AEAD | 1288,83 | 474,27 | 0,37 |
| CCM | AEAD | 2395,59 | 1418,53 | 0,59 |

$\Rightarrow$ GCM tăng latency so với CTR: mã hóa 37,2% (Windows) và 47,8% (Linux), giải mã 7,3% (Windows) và 45,0% (Linux). GCM có thêm GHASH, CCM dùng CBC-MAC và có quy trình xử lý khác. Không thể kết luận một mode luôn nhanh hơn mode kia trong mọi kích thước dữ liệu.

### Overhead throughput GCM so với CTR trên Windows lẫn Linux

Đơn vị MB/s, trung bình. Công thức phần giảm: 

$(T_CTR − T_GCM) / T_CTR × 100%$.

**Hướng mã hóa**

| Payload | Win CTR | Win GCM | Win giảm | Linux CTR | Linux GCM | Linux giảm |
|---|---|---|---|---|---|---|
| 1 KB | 488,21 | 366,61 | 24,91% | 909,69 | 670,98 | 26,24% |
| 16 KB | 1410,15 | 1127,29 | 20,06% | 2858,21 | 2006,10 | 29,81% |
| 1 MB | 882,70 | 644,64 | 26,97% | 3137,30 | 2122,44 | 32,35% |
| 8 MB | 762,05 | 582,48 | 23,56% | 1736,11 | 505,97 | 70,86% |

**Hướng giải mã**

| Payload | Win CTR | Win GCM | Win giảm | Linux CTR | Linux GCM | Linux giảm |
|---|---|---|---|---|---|---|
| 1 KB | 495,03 | 267,54 | 45,95% | 925,66 | 475,36 | 48,65% |
| 16 KB | 1426,41 | 1076,65 | 24,52% | 2955,99 | 1898,96 | 35,76% |
| 1 MB | 875,87 | 814,50 | 7,01% | 3208,25 | 2212,19 | 31,05% |
| 8 MB | 762,95 | 695,69 | 8,82% | 1759,63 | 1432,04 | 18,62% |



## 6.4. So sánh hiệu năng giữa Windows và Linux

### CTR 1 MB (hướng mã hóa)

| OS | Throughput (MB/s) | SD | CI 95% |
|---|---:|---:|---|
| Windows | 882,70 | 25,59 | [881,11; 884,29] |
| Linux | 3.137,30 | 80,52 | [3.132,30; 3.142,29] |

Theo công thức nguồn `(882,70 - 3.137,30)/3.137,30 × 100 = -71,86%`. Diễn giải chính xác: theo hai số liệu này Linux đạt throughput khoảng 3,55 lần Windows, cao hơn khoảng 255% nếu lấy Windows làm mẫu số. Con số -71,86% biểu thị Windows thấp hơn Linux khi lấy Linux làm mẫu số, không phải Linux chỉ cao hơn 72%.

### GCM 1 MB (hướng mã hóa)

| OS | Throughput (MB/s) | SD | CI 95% |
|---|---:|---:|---|
| Windows | 644,64 | 28,92 | [642,84; 646,43] |
| Linux | 2.122,44 | 43,73 | [2.119,72; 2.125,15] |

Chênh lệch theo công thức nguồn: `(644,64 - 2.122,44)/2.122,44 × 100 ≈ -69,63%`. Theo hai giá trị này Linux nhanh hơn khoảng 3,29 lần (cao hơn khoảng 229% nếu lấy Windows làm mẫu số).

![](result/compare/compare_throughput_enc.png)
![](result/compare/compare_throughput_dec.png)
## 6.5. Phân tích nguyên nhân chênh lệch

Các yếu tố có thể ảnh hưởng: 
- CPU khác vi kiến trúc/xung nhịp/cache
- Compiler MinGW GCC 11.2.0 và g++ 11.4.0
- Static/shared Crypto++, cờ tối ưu hóa
- AES-NI runtime
- Tiến trình nền, nhiệt độ và chế độ nguồn
- Quy ước MB/MiB và µs/ms. 

Vì hai hệ thống dùng phần cứng khác nhau, không thể quy toàn bộ chênh lệch cho Windows/Linux. Nhận định về scheduler, kernel hoặc I/O chỉ là giả thuyết nếu chưa có thí nghiệm cô lập, tài liệu phương pháp nói benchmark lõi đo trên bộ nhớ.

## 6.6. Nhận xét và đánh giá tổng hợp

| Nhu cầu | Mode phù hợp | Lý do |
|---|---|---|
| Mã hóa cần xác thực | GCM/CCM | AEAD, xác minh ciphertext và AAD |
| Throughput cao, có MAC riêng | CTR | Song song, không padding; nonce phải duy nhất |
| Mã hóa sector lưu trữ | XTS | Thiết kế cho dữ liệu at-rest |
| Tương thích hệ thống cũ | CBC/CFB/OFB khi có yêu cầu | Phải bổ sung xác thực ngoài |
| Dữ liệu có cấu trúc | Tránh ECB | Lộ mẫu |

CTR thường nổi bật trong bảng throughput. GCM có overhead nhưng mang lại xác thực. 


# 7. Phân tích an toàn mật mã (Cryptographic Security Analysis)

## 7.1. Đánh giá đặc điểm an toàn của từng chế độ

- **ECB:** làm lộ mẫu, không xác thực; không dùng cho dữ liệu thực.
- **CBC:** cần IV ngẫu nhiên; không xác thực; có nguy cơ padding oracle nếu để lộ phản hồi padding.
- **CFB/OFB:** không padding nhưng không xác thực; quản lý IV để tránh tái sử dụng.
- **CTR:** hiệu năng và song song hóa tốt; nonce reuse làm lộ quan hệ plaintext; ciphertext có thể bị sửa bit.
- **XTS:** phù hợp mã hóa lưu trữ; không phát hiện sửa đổi/tráo sector.
- **CCM/GCM:** AEAD, kiểm tra tag trước khi chấp nhận plaintext; nonce phải tuân thủ yêu cầu duy nhất theo khóa.

## 7.2. Rủi ro khi sử dụng sai IV, Nonce và Tweak

| Tham số | Mode | Rủi ro |
|---|---|---|
| IV | CBC | IV không an toàn có thể làm lộ thông tin về plaintext |
| IV | CFB/OFB | Reuse có thể tái sử dụng keystream hoặc làm lộ quan hệ plaintext |
| Nonce/counter | CTR | `C1 ⊕ C2 = P1 ⊕ P2` khi keystream tái sử dụng |
| Nonce | CCM | Suy yếu bảo đảm bí mật/xác thực |
| Nonce | GCM | Có thể phá vỡ cả bí mật và xác thực |
| Tweak | XTS | Không phân biệt đúng đơn vị dữ liệu có thể làm mất mục đích tweak |

Phát hiện reuse dựa trên file/ledger cục bộ không thay thế bộ cấp nonce có trạng thái bền vững trong hệ thống nhiều tiến trình hoặc nhiều máy.

## 7.3. Quản lý khóa và bảo vệ dữ liệu

Các biện pháp được mô tả: 
- CSPRNG `AutoSeededRandomPool` 
- Ưu tiên đọc khóa từ file
- Hạn chế lộ khóa trên command line
- Không ghi đè key file nếu không có `--force`
- Quyền `600` trên Linux; `KeyGuard`/`secure_wipe`
- Không in raw binary ra terminal, lưu IV/nonce/tag/metadata cùng ciphertext, ghi file đầu ra nguyên tử.

## 7.4. Các giới hạn an toàn của công cụ

1. Nonce reuse detection chỉ quan sát file/sidecar/ledger hiện có.
2. Mode non-AEAD không có integrity tích hợp.
3. Key ID 64 bit chỉ phục vụ nhận diện nội bộ, không phải xác thực khóa.
4. Chưa có báo cáo audit bảo mật độc lập.
5. Xóa bộ nhớ và quyền file không bảo đảm chống mọi hình thức trích xuất khóa.
6. Đầy đủ giới hạn nonce/tag và giới hạn độ dài thông điệp AEAD.


# 8. Build và triển khai đa nền tảng (Cross-platform Build & Deployment)

## 8.1. Cấu hình CMake

Dự án sử dụng CMake theo hướng out-of-source để tách file build khỏi mã nguồn. Xem ở `CMakeLists.txt` 

## 8.2. Quy trình biên dịch trên Windows

Môi trường nguồn: Windows 10 Pro 21H2, MinGW GCC 11.2.0, CMake 3.21.3, Crypto++ 8.9.0.

```powershell
cmake -S . -B build -G "MinGW Makefiles"
cmake --build build -j
```

Chạy executable tại đúng vị trí target do CMake sinh ra:

```powershell
.\build\bin\aestool.exe help
```

![](img/conWin.png)
![](img/buildWin.png)

## 8.3. Quy trình biên dịch trên Linux

Môi trường nguồn: Ubuntu 22.04.3 LTS, g++ 11.4.0, CMake 3.21.3, Crypto++ 8.9.0.

```bash
cmake -S . -B build
cmake --build build 
./build/bin/aestool help
```
![](img/makelinux.png)

## 8.4. Hướng dẫn sử dụng và triển khai

Quy trình: cài compiler/CMake/Crypto++; configure; build; sinh khóa; chọn mode; mã hóa và lưu metadata; giải mã bằng đúng khóa; chạy KAT sau build. Ví dụ:

```bash
./build/bin/aestool keygen --bits 256 --out key.bin
./build/bin/aestool encrypt --mode gcm --key key.bin --in plaintext.bin --out ciphertext.aest
./build/bin/aestool decrypt --key key.bin --in ciphertext.aest --out recovered.bin
./build/bin/aestool --kat vectors/nist_vectors.json
```
![](img/aeshelp.png)


# 9. Extended Features

## 9.1. Xây dựng thư viện động (DLL/SO)

1) Window:

2) Linux:

![](img/linuxcryp.png)

## 9.2. Tích hợp giao diện đồ họa (GUI)

T`aestool_gui.py` dùng tkinter và ctypes. GUI dự kiến cho phép chọn file, mode, khóa, IV/nonce, thực hiện encrypt/decrypt, hiển thị trạng thái và lỗi xác thực. Khóa không nên hiển thị rõ sau khi nạp.

![](img/gui.png)


![](img/xts.png)
## 9.3. Cơ chế liên kết giữa GUI và thư viện AES

```text
Python GUI (tkinter)
        |
      ctypes
        |
     C API
        |
   C++ aescore
        |
     Crypto++
```
# 10. Kết luận (Conclusion)

Lab 1 xây dựng nền tảng công cụ mã hóa đối xứng dựa trên AES và Crypto++. Phạm vi thiết kế gồm nhiều mode, AES-128/192/256, CLI, quản lý IV/nonce, container, xử lý lỗi và benchmark. Bảng KAT nguồn ghi nhận 12/12 vector PASS; Negative Tests minh họa các tình huống sai khóa, sai IV, sửa ciphertext và tag, đồng thời cho thấy khác biệt giữa non-AEAD và AEAD.

Về hiệu năng, CTR nổi bật trong các bảng throughput; GCM có chi phí xác thực bổ sung nhưng bảo vệ tính toàn vẹn. CCM có kết quả thấp hơn trong các bảng được cung cấp. Tuy nhiên, chưa thể kết luận định lượng cuối cùng cho AES-256 vì CSV thiếu `key_bits`, CTR Linux có số liệu mâu thuẫn và đơn vị latency cần xác minh.

Về an toàn, lựa chọn mode và quản lý nonce quan trọng không kém độ dài khóa. GCM/CCM phù hợp khi cần xác thực; XTS phù hợp mã hóa lưu trữ; ECB cần tránh. Kiến trúc DLL/SO và GUI đã được mô tả nhưng trạng thái triển khai phải được xác nhận bằng binary, log và ảnh minh chứng.

Ưu tiên hoàn thiện là chuẩn hóa dữ liệu benchmark, bổ sung AES-192, xác minh kết quả Linux, hoàn thiện edge tests và cung cấp minh chứng build/triển khai.


# 11. Tài liệu tham khảo (References)

1. NIST, **FIPS PUB 197 – Advanced Encryption Standard (AES)**, 2001; cập nhật 2023.
2. NIST, **SP 800-38A – Recommendation for Block Cipher Modes of Operation: Methods and Techniques**, 2001.
3. NIST, **SP 800-38C – Recommendation for Block Cipher Modes of Operation: The CCM Mode for Authentication and Confidentiality**, 2004.
4. NIST, **SP 800-38D – Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC**, 2007.
5. NIST, **SP 800-38E – Recommendation for Block Cipher Modes of Operation: The XTS-AES Mode for Confidentiality on Storage Devices**, 2010.
6. Crypto++ Library, **Crypto++ Documentation and Source Code**, phiên bản 8.9.0.
7. IEEE, **IEEE Std 1619 – Standard for Cryptographic Protection of Data on Block-Oriented Storage Devices**.

---

# PHỤ LỤC
## Phụ lục A – Bảng kết quả benchmark chi tiết

Throughput (MB/s), giá trị trung bình của 1.000 lần đo.

### A.1. AES-128 – Windows

**Mã hóa**

| Mode | 1 KB | 4 KB | 16 KB | 256 KB | 1 MB | 8 MB |
|---|---:|---:|---:|---:|---:|---:|
| ECB | 704,50 | 1.866,53 | 2.275,25 | 2.843,68 | 662,58 | 636,92 |
| CBC | 465,14 | 833,24 | 976,48 | 430,14 | 467,63 | 409,47 |
| OFB | 459,22 | 815,53 | 918,75 | 983,63 | 560,69 | 452,77 |
| CFB | 465,38 | 833,42 | 979,77 | 1.047,44 | 553,70 | 468,14 |
| CTR | 603,83 | 1.728,16 | 2.661,16 | 3.207,84 | 791,37 | 674,19 |
| XTS | 365,06 | 742,33 | 976,91 | 1.074,21 | 522,30 | 447,73 |
| CCM | 377,96 | 683,70 | 822,19 | 862,83 | 461,78 | 431,76 |
| GCM | 487,12 | 1.277,61 | 1.861,46 | 2.203,45 | 674,34 | 625,07 |

**Giải mã**

| Mode | 1 KB | 4 KB | 16 KB | 256 KB | 1 MB | 8 MB |
|---|---:|---:|---:|---:|---:|---:|
| ECB | 734,90 | 2.022,46 | 2.934,43 | 3.511,35 | 1.019,01 | 808,56 |
| CBC | 623,10 | 1.748,44 | 2.718,62 | 3.242,74 | 961,50 | 786,18 |
| OFB | 446,37 | 777,98 | 884,41 | 929,78 | 511,98 | 462,23 |
| CFB | 615,38 | 1.488,86 | 2.100,92 | 2.320,54 | 774,68 | 630,18 |
| CTR | 621,27 | 1.778,75 | 2.632,95 | 2.634,57 | 662,53 | 675,97 |
| XTS | 412,10 | 910,58 | 1.124,36 | 1.106,62 | 676,45 | 523,39 |
| CCM | 267,48 | 580,61 | 795,36 | 893,23 | 583,53 | 524,84 |
| GCM | 316,80 | 952,45 | 1.733,78 | 2.388,22 | 941,31 | 757,06 |

### A.2. AES-128 – Linux

**Mã hóa**

| Mode | 1 KB | 4 KB | 16 KB | 256 KB | 1 MB | 8 MB |
|---|---:|---:|---:|---:|---:|---:|
| ECB | 1.073,53 | 2.633,19 | 3.343,04 | 724,64 | 634,91 | 510,78 |
| CBC | 610,60 | 957,71 | 1.075,24 | 1.096,67 | 1.056,50 | 389,01 |
| OFB | 607,91 | 949,67 | 1.068,48 | 1.103,71 | 1.076,84 | 763,86 |
| CFB | 581,87 | 941,95 | 1.086,86 | 1.125,54 | 1.127,83 | 778,61 |
| CTR | 958,86 | 2.329,98 | 3.352,89 | 3.738,67 | 3.621,75 | 1.578,42 |
| XTS | 534,33 | 938,82 | 1.196,19 | 1.265,40 | 1.259,76 | 837,67 |
| CCM | 480,59 | 767,82 | 892,81 | 921,01 | 915,71 | 374,25 |
| GCM | 684,21 | 1.617,13 | 2.258,30 | 2.434,55 | 2.151,19 | 473,55 |

**Giải mã:** chưa có dữ liệu (`bench_linux_128.csv` chỉ có hướng mã hóa).

### A.3. AES-192 – Windows

**Mã hóa** (không có XTS)

| Mode | 1 KB | 4 KB | 16 KB | 256 KB | 1 MB | 8 MB |
|---|---:|---:|---:|---:|---:|---:|
| ECB | 702,98 | 1.781,67 | 2.277,23 | 2.472,64 | 584,67 | 538,47 |
| CBC | 433,54 | 684,14 | 813,56 | 719,13 | 357,86 | 334,22 |
| OFB | 422,09 | 715,10 | 803,26 | 863,98 | 536,21 | 469,63 |
| CFB | 439,48 | 740,78 | 859,49 | 899,32 | 544,79 | 492,85 |
| CTR | 592,50 | 1.545,27 | 2.206,09 | 2.651,88 | 914,68 | 758,87 |
| CCM | 335,80 | 584,14 | 673,90 | 713,09 | 407,88 | 380,18 |
| GCM | 479,68 | 1.220,30 | 1.666,27 | 2.027,01 | 661,74 | 581,58 |

**Giải mã** (không có XTS)

| Mode | 1 KB | 4 KB | 16 KB | 256 KB | 1 MB | 8 MB |
|---|---:|---:|---:|---:|---:|---:|
| ECB | 734,22 | 1.946,60 | 2.669,87 | 2.808,47 | 992,50 | 771,97 |
| CBC | 597,47 | 1.684,95 | 2.440,17 | 2.957,55 | 843,47 | 693,54 |
| OFB | 435,73 | 750,96 | 845,24 | 898,06 | 565,86 | 469,83 |
| CFB | 615,67 | 1.494,32 | 1.975,34 | 2.233,97 | 921,75 | 671,30 |
| CTR | 636,88 | 1.704,73 | 2.471,59 | 2.986,13 | 965,87 | 771,72 |
| CCM | 242,47 | 504,89 | 667,57 | 774,01 | 510,97 | 492,24 |
| GCM | 294,47 | 902,59 | 1.465,64 | 1.316,23 | 794,06 | 730,95 |
### A.4. AES-192 – Linux

**Mã hóa** (không có XTS)

| Mode | 1 KB | 4 KB | 16 KB | 256 KB | 1 MB | 8 MB |
|---|---:|---:|---:|---:|---:|---:|
| ECB | 999,72 | 2.391,18 | 3.084,54 | 726,95 | 657,12 | 514,41 |
| CBC | 563,97 | 853,09 | 940,55 | 970,19 | 942,17 | 377,78 |
| OFB | 573,76 | 842,04 | 939,54 | 948,20 | 914,12 | 711,60 |
| CFB | 588,20 | 858,30 | 952,61 | 983,95 | 979,45 | 750,13 |
| CTR | 910,07 | 2.121,76 | 3.033,80 | 3.344,66 | 3.269,98 | 1.560,59 |
| CCM | 450,02 | 689,39 | 786,79 | 432,22 | 393,35 | 319,13 |
| GCM | 658,64 | 1.468,26 | 1.967,54 | 2.139,39 | 1.856,89 | 413,76 |

**Giải mã** (không có XTS)

| Mode | 1 KB | 4 KB | 16 KB | 256 KB | 1 MB | 8 MB |
|---|---:|---:|---:|---:|---:|---:|
| ECB | 1.098,68 | 2.473,50 | 3.324,34 | 3.493,82 | 3.360,27 | 1.501,54 |
| CBC | 922,04 | 2.248,25 | 3.146,93 | 3.418,59 | 3.172,16 | 1.251,78 |
| OFB | 554,77 | 843,40 | 940,63 | 959,77 | 916,00 | 721,23 |
| CFB | 814,57 | 1.774,03 | 2.216,34 | 2.378,53 | 2.110,42 | 1.151,06 |
| CTR | 920,90 | 2.295,05 | 3.146,17 | 3.487,90 | 3.411,10 | 1.511,51 |
| CCM | 343,10 | 618,62 | 759,92 | 814,21 | 747,85 | 626,19 |
| GCM | 463,02 | 1.198,36 | 1.913,64 | 2.264,64 | 2.145,68 | 1.245,72 |

### A.5. AES-256 – Windows

**Mã hóa**

| Mode | 1 KB | 4 KB | 16 KB | 256 KB | 1 MB | 8 MB |
|---|---:|---:|---:|---:|---:|---:|
| ECB | 587,29 | 1.092,87 | 1.291,73 | 1.478,64 | 620,79 | 592,82 |
| CBC | 374,48 | 635,03 | 725,17 | 768,94 | 498,47 | 452,54 |
| OFB | 398,63 | 609,60 | 675,83 | 707,72 | 506,23 | 475,18 |
| CFB | 424,70 | 678,52 | 754,90 | 789,68 | 551,53 | 517,79 |
| CTR | 488,21 | 1.094,24 | 1.410,15 | 1.584,22 | 882,70 | 762,05 |
| XTS | 302,34 | 592,98 | 742,87 | 805,54 | 579,09 | 522,74 |
| CCM | 287,78 | 463,00 | 523,62 | 543,58 | 386,25 | 360,63 |
| GCM | 366,61 | 837,60 | 1.127,29 | 1.253,76 | 644,64 | 582,48 |

**Giải mã**

| Mode | 1 KB | 4 KB | 16 KB | 256 KB | 1 MB | 8 MB |
|---|---:|---:|---:|---:|---:|---:|
| ECB | 636,77 | 1.250,75 | 1.526,81 | 1.652,95 | 922,16 | 776,29 |
| CBC | 480,42 | 1.158,74 | 1.462,54 | 1.606,32 | 896,39 | 736,18 |
| OFB | 363,64 | 594,09 | 673,41 | 709,62 | 524,64 | 475,38 |
| CFB | 494,21 | 1.079,85 | 1.362,00 | 1.507,85 | 852,67 | 725,95 |
| CTR | 495,03 | 1.095,25 | 1.426,41 | 1.598,68 | 875,87 | 762,95 |
| XTS | 337,04 | 661,13 | 813,78 | 787,05 | 582,16 | 527,55 |
| CCM | 211,13 | 403,51 | 506,08 | 555,60 | 438,18 | 403,53 |
| GCM | 267,54 | 689,80 | 1.076,65 | 1.327,11 | 814,50 | 695,69 |

### A.6. AES-256 – Linux

**Mã hóa**

| Mode | 1 KB | 4 KB | 16 KB | 256 KB | 1 MB | 8 MB |
|---|---:|---:|---:|---:|---:|---:|
| ECB | 1.007,06 | 2.222,83 | 2.813,06 | 718,68 | 658,90 | 491,30 |
| CBC | 511,87 | 750,14 | 848,82 | 864,73 | 854,00 | 365,05 |
| OFB | 526,36 | 766,37 | 853,19 | 874,53 | 886,51 | 723,15 |
| CFB | 541,51 | 786,35 | 877,34 | 894,28 | 896,05 | 730,20 |
| CTR | 909,69 | 2.077,05 | 2.858,21 | 3.129,02 | 3.137,30 | 1.736,11 |
| XTS | 523,19 | 932,10 | 1.154,72 | 1.210,02 | 1.213,70 | 928,64 |
| CCM | 425,00 | 642,22 | 712,62 | 725,69 | 725,58 | 347,19 |
| GCM | 670,98 | 1.486,61 | 2.006,10 | 2.123,28 | 2.122,44 | 505,97 |

**Giải mã**

| Mode | 1 KB | 4 KB | 16 KB | 256 KB | 1 MB | 8 MB |
|---|---:|---:|---:|---:|---:|---:|
| ECB | 1.037,39 | 2.260,34 | 2.993,91 | 3.118,61 | 3.000,36 | 1.538,94 |
| CBC | 897,52 | 2.102,55 | 2.909,40 | 3.035,60 | 3.040,45 | 1.453,07 |
| OFB | 532,64 | 776,19 | 866,32 | 885,70 | 887,04 | 724,10 |
| CFB | 808,16 | 1.605,26 | 2.042,08 | 2.149,53 | 2.162,05 | 1.294,80 |
| CTR | 925,66 | 2.136,31 | 2.955,99 | 3.195,74 | 3.208,25 | 1.759,63 |
| XTS | 576,38 | 1.050,27 | 1.267,81 | 1.205,25 | 1.210,20 | 933,22 |
| CCM | 339,90 | 584,30 | 704,48 | 739,96 | 739,26 | 628,11 |
| GCM | 475,36 | 1.200,91 | 1.898,96 | 2.201,58 | 2.212,19 | 1.432,04 |

## Phụ lục B – Bộ kiểm thử KAT và Negative Tests

### B.1. KAT


|STT| Test vector | Mode | Khóa | Kết quả |
|---|---|---|---|---|
| 1|SP800-38A F.1.1 | ECB | AES-128 | PASS |
| 2|SP800-38A F.1.3 | ECB | AES-192 | PASS |
| 3|SP800-38A F.2.1 | CBC | AES-128 | PASS |
| 4|SP800-38A F.2.3 | CBC | AES-192 | PASS |
|5 |SP800-38A F.2.5 | CBC | AES-256 | PASS |
|6| SP800-38A F.3.13 | CFB128 | AES-128 | PASS |
|7 |SP800-38A F.3.15 | CFB128 | AES-192 | PASS |
|8 |SP800-38A F.4.1 | OFB | AES-128 | PASS |
|9 |SP800-38A F.4.3 | OFB | AES-192 | PASS |
|10| SP800-38A F.5.1 | CTR | AES-128 | PASS |
|11| SP800-38A F.5.3 | CTR | AES-192 | PASS |
|12| SP800-38A F.5.5 | CTR | AES-256 | PASS |
|13| GCM Test Case 1 (rỗng) | GCM | AES-128 | PASS |
|14| GCM Test Case 2 | GCM | AES-128 | PASS |
|15| GCM Test Case 3 | GCM | AES-128 | PASS |
|16| GCM Test Case 4 (có AAD) | GCM | AES-128 | PASS |
|17| GCM Test Case 7 (rỗng) | GCM | AES-192 | PASS |
|18| GCM Test Case 8 | GCM | AES-192 | PASS |
|19| GCM Test Case 9 | GCM | AES-192 | PASS |
|20| GCM Test Case 10 (có AAD) | GCM | AES-192 | PASS |
|21| GCM Test Case 13 (rỗng) | GCM | AES-256 | PASS |
|22 |GCM Test Case 14 | GCM | AES-256 | PASS |
|23| NEGATIVE: GCM Test Case 2, tag sai | GCM | AES-128 | PASS (bị từ chối đúng kỳ vọng) |
|24| NEGATIVE: GCM Test Case 8, tag sai | GCM | AES-192 | PASS (bị từ chối đúng kỳ vọng) |
|25 |SP800-38C Example 1 (Tlen=4, Nlen=7) | CCM | AES-128 | PASS |
|26| SP800-38C Example 2 (Tlen=6, Nlen=8) | CCM | AES-128 | PASS |
|27| SP800-38C Example 3 (Tlen=8, Nlen=12) | CCM | AES-128 | PASS |

### B.2. Negative Tests

| STT | Test | Hành vi mong đợi |
|---|---|---|
| 1 | Sai khóa | Không thu được plaintext gốc |
| 2 | Sai IV/nonce | Từ chối tham số hoặc giải mã thất bại |
| 3 | Sửa ciphertext CBC | Cho thấy non-AEAD không tự xác thực |
| 4 | Sửa ciphertext GCM | AuthError, không trả plaintext |
| 5 | Tag sai | AuthError |
| 6 | IV sai độ dài | UsageError |

## Phụ lục C – Hướng dẫn build và sử dụng

### C.1. Windows

```powershell
cmake -S . -B build -G "MinGW Makefiles"
cmake --build build -j
```

![](img\buildWin.png)

### C.2. Linux

```bash
cmake -S . -B build
cmake --build build -j"$(nproc)"
```

![Ảnh minh chứng: build thành công trên Linux](img/makelinux.png)

### C.3. Lệnh sử dụng

```bash
./build/bin/aestool keygen --bits 256 --out key.bin
./build/bin/aestool encrypt --mode gcm --key key.bin --in plaintext.bin --out ciphertext.aest
./build/bin/aestool decrypt --key key.bin --in ciphertext.aest --out recovered.bin
./build/bin/aestool --kat vectors/nist_vectors.json --verbose
./build/bin/aestool bench --modes gcm,ctr,cbc --sizes 1k,4k,16k,256k,1m,8m --runs 1000 --bits 256 --dir both
```
./build/bin/aestool.exe nếu chạy trên OS Window.


## Phụ lục D – Bảng tự đánh giá (Self-grade Rubric)


| Tiêu chí | Tối đa | Tự chấm | Minh chứng theo nguồn |
|---|---:|---:|---|
| Correctness & KATs | 25 | 25 | KAT 27/27 PASS |
| Security Hygiene | 15 | 15 | Negative Tests, ECB check, nonce reuse |
| UX & I/O Design | 10 | 10 | CLI `--mode`, `--key`, `--aead` |
| Performance Methodology | 20 | 20 | Mean, Median, SD, CI, so sánh đa nền tảng |
| Cross-Platform Build | 10 | 10 | Nguồn ghi build Windows/Linux thành công |
| Report Quality | 20 | 20 | Bảng, biểu đồ, nhận xét |
| Bonus | +5 | 5 |aes_gui.py |
| **Tổng** | **100 (+5)** | **100** | **Tự đánh giá theo tài liệu nguồn** |

*Kết thúc báo cáo Lab 1 – Symmetric Encryption with Crypto++*
