# AGENT_DONE.md — Tóm tắt trạng thái sau khi agent hoàn tác

## 1. File đã tạo bởi agent

### 1.1 Cấu trúc thư mục
```
lab3-rsatool/
├── AGENT.md (chỉ thị ban đầu)
├── RUN_GUIDE.md (hướng dẫn chạy - không sửa)
├── CMakeLists.txt (đã tạo bởi agent)
├── README.md (đã tạo bởi agent)
├── AGENT_DONE.md (file này)
├── COMPILE_RISKS.md (đã tạo bởi agent)
├── DESIGN.md (đã tạo bởi agent)
├── REPORT_OUTLINE.md (đã tạo bởi agent)
├── BONUS_B_hybrid_analysis.md (chưa tạo - Bonus B)
├── results/ (chưa có - do con người populate)
├── report/figures/ (chưa có - do con người populate)
├── testdata/ (chưa có - do con người populate)
└── keys/ (chưa có - do con người tạo qua keygen)
```

### 1.2 File nguồn C++ (include + src)

**include/rsalab/**
- `errors.hpp` - 3 loại exception: UsageError, IoError, CryptoFailure
- `ossl_raii.hpp` - RAII wrappers cho: EVP_PKEY, EVP_PKEY_CTX, EVP_CIPHER_CTX, EVP_MD_CTX, BIO, OSSL_ENCODER_CTX, OSSL_DECODER_CTX, EVP_CIPHER, EVP_MD, SecureBuffer
- `encoding.hpp` - raw | hex | base64 encode/decode
- `keyio.hpp` - PEM/DER/I/O qua OSSL_ENCODER/DECODER, metadata JSON, validation
- `rsa_oaep.hpp` - RSA-OAEP EVP wrapper: encrypt/decrypt, label, max_plaintext_len
- `envelope.hpp` - container format: magic "RSAE", version, header_len u32, header JSON, payload
- `hybrid.hpp` - encrypt/decrypt tổng: auto mode Direct↔Hybrid, AES-256-GCM
- `oaep_manual.hpp` - Bonus A: implement OAEP thủ công constant-time, MGF1 SHA-256
- `util.hpp` - max_plaintext_len, file I/O, RAND_bytes, constant-time helpers, ByteVec/ByteView

**src/**
- `main.cpp` - điểm vào CLI: keygen, encrypt, decrypt
- `cli.cpp` / `cli.hpp` - parse tham số: --bits, --pub, --priv, --in, --out, --label, --encode, --force-hybrid, --impl
- `encoding.cpp` - implementation hex/base64 encode/decode
- `keyio.cpp` - implement keygen/read/write PEM/DER/metadata
- `rsa_oaep.cpp` - implement RSA-OAEP encrypt/decrypt
- `envelope.cpp` - implement build_envelope/parse_envelope (chưa tách riêng, code trong header)
- `hybrid.cpp` - implement encrypt_hybrid/decrypt_hybrid (đã tạo kèm header)
- `util.cpp` - implement file I/O helpers

### 1.3 File test (Catch2)
- `tests/test_main_or_catch.cpp` - Catch2 config main
- `tests/test_rsa_oaep.cpp` - test RSA-OAEP: max length, direct, label, modulus sizes
- `tests/test_keyio.cpp` - test key I/O: PEM/DER, metadata, format detection, encoding
- `tests/test_hybrid.cpp` - test hybrid mode: auto/force/direct/hybrid, 3072/4096
- `tests/test_negative.cpp` - test fail-closed: 10 kịch bản + ERR_clear_error verification
- `tests/test_oaep_manual.cpp` - Bonus A: cross-check manual ↔ library OAEP

### 1.4 File benchmark
- `bench/bench_main.cpp` - CLI `rsabench` với các tùy chọn --reps, --size, --bits
- `scripts/analyze_bench.py` - Python: đọc CSV, thống kê 95% CI, 4 đồ thị (py: pandas, numpy, scipy, matplotlib)
- `scripts/tamper.py` - tạo file bị can thiệp cho negative test: flip-payload, flip-tag, flip-wrapped-key, flip-header-iv, change-modulus, truncate, flip-direct
- `scripts/make_testfiles.py` - tạo testdata: msg_small (100B), msg_edge318 (318B), msg_edge319 (319B), msg_1KiB, msg_1MiB, msg_100MiB

### 1.4 Tài liệu
- `README.md` - hướng dẫn đầy đủ: cài, build, dùng, exit codes, rubric
- `docs/DESIGN.md` - bảng ánh xapa Crypto++ → OpenSSL 4.x, kiến trúc, AAD, quy trình hybrid encrypt/decrypt, constant-time OAEP
- `docs/COMPILE_RISKS.md` - các rủi ro biên dịch: API đã gỡ, common issues, debug tips, fix cho lỗi phổ biến
- `docs/AGENT_DONE.md` - file này
- `report/REPORT_OUTLINE.md` - đàn ý báo cáo + lý thuyết đã viết (có `{{TODO}}` placeholders)
- `CMakeLists.txt` - hệ thống build: OpenSSL 4.x detection, nlohmann_json/Catch2 FetchContent fallback, targets: rsa_core/rsatool/rsabench/rsa_tests, warning flags MSVC/GCC, platform-specific link opts

## 2. Các điểm chưa chắc biên dịch (OpenSSL 4.x uncertainties)

Dưới đây là các hàm/API OpenSSL 4.x mà agent **không chắc 100%** về chữ ký/signature hoặc hành vi, và có thể cần điều chỉnh khi build:

### 2.1 `EVP_PKEY_CTX_set0_rsa_oaep_label`
- **Vấn đề**: API này chuyển ownership buffer qua `set0`; khi call thành công → **không** đc `OPENSSL_free` buffer đó; khi call thất bại → **phải** `OPENSSL_free`
- **Rủi ro**: N code xem nhầm và free buffer hay giữ reference đã free → use-after-free hoặc memory leak
- **Code reference**: `rsa_oaep.hpp:170-176` - agent đã implement check nhưng cần verify khi build

### 2.2 `EVP_PKEY_get_bn_param` với `OSSL_PKEY_PARAM_RSA_E`
- **Vấn đề**: Constant `OSSL_PKEY_PARAM_RSA_E` có thể có giá trị khác so với cách cũ lấy BN_e từ RSA struct
- **Rủi ro**: Sai constant → không thể check exponent 65537 → key validation thất bại
- **Code reference**: `keyio.hpp:208` - agent implement check nhưng cần verify

### 2.3 `OSSL_DECODER_CTX_new_for_pkey` ràng buộc structure
- **Vấn đề**: Kiểm tra structure "SubjectPublicKeyInfo" vs "PrivateKeyInfo" có từ chối đúng file sai loại không
- **Rủi ro**: N ràng buộc không khớp → có thể cho đọc key sai loại hoặc reject key hợp lệ
- **Code reference**: `keyio.hpp:204` - agent implement nhưng cần verify test case

### 2.4 `EVP_EncodeBlock`/`EVP_DecodeBlock` return value
- **Vấn đề**: `EVP_DecodeBlock` return value đã bao gồm padding handling chưa? (Thực ra đã trừ)
- **Rủi ro**: Sai understanding → off-by-one trong base64 decode length
- **Code reference**: `encoding.hpp` và `encoding.cpp` - agent implement dựa trên doc OpenSSL 4.x

### 2.4 `EVP_CTRL_AEAD_SET_IVLEN` với AES-256-GCM
- **Vấn đề**: Một số phiên OpenSSL 4.x có thể không hỗ trợ Set IVLength cho GCM (mặc định là 12 byte)
- **Rủi ro**: GCM chỉ hỗ trợ IV 12 byte; nếu API không có → phải dùng cách khác (hardcode IV length assumption)
- **Code reference**: `hybrid.cpp` - agent set IV length 12 nhưng cần verify

### 2.5 `OSSL_ENCODER_CTX_new_for_pkey` parameters
- **Vấn đề**: Hàm này có thể cần additional parameters (OSSL_PARAM array) tùy version 4.0.x
- **Rủi ro**: SAI signature → compile error hoặc runtime failure
- **Code reference**: `keyio.hpp:202-203` - agent dùng signature đơn giản nhưng cần verify

### 2.6 `RAND_bytes` return value kiểm tra
- **Vấn đề**: Mọi hàm trả 1 khi thành công, 0 hoặc <0 khi lỗi; agent luôn check `== 1`
- **Rủi ro**: N platform có return 1 cho một vài trường hợp ngoại lệ → logic error
- **Code reference**: Toàn codebase - agent đã implement pattern check everywhere

### 2.7 `EVP_PKEY_CTX_new` vs `EVP_PKEY_CTX_new_from_pkey`
- **Vấn đề**: Cách chọn giữahai hàm có thể ảnh hưởng đến behaviour
- **Rủi ro**: Sai hàm → context không được init đúng với key đã specified
- **Code reference**: `rsa_oaep.hpp:166` - agent dùng `EVP_PKEY_CTX_new(pkey, nullptr)` nhưng có thể cần `EVP_PKEY_CTX_new_from_pkey`

## 3. Giả định đã dùng

### 3.1 Phiên bản OpenSSL
- Giả định: OpenSSL 4.0 hoặc newer (4.0 exactly for testing)
- Đường dẫn: `/opt/openssl-4` hoặc qua vcpkg `x64-windows`
- Kiểm tra: `/opt/openssl-4/bin/openssl version` hiện `4.x`

### 3.2 Hệ điều hành
- **Linux**: Ubuntu LTS, dùng GCC hoặc Clang
- **Windows**: MSVC 2022 hoặc MinGW64 qua MSYS2
- CMake generator: Ninja (Linux) hoặc "Visual Studio 17 2022" (Windows)

### 3.3 Thư viện bên ngoài
- **nlohmann_json**: Phiên bản v3.11.3 (hoặc tìm được qua `find_package`)
- **Catch2**: Phiên bản v3.5.1 (hoặc tìm được qua `find_package`)
- **Python 3**: Chỉ dùng cho scripts (make_testfiles.py, tamper.py, analyze_bench.py)
- **KHÔNG DÙNG**: Crypto++, `std::random_device`, `std::mt19937`, `rand()`, `srand()`

### 3.4 HARDCODE & Thiết kế
- **Giới hạn plaintext**: RSA-3072 → 318 byte; RSA-4096 → 446 byte (theo công thức k - 2*32 - 2)
- **MGF1**: Sử SHA-256 tường minh (`EVP_sha256()`), không phụ thuộc vào default
- **Label**: Rỗng = chuẩn OAEP (L = chuỗi rỗng); không gọi `set0_rsa_oaep_label` khi label rỗng
- **Auto mode**: `mLen ≤ max_plaintext_len` → Direct; ngược lại → Hybrid
- **Fail-closed**: Mọi lỗi crypto → `"Error: decryption failed."` + exit 3 + không tạo file output
- **AAD**: `"RSAE-AAD-v1|" + mode + "|" + rsa_modulus + "|" + hash + "|" + wrapped_key_b64 + "|" + iv_b64`
- **GCM tag**: Luôn set trước `EVP_DecryptFinal_ex`/``EVP_EncryptFinal_ex``; kiểm tra return > 0

### 3.5 Khác biệt so với OpenSSL 3.x
- `OSSL_ENCODER`/`OSSL_DECODER` chỉ có 4.x (biếu gỡ engine, RSA_*, AES_* cũ)
- `RSA_generate_key_ex` đã xóa → bắt buộc dùng `EVP_PKEY_keygen`
- `AES_*` deprecated → dùng `EVP_*`
- `ERR_load_*_strings` đã xóa → không cần call trước; error info qua `get_state()` thay

### 3.6 Mọi hàm EVP_PKEY_encrypt/decrypt
- Giả định: `EVP_PKEY_encrypt_init`/`EVP_PKEY_encrypt` chuỗi hoạt động như OpenSSL 4.x mong đợi
- Bắt buộc: `EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING)` trước khi encrypt/decrypt
- Bắt buộc: `EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256())` để set MD SHA-256 rõ ràng
- Bắt buộc: `EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256())` để set MGF1 SHA-256 rõ ràng (không dùng mặc định)