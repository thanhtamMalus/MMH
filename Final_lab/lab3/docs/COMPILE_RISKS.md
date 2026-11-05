# COMPILE_RISKS.md — Các rủi ro biên dịch & các điểm cần lưu ý

## 1. Vấn đề OpenSSL 4.x API thay đổi

### 1.1 API đã gỡ (removed) - CẤM KỴT
Các hàm sau đây **không tồn tại** trong OpenSSL 4.0 và sẽ gây lỗi biên dịch:
- `RSA_new`, `RSA_generate_key_ex` — Sử `EVP_PKEY_keygen` thay
- `RSA_public_encrypt`, `RSA_private_decrypt` — Sử `EVP_PKEY_encrypt/decrypt` với `RSA_PKCS1_OAEP_PADDING` hoặc `RSA_NO_PADDING`
- `RSA_padding_add`, `RSA_check_key` — Các hàm low-level đã bị xóa
- `RSA_get0_n`, `RSA_get0_e`, `RSA_get0_d` — Sử `EVP_PKEY_get_bn_param` thay
- `EVP_PKEY_assign_RSA` — Sử `EVP_PKEY_new` + `EVP_PKEY_set1_RSA` hoặc keygen
- `EVP_PKEY_get0_RSA` — Sử `EVP_PKEY_get1_RSA` (copy) hoặc accessor đã định义
- `AES_encrypt`, `AES_decrypt` — Sử `EVP_EncryptInit_ex2`/`EVP_DecryptInit_ex2` với `EVP_aes_256_gcm`
- `SHA256_Init`, `SHA256_Update`, `SHA256_Final` — Sử `EVP_DigestInit_ex`/`Update`/`Final` hoặc `EVP_Digest`
- `HMAC_CTX_init`, `HMAC_Update`, `HMAC_Final` — Sử `EVP_MAC` hoặc `HMAC_CTX_new`/`Update`/`Final` (còn có nhưng deprecated trong 4.x)
- `ENGINE_load_private_key` — Engine đã bị gỡ hoàn toàn ở OpenSSL 4.0
- `ENGINE_free` — Xóa hoàn toàn
- `ERR_load_error_strings`, `ERR_remove_thread_state` — Đã gỡ; lỗi quản lý qua `extern` variables thay
- `X509_cmp_time` — Sử `OSSL_PKEY_PARAM_DATE` hoặc so sánh BIGNUM khác

### 1.2 API thay đổi quan trọng
- `EVP_PKEY_CTX_set0_rsa_oaep_label`: Buffer ownership chuyển qua `set0`; sau khi call thành công **không** đc `OPENSSL_free` buffer đó; call thất bại → **phải** `OPENSSL_free`
- `EVP_DecryptInit_ex2`/`EVP_EncryptInit_ex2`: Tham số thứ 5 (future) thay đổi trong 4.x; luôn truyền `nullptr`
- `EVP_MD_CTX_new`/`EVP_MD_CTX_free`: Vẫn có nhưng phải kiểm tra NULL trả về
- `BIO_new`/`BIO_free`: Vẫn có; `BIO_free_all` cho BIO chain free

### 1.3 CFLAGS quan trọng
- Luôn define `OPENSSL_NO_DEPRECATED` cho mọi target (xem CMakeLists.txt)
- Nếu lỡ dùng API deprecated → trình biên dịch sẽ báo error (do define này)
- CMake đã bật `-Werror` cho MSVC `/W4 /permissive-` và GCC/Clang `-Wall -Wextra -Wpedantic`

## 2. Rủi ro Common

### 2.1 Tràn bộ nhớ khi ép `size_t → int`
Nhiều hàm OpenSSL (`EVP_EncryptUpdate`, `EVP_DecryptUpdate`,...) nhận `int` làm độ dài.
- **Quy tắc**: Xử lý dữ liệu lớn theo khối (vd. 1 MiB) trong vòng lặp
- **Kiểm tra**: `if (size > INT_MAX) throw IoError("Data too large")`
- **Buffer**: `reserve` đúng kích thước từ đầu cho `std::vector`

### 2.2 Null pointer dereference
- Luôn kiểm tra giá trị trả về của `unique_ptr` creation
- Ví dụ: `PkeyCtxPtr ctx(EVP_PKEY_CTX_new(pkey, nullptr));` → nếu `ctx` là NULL → throw
- Mọi `get()` access phải kiểm tra trước

### 2.3 Memory leak qua exception
- **Quy tắc**: Mọi object OpenSSL tạo ra đều có unique_ptr deleter
- **Ví dụ xấu**: `EVP_PKEY_CTX_new()` → nếu `EVP_PKEY_encrypt_init()` thất bại → leak ctx
- **Ví dụ tốt**: Sử `PkeyCtxPtr` → destructor tự free khi ném exception

### 2.4 SAT mismatch (Windows MSVC)
- Nếu link OpenSSL động → runtimeMD/MT phải khớp với bản OpenSSL được build
- Nếu dùng vcpkg → dùng triplet `x64-windows` hoặc `x64-windows-static`
- CMake có `option(OPENSSL_USE_STATIC_LIBS ...)` để chọn

### 2.5 Đọc file PEM/DER sai loại
- `OSSL_DECODER_CTX_new_for_pkey` với ràng buộc `structure` ("SubjectPublicKeyInfo" | "PrivateKeyInfo")
- Nạp PUBLIC key vào `--priv` → throw IoError (tự từ chối)
- Nạp `RSA PRIVATE KEY` (PKCS#1) khi yêu cầu PKCS#8 → throw IoError
- Luôn kiểm tra `EVP_PKEY_is_a(pkey, "RSA")` sau khi nạp

### 2.6 Threading issues
- `EVP_PKEY_CTX` **không an toàn** giữa threads → tạo ctx mới cho mỗi lần gọi
- `RAND_bytes` thread-safe do DRBG trong OpenSSL
- Không chia sẻ `EVP_CIPHER_CTX` giữa threads

### 2.7 Hex encoding padding
- Hex encode: chữ thường khi ghi
- Hex decode: chấp nhận hoa/thường khi đọc
- Từ chối ký tự lạ / độ dài lẻ → throw UsageError
- Padding `=` trong base64: EVP_DecodeBlock **không tự trừ**; phải trừ số byte `=` đệm khỏi độ dài trả về (hoặc依靠 return value của EVP_DecodeBlock đã trừ đúng)

### 2.8 Base64 decode
- EVP_DecodeBlock return value: số byte dữ liệu thực (already exclude padding)
- Không cần thủ công trừ `=`; dùng return value trực tiếp
- Tuy nhiên kiểm tra độ dài input % 4 == 0 (sau khi strip whitespace)

### 2.9 Atomic file write
- Luôn ghi vào file `.tmp` trước rồi `rename`/`MoveFileEx`
- Ném exception giữa lúc ghi → không留下 file nửa vời
- Buffer chứa dữ liệu sensitive (private key DER/PEM) phải `OPENSSL_cleanse` sau khi ghi file

### 2.10 CMake FetchContent network
- Nếu không có Internet → cần cài nlohmann_json/catch2 qua system package
- `.venv` hoặc system install `apt install nlohmann-json3-dev catch2`
- CMake sẽ tự FetchContent nếu không có package cục bộ

## 3. Debug tips

### 3.1 Kiểm tra OpenSSL version:
```bash
cmake -S . -B build 2>&1 | grep "OpenSSL version"
# hoặc
/opt/openssl-4/bin/openssl version
```

### 3.2 Bật thêm warnings:
```bash
cmake -DCMAKE_CXX_FLAGS="-Wall -Wextra -Wpedantic -Werror" -S . -B build
```

### 3.3 Missing symbol:
```bash
# Linux: kiểm tra symbol
nm -D build/bin/rsatool | grep RSA_
# Windows: Dependency Walker hoặc dumpbin
```

### 3.4 Xem OpenSSL include/lies:
```bash
cmake -S . -B build 2>&1 | grep "OpenSSL include"
# Kiểm tra header include đúng: #include <openssl/evp.h>, #include <openssl/rand.h>
```

### 3.5 RAII violation detector:
- Sử `unique_ptr` với custom deleter cho mọi object OpenSSL
- N pointer bị NULL khi ném exception → kiểm tra `if (!ptr) throw IoError(...)` ngay lập tức

## 4. Mảng lỗi phổ biến (Compile Errors Fixes)

| Lỗi | Nguyên nhân | Fix |
|-----|-----------|-----|
| `cannot find -lcrypto` | OpenSSL không link được | Kiểm tra `-DOPENSSL_ROOT_DIR`; bật `OPENSSL_USE_STATIC_LIBS` |
| `undefined reference to EVP_PKEY_new_raw_private_key` | API không có ở phiên bản này | Sử API thay thế hoặc conditional compile |
| `expected identifier before '>' token` | `vector<vector<>>` cũ | Sử `vector<vector<unsigned char>>` (c++11+} |
| `‘OPENSSL_NO_DEPRECATED’ was not defined` | Thiếu define trong CMake | Đã bật trong CMakeLists.txt qua `target_compile_definitions` |
| `‘EVP_PKEY_CTX_set0_rsa_oaep_label’ was not declared in this scope` | Sử OpenSSL < 4.0 | Cần OpenSSL ≥ 4.0; không thể dùng với 3.x |
| `‘RSA_PKCS1_OAEP_PADDING’ was not declared in this scope` | Constant đã thay tên | OpenSSL 4.x có thể đổi tên constant; kiểm tra header |
| `called object type 'EVP_PKEY *' is not a function type` | Sử sai API | Kiểm tra doc OpenSSL 4.x; dùng `EVP_PKEY_encrypt_init`/`EVP_PKEY_decrypt_init` chuỗi |
| `invalid use of incomplete type 'struct EVP_PKEY_S'` | Thiếu `#include <openssl/evp.h>` | Thêm include cần thiết |
| `‘CRYPTO_memcmp’ was not declared in this scope` | Thiếu `#include <openssl/crypto.h>` | Thêm include |
| `expected unqualified-id before 'token'` | Missing semicolon or brace | Kiểm tra syntax file trước cùng |
| `‘int’ overflows in conversion to unsigned int` | `size_t → int` without check | Thêm kiểm tra `if (size > INT_MAX)` trước khi ép |