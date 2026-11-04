# DESIGN.md — Quyết định thiết kế, định dạng envelope, bảng ánh xạ API OpenSSL

## 4.0. Bảng ánh xạ Crypto++ → OpenSSL 4.x

| Crypto++ (bản cũ) | OpenSSL 4.x (bản mới) |
|---|---|
| `AutoSeededRandomPool` | `RAND_bytes` / `RAND_priv_bytes` |
| `RSAES<OAEP<SHA256>>::Encryptor/Decryptor` | `EVP_PKEY_CTX` + `EVP_PKEY_encrypt` / `EVP_PKEY_decrypt` với `RSA_PKCS1_OAEP_PADDING` |
| `Name::EncodingParameters` (label) | `EVP_PKEY_CTX_set0_rsa_oaep_label` |
| `InvertibleRSAFunction::GenerateRandomWithKeySize` | `EVP_PKEY_keygen` + `EVP_PKEY_CTX_set_rsa_keygen_bits` |
| `X509PublicKey::Save` / `PKCS8PrivateKey::Save` | `OSSL_ENCODER_*` (`SubjectPublicKeyInfo` / `PrivateKeyInfo`, `PEM`/`DER`) |
| `Base64Encoder`, `HexEncoder` | `EVP_EncodeBlock`/`EVP_DecodeBlock` (base64), hex tự viết |
| `GCM<AES>` + `AuthenticatedEncryptionFilter` | `EVP_CIPHER_CTX` + `EVP_aes_256_gcm` / `"AES-256-GCM"` |
| `SecByteBlock` | `SecureBuffer` + `OPENSSL_cleanse` |
| `VerifyBufsEqual` | `CRYPTO_memcmp` (constant-time) |
| `StringSource/StringSink` | `std::vector<unsigned char>` / `std::string` |
| `Integer` / `ModularExponentiation` (Bonus A) | `EVP_PKEY_encrypt/decrypt` với `RSA_NO_PADDING` (hoặc `BN_mod_exp_mont_consttime`) |
| `SHA256` | `EVP_MD_CTX` / `EVP_Digest` với `SHA2-256` |

## 4.1. Kiến trúc tổng quát

Projekt được xây dựng theo mô hình layer:
1. **Layer 0**: CMake build system, OpenSSL 4.x detection, nlohmann_json, Catch2
2. **Layer 1**: RAII wrappers (`ossl_raii.hpp`) - quản lý vòng đời OpenSSL objects
3. **Layer 2**: Utilitaires (`util.hpp`) - file I/O, RNG, helpers constant-time
4. **Layer 3**: Mã hóa lõi (`rsa_oaep.hpp`) - RSA-OAEP EVP wrapper, MGF1, giới hạn plaintext
5. **Layer 4**: Envelope & AAD (`envelope.hpp`) - container format, additional authenticated data
6. **Layer 5**: Hybrid encryption (`hybrid.hpp`) - auto mode Direct↔Hybrid, AES-256-GCM
7. **Layer 6**: Quản lý khóa (`keyio.hpp`) - PEM/DER/I/O, OSSL_ENCODER/DECODER, metadata
8. **Layer 7**: Mã hóa/giải mãCLI (`cli.hpp`, `main.cpp`) - parse tham số, giao diện dòng lệnh
9. **Layer 8**: Bonus A (`oaep_manual.hpp`) - implement OAEP thủ công constant-time

## 4.2. Quy ước lỗi (Error handling)

### Fail-closed principle:
- Mọi lỗi giải mã/xác thực → `throw CryptoFailure` → main in `"Error: decryption failed."` → exit 3
- File output không được tạo ra khi có lỗi
- Không in chi tiết OpenSSL (ERR_error_string*, ERR_print_errors*) cho user
- ERR_clear_error() gọi đầu mỗi hàm public và ngay trước khi ném exception

### Exit codes:
- `0`: Thành công
- `1`: Sai tham số/cú pháp (UsageError)
- `2`: Lỗi I/O/khóa không đọc được (IoError)
- `3`: Giải mã/xác thực thất bại (CryptoFailure)

### Chung chung thông báo:
```
Error: decryption failed.
```
- Không chứa: "padding", "tag", "label", "OAEP", "mac"
- Không chứa chuỗi OpenSSL: "error:", "routines", "evp", "rsa_"
- Không in stack trace hoặc chi tiết bộ nhớ

## 4.3. Định dạng envelope

### Container binary format:
```
+--------+---------+----------------+------------------+-----------------+
| "RSAE" | ver=0x01| header_len u32 | header JSON      | payload bytes   |
| 4 byte | 1 byte  | big-endian     | (UTF-8, ≤ 64KiB)  | (xem dưới)      |
+--------+---------+----------------+------------------+-----------------+
```
- **Magic**: 4 byte `"RSAE"` (0x52, 0x53, 0x41, 0x45)
- **Version**: 1 byte, phải là 0x01
- **Header length**: 4 byte big-endian integersize of following JSON
- **Header JSON**: UTF-8, tối đa 65536 byte
- **Payload**: Dữ liệu mã hóa (Direct: RSA ciphertext; Hybrid: AES-GCM ciphertext)

### Header JSON fields (Hybrid mode):
```json
{
  "mode": "RSA-OAEP-AES-GCM",
  "rsa_modulus": 3072,
  "hash": "SHA-256",
  "wrapped_key": "<base64 32-byte AES key>",
  "iv": "<base64 12-byte IV>",
  "tag": "<base64 16-byte GCM tag>"
}
```

### Header JSON fields (Direct mode):
```json
{
  "mode": "RSA-OAEP",
  "rsa_modulus": 3072,
  "hash": "SHA-256"
}
```

### AAD (Additional Authenticated Data):
```
"RSAE-AAD-v1|" + mode + "|" + rsa_modulus + "|" + hash + "|" + wrapped_key_b64 + "|" + iv_b64
```
- Được cung cấp cho EVP_AEAD_SET_TAG trước khi EVP_DecryptUpdate/EncryptUpdate
- Ràng buộc header vào GCM authentication; sửa header → xác thực thất bại

## 4.4. Quy trình hybrid encrypt (chi tiết)

1. Tạo khóa AES-256 ngẫu nhiên (32 byte) qua `RAND_bytes`
2. Tạo IV ngẫu nhiên 12 byte qua `RAND_bytes`
3. RSA-OAEP encrypt khóa AES → `wrapped_key` (k byte = modulus bytes)
4. Base64-encode `wrapped_key` → `wrapped_key_b64`
5. Base64-encode IV → `iv_b64`
6. Xây dựng AAD: `"RSAE-AAD-v1|" + "RSA-OAEP-AES-GCM" + "|" + modulus + "|" + "SHA-256" + "|" + wrapped_key_b64 + "|" + iv_b64`
7. AES-256-GCM encrypt plaintext với key, IV, AAD → `ciphertext` + `tag` (16 byte)
8. Base64-encode `tag` → `tag_b64`
9. Xây dựng header JSON với các field: mode, rsa_modulus, hash, wrapped_key, iv, tag
10. Xây dựng envelope container: magic + version + header_len + header_json + payload (ciphertext chỉ)

## 4.5. Quy trình hybrid decrypt (chi tiết)

1. Parse envelope: kiểm tra magic "RSAE", version 0x01, header_len, JSON hợp lệ
2. Kiểm tra: mode phải là "RSA-OAEP-AES-GCM", hash == "SHA-256", rsa_modulus khớp bitsize khóa private
3. Base64-decode `wrapped_key` → khóa AES (phải là 32 byte)
4. Base64-decode `iv` → IV (phải là 12 byte)
5. Base64-decode `tag` → tag (phải là 16 byte)
6. RSA-OAEP unwrap khóa AES sử dụng label tương ứng → kiểm tra kết quả là 32 byte
7. Đặt tag vào `EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag)`
8. Cung cấp AAD: `"RSAE-AAD-v1|" + mode + "|" + rsa_modulus + "|" + "SHA-256" + "|" + wrapped_key_b64 + "|" + iv_b64`
9. AES-256-GCM decrypt: `EVP_DecryptUpdate` → `EVP_DecryptFinal_ex`
   - Chỉ khi `Final` trả > 0 mới coi là xác thực thành công
   - Thất bại → throw CryptoFailure, không ghi file output
10. Ghi plaintext ra file (atomically); nếu Final thất bại → xóa sạch bộ đệm OPENSSL_cleanse

## 4.6. QRCode constant-time OAEP decode (Bonus A)

### Tại sao decode phải constant-time?
Tấn công Manger (2001): oracle phân biệt lỗi "byte đầu ≠ 0x00" với lỗi khác → khôi phục plaintext từng bit/byte. Do đó mọi lỗi phải không phân biệt được cả về thông điệp lẫn thời gian.

### Quy trình EME-OAEP-DECODE constant-time:

1. **Kiểm tra EM[0] == 0x00**: Sử dụng bitmask `mask = (x - 1) >> 63` để không có early return
2. **Extract maskedSeed (32 byte) và maskedDB (k-33 byte)** từ EM
3. **Comput seed = maskedSeed ⊕ MGF1(maskedDB, hLen)**: Sử dụng MGF1 đã implement
4. **Compute lHash' = SHA-256(seed)**: So sánh với lHash cố định bằng `CRYPTO_memcmp`
5. **Scan DB tìm 0x01**: Duyệt Toàn bộ DB với bitmask chọn vị trí而非 early return
6. **Extract message M**: Lấy dữ liệu sau byte 0x01
7. **Kết quả**: Một giá trị duy nhất (thành công/thất bại) ở cuối cùng

### Helper functions constant-time:
- `ct_is_zero(x)`: Trả 1 nếu x == 0, 0 nếu không (dùng cho bitwise operations)
- `ct_select(a, b, sel)`: Trả a nếu sel==0, b nếu sel==1 (dùng volatile hoặc std::atomic)
- `CRYPTO_memcmp()`: So sánh constant-time từ OpenSSL

### Buffer zeroization:
- Tất cả buffer trung gian (EM, DB, seed) phải `OPENSSL_cleanse` sau khi dùng
- Không giữ bản sao của dữ liệu bí mật sau khi xong

## 4.7. CMake target structure

```
add_library(rsa_core STATIC ...)
  │
  └─▶ add_executable(rsatool src/main.cpp)
  │             └─▶ link rsa_core + rsalab::openssl
  │
  └─▶ add_executable(rsabench bench/bench_main.cpp)
  │
  └─▶ add_executable(rsa_tests tests/*.cpp)
          └─▶ link rsa_core + rsalab::openssl + nlohmann_json
                  └─▶ enable_testing() + add_test()
```

## 4.8. Lưu ý triển khai quan trọng

### OpenSSL 4.x vs 3.x:
- API high-level `EVP_*` không bị thay đổi nhiều nhưng `OPENSSL_NO_DEPRECATED` phải define
- `OSSL_ENCODER`/`OSSL_DECODER` chỉ có sẵn 4.x (xóa hoàn toàn ở 4.0 các engine, RSA_*, AES_* cũ)
- `EVP_PKEY_CTX_set0_rsa_oaep_label` quản lý ownership buffer qua `set0` (không gọi `OPENSSL_free` sau khi thành công)
- `RAND_bytes` vẫn hoạt động giống hệt nhưng cần check return == 1 nghiêm ngặt

### RAII bắt buộc:
- Mọi `EVP_PKEY`, `EVP_PKEY_CTX`, `EVP_CIPHER_CTX`, `EVP_MD_CTX`, `BIO`, `OSSL_ENCODER_CTX`, `OSSL_DECODER_CTX` đều phải có `unique_ptr` với custom deleter
- Không được gọi `*_free` thủ công rải rác; RAII handle lỗi khi ném exception
- Không gọi `OPENSSL_cleanup()` và không dựa vào `atexit` (4.0 xóa hoàn toàn)

### OpenSSL_cleanse:
- Dùng cho: khóa AES, plaintext tạm, khóa private đã nạp ra buffer
- `SecureBuffer` RAII wrapper có destructor gọi `OPENSSL_cleanse`
- `std::vector` có thể realloc → phải `reserve` đúng kích thước từ đầu

### Threading:
- `EVP_PKEY_CTX` không an toàn giữa threads → tạo ctx mới cho mỗi lần gọi (hoặc `thread_local`)
- `RAND_bytes` thread-safe do DRBG trong OpenSSL

## 4.9. Mapping API decisions

Key design decisions and their API justifications:

| Decision | API Chosen | Rationale |
|----------|-----------|-----------|
| RSA-OAEP implementation | `EVP_PKEY_encrypt/decrypt` với `RSA_PKCS1_OAEP_PADDING` | Sử dụng high-level API an toàn, có built-in blinding, error handling |
| MGF1 | Implement thủ công qua `EVP_Digest` SHA-256 | Không dùng `PKCS1_MGF1` (low-level); cache đối tượng để không fetch lại trong loop |
| Label handling | `EVP_PKEY_CTX_set0_rsa_oaep_label` | Quản lý ownership đúng; label rỗng = không gọi set label (mặc định OAEP) |
| AES-256-GCM | `EVP_aes_256_gcm` với `EVP_CTRL_AEAD_SET_IVLEN(12)` | GCM chỉ hỗ trợ IV 12 byte; set IV length qua control |
| AAD cho GCM | `EVP_EncryptUpdate`/`EVP_DecryptUpdate` với nullptr output | Cách chỉ định AAD theo spec AGENT.md |
| Error messages | `CryptoFailure` + `"Error: decryption failed."` | Fail-closed; không leak chi tiết OpenSSL |
| Key loading | `OSSL_DECODER_CTX_new_for_pkey` + ràng buộc structure | Tự động từ chối file sai loại (PUBLIC vào --priv v.v.) |
| Random number | `RAND_bytes` | CSPRNG of OpenSSL; không dùng bất kỳ module random C++ nào |