# AGENT.md — Lab 3: RSA-OAEP & Hybrid Encryption (`rsatool`) — OpenSSL 4.x

> File này là **chỉ thị cho bot/agent**. Đọc toàn bộ trước khi viết bất kỳ file nào.
> Nhiệm vụ của agent: **VIẾT FILE** (mã nguồn, CMake, test, bench, script, README, tài liệu báo cáo).
> **KHÔNG chạy lệnh terminal.** Việc build/chạy/lấy kết quả do con người thực hiện theo `RUN_GUIDE.md`.

---

## 0. Quy tắc tối thượng (đọc kỹ)

1. **CẤM chạy terminal**: không chạy `cmake`, `make`, `ninja`, `ctest`, `rsatool`, `rsabench`, `openssl`, `python`, `pip`, `apt`, `vcpkg`… Chỉ tạo/sửa file.
2. Vì không được biên dịch thử, agent phải **tự rà soát code** trước khi kết thúc mỗi phase: include thiếu, sai chữ ký hàm OpenSSL, sai tên target CMake, lỗi cú pháp, rò rỉ đối tượng OpenSSL. Ghi các điểm còn rủi ro biên dịch vào `docs/COMPILE_RISKS.md`.
3. **CẤM tuyệt đối** `rand()`, `srand()`, `std::random_device`, `std::mt19937` (kể cả trong test, bench, tool). Chỉ dùng `RAND_bytes` (hoặc `RAND_priv_bytes` cho khóa/IV bí mật) của OpenSSL, **luôn kiểm tra giá trị trả về == 1**. Dùng `grep` thủ công trong đầu: trong repo không được có chuỗi cấm này (kể cả trong comment, trừ file `AGENT.md`/`RUN_GUIDE.md`).
4. **Fail-closed**: mọi lỗi giải mã/xác thực → không ghi file output, không in plaintext một phần, thông báo lỗi **chung chung** (xem §5).
5. Không tự bịa số liệu benchmark/kết quả test. Chỗ cần số liệu trong báo cáo dùng placeholder dạng `{{TODO: dán số liệu từ results/xxx}}`.
6. Mã nguồn chạy được trên **Windows (MSVC / MinGW64)** và **Linux (Ubuntu LTS)**: không dùng API riêng nền tảng ngoài `#ifdef` có fallback; đường dẫn dùng `std::filesystem`; mở file ở chế độ **binary**.
7. C++17. Comment code bằng tiếng Việt hoặc tiếng Anh nhất quán (ưu tiên tiếng Anh cho identifier, tiếng Việt cho giải thích khó).
8. Thư viện mật mã duy nhất: **OpenSSL 4.x (≥ 4.0)**, chỉ dùng `libcrypto` (không cần `libssl`). **Không** dùng Crypto++ hay thư viện mật mã nào khác; không trộn thư viện trong lõi.
9. **Chính sách API OpenSSL 4.x** (bắt buộc):
   - Chỉ dùng **API cấp cao, không deprecated**: `EVP_*`, `EVP_PKEY_*`, `EVP_PKEY_CTX_*`, `OSSL_ENCODER_*`, `OSSL_DECODER_*`, `OSSL_PARAM`, `BIO_*`, `RAND_bytes`, `CRYPTO_memcmp`, `OPENSSL_cleanse`.
   - **CẤM** API low-level/deprecated/đã gỡ: `RSA_new`, `RSA_generate_key_ex`, `RSA_public_encrypt`, `RSA_private_decrypt`, `RSA_padding_*`, `RSA_get0_*` để thao tác khóa, `EVP_PKEY_assign_RSA`, `EVP_PKEY_get0_RSA`, `AES_*`, `SHA256_*`, `HMAC_CTX_*` kiểu cũ, `EVP_CIPHER_CTX_init`, mọi hàm `ENGINE_*` (**engine đã bị gỡ hoàn toàn ở 4.0**), `EVP_PKEY_asn1_*`, `EVP_MD_CTX_get0_md_data`, `ERR_load_*_strings`, `ERR_remove_thread_state`, `X509_cmp_time` và họ hàng.
   - Không thao tác trực tiếp trên `ASN1_STRING` (đã opaque ở 4.0); không cần thiết cho lab này.
   - Định nghĩa `OPENSSL_NO_DEPRECATED` cho mọi target (xem §3) để trình biên dịch báo lỗi nếu lỡ dùng API deprecated.
   - **Không tự gọi `OPENSSL_cleanup()`** và không dựa vào `atexit` của OpenSSL (4.0 không còn dọn bằng `atexit`). Giải phóng đối tượng bằng RAII là đủ.
   - Nếu **không chắc** chữ ký/tên hàm trong OpenSSL 4.0: không đoán bừa; dùng API tương đương chắc chắn nhất (theo tài liệu `https://docs.openssl.org/4.0/`) và ghi mục đó vào `docs/COMPILE_RISKS.md`.
10. **Kiểm tra phiên bản lúc biên dịch**: trong `util.hpp` (hoặc `ossl_raii.hpp`) thêm
    ```cpp
    #include <openssl/opensslv.h>
    static_assert(OPENSSL_VERSION_MAJOR >= 4, "rsatool requires OpenSSL 4.x or newer");
    ```
11. **RAII bắt buộc** cho mọi đối tượng OpenSSL (xem §4.0): không có `*_free` gọi thủ công rải rác; không rò rỉ khi ném exception.

---

## 1. Tổng quan yêu cầu Lab 3

- Công cụ CLI tên **`rsatool`**: `keygen`, `encrypt`, `decrypt`.
- RSA-OAEP: modulus **≥ 3072 bit** (bắt buộc 3072; thêm 4096 để so sánh), hash **SHA-256**, MGF1 **SHA-256**, hỗ trợ **OAEP label** (`--label`).
- Giới hạn plaintext: `mLen ≤ k − 2·hLen − 2` (k = byte của modulus, hLen = 32).
  - RSA-3072: k = 384 → mLen tối đa **318** byte.
  - RSA-4096: k = 512 → mLen tối đa **446** byte.
- Vượt giới hạn → **tự động Hybrid (Envelope)**: sinh khóa AES-256 ngẫu nhiên → mã hóa dữ liệu bằng **AES-256-GCM (IV 96-bit, tag 128-bit)** → bọc khóa AES bằng RSA-OAEP(SHA-256) → xuất envelope.
- Unit test tự động (Catch2, chạy qua `ctest`), benchmark + thống kê (95% CI) + đồ thị, build bằng CMake out-of-source.
- Bonus A (+5): tự cài OAEP bằng tay (MGF1, XOR mask, unpad constant-time).
- Bonus B (+10): phân tích bảo mật mã hóa lai, TLS handshake, forward secrecy, lộ trình ECDHE / ML-KEM.

---

## 2. Cấu trúc thư mục BẮT BUỘC tạo

```
lab3-rsatool/
├── CMakeLists.txt
├── README.md                    # agent viết (xem §9)
├── AGENT.md                     # (file này)
├── RUN_GUIDE.md                 # đã có sẵn, KHÔNG ghi đè nội dung; chỉ sửa mục cài đặt thư viện (Crypto++ → OpenSSL 4.x) và nếu CLI/đường dẫn lệch
├── cmake/
│   └── FindDeps.cmake           # (tuỳ chọn) gom find_package / FetchContent
├── include/rsalab/
│   ├── errors.hpp
│   ├── ossl_raii.hpp            # unique_ptr + custom deleter cho EVP_PKEY, EVP_PKEY_CTX, EVP_CIPHER_CTX, EVP_MD_CTX, BIO, OSSL_ENCODER_CTX, OSSL_DECODER_CTX; SecureBuffer (OPENSSL_cleanse)
│   ├── encoding.hpp             # raw | hex | base64
│   ├── keyio.hpp                # PEM/DER/metadata
│   ├── rsa_oaep.hpp             # RSA-OAEP wrapper (thư viện)
│   ├── envelope.hpp             # container + header JSON + AAD
│   ├── hybrid.hpp               # encrypt/decrypt tổng (auto mode)
│   ├── oaep_manual.hpp          # Bonus A
│   └── util.hpp                 # đọc/ghi file, rng (RAND_bytes), constant-time helpers
├── src/
│   ├── main.cpp                 # CLI rsatool
│   ├── cli.cpp / cli.hpp        # parse tham số
│   ├── encoding.cpp
│   ├── keyio.cpp
│   ├── rsa_oaep.cpp
│   ├── envelope.cpp
│   ├── hybrid.cpp
│   ├── oaep_manual.cpp
│   └── util.cpp
├── tests/
│   ├── test_main_or_catch.cpp
│   ├── test_rsa_oaep.cpp
│   ├── test_keyio.cpp
│   ├── test_hybrid.cpp
│   ├── test_negative.cpp
│   └── test_oaep_manual.cpp     # Bonus A
├── bench/
│   └── bench_main.cpp           # executable rsabench
├── scripts/
│   ├── analyze_bench.py         # đọc CSV → thống kê + 95% CI + đồ thị
│   ├── tamper.py                # tạo file bị can thiệp cho negative test thủ công
│   └── make_testfiles.py        # tạo file 1KiB/1MiB/100MiB (dữ liệu giả, không cần bảo mật)
├── docs/
│   ├── COMPILE_RISKS.md
│   ├── DESIGN.md                # quyết định thiết kế, định dạng envelope, bảng ánh xạ API OpenSSL
│   └── BONUS_B_hybrid_analysis.md
├── report/
│   ├── REPORT_OUTLINE.md        # dàn ý + nội dung lý thuyết đã viết sẵn
│   └── figures/.gitkeep
└── results/
    └── .gitkeep                 # con người sẽ bỏ log/CSV/hình vào đây
```

> `make_testfiles.py` được phép dùng `os.urandom` (CSPRNG của Python). Không dùng module `random`.

---

## 3. CMake (`CMakeLists.txt`)

Yêu cầu:

- `cmake_minimum_required(VERSION 3.16)`, `project(rsatool LANGUAGES CXX)`, `CMAKE_CXX_STANDARD 17`, `CMAKE_CXX_STANDARD_REQUIRED ON`, `CMAKE_CXX_EXTENSIONS OFF`.
- Mặc định `CMAKE_BUILD_TYPE=Release` nếu generator đơn cấu hình và chưa đặt.
- Ngăn in-source build: `if(CMAKE_SOURCE_DIR STREQUAL CMAKE_BINARY_DIR) message(FATAL_ERROR ...)`.
- **Tìm OpenSSL 4.x**:
  1. `find_package(OpenSSL 4.0 REQUIRED COMPONENTS Crypto)` (cung cấp target `OpenSSL::Crypto`). Cho phép người dùng chỉ đường dẫn bằng `-DOPENSSL_ROOT_DIR=...` hoặc `-DCMAKE_PREFIX_PATH=...` (quan trọng vì OpenSSL 4.x thường **không** có sẵn trong `apt` của Ubuntu LTS — người dùng sẽ build/cài vào `/opt/openssl-4` hoặc dùng vcpkg).
  2. Sau khi tìm thấy: `message(STATUS "OpenSSL version: ${OPENSSL_VERSION}")`, `message(STATUS "OpenSSL include: ${OPENSSL_INCLUDE_DIR}")`, `message(STATUS "OpenSSL libs: ${OPENSSL_CRYPTO_LIBRARY}")`.
  3. Nếu `OPENSSL_VERSION VERSION_LESS 4.0` → `message(FATAL_ERROR "Cần OpenSSL >= 4.0 (tìm thấy ${OPENSSL_VERSION}). Truyền -DOPENSSL_ROOT_DIR=<đường dẫn OpenSSL 4.x>. Xem RUN_GUIDE.md.")`.
  4. Tạo target `INTERFACE` alias `rsalab::openssl`: `target_link_libraries(... INTERFACE OpenSSL::Crypto)` và `target_compile_definitions(... INTERFACE OPENSSL_NO_DEPRECATED)`. Phần còn lại của dự án chỉ link `rsalab::openssl`.
  5. Tuỳ chọn `option(OPENSSL_USE_STATIC_LIBS "Link OpenSSL tĩnh" OFF)` (đặt `set(OPENSSL_USE_STATIC_LIBS TRUE)` **trước** `find_package` nếu bật). Với static: `if(WIN32)` thêm `ws2_32 crypt32 user32 advapi32`; Linux thêm `${CMAKE_DL_LIBS}` và `Threads::Threads` (`find_package(Threads REQUIRED)`).
  6. Linux khi OpenSSL cài ngoài đường dẫn hệ thống: bật `set(CMAKE_BUILD_RPATH_USE_ORIGIN ON)` và `set(CMAKE_INSTALL_RPATH_USE_LINK_PATH ON)` để chạy được mà không cần `LD_LIBRARY_PATH`; ghi chú trong README.
- `nlohmann_json`: `find_package(nlohmann_json CONFIG QUIET)`; nếu không có → `FetchContent` (v3.11.3).
- `Catch2 v3`: `find_package(Catch2 3 QUIET)`; nếu không có → `FetchContent` (v3.5.x). Dùng `catch_discover_tests` hoặc `add_test`.
- Target:
  - `rsa_core` (STATIC): toàn bộ `src/*.cpp` trừ `main.cpp`; link `rsalab::openssl`, `nlohmann_json::nlohmann_json`.
  - `rsatool` (EXECUTABLE): `src/main.cpp` + link `rsa_core`.
  - `rsabench` (EXECUTABLE): `bench/bench_main.cpp`.
  - `rsa_tests` (EXECUTABLE): `tests/*.cpp`; `enable_testing()` + `add_test`.
- Bật cảnh báo: MSVC `/W4 /permissive-`; GCC/Clang `-Wall -Wextra -Wpedantic`.
- MSVC: `/EHsc`, định nghĩa `_CRT_SECURE_NO_WARNINGS`; đảm bảo **cùng kiểu runtime (MD/MT)** với bản OpenSSL được cài (OpenSSL 4.0 cho phép chọn runtime VC tĩnh/động khi build) — ghi chú trong README. Nếu link OpenSSL động trên Windows, DLL (`libcrypto-4-x64.dll` hoặc tên tương ứng) phải nằm trong `PATH` hoặc cạnh file `.exe` — ghi chú trong README/RUN_GUIDE, có thể thêm bước `add_custom_command(POST_BUILD ...)` copy DLL (chỉ khi `WIN32` và tìm được DLL).
- MinGW: link `-lws2_32 -lcrypt32` khi dùng OpenSSL tĩnh (dùng `if(MINGW)`).
- Output executable vào `${CMAKE_BINARY_DIR}/bin` (đặt `RUNTIME_OUTPUT_DIRECTORY`, và biến thể per-config cho MSVC).

---

## 4. Đặc tả kỹ thuật chi tiết

### 4.0. Quy ước OpenSSL chung (áp dụng cho mọi module)

- **RAII** (`ossl_raii.hpp`): định nghĩa các alias, ví dụ
  `using PkeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;`, tương tự cho `EVP_PKEY_CTX`, `EVP_CIPHER_CTX`, `EVP_MD_CTX`, `BIO` (`BIO_free_all`), `OSSL_ENCODER_CTX`, `OSSL_DECODER_CTX`, `EVP_CIPHER` / `EVP_MD` (khi dùng `*_fetch`, free bằng `EVP_CIPHER_free` / `EVP_MD_free`).
- **Kiểm tra mọi giá trị trả về**: hầu hết hàm OpenSSL trả `1` khi thành công, `0` hoặc `<0` khi lỗi; con trỏ `NULL` khi lỗi. Lỗi → ném `CryptoFailure`/`IoError` đúng nhóm (§5).
- **Hàng đợi lỗi OpenSSL**: gọi `ERR_clear_error()` ở đầu mỗi hàm công khai và ngay trước khi ném `CryptoFailure`, để lỗi cũ không "dính" sang thao tác sau. **Không** in `ERR_error_string_n` / `ERR_reason_error_string` ra người dùng ở đường giải mã (§5). Ở các đường khác chỉ in khi có `--verbose`.
- **Độ dài `int`**: nhiều hàm OpenSSL (`EVP_EncryptUpdate`, `EVP_DecryptUpdate`, …) nhận độ dài kiểu `int`. Xử lý dữ liệu lớn theo **khối (vd. 1 MiB)** trong vòng lặp; kiểm tra tràn khi ép `size_t → int`.
- **Zeroize**: dùng `OPENSSL_cleanse(ptr, len)` cho khóa AES, plaintext tạm, khóa private đã nạp ra buffer. Cung cấp `SecureBuffer` (RAII, `std::vector<unsigned char>` hoặc tương đương; destructor gọi `OPENSSL_cleanse`). Lưu ý `std::vector` có thể realloc làm sót bản sao — `reserve` đúng kích thước từ đầu.
- **So sánh bí mật**: dùng `CRYPTO_memcmp` (constant-time), **không** dùng `memcmp`/`==` cho dữ liệu liên quan tới bí mật.
- **Hash/Cipher**: ưu tiên `EVP_MD_fetch(nullptr, "SHA2-256", nullptr)` / `EVP_CIPHER_fetch(nullptr, "AES-256-GCM", nullptr)` và **cache** đối tượng đã fetch (không fetch lại trong vòng lặp benchmark). Dùng `EVP_sha256()` cũng được (không deprecated) nhưng phải nhất quán một kiểu trong toàn dự án.
- **Bảng ánh xạ Crypto++ → OpenSSL** (đưa vào `docs/DESIGN.md` mục "Ánh xạ API"):

| Crypto++ (bản cũ) | OpenSSL 4.x (bản mới) |
|---|---|
| `AutoSeededRandomPool` | `RAND_bytes` / `RAND_priv_bytes` |
| `RSAES<OAEP<SHA256>>::Encryptor/Decryptor` | `EVP_PKEY_CTX` + `EVP_PKEY_encrypt` / `EVP_PKEY_decrypt` với `RSA_PKCS1_OAEP_PADDING` |
| `Name::EncodingParameters` (label) | `EVP_PKEY_CTX_set0_rsa_oaep_label` |
| `InvertibleRSAFunction::GenerateRandomWithKeySize` | `EVP_PKEY_Q_keygen(nullptr, nullptr, "RSA", bits)` hoặc `EVP_PKEY_keygen` + `EVP_PKEY_CTX_set_rsa_keygen_bits` |
| `X509PublicKey::Save` / `PKCS8PrivateKey::Save` | `OSSL_ENCODER_*` (`SubjectPublicKeyInfo` / `PrivateKeyInfo`, `PEM`/`DER`) |
| `Base64Encoder`, `HexEncoder` | `EVP_EncodeBlock`/`EVP_DecodeBlock` (base64), hex tự viết |
| `GCM<AES>` + `AuthenticatedEncryptionFilter` | `EVP_CIPHER_CTX` + `EVP_aes_256_gcm` / `"AES-256-GCM"` |
| `SecByteBlock` | `SecureBuffer` + `OPENSSL_cleanse` |
| `VerifyBufsEqual` | `CRYPTO_memcmp` |
| `StringSource/StringSink` | `std::vector<unsigned char>` / `std::string` |
| `Integer` / `ModularExponentiation` (Bonus A) | `EVP_PKEY_encrypt/decrypt` với `RSA_NO_PADDING` (hoặc `BN_mod_exp_mont_consttime`) |
| `SHA256` | `EVP_MD_CTX` / `EVP_Digest` với `SHA2-256` |

### 4.1. `rsa_oaep` (lõi RSA-OAEP)

- Dùng **EVP high-level**: `EVP_PKEY_CTX_new(pkey, nullptr)` (hoặc `EVP_PKEY_CTX_new_from_pkey(nullptr, pkey, nullptr)`) → `EVP_PKEY_encrypt_init` / `EVP_PKEY_decrypt_init`, rồi theo **đúng thứ tự**:
  1. `EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING)`
  2. `EVP_PKEY_CTX_set_rsa_oaep_md(ctx, sha256)`
  3. `EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, sha256)` — **đặt tường minh** MGF1 = SHA-256 (không dựa vào mặc định; ghi chú rõ trong code).
  4. (nếu label không rỗng) `EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, buf, len)`.
  5. Gọi `EVP_PKEY_encrypt(ctx, nullptr, &outlen, in, inlen)` để lấy độ dài, rồi gọi lần hai để mã hóa; tương tự `EVP_PKEY_decrypt`.
- **Label**: `EVP_PKEY_CTX_set0_rsa_oaep_label` **nhận quyền sở hữu** vùng nhớ: buffer phải cấp bằng `OPENSSL_malloc` (copy từ label gốc); khi hàm thành công thì **không** được `OPENSSL_free` nữa; khi hàm thất bại thì **phải** tự `OPENSSL_free`. Viết helper riêng để xử lý đúng việc này. Label rỗng = **không gọi** hàm set label (khớp chuẩn: L = chuỗi rỗng). Cả encrypt và decrypt phải dùng cùng label.
- Hàm cần có:
  - `size_t max_plaintext_len(unsigned modulus_bits)` = `k - 2*32 - 2` với `k = (modulus_bits + 7) / 8`.
  - `ByteVec oaep_encrypt(const PublicKey&, ByteView msg, ByteView label)` — ném lỗi nếu `msg.size() > max`. (RNG do OpenSSL lấy nội bộ từ DRBG mặc định; không cần truyền RNG.)
  - `ByteVec oaep_decrypt(const PrivateKey&, ByteView ct, ByteView label)` — ném `CryptoFailure` (generic) khi lỗi; **không** phân biệt nguyên nhân. Kiểm tra `ct.size() == k` trước, sai → cùng lỗi generic.
- `PublicKey`/`PrivateKey` ở `keyio.hpp` có thể là wrapper mỏng quanh `PkeyPtr` (`EVP_PKEY*`). Dùng `EVP_PKEY_get_bits` / `EVP_PKEY_get_size` để lấy độ dài; kiểm tra `EVP_PKEY_is_a(pkey, "RSA")`.
- Chia sẻ `EVP_PKEY_CTX` giữa các luồng là **không an toàn**; tạo ctx mới cho mỗi lần gọi (hoặc `thread_local`).

### 4.2. Quản lý khóa (`keyio`)

`rsatool keygen --bits 3072 --pub pub.pem --priv priv.pem` phải xuất **tất cả**:

| File | Nội dung |
|---|---|
| `pub.pem` | Public key, **SPKI** (`-----BEGIN PUBLIC KEY-----`) |
| `priv.pem` | Private key, **PKCS#8** (`-----BEGIN PRIVATE KEY-----`) |
| `pub.der`, `priv.der` | Cùng khóa ở dạng DER (suy ra từ đường dẫn: đổi đuôi `.pem`→`.der`; nếu đường dẫn không có đuôi `.pem` thì thêm `.der`) |
| `<tên priv không đuôi>.meta.json` | Metadata (xem dưới) |

- Metadata đúng schema:
  ```json
  {
    "creation_time": "YYYY-MM-DDTHH:MM:SSZ",
    "modulus_bits": 3072,
    "hash": "SHA-256"
  }
  ```
  `creation_time` là UTC, định dạng ISO-8601 kết thúc `Z` (dùng `std::gmtime`/`gmtime_s` theo nền tảng, hoặc `std::chrono` + tự format). Có thể ghi thêm `public_exponent: 65537`, **không** bắt buộc; nếu thêm, không làm hỏng 3 trường chuẩn.
- **Sinh khóa**: `EVP_PKEY_Q_keygen(nullptr, nullptr, "RSA", (size_t)bits)` (mặc định e = 65537), hoặc `EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr)` → `EVP_PKEY_keygen_init` → `EVP_PKEY_CTX_set_rsa_keygen_bits` → `EVP_PKEY_keygen`. **Không** dùng `RSA_generate_key_ex`.
- **PEM/DER do OpenSSL xử lý** (không cần tự viết PEM): dùng **`OSSL_ENCODER`** để ghi và **`OSSL_DECODER`** để đọc (header `<openssl/encoder.h>`, `<openssl/decoder.h>`):
  - Public: `OSSL_ENCODER_CTX_new_for_pkey(pkey, EVP_PKEY_PUBLIC_KEY, "PEM" | "DER", "SubjectPublicKeyInfo", nullptr)` → `OSSL_ENCODER_to_bio`.
  - Private: `OSSL_ENCODER_CTX_new_for_pkey(pkey, EVP_PKEY_KEYPAIR, "PEM" | "DER", "PrivateKeyInfo", nullptr)` — **không đặt cipher/passphrase** (khóa không mã hóa, đúng yêu cầu lab; ghi cảnh báo trong README).
  - Đọc: `OSSL_DECODER_CTX_new_for_pkey(&pkey, "PEM" | "DER", "SubjectPublicKeyInfo" | "PrivateKeyInfo", "RSA", selection, nullptr, nullptr)` → `OSSL_DECODER_from_bio`. Việc ràng buộc `structure` giúp **từ chối file sai loại** (đưa PUBLIC key vào `--priv`, hoặc PKCS#1 `RSA PRIVATE KEY` khi yêu cầu PKCS#8) → lỗi `IoError`/mã 2.
  - Phương án dự phòng nếu `OSSL_ENCODER/DECODER` gây khó: `PEM_write_bio_PUBKEY` / `PEM_read_bio_PUBKEY` / `i2d_PUBKEY_bio` / `d2i_PUBKEY_bio` cho public; `PEM_write_bio_PKCS8PrivateKey(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr)` / `i2d_PKCS8PrivateKey_bio` / `PEM_read_bio_PrivateKey` / `d2i_PKCS8PrivateKey_bio` cho private. Phải kiểm chứng thực tế header PEM là `PRIVATE KEY` (PKCS#8) và ghi vào `docs/COMPILE_RISKS.md`.
  - Nạp từ file vào memory rồi dùng `BIO_new_mem_buf` (có thể dùng `BIO_new_mem_buf` với dữ liệu đã đọc bằng `std::ifstream` binary để thống nhất I/O). Parser phải chịu được `\r\n` và khoảng trắng thừa (OpenSSL PEM reader đã xử lý; thêm test).
  - Cần load được cả DER lẫn PEM: `--pub x.der` / `--priv x.der` **tự nhận theo nội dung** (PEM bắt đầu bằng `-----BEGIN`; DER bắt đầu bằng byte `0x30`), không chỉ dựa vào đuôi file.
- **Kiểm tra sau khi nạp khóa**: `EVP_PKEY_is_a(pkey, "RSA")`; `EVP_PKEY_get_bits(pkey) >= 3072` (khi dùng cho encrypt/decrypt thực tế); lấy `e` bằng `EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, &bn)` và cảnh báo/từ chối nếu `e != 65537`; với khóa private có thể gọi thêm `EVP_PKEY_private_check` (nếu khả dụng) — lỗi → `IoError`.
- Public exponent **e = 65537**. Kiểm tra `bits ≥ 3072` khi keygen (từ chối <3072 với mã lỗi usage, trừ cờ ẩn `--allow-weak-for-test` chỉ dùng trong unit test, không công bố trong help).
- Linux: sau khi ghi `priv.pem`/`priv.der` → `chmod 0600` (`std::filesystem::permissions`). Windows: bỏ qua.
- Ghi file **atomically** (ghi `.tmp` rồi rename) để không để lại file nửa vời. Buffer chứa private key DER/PEM tạm trong RAM phải `OPENSSL_cleanse` sau khi ghi.

### 4.3. Mã hóa / Giải mã

CLI:

```
rsatool encrypt --in msg.bin --pub pub.pem --out ct.bin [--label TEXT] [--encode raw|hex|base64] [--force-hybrid] [--impl lib|manual]
rsatool decrypt --in ct.bin --priv priv.pem --out msg.bin [--label TEXT] [--encode raw|hex|base64] [--impl lib|manual]
```

- `--label` là chuỗi UTF-8 bất kỳ (nhận cả `--label-hex` tuỳ chọn). Mặc định rỗng. **Decrypt phải truyền đúng label** (label không lưu trong file vì là tham số ngữ cảnh).
- `--encode` quy định định dạng **file ciphertext** (encrypt: ghi ra; decrypt: đọc vào). Mặc định `raw`. Với `base64`/`hex`, bỏ qua whitespace khi đọc.
  - Base64: ghi bằng `EVP_EncodeBlock` (không xuống dòng); đọc: loại whitespace → kiểm tra bộ ký tự hợp lệ và độ dài chia hết cho 4 → `EVP_DecodeBlock` → **trừ số byte `=` đệm** khỏi độ dài trả về (vì `EVP_DecodeBlock` không tự trừ) → trả `-1` thì lỗi. Với base64 trong header JSON, **từ chối** ký tự xuống dòng/whitespace và padding sai.
  - Hex: tự viết hàm encode/decode (chữ thường khi ghi, chấp nhận hoa/thường khi đọc, từ chối ký tự lạ/độ dài lẻ).
- Auto mode: `size(msg) ≤ max_plaintext_len` → **Direct**; ngược lại → **Hybrid**. `--force-hybrid` ép Hybrid (dùng cho benchmark/test).
- **Cả hai mode dùng chung container** để `decrypt` tự nhận diện, không phải đoán:

```
+--------+---------+----------------+------------------+-----------------+
| "RSAE" | ver=0x01| header_len u32 | header JSON      | payload bytes   |
| 4 byte | 1 byte  | big-endian     | (UTF-8, ≤ 64KiB)  | (xem dưới)      |
+--------+---------+----------------+------------------+-----------------+
```

  - Direct: `header.mode = "RSA-OAEP"`, payload = RSA ciphertext (đúng k byte).
  - Hybrid: `header.mode = "RSA-OAEP-AES-GCM"`, payload = AES-256-GCM ciphertext (không gồm tag; tag nằm ở header).
- Header Hybrid **đúng các trường** của đề (thứ tự key cố định khi serialize):

```json
{
  "mode": "RSA-OAEP-AES-GCM",
  "rsa_modulus": 3072,
  "hash": "SHA-256",
  "wrapped_key": "<base64 của RSA-OAEP(AES key 32 byte)>",
  "iv": "<base64 của 12 byte>",
  "tag": "<base64 của 16 byte>"
}
```

  Header Direct: `{"mode":"RSA-OAEP","rsa_modulus":3072,"hash":"SHA-256"}`.
- **AES-256-GCM** (EVP): key 32 byte và IV **12 byte** đều sinh bằng `RAND_priv_bytes`/`RAND_bytes`; tag 16 byte. Quy trình:
  - Mã hóa: `EVP_EncryptInit_ex2(ctx, cipher, nullptr, nullptr, nullptr)` → đặt độ dài IV = 12 (`EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr)` hoặc qua `OSSL_PARAM` `OSSL_CIPHER_PARAM_AEAD_IVLEN`) → `EVP_EncryptInit_ex2(ctx, nullptr, key, iv, nullptr)` → **AAD**: `EVP_EncryptUpdate(ctx, nullptr, &len, aad, aad_len)` → dữ liệu: `EVP_EncryptUpdate` theo khối → `EVP_EncryptFinal_ex` → lấy tag: `EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag)`.
  - Giải mã: tương tự, nhưng **đặt tag trước `Final`**: `EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag)` → AAD → `EVP_DecryptUpdate` → `EVP_DecryptFinal_ex`; **chỉ khi `Final` trả > 0 mới coi là xác thực thành công**.
  - Cảnh báo: `EVP_DecryptUpdate` **đã xuất plaintext trước khi tag được xác minh** → plaintext chỉ được ghi vào bộ đệm RAM; không được dùng/ghi ra file/in ra cho tới khi `Final` thành công.
- **AAD (ràng buộc header vào GCM)** để sửa header → xác thực thất bại. AAD = chuỗi byte ASCII:
  `"RSAE-AAD-v1|" + mode + "|" + rsa_modulus + "|" + hash + "|" + wrapped_key_b64 + "|" + iv_b64`
  (không gồm `tag`). Ghi rõ công thức này trong `docs/DESIGN.md`.
- **Giải mã Hybrid — thứ tự bắt buộc**:
  1. Parse container nghiêm ngặt: magic, version, `header_len ≤ 65536`, JSON hợp lệ, chỉ chấp nhận `mode` trong danh sách cho phép, `hash == "SHA-256"`, `rsa_modulus` **khớp** bit-size khóa private, `iv` giải base64 đúng 12 byte, `tag` đúng 16 byte, `wrapped_key` đúng k byte. Sai bất kỳ → lỗi generic.
  2. RSA-OAEP unwrap khóa AES (label truyền vào), kiểm tra kết quả đúng 32 byte. Sai → lỗi generic (**cùng thông báo & cùng mã thoát** với mọi lỗi khác).
  3. AES-GCM giải mã có xác thực **vào bộ đệm trong RAM** (`SecureBuffer`). Chỉ khi `EVP_DecryptFinal_ex` thành công mới ghi ra file output (ghi atomically). Thất bại → **không tạo/không để lại** file output; xóa sạch bộ đệm bằng `OPENSSL_cleanse`.
  4. Tuyệt đối **không tự so sánh tag bằng `memcmp`/`==`**; để OpenSSL GCM xác thực trong `EVP_DecryptFinal_ex` (nếu cần so sánh bí mật khác, dùng `CRYPTO_memcmp`).
- Xử lý dữ liệu lớn: 100 MiB đọc cả vào RAM là chấp nhận được; nhưng cấp phát đúng kích thước một lần (`reserve`/`resize`), xử lý theo khối 1 MiB vì tham số độ dài là `int`, tránh copy thừa.
- Zeroize khóa AES, plaintext tạm sau khi dùng (`OPENSSL_cleanse`).
- `--impl manual` (Bonus A) chỉ áp dụng cho **bước RSA-OAEP** (Direct và wrap khóa Hybrid); phần AES-GCM luôn dùng EVP.

### 4.4. Mã lỗi & thông điệp (xem §5)

---

## 5. Xử lý lỗi an toàn (Fail-closed, không rò rỉ)

- Định nghĩa `rsalab::UsageError`, `rsalab::IoError`, `rsalab::CryptoFailure`.
- Mã thoát: `0` OK · `1` sai tham số · `2` lỗi I/O/khóa không đọc được · `3` giải mã/xác thực thất bại.
- **Mọi** lỗi crypto khi giải mã (OAEP sai, sai label, sai khóa, tag sai, header sai, base64 hỏng, độ dài sai…) → in **đúng một** thông báo: `Error: decryption failed.` (stderr) + exit 3. **Không** nêu "padding sai", "tag sai", "label sai", không in độ dài, **không in nội dung hàng đợi lỗi OpenSSL** (`ERR_error_string*`, `ERR_print_errors*`) hay exception chi tiết của thư viện. Luôn `ERR_clear_error()` trước khi trả lỗi.
- Encrypt/keygen: lỗi `msg quá lớn` không xảy ra ở auto mode; lỗi I/O thì mô tả rõ (không nhạy cảm). Lỗi OpenSSL ở các đường này chỉ in chuỗi chung (`Error: cryptographic operation failed.`); chi tiết `ERR_*` chỉ in khi có `--verbose`.
- Không log key, plaintext, label, IV ở chế độ mặc định. Cờ `--verbose` chỉ in kích thước file, mode đã chọn (Direct/Hybrid) và phiên bản OpenSSL (`OpenSSL_version(OPENSSL_VERSION)`) — được phép.
- Giải mã Direct và Hybrid khi lỗi RSA unwrap: thời gian xử lý nên gần như nhau (không return sớm lộ nhánh quá khác biệt; ghi rõ giới hạn trong DESIGN.md — thời gian của thư viện nằm ngoài kiểm soát). Ghi chú thêm: OpenSSL triển khai giải mã OAEP với xử lý lỗi không phân biệt nguyên nhân ở mức API (`EVP_PKEY_decrypt` chỉ trả thất bại chung), nhưng không nên coi đây là bảo đảm constant-time tuyệt đối.

---

## 6. Unit tests (Catch2 v3, chạy qua `ctest`)

Dùng khóa **RSA-3072 sinh một lần/test-suite** (static fixture) vì sinh khóa chậm; dùng RNG an toàn (`RAND_bytes`). Các test bắt buộc:

**Đúng đắn (`test_rsa_oaep`, `test_hybrid`, `test_keyio`)**
- Round-trip Direct: msg rỗng, 1 byte, đúng `mLen_max` (318 với 3072), vẫn Direct.
- `mLen_max + 1` → auto chuyển Hybrid, round-trip đúng.
- Hybrid: 1 KiB, 1 MiB (100 MiB **không** đưa vào unit test; để cho benchmark).
- Cả RSA-3072 và RSA-4096 (4096 test có thể đánh dấu tag `[slow]`; vẫn chạy mặc định).
- Label khớp → OK; label rỗng ↔ rỗng → OK.
- `max_plaintext_len(3072)==318`, `max_plaintext_len(4096)==446`.
- Keyio: save PEM → load PEM khớp; save DER → load DER khớp; PEM↔DER cho cùng khóa; metadata đủ 3 trường đúng kiểu, `creation_time` khớp regex `^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$`; `modulus_bits==3072`; `hash=="SHA-256"`; từ chối `bits<3072`; file `pub.pem` bắt đầu bằng `-----BEGIN PUBLIC KEY-----`, `priv.pem` bắt đầu bằng `-----BEGIN PRIVATE KEY-----`; dùng file public làm `--priv` (và ngược lại) → bị từ chối; PEM có `\r\n` vẫn đọc được.
- Encoding: raw/hex/base64 round-trip (gồm trường hợp độ dài chia 3 dư 0/1/2 để kiểm tra padding `=`).
- Hai lần encrypt cùng plaintext → ciphertext **khác nhau** (OAEP/GCM ngẫu nhiên hóa); hai envelope có IV khác nhau, wrapped_key khác nhau.
- Kiểm tra phiên bản: test `OpenSSL_version_num()` / `OPENSSL_VERSION_MAJOR >= 4`.

**Tiêu cực / Fail-closed (`test_negative`)** — mỗi test kiểm tra: ném `CryptoFailure` (hoặc trả mã 3), thông điệp **đúng bằng** `"decryption failed"` (không rò rỉ), và **file output không tồn tại / plaintext rỗng**:
1. Lật 1 bit trong RSA ciphertext (Direct) → thất bại.
2. Lật 1 bit trong payload AES-GCM (Hybrid) → thất bại (lỗi xác thực tag).
3. Lật 1 bit trong `tag` → thất bại.
4. Giải mã bằng **private key khác** → thất bại (cả Direct và Hybrid).
5. Giải mã với **label sai** (và label thiếu) → thất bại (cả Direct và Hybrid).
6. Sửa header JSON: đổi `iv`, đổi `wrapped_key`, đổi `rsa_modulus`, đổi `mode`, thêm khoảng trắng/field lạ, `header_len` giả → thất bại.
7. Cắt cụt envelope (thiếu payload/tag), thêm byte thừa vào cuối → thất bại.
8. Magic/version sai → thất bại.
9. Test thông điệp lỗi: chuỗi lỗi không chứa các từ `padding`, `tag`, `label`, `OAEP`, `mac`, **và không chứa chuỗi đặc trưng của OpenSSL** như `error:`, `routines`, `evp`, `rsa_` (kiểm tra bằng so sánh với chuỗi generic cố định).
10. Hàng đợi lỗi OpenSSL không "rò" sang thao tác kế tiếp: sau một lần giải mã thất bại, một lần giải mã đúng ngay sau đó vẫn thành công (`ERR_clear_error` hoạt động đúng).

**Bonus A (`test_oaep_manual`)**: cross-check — `manual_encrypt` ↔ `library_decrypt` và `library_encrypt` ↔ `manual_decrypt` đều round-trip; kèm test lỗi (sai label, lật bit) → cùng một lỗi generic.

---

## 7. Benchmark (`bench/bench_main.cpp` → `rsabench`)

CLI: `rsabench --out results/bench_raw.csv [--reps-keygen N] [--reps-rsa N] [--reps-aes N] [--quick] [--env-out results/bench_env.txt]`

- Đồng hồ: `std::chrono::steady_clock`, đơn vị **micro/nano giây**; **warm-up** ≥ 3 lần bỏ ra ngoài; chống tối ưu hóa bỏ code (dùng kết quả: cộng vào biến `volatile`/in checksum).
- **Tách chi phí khởi tạo ra khỏi vùng đo** khi phù hợp: `EVP_MD_fetch`/`EVP_CIPHER_fetch` và nạp khóa thực hiện **một lần ngoài vòng lặp**; chỉ đo phép toán cần đo (ghi rõ trong README phần nào nằm trong/ngoài vùng đo, vd. `EVP_PKEY_CTX_new` + `*_init` có tính vào RSA encrypt/decrypt hay không — chọn một cách và nhất quán).
- Mặc định: keygen 3072 & 4096 mỗi cái **N=20** lần (keygen chậm, có `--quick` giảm xuống 3); RSA-OAEP encrypt/decrypt (plaintext 32 byte, label rỗng) mỗi key size **N=200**; AES-GCM throughput trên 1 KiB / 1 MiB / 100 MiB, mỗi cỡ **N=30 / 30 / 10**; **Hybrid tổng** (sinh khóa AES + GCM + RSA wrap) trên 3 cỡ đó cho **cả RSA-3072 và RSA-4096**, cùng số lần như trên.
- Đo **từng mẫu riêng lẻ** (không chỉ trung bình). Ghi CSV dạng "long":
  `timestamp_utc,suite,op,rsa_bits,size_bytes,rep,time_ns,throughput_mib_s`
  - `suite ∈ {rsa, aesgcm, hybrid}`; `op ∈ {keygen, encrypt, decrypt}`; `throughput_mib_s` chỉ cho `aesgcm`/`hybrid` (**dùng MiB/s** = 2^20 byte/s; ghi chú trong README).
- In ra stdout thông tin môi trường: **phiên bản OpenSSL** (`OpenSSL_version(OPENSSL_VERSION)`, `OPENSSL_VERSION_STR` nếu có), **thông tin CPU/tăng tốc phần cứng** (`OpenSSL_version(OPENSSL_CPU_INFO)` — trên x86 cho biết `OPENSSL_ia32cap`; AES-NI/PCLMULQDQ được OpenSSL tự dùng nếu CPU hỗ trợ), OS, compiler, loại build, tên provider mặc định — con người sẽ copy vào báo cáo. Ghi cả thông tin này vào `results/bench_env.txt` (tham số `--env-out`).
- Dữ liệu test cho AES: buffer sinh bằng `RAND_bytes` (hoặc đệm byte cố định — throughput AES không phụ thuộc nội dung).
- **Không** hardcode kết quả.

### `scripts/analyze_bench.py`

- Đọc `results/bench_raw.csv`, dùng `pandas`, `numpy`, `scipy.stats` (t-interval), `matplotlib`.
- Với mỗi nhóm: n, mean, std, median, min, max, **khoảng tin cậy 95%** (`t.interval(0.95, n-1, loc=mean, scale=sem)`).
- Xuất: `results/bench_summary.csv`, `results/bench_summary.md` (bảng Markdown dán thẳng vào báo cáo).
- Đồ thị (PNG 200 dpi + SVG, vào `report/figures/`), **có error bar = 95% CI**, trục có đơn vị, tiêu đề, chú thích:
  1. `latency_rsa_keygen.png` — keygen 3072 vs 4096 (log-scale nếu cần).
  2. `latency_rsa_encdec.png` — encrypt vs decrypt, 3072 vs 4096 (nhóm cột).
  3. `throughput_aesgcm.png` — MiB/s theo cỡ dữ liệu.
  4. `latency_hybrid_total.png` — tổng thời gian hybrid theo 1 KiB / 1 MiB / 100 MiB (log-log), 3072 vs 4096.
  5. (tuỳ chọn) so sánh "RSA thuần chia khối" vs Hybrid mô phỏng bằng ngoại suy từ latency RSA — chỉ làm nếu ghi rõ là ước lượng.
- Có `argparse` và thông báo lỗi rõ ràng nếu thiếu cột/thư viện.

### `scripts/tamper.py`

CLI: `python scripts/tamper.py --in ct.bin --out ct_bad.bin --mode {flip-payload,flip-tag,flip-wrapped-key,flip-header-iv,change-modulus,truncate,flip-direct}`
- Parse container (magic/version/header_len/JSON/payload) rồi sửa đúng chỗ (lật 1 bit bằng chỉ số cố định, sửa JSON rồi **giữ nguyên** header_len đã cập nhật đúng). Chỉ làm việc với file `--encode raw`.

### `scripts/make_testfiles.py`

Tạo `testdata/msg_small.bin` (100 B), `msg_edge318.bin` (318 B), `msg_edge319.bin` (319 B), `msg_1KiB.bin`, `msg_1MiB.bin`, `msg_100MiB.bin` bằng `os.urandom` (ghi theo khối 1 MiB để khỏi tốn RAM). Thêm `testdata/` vào `.gitignore`.

---

## 8. Bonus

### Bonus A — OAEP thủ công (`oaep_manual.hpp/.cpp`) (+5)

- Tự cài (chỉ dùng SHA-256 của OpenSSL qua `EVP_Digest`/`EVP_MD_CTX` và phép RSA **thô** — **không** dùng `RSA_PKCS1_OAEP_PADDING` bên trong):
  - `mgf1_sha256(seed, maskLen)` — tự cài MGF1 (`T = Hash(seed || I2OSP(counter,4))` nối lại, cắt đủ `maskLen`), không dùng `PKCS1_MGF1` (API low-level).
  - EME-OAEP-ENCODE: `DB = lHash || PS || 0x01 || M`; `seed` ngẫu nhiên 32 byte (`RAND_bytes`); `maskedDB = DB ⊕ MGF1(seed)`; `maskedSeed = seed ⊕ MGF1(maskedDB)`; `EM = 0x00 || maskedSeed || maskedDB`.
  - RSA thô: `c = EM^e mod n` / `EM = c^d mod n` bằng `EVP_PKEY_CTX` với `EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_NO_PADDING)` + `EVP_PKEY_encrypt` / `EVP_PKEY_decrypt` (đầu vào phải đúng k byte; OAEP encode đã đảm bảo EM < n vì byte đầu = 0x00). Hoặc phương án `BN_mod_exp_mont_consttime` với `BIGNUM` (`BN_bin2bn`/`BN_bn2binpad`) — ưu tiên phương án EVP để giữ blinding của OpenSSL.
  - EME-OAEP-DECODE **constant-time**: không `return` sớm; gom các cờ lỗi (`Y != 0`, `lHash' != lHash`, không tìm thấy `0x01`, …) bằng phép bit-mask (`mask = (x - 1) >> 63`, hàm `ct_select`, `ct_is_zero`, `ct_eq`), quét **toàn bộ** DB với độ dài cố định để tìm vị trí `0x01` không phân nhánh theo dữ liệu, rồi trả về một kết quả duy nhất (thành công/thất bại) ở cuối. So sánh `lHash` bằng `CRYPTO_memcmp`. Dùng `volatile`/`std::atomic_signal_fence` hoặc kỹ thuật tương đương để giảm rủi ro compiler tối ưu hoá phá constant-time; ghi chú giới hạn (các hàm constant-time nội bộ của OpenSSL không phải API công khai nên tự viết helper; bản thân phép RSA thô của thư viện không đảm bảo constant-time tuyệt đối). Buffer trung gian (`EM`, `DB`, `seed`) phải `OPENSSL_cleanse`.
- Thêm tuỳ chọn CLI `--impl lib|manual` (mặc định `lib`) cho `encrypt`/`decrypt` để minh hoạ.
- Trong `report/REPORT_OUTLINE.md`: giải thích **vì sao decode phải constant-time** (tấn công **Manger**: oracle phân biệt lỗi "byte đầu ≠ 0x00" với lỗi khác → khôi phục plaintext từng bit/byte; nên mọi lỗi phải không phân biệt được cả về thông điệp lẫn thời gian).

### Bonus B — Phân tích bảo mật lai (`docs/BONUS_B_hybrid_analysis.md`) (+10)

Viết đầy đủ (có thể dùng làm chương báo cáo, tiếng Việt, có công thức & sơ đồ ASCII/Mermaid), gồm:
1. So sánh Envelope vs RSA trực tiếp: giới hạn kích thước, hiệu năng, tính ngẫu nhiên hóa, xác thực toàn vẹn (GCM) mà RSA-OAEP đơn thuần không cung cấp cho file, rủi ro tái sử dụng khóa/IV (nonce reuse trong GCM là thảm họa → mỗi lần mã hóa sinh khóa AES mới nên an toàn).
2. TLS handshake như một thiết kế lai: (a) TLS 1.2 RSA key-exchange (pre-master secret bọc bằng RSA) vs (b) ECDHE; vai trò KDF (HKDF), AEAD (AES-GCM/ChaCha20-Poly1305), chứng chỉ & chữ ký xác thực.
3. **Forward secrecy**: vì sao RSA key transport thuần **không** có FS (lộ `d` ⇒ giải mã mọi phiên ghi lại — "harvest now, decrypt later"); ECDHE ephemeral khắc phục thế nào.
4. Lộ trình nâng cấp: ECDHE (X25519/P-256) + HKDF + AEAD; sau đó **ML-KEM** (FIPS 203) lai X25519+ML-KEM (hybrid KEM) — nối sang Lab 6; liệt kê thay đổi cần làm trong `rsatool` (KEM/DEM API, versioning container). Có thể nêu OpenSSL 4.x đã hỗ trợ ML-KEM/hybrid group ở tầng provider/TLS, và cách dùng `EVP_PKEY_encapsulate`/`EVP_PKEY_decapsulate` cho KEM (chỉ nêu hướng, không bắt buộc cài).
5. Mở rộng tuỳ chọn: AES-CTR+HMAC (Encrypt-then-MAC) vs AES-GCM; thiết kế thí nghiệm đo biến thiên thời gian khi xác thực thất bại (agent chỉ **viết mã thí nghiệm** trong `bench/` dưới cờ `--timing-failure`, kết quả do con người chạy; ghi cột `suite=authfail` trong CSV).

---

## 9. README.md (agent phải viết)

Nội dung tối thiểu (tiếng Việt):
1. Giới thiệu & tính năng.
2. Yêu cầu hệ thống & thư viện (**OpenSSL ≥ 4.0** — chỉ `libcrypto`; nlohmann_json, Catch2, Python 3 cho script).
3. **Cài thư viện** (ngắn gọn, trỏ đến `RUN_GUIDE.md` cho chi tiết):
   - **Ubuntu**: kho `apt` của Ubuntu LTS thường chỉ có OpenSSL 3.x → hướng dẫn **build OpenSSL 4.x từ source** (tải tarball từ trang phát hành chính thức, `./Configure --prefix=/opt/openssl-4 --openssldir=/opt/openssl-4/ssl --libdir=lib`, `make -j`, `make install`), rồi cấu hình lab bằng `-DOPENSSL_ROOT_DIR=/opt/openssl-4`. Kiểm tra bằng `/opt/openssl-4/bin/openssl version` (phải thấy 4.x). Cảnh báo **không** ghi đè OpenSSL của hệ thống.
   - **Windows**: `vcpkg install openssl` (**kiểm tra phiên bản cài được là 4.x** bằng `vcpkg list`; nếu vcpkg chưa có 4.x thì build từ source bằng Perl + NASM + MSVC), hoặc dùng bản cài đã build sẵn; truyền `-DOPENSSL_ROOT_DIR` / `CMAKE_TOOLCHAIN_FILE` tương ứng. Nhắc về DLL runtime và việc khớp MD/MT.
   - **Cảnh báo chung**: nếu CMake báo tìm thấy OpenSSL 3.x → sai đường dẫn, xem hướng dẫn trên.
4. **Build** out-of-source trên Linux/MSVC/MinGW (lệnh `cmake -S . -B build -DOPENSSL_ROOT_DIR=... ...`, `cmake --build build --config Release`).
5. Cách dùng CLI: ví dụ keygen/encrypt/decrypt, `--label`, `--encode`, `--force-hybrid`, `--impl`.
6. Giải thích **định dạng file** (PEM/DER/metadata, container & envelope header, AAD) — tóm tắt từ `docs/DESIGN.md`.
7. Chạy test (`ctest --test-dir build -C Release --output-on-failure`) và benchmark (`rsabench`, `analyze_bench.py`).
8. Mã thoát & thông báo lỗi.
9. Ghi chú bảo mật (RNG = DRBG của OpenSSL qua `RAND_bytes`, fail-closed, giới hạn constant-time, khóa private không mã hóa bằng passphrase, không dùng cho sản xuất).
10. Cấu trúc thư mục & bảng ánh xạ **rubric → vị trí trong repo**.
11. Vấn đề đã biết / giới hạn (vd. phụ thuộc OpenSSL 4.x; API OpenSSL 4.0 có thể khác 3.x ở các hàm đã gỡ).

---

## 10. `report/REPORT_OUTLINE.md` (agent viết sẵn phần lý thuyết)

Dàn ý báo cáo kỹ thuật + **viết sẵn nội dung lý thuyết bắt buộc** (tiếng Việt, có công thức LaTeX đơn giản):
1. Giới thiệu & mục tiêu.
2. Lý thuyết RSA-OAEP: sơ đồ OAEP, vì sao đạt **IND-CCA2** (mô hình ngẫu nhiên, ràng buộc plaintext-awareness, chứng minh sơ lược Fujisaki-Okamoto–Shoup–Pointcheval).
3. Vì sao **PKCS#1 v1.5** không an toàn: **Bleichenbacher 1998** (padding oracle), lỗi ROBOT, so sánh với OAEP.
4. Giới hạn plaintext `mLen ≤ k − 2hLen − 2`: suy ra công thức, ví dụ 3072/4096 (318/446), lý do RSA không dùng trực tiếp cho file lớn (giới hạn, tốc độ, không xác thực, chi phí bộ nhớ).
5. Mã hóa lai/Envelope: sơ đồ khối, định dạng, AAD, vì sao GCM yêu cầu IV duy nhất.
6. Thiết kế & triển khai: kiến trúc module, **lựa chọn OpenSSL 4.x và API EVP/OSSL_ENCODER**, định dạng khóa, quyết định thiết kế, xử lý lỗi fail-closed.
7. Kiểm thử: bảng test (tên, mục đích, kết quả `{{TODO: dán kết quả ctest}}`).
8. Hiệu năng: phương pháp đo, môi trường `{{TODO}}` (phiên bản OpenSSL, CPU, OS, compiler), bảng/ đồ thị `{{TODO: chèn từ report/figures}}`, **phân tích bắt buộc**:
   - chi phí **giải mã RSA (d lớn)** vs **mã hóa RSA (e=65537 nhỏ)**: số phép nhân modulo ~ log₂d vs 17 (e = 2¹⁶+1), CRT tăng tốc ~4×;
   - đánh đổi kích thước khóa ↔ hiệu năng (3072 vs 4096: độ phức tạp ~O(k³) cho decrypt);
   - ưu thế của Hybrid so với RSA thuần; lý do mã hóa đối xứng áp đảo về băng thông (AES-NI, CLMUL/GHASH, xử lý theo luồng).
9. Bonus A, Bonus B (tham chiếu docs).
10. Kết luận, hạn chế, hướng phát triển (ECDHE, ML-KEM).
11. Tài liệu tham khảo (RFC 8017, NIST SP 800-38D, Bleichenbacher 1998, Manger 2001, FIPS 203, RFC 8446, tài liệu OpenSSL 4.0 `docs.openssl.org/4.0/`…).
12. Phụ lục: lệnh đã chạy, log (`{{TODO}}`).

Ghi **cuối file** một bảng checklist các số liệu/hình/log mà con người cần dán, trỏ đúng tên file trong `results/` (đồng bộ với `RUN_GUIDE.md` §8).

---

## 11. Quy trình làm việc cho agent (làm tuần tự, tick từng phase)

**Phase 1 — Khung dự án**
- [ ] Tạo cây thư mục §2, `.gitignore` (`build/`, `testdata/`, `*.pem`, `*.der` khóa test… — ngoại trừ cần thiết), `CMakeLists.txt` (tìm OpenSSL ≥ 4.0, `OPENSSL_NO_DEPRECATED`).
- [ ] `errors.hpp`, `ossl_raii.hpp`, `util.hpp/.cpp`, `encoding.*`.

**Phase 2 — Lõi mật mã**
- [ ] `keyio.*` (OSSL_ENCODER/OSSL_DECODER, PKCS#8/SPKI, PEM/DER, metadata).
- [ ] `rsa_oaep.*` (EVP_PKEY_CTX, label, giới hạn mLen).
- [ ] `envelope.*` + `hybrid.*` (container, AAD, AES-256-GCM qua EVP, auto mode, fail-closed).

**Phase 3 — CLI**
- [ ] `cli.*`, `main.cpp`: `keygen`, `encrypt`, `decrypt`, `--help`, mã thoát §5.

**Phase 4 — Test**
- [ ] Toàn bộ test §6; đảm bảo test không phụ thuộc file ngoài (tự sinh khóa/ dữ liệu trong bộ nhớ hoặc thư mục tạm).

**Phase 5 — Benchmark & script**
- [ ] `bench_main.cpp`, `analyze_bench.py`, `tamper.py`, `make_testfiles.py`.

**Phase 6 — Bonus**
- [ ] `oaep_manual.*` + test + `--impl`.
- [ ] `docs/BONUS_B_hybrid_analysis.md`.

**Phase 7 — Tài liệu**
- [ ] `README.md`, `docs/DESIGN.md` (có bảng ánh xạ API §4.0), `report/REPORT_OUTLINE.md`, `docs/COMPILE_RISKS.md`.
- [ ] Đối chiếu `RUN_GUIDE.md`: mọi lệnh/đường dẫn/tên file trong đó phải khớp thực tế code; cập nhật mục cài đặt thư viện từ Crypto++ sang OpenSSL 4.x. Nếu lệch, **sửa code** (ưu tiên) hoặc sửa guide tối thiểu và ghi vào `docs/COMPILE_RISKS.md` mục "Thay đổi so với guide".

**Phase 8 — Tự rà soát (không chạy gì)**
- [ ] Grep thủ công chuỗi cấm (`rand(`, `random_device`, `mt19937`) và **API cấm của OpenSSL** (`RSA_`, `AES_encrypt`, `SHA256_Init`, `ENGINE_`, `ERR_load_`, `#include <cryptopp`, `CryptoPP`).
- [ ] Kiểm tra mọi `#include <openssl/...>` đúng header (`evp.h`, `rand.h`, `err.h`, `encoder.h`, `decoder.h`, `core_names.h`, `param_build.h`, `crypto.h`).
- [ ] Mỗi đối tượng OpenSSL đều có chủ sở hữu RAII; mọi giá trị trả về đều được kiểm tra; `set0_rsa_oaep_label` xử lý đúng quyền sở hữu.
- [ ] Kiểm tra mọi tên hàm được khai báo & định nghĩa đồng nhất.
- [ ] Kiểm tra từng yêu cầu ở §12.

---

## 12. Definition of Done (đối chiếu rubric)

| Hạng mục (điểm) | Phải có |
|---|---|
| RSA-OAEP SHA-256 (20) | `rsa_oaep.*` (EVP, MGF1=SHA-256 tường minh), label, giới hạn mLen, RSA-3072 + 4096 |
| Hybrid Envelope (20) | AES-256-GCM (EVP), IV 96-bit, wrap OAEP, header JSON đúng trường, AAD, auto-mode |
| Khóa & định dạng (15) | PEM + DER + metadata JSON đúng schema, PKCS#8/SPKI (OSSL_ENCODER/DECODER), chmod 0600 |
| Negative test (15) | Đủ 5 kịch bản đề + các biến thể §6, lỗi generic (không rò chuỗi OpenSSL), không để lại output |
| Benchmark (15) | `rsabench` + CSV mẫu riêng lẻ + `analyze_bench.py` (95% CI, 4 đồ thị) + `bench_env.txt` có phiên bản OpenSSL |
| CMake + README (5) | Build out-of-source Win/Linux, yêu cầu OpenSSL ≥ 4.0 có kiểm tra, README đầy đủ §9 |
| Báo cáo (10) | `REPORT_OUTLINE.md` có sẵn lý thuyết bắt buộc |
| Bonus A (+5) | `oaep_manual.*` constant-time + test cross-check |
| Bonus B (+10) | `BONUS_B_hybrid_analysis.md` đủ 4 mục + mục mở rộng |

Khi hoàn tất: tạo `docs/AGENT_DONE.md` liệt kê file đã tạo, những điểm chưa chắc biên dịch (đặc biệt các hàm OpenSSL 4.x chưa chắc chắn), và các giả định đã dùng. **Dừng ở đó — không chạy lệnh nào.**