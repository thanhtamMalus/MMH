# AGENT.md — Lab 3: RSA-OAEP & Hybrid Encryption (`rsatool`)

> File này là **chỉ thị cho bot/agent**. Đọc toàn bộ trước khi viết bất kỳ file nào.
> Nhiệm vụ của agent: **VIẾT FILE** (mã nguồn, CMake, test, bench, script, README, tài liệu báo cáo).
> **KHÔNG chạy lệnh terminal.** Việc build/chạy/lấy kết quả do con người thực hiện theo `RUN_GUIDE.md`.

---

## 0. Quy tắc tối thượng (đọc kỹ)

1. **CẤM chạy terminal**: không chạy `cmake`, `make`, `ninja`, `ctest`, `rsatool`, `rsabench`, `python`, `pip`, `apt`, `vcpkg`… Chỉ tạo/sửa file.
2. Vì không được biên dịch thử, agent phải **tự rà soát code** trước khi kết thúc mỗi phase: include thiếu, sai namespace, sai chữ ký hàm, sai tên target CMake, lỗi cú pháp. Ghi các điểm còn rủi ro biên dịch vào `docs/COMPILE_RISKS.md`.
3. **CẤM tuyệt đối** `rand()`, `srand()`, `std::random_device`, `std::mt19937` (kể cả trong test, bench, tool). Chỉ dùng `CryptoPP::AutoSeededRandomPool` (hoặc `RAND_bytes` nếu dùng OpenSSL). Dùng `grep` thủ công trong đầu: trong repo không được có chuỗi cấm này (kể cả trong comment, trừ file `AGENT.md`/`RUN_GUIDE.md`).
4. **Fail-closed**: mọi lỗi giải mã/xác thực → không ghi file output, không in plaintext một phần, thông báo lỗi **chung chung** (xem §5).
5. Không tự bịa số liệu benchmark/kết quả test. Chỗ cần số liệu trong báo cáo dùng placeholder dạng `{{TODO: dán số liệu từ results/xxx}}`.
6. Mã nguồn chạy được trên **Windows (MSVC / MinGW64)** và **Linux (Ubuntu LTS)**: không dùng API riêng nền tảng ngoài `#ifdef` có fallback; đường dẫn dùng `std::filesystem`; mở file ở chế độ **binary**.
7. C++17. Comment code bằng tiếng Việt hoặc tiếng Anh nhất quán (ưu tiên tiếng Anh cho identifier, tiếng Việt cho giải thích khó).
8. Thư viện chính: **Crypto++**. (OpenSSL không dùng, trừ khi cần; không trộn hai thư viện trong lõi.)

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
├── RUN_GUIDE.md                 # đã có sẵn, KHÔNG ghi đè nội dung; chỉ sửa nếu CLI/đường dẫn lệch
├── cmake/
│   └── FindDeps.cmake           # (tuỳ chọn) gom find_package / FetchContent
├── include/rsalab/
│   ├── errors.hpp
│   ├── encoding.hpp             # raw | hex | base64
│   ├── keyio.hpp                # PEM/DER/metadata
│   ├── rsa_oaep.hpp             # RSA-OAEP wrapper (thư viện)
│   ├── envelope.hpp             # container + header JSON + AAD
│   ├── hybrid.hpp               # encrypt/decrypt tổng (auto mode)
│   ├── oaep_manual.hpp          # Bonus A
│   └── util.hpp                 # đọc/ghi file, rng, constant-time helpers
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
│   ├── DESIGN.md                # quyết định thiết kế, định dạng envelope
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
- Tìm Crypto++ theo thứ tự (viết linh hoạt, in `message(STATUS ...)` kết quả):
  1. `find_package(cryptopp CONFIG)` (vcpkg; target `cryptopp::cryptopp` hoặc `cryptopp-static`).
  2. `pkg-config` (`libcrypto++` / `libcryptopp`) qua `PkgConfig::CRYPTOPP`.
  3. `find_library(cryptopp)` + `find_path(cryptopp/cryptlib.h)`.
  Tạo target `INTERFACE` alias `rsalab::cryptopp` để phần còn lại không quan tâm nguồn.
- `nlohmann_json`: `find_package(nlohmann_json CONFIG QUIET)`; nếu không có → `FetchContent` (v3.11.3).
- `Catch2 v3`: `find_package(Catch2 3 QUIET)`; nếu không có → `FetchContent` (v3.5.x). Dùng `catch_discover_tests` hoặc `add_test`.
- Target:
  - `rsa_core` (STATIC): toàn bộ `src/*.cpp` trừ `main.cpp`.
  - `rsatool` (EXECUTABLE): `src/main.cpp` + link `rsa_core`.
  - `rsabench` (EXECUTABLE): `bench/bench_main.cpp`.
  - `rsa_tests` (EXECUTABLE): `tests/*.cpp`; `enable_testing()` + `add_test`.
- Bật cảnh báo: MSVC `/W4 /permissive-`; GCC/Clang `-Wall -Wextra -Wpedantic`.
- MSVC: `/EHsc`, định nghĩa `_CRT_SECURE_NO_WARNINGS`, `CRYPTOPP_...` nếu cần; đảm bảo cùng runtime (MD/MT) với bản Crypto++ được cài — ghi chú trong README.
- MinGW: link `-lws2_32` nếu Crypto++ yêu cầu (dùng `if(MINGW)`).
- Output executable vào `${CMAKE_BINARY_DIR}/bin` (đặt `RUNTIME_OUTPUT_DIRECTORY`, và biến thể per-config cho MSVC).

---

## 4. Đặc tả kỹ thuật chi tiết

### 4.1. `rsa_oaep` (lõi RSA-OAEP)

- Dùng `CryptoPP::RSAES<CryptoPP::OAEP<CryptoPP::SHA256>>::Encryptor/Decryptor` (OAEP<SHA256> mặc định MGF1 dùng cùng SHA-256 — ghi chú rõ trong code).
- **Label**: truyền qua `CryptoPP::Name::EncodingParameters()` bằng `CryptoPP::MakeParameters(CryptoPP::Name::EncodingParameters(), CryptoPP::ConstByteArrayParameter(label_bytes))` cho cả encrypt và decrypt. Label rỗng = không có nhãn (khớp chuẩn: L = chuỗi rỗng).
- Hàm cần có:
  - `size_t max_plaintext_len(unsigned modulus_bits)` = `k - 2*32 - 2`.
  - `ByteVec oaep_encrypt(const PublicKey&, ByteView msg, ByteView label, RNG&)` — ném lỗi nếu `msg.size() > max`.
  - `ByteVec oaep_decrypt(const PrivateKey&, ByteView ct, ByteView label)` — ném `CryptoFailure` (generic) khi lỗi; **không** phân biệt nguyên nhân.
- RNG: `AutoSeededRandomPool` (một instance, không copy).

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
- **PEM tự viết** (Crypto++ chuẩn không có PEM): DER → Base64 (`CryptoPP::Base64Encoder`, `insertLineBreaks=false`) → tự ngắt dòng **64 ký tự** → bọc header/footer. Parser phải chịu được `\r\n`, khoảng trắng thừa, và từ chối header sai loại (PUBLIC vs PRIVATE).
- Lưu khóa private bằng **PKCS#8**: dùng `PrivateKey::Save` cho RSA gốc sinh `RSAPrivateKey` (PKCS#1); để ra PKCS#8 dùng `CryptoPP::PKCS8PrivateKey::Save`/`DEREncodePrivateKey` kèm `PrivateKeyInfo` (algorithm OID rsaEncryption `1.2.840.113549.1.1.1`, NULL params). Public dùng `X509PublicKey::Save` (SPKI). Cần load được cả định dạng DER lẫn PEM (`--pub x.der` tự nhận theo đuôi/nội dung).
- Public exponent **e = 65537**. Kiểm tra `bits ≥ 3072` khi keygen (từ chối <3072 với mã lỗi usage, trừ cờ ẩn `--allow-weak-for-test` chỉ dùng trong unit test, không công bố trong help).
- Linux: sau khi ghi `priv.pem`/`priv.der` → `chmod 0600` (`std::filesystem::permissions`). Windows: bỏ qua.
- Ghi file **atomically** (ghi `.tmp` rồi rename) để không để lại file nửa vời.

### 4.3. Mã hóa / Giải mã

CLI:

```
rsatool encrypt --in msg.bin --pub pub.pem --out ct.bin [--label TEXT] [--encode raw|hex|base64] [--force-hybrid]
rsatool decrypt --in ct.bin --priv priv.pem --out msg.bin [--label TEXT] [--encode raw|hex|base64]
```

- `--label` là chuỗi UTF-8 bất kỳ (nhận cả `--label-hex` tuỳ chọn). Mặc định rỗng. **Decrypt phải truyền đúng label** (label không lưu trong file vì là tham số ngữ cảnh).
- `--encode` quy định định dạng **file ciphertext** (encrypt: ghi ra; decrypt: đọc vào). Mặc định `raw`. Với `base64`/`hex`, bỏ qua whitespace khi đọc.
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
- **AES-GCM**: key 32 byte và IV **12 byte** đều sinh bằng `AutoSeededRandomPool`; tag 16 byte; dùng `CryptoPP::GCM<AES>` + `AuthenticatedEncryptionFilter` / `AuthenticatedDecryptionFilter`.
- **AAD (ràng buộc header vào GCM)** để sửa header → xác thực thất bại. AAD = chuỗi byte ASCII:
  `"RSAE-AAD-v1|" + mode + "|" + rsa_modulus + "|" + hash + "|" + wrapped_key_b64 + "|" + iv_b64`
  (không gồm `tag`). Ghi rõ công thức này trong `docs/DESIGN.md`.
- **Giải mã Hybrid — thứ tự bắt buộc**:
  1. Parse container nghiêm ngặt: magic, version, `header_len ≤ 65536`, JSON hợp lệ, chỉ chấp nhận `mode` trong danh sách cho phép, `hash == "SHA-256"`, `rsa_modulus` **khớp** bit-size khóa private, `iv` giải base64 đúng 12 byte, `tag` đúng 16 byte, `wrapped_key` đúng k byte. Sai bất kỳ → lỗi generic.
  2. RSA-OAEP unwrap khóa AES (label truyền vào). Sai → lỗi generic (**cùng thông báo & cùng mã thoát** với mọi lỗi khác).
  3. AES-GCM giải mã có xác thực **vào bộ đệm trong RAM** (`StringSink`). Chỉ khi xác thực thành công mới ghi ra file output (ghi atomically). Thất bại → **không tạo/không để lại** file output; xóa sạch bộ đệm (`SecByteBlock` tự zeroize; `std::fill` hoặc `CryptoPP::SecureWipeBuffer` cho vùng khác).
  4. Tuyệt đối **không tự so sánh tag bằng `memcmp`/`==`**; để Crypto++ GCM xác thực (hoặc dùng `CryptoPP::VerifyBufsEqual`, vốn constant-time).
- Xử lý dữ liệu lớn: 100 MiB đọc cả vào RAM là chấp nhận được; nhưng dùng `SecByteBlock`/`std::vector` đúng cách, tránh copy thừa.
- Zeroize khóa AES, plaintext tạm sau khi dùng.

### 4.4. Mã lỗi & thông điệp (xem §5)

---

## 5. Xử lý lỗi an toàn (Fail-closed, không rò rỉ)

- Định nghĩa `rsalab::UsageError`, `rsalab::IoError`, `rsalab::CryptoFailure`.
- Mã thoát: `0` OK · `1` sai tham số · `2` lỗi I/O/khóa không đọc được · `3` giải mã/xác thực thất bại.
- **Mọi** lỗi crypto khi giải mã (OAEP sai, sai label, sai khóa, tag sai, header sai, base64 hỏng, độ dài sai…) → in **đúng một** thông báo: `Error: decryption failed.` (stderr) + exit 3. **Không** nêu "padding sai", "tag sai", "label sai", không in độ dài, không in exception của Crypto++.
- Encrypt: lỗi `msg quá lớn` không xảy ra ở auto mode; lỗi I/O thì mô tả rõ (không nhạy cảm).
- Không log key, plaintext, label, IV ở chế độ mặc định. Cờ `--verbose` chỉ in kích thước file & mode đã chọn (Direct/Hybrid) — được phép.
- Giải mã Direct và Hybrid khi lỗi RSA unwrap: thời gian xử lý nên gần như nhau (không return sớm lộ nhánh quá khác biệt; ghi rõ giới hạn trong DESIGN.md — thời gian của thư viện nằm ngoài kiểm soát).

---

## 6. Unit tests (Catch2 v3, chạy qua `ctest`)

Dùng khóa **RSA-3072 sinh một lần/test-suite** (static fixture) vì sinh khóa chậm; dùng RNG an toàn. Các test bắt buộc:

**Đúng đắn (`test_rsa_oaep`, `test_hybrid`, `test_keyio`)**
- Round-trip Direct: msg rỗng, 1 byte, đúng `mLen_max` (318 với 3072), vẫn Direct.
- `mLen_max + 1` → auto chuyển Hybrid, round-trip đúng.
- Hybrid: 1 KiB, 1 MiB (100 MiB **không** đưa vào unit test; để cho benchmark).
- Cả RSA-3072 và RSA-4096 (4096 test có thể đánh dấu tag `[slow]`; vẫn chạy mặc định).
- Label khớp → OK; label rỗng ↔ rỗng → OK.
- `max_plaintext_len(3072)==318`, `max_plaintext_len(4096)==446`.
- Keyio: save PEM → load PEM khớp; save DER → load DER khớp; PEM↔DER cho cùng khóa; metadata đủ 3 trường đúng kiểu, `creation_time` khớp regex `^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$`; `modulus_bits==3072`; `hash=="SHA-256"`; từ chối `bits<3072`.
- Encoding: raw/hex/base64 round-trip.
- Hai lần encrypt cùng plaintext → ciphertext **khác nhau** (OAEP/GCM ngẫu nhiên hóa); hai envelope có IV khác nhau, wrapped_key khác nhau.

**Tiêu cực / Fail-closed (`test_negative`)** — mỗi test kiểm tra: ném `CryptoFailure` (hoặc trả mã 3), thông điệp **đúng bằng** `"decryption failed"` (không rò rỉ), và **file output không tồn tại / plaintext rỗng**:
1. Lật 1 bit trong RSA ciphertext (Direct) → thất bại.
2. Lật 1 bit trong payload AES-GCM (Hybrid) → thất bại (lỗi xác thực tag).
3. Lật 1 bit trong `tag` → thất bại.
4. Giải mã bằng **private key khác** → thất bại (cả Direct và Hybrid).
5. Giải mã với **label sai** (và label thiếu) → thất bại (cả Direct và Hybrid).
6. Sửa header JSON: đổi `iv`, đổi `wrapped_key`, đổi `rsa_modulus`, đổi `mode`, thêm khoảng trắng/field lạ, `header_len` giả → thất bại.
7. Cắt cụt envelope (thiếu payload/tag), thêm byte thừa vào cuối → thất bại.
8. Magic/version sai → thất bại.
9. Test thông điệp lỗi: chuỗi lỗi không chứa các từ `padding`, `tag`, `label`, `OAEP`, `mac` (kiểm tra bằng so sánh với chuỗi generic cố định).

**Bonus A (`test_oaep_manual`)**: cross-check — `manual_encrypt` ↔ `library_decrypt` và `library_encrypt` ↔ `manual_decrypt` đều round-trip; kèm test lỗi (sai label, lật bit) → cùng một lỗi generic.

---

## 7. Benchmark (`bench/bench_main.cpp` → `rsabench`)

CLI: `rsabench --out results/bench_raw.csv [--reps-keygen N] [--reps-rsa N] [--reps-aes N] [--quick]`

- Đồng hồ: `std::chrono::steady_clock`, đơn vị **micro/nano giây**; **warm-up** ≥ 3 lần bỏ ra ngoài; chống tối ưu hóa bỏ code (dùng kết quả: cộng vào biến `volatile`/in checksum).
- Mặc định: keygen 3072 & 4096 mỗi cái **N=20** lần (keygen chậm, có `--quick` giảm xuống 3); RSA-OAEP encrypt/decrypt (plaintext 32 byte, label rỗng) mỗi key size **N=200**; AES-GCM throughput trên 1 KiB / 1 MiB / 100 MiB, mỗi cỡ **N=30 / 30 / 10**; **Hybrid tổng** (sinh khóa AES + GCM + RSA wrap) trên 3 cỡ đó cho **cả RSA-3072 và RSA-4096**, cùng số lần như trên.
- Đo **từng mẫu riêng lẻ** (không chỉ trung bình). Ghi CSV dạng "long":
  `timestamp_utc,suite,op,rsa_bits,size_bytes,rep,time_ns,throughput_mb_s`
  - `suite ∈ {rsa, aesgcm, hybrid}`; `op ∈ {keygen, encrypt, decrypt}`; `throughput_mb_s` chỉ cho `aesgcm`/`hybrid` (MB = 10^6 byte hay MiB? **dùng MiB/s**, đặt tên cột `throughput_mib_s` và ghi chú trong README).
- In ra stdout thông tin môi trường: CPU (nếu lấy được, vd. `CRYPTOPP`'s `HasAESNI()`/`HasCLMUL()`), OS, compiler, loại build, phiên bản Crypto++ — con người sẽ copy vào báo cáo. Ghi cả thông tin này vào `results/bench_env.txt` (tham số `--env-out`).
- Dữ liệu test cho AES: buffer sinh bằng `AutoSeededRandomPool` (hoặc đệm byte cố định — throughput AES không phụ thuộc nội dung).
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

- Tự cài (chỉ dùng SHA-256 của thư viện và phép luỹ thừa modulo `CryptoPP::Integer`/`ModularExponentiation` cho RSA thô — **không** gọi `OAEP<SHA256>` bên trong):
  - `mgf1_sha256(seed, maskLen)`.
  - EME-OAEP-ENCODE: `DB = lHash || PS || 0x01 || M`; `seed` ngẫu nhiên 32 byte (`AutoSeededRandomPool`); `maskedDB = DB ⊕ MGF1(seed)`; `maskedSeed = seed ⊕ MGF1(maskedDB)`; `EM = 0x00 || maskedSeed || maskedDB`.
  - RSA thô: `c = EM^e mod n` / `EM = c^d mod n` (chuyển I2OSP/OS2IP đúng độ dài k).
  - EME-OAEP-DECODE **constant-time**: không `return` sớm; gom các cờ lỗi (`Y != 0`, `lHash' != lHash`, không tìm thấy `0x01`, …) bằng phép bit-mask (`mask = (x - 1) >> 63`, hàm `ct_select`, `ct_is_zero`, `ct_eq`), quét **toàn bộ** DB với độ dài cố định để tìm vị trí `0x01` không phân nhánh theo dữ liệu, rồi trả về một kết quả duy nhất (thành công/thất bại) ở cuối. Dùng `volatile`/`std::atomic_signal_fence` hoặc kỹ thuật tương đương để giảm rủi ro compiler tối ưu hoá phá constant-time; ghi chú giới hạn (BigInteger của thư viện không đảm bảo constant-time).
- Thêm tuỳ chọn CLI `--impl lib|manual` (mặc định `lib`) cho `encrypt`/`decrypt` để minh hoạ.
- Trong `report/REPORT_OUTLINE.md`: giải thích **vì sao decode phải constant-time** (tấn công **Manger**: oracle phân biệt lỗi "byte đầu ≠ 0x00" với lỗi khác → khôi phục plaintext từng bit/byte; nên mọi lỗi phải không phân biệt được cả về thông điệp lẫn thời gian).

### Bonus B — Phân tích bảo mật lai (`docs/BONUS_B_hybrid_analysis.md`) (+10)

Viết đầy đủ (có thể dùng làm chương báo cáo, tiếng Việt, có công thức & sơ đồ ASCII/Mermaid), gồm:
1. So sánh Envelope vs RSA trực tiếp: giới hạn kích thước, hiệu năng, tính ngẫu nhiên hóa, xác thực toàn vẹn (GCM) mà RSA-OAEP đơn thuần không cung cấp cho file, rủi ro tái sử dụng khóa/IV (nonce reuse trong GCM là thảm họa → mỗi lần mã hóa sinh khóa AES mới nên an toàn).
2. TLS handshake như một thiết kế lai: (a) TLS 1.2 RSA key-exchange (pre-master secret bọc bằng RSA) vs (b) ECDHE; vai trò KDF (HKDF), AEAD (AES-GCM/ChaCha20-Poly1305), chứng chỉ & chữ ký xác thực.
3. **Forward secrecy**: vì sao RSA key transport thuần **không** có FS (lộ `d` ⇒ giải mã mọi phiên ghi lại — "harvest now, decrypt later"); ECDHE ephemeral khắc phục thế nào.
4. Lộ trình nâng cấp: ECDHE (X25519/P-256) + HKDF + AEAD; sau đó **ML-KEM** (FIPS 203) lai X25519+ML-KEM (hybrid KEM) — nối sang Lab 6; liệt kê thay đổi cần làm trong `rsatool` (KEM/DEM API, versioning container).
5. Mở rộng tuỳ chọn: AES-CTR+HMAC (Encrypt-then-MAC) vs AES-GCM; thiết kế thí nghiệm đo biến thiên thời gian khi xác thực thất bại (agent chỉ **viết mã thí nghiệm** trong `bench/` dưới cờ `--timing-failure`, kết quả do con người chạy; ghi cột `suite=authfail` trong CSV).

---

## 9. README.md (agent phải viết)

Nội dung tối thiểu (tiếng Việt):
1. Giới thiệu & tính năng.
2. Yêu cầu hệ thống & thư viện (Crypto++, nlohmann_json, Catch2, Python 3 cho script).
3. **Cài thư viện**: Ubuntu (`apt`) và Windows (`vcpkg`) — ngắn gọn, trỏ đến `RUN_GUIDE.md` cho chi tiết.
4. **Build** out-of-source trên Linux/MSVC/MinGW (lệnh `cmake -S . -B build ...`, `cmake --build build --config Release`).
5. Cách dùng CLI: ví dụ keygen/encrypt/decrypt, `--label`, `--encode`, `--force-hybrid`, `--impl`.
6. Giải thích **định dạng file** (PEM/DER/metadata, container & envelope header, AAD) — tóm tắt từ `docs/DESIGN.md`.
7. Chạy test (`ctest --test-dir build -C Release --output-on-failure`) và benchmark (`rsabench`, `analyze_bench.py`).
8. Mã thoát & thông báo lỗi.
9. Ghi chú bảo mật (RNG, fail-closed, giới hạn constant-time, không dùng cho sản xuất).
10. Cấu trúc thư mục & bảng ánh xạ **rubric → vị trí trong repo**.
11. Vấn đề đã biết / giới hạn.

---

## 10. `report/REPORT_OUTLINE.md` (agent viết sẵn phần lý thuyết)

Dàn ý báo cáo kỹ thuật + **viết sẵn nội dung lý thuyết bắt buộc** (tiếng Việt, có công thức LaTeX đơn giản):
1. Giới thiệu & mục tiêu.
2. Lý thuyết RSA-OAEP: sơ đồ OAEP, vì sao đạt **IND-CCA2** (mô hình ngẫu nhiên, ràng buộc plaintext-awareness, chứng minh sơ lược Fujisaki-Okamoto–Shoup–Pointcheval).
3. Vì sao **PKCS#1 v1.5** không an toàn: **Bleichenbacher 1998** (padding oracle), lỗi ROBOT, so sánh với OAEP.
4. Giới hạn plaintext `mLen ≤ k − 2hLen − 2`: suy ra công thức, ví dụ 3072/4096 (318/446), lý do RSA không dùng trực tiếp cho file lớn (giới hạn, tốc độ, không xác thực, chi phí bộ nhớ).
5. Mã hóa lai/Envelope: sơ đồ khối, định dạng, AAD, vì sao GCM yêu cầu IV duy nhất.
6. Thiết kế & triển khai: kiến trúc module, định dạng khóa, quyết định thiết kế, xử lý lỗi fail-closed.
7. Kiểm thử: bảng test (tên, mục đích, kết quả `{{TODO: dán kết quả ctest}}`).
8. Hiệu năng: phương pháp đo, môi trường `{{TODO}}`, bảng/ đồ thị `{{TODO: chèn từ report/figures}}`, **phân tích bắt buộc**:
   - chi phí **giải mã RSA (d lớn)** vs **mã hóa RSA (e=65537 nhỏ)**: số phép nhân modulo ~ log₂d vs 17 (e = 2¹⁶+1), CRT tăng tốc ~4×;
   - đánh đổi kích thước khóa ↔ hiệu năng (3072 vs 4096: độ phức tạp ~O(k³) cho decrypt);
   - ưu thế của Hybrid so với RSA thuần; lý do mã hóa đối xứng áp đảo về băng thông (AES-NI, CLMUL/GHASH, xử lý theo luồng).
9. Bonus A, Bonus B (tham chiếu docs).
10. Kết luận, hạn chế, hướng phát triển (ECDHE, ML-KEM).
11. Tài liệu tham khảo (RFC 8017, NIST SP 800-38D, Bleichenbacher 1998, Manger 2001, FIPS 203, RFC 8446…).
12. Phụ lục: lệnh đã chạy, log (`{{TODO}}`).

Ghi **cuối file** một bảng checklist các số liệu/hình/log mà con người cần dán, trỏ đúng tên file trong `results/` (đồng bộ với `RUN_GUIDE.md` §8).

---

## 11. Quy trình làm việc cho agent (làm tuần tự, tick từng phase)

**Phase 1 — Khung dự án**
- [ ] Tạo cây thư mục §2, `.gitignore` (`build/`, `testdata/`, `*.pem`, `*.der` khóa test… — ngoại trừ cần thiết), `CMakeLists.txt`.
- [ ] `errors.hpp`, `util.hpp/.cpp`, `encoding.*`.

**Phase 2 — Lõi mật mã**
- [ ] `keyio.*` (PEM tự viết, DER, PKCS#8/SPKI, metadata).
- [ ] `rsa_oaep.*` (label, giới hạn mLen).
- [ ] `envelope.*` + `hybrid.*` (container, AAD, auto mode, fail-closed).

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
- [ ] `README.md`, `docs/DESIGN.md`, `report/REPORT_OUTLINE.md`, `docs/COMPILE_RISKS.md`.
- [ ] Đối chiếu `RUN_GUIDE.md`: mọi lệnh/đường dẫn/tên file trong đó phải khớp thực tế code. Nếu lệch, **sửa code** (ưu tiên) hoặc sửa guide tối thiểu và ghi vào `docs/COMPILE_RISKS.md` mục "Thay đổi so với guide".

**Phase 8 — Tự rà soát (không chạy gì)**
- [ ] Grep thủ công chuỗi cấm (`rand(`, `random_device`, `mt19937`).
- [ ] Kiểm tra mọi `#include`, mọi tên hàm được khai báo & định nghĩa đồng nhất.
- [ ] Kiểm tra từng yêu cầu ở §12.

---

## 12. Definition of Done (đối chiếu rubric)

| Hạng mục (điểm) | Phải có |
|---|---|
| RSA-OAEP SHA-256 (20) | `rsa_oaep.*`, label, giới hạn mLen, RSA-3072 + 4096 |
| Hybrid Envelope (20) | AES-256-GCM, IV 96-bit, wrap OAEP, header JSON đúng trường, AAD, auto-mode |
| Khóa & định dạng (15) | PEM + DER + metadata JSON đúng schema, PKCS#8/SPKI, chmod 0600 |
| Negative test (15) | Đủ 5 kịch bản đề + các biến thể §6, lỗi generic, không để lại output |
| Benchmark (15) | `rsabench` + CSV mẫu riêng lẻ + `analyze_bench.py` (95% CI, 4 đồ thị) |
| CMake + README (5) | Build out-of-source Win/Linux, README đầy đủ §9 |
| Báo cáo (10) | `REPORT_OUTLINE.md` có sẵn lý thuyết bắt buộc |
| Bonus A (+5) | `oaep_manual.*` constant-time + test cross-check |
| Bonus B (+10) | `BONUS_B_hybrid_analysis.md` đủ 4 mục + mục mở rộng |

Khi hoàn tất: tạo `docs/AGENT_DONE.md` liệt kê file đã tạo, những điểm chưa chắc biên dịch, và các giả định đã dùng. **Dừng ở đó — không chạy lệnh nào.**