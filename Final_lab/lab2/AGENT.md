# Hướng dẫn cho AI Agent: Lab 2 · AES-128 (CTR Mode) bằng C++ thuần

> Bạn là một AI coding agent. Nhiệm vụ: **xây dựng toàn bộ dự án Lab 2** (chạy được trên **Windows 10/11 và Linux/Ubuntu LTS**), **chạy kiểm thử thật**, và **viết `README.md` đầy đủ** theo thang điểm bên dưới.
> Đọc kỹ toàn bộ file này trước khi viết dòng code đầu tiên. Các mục "CẤM" và mục "Đa nền tảng" là ràng buộc cứng, không được thương lượng.
> **Mọi đường dẫn trong file này đều tính từ thư mục `lab2/`.**

---

## 0. Tóm tắt dự án

| Mục | Nội dung |
| :--- | :--- |
| Tên | **Lab 2 — AES-128 Implementation in Pure C++ (CTR Mode, FIPS-197 Compliant)** |
| Ngôn ngữ | C++17 (chỉ dùng C++ STL cho phần mật mã) |
| Build | **CMake ≥ 3.16** (bắt buộc), `CMakeLists.txt` nằm **bên trong `lab2/`** |
| Hệ điều hành bắt buộc | **Windows 10/11** và **Linux (khuyên dùng Ubuntu LTS 22.04/24.04)** |
| Trình biên dịch | Windows: **MSVC** (VS 2019+) hoặc **MinGW-w64** (GCC ≥ 9). Linux: **GCC ≥ 9 / Clang ≥ 10** |
| Sản phẩm chính | Binary `aestool` (CLI), thư viện `aes` (static lib), unit test, chương trình benchmark `aes_bench`, `README.md`, **binary đã biên dịch cho cả Windows và Linux** |
| Chuẩn | FIPS-197 (AES), NIST SP 800-38A (CTR) |

---

## 1. Ràng buộc CẤM, Fail-Closed & Đa nền tảng

### 1.1 Danh sách CẤM

1. **CẤM dùng thư viện mật mã bên ngoài** (Crypto++, OpenSSL, libsodium, mbedTLS, BoringSSL, …) trong mã nguồn `aestool` và thư viện `aes`. AES, CTR, KeyExpansion, S-box… đều phải **tự viết thủ công**.
   - *Ngoại lệ duy nhất:* **script kiểm thử cross-validation** được gọi `openssl` CLI (hoặc Crypto++) **chỉ để so sánh kết quả**; script này không được link vào binary `aestool`.
2. **CẤM AES-NI / intrinsics phần cứng trong phần cốt lõi.** Chỉ được dùng trong phần Bonus C, đặt ở file riêng, bật bằng tùy chọn CMake `-DAES_ENABLE_AESNI=ON` (mặc định **OFF**).
3. **CẤM tái sử dụng (Key, Nonce/IV)** — lỗi an ninh nghiêm trọng (keystream reuse / two-time pad). CLI phải cảnh báo rõ trong help và README.
4. **CẤM bộ sinh số ngẫu nhiên không an toàn:** không dùng `rand()`, `std::random_device`, `std::mt19937` cho mục đích mật mã. Sinh key/IV (lệnh phụ `keygen`/`ivgen`) phải dùng CSPRNG của hệ điều hành (xem mục 1.3). Lỗi đọc CSPRNG ⇒ fail closed.
5. **CẤM tiếp tục xử lý khi dữ liệu không hợp lệ (Fail-Closed).** Chương trình phải dừng **ngay**, trả exit code ≠ 0, in lỗi ra `stderr`, và **không để lại file output dở dang** khi:
   - Key không đúng **16 bytes**;
   - IV không đúng **16 bytes**;
   - Counter bị **tràn (overflow)**;
   - Lỗi I/O (không mở/đọc/ghi được file, ghi thiếu byte);
   - Tham số CLI thiếu/sai/mode không được hỗ trợ.

### 1.2 Quy tắc phụ (nên làm)

- Ghi output vào file tạm rồi đổi tên khi thành công; khi lỗi thì xóa file tạm.
- Xóa (zeroize) key, round keys, keystream block khỏi bộ nhớ sau khi dùng (ghi qua `volatile` pointer hoặc `SecureZeroMemory` / `explicit_bzero` trong lớp platform).
- Không in key/IV/plaintext ra log.
- Không dùng `using namespace std;` trong header.

### 1.3 YÊU CẦU ĐA NỀN TẢNG (BẮT BUỘC — Windows + Linux)

Dự án **phải biên dịch, chạy và vượt qua toàn bộ test trên cả hai hệ điều hành**. Chỉ chạy được trên một OS = **không đạt yêu cầu**.

**a) Ma trận môi trường hỗ trợ**

| OS | Trình biên dịch | Generator gợi ý |
| :--- | :--- | :--- |
| Ubuntu LTS (22.04 / 24.04) | GCC ≥ 9 và Clang ≥ 10 | Unix Makefiles / Ninja |
| Windows 10/11 | MSVC (Visual Studio 2019/2022) | Visual Studio (multi-config) |
| Windows 10/11 | MinGW-w64 (MSYS2 UCRT64, GCC ≥ 9) | MinGW Makefiles / Ninja |

**b) Quy trình build chuẩn (out-of-source) phải chạy mượt trên cả 2 OS** — chạy từ trong `lab2/`:

```
mkdir build && cd build
cmake ..
cmake --build .
```

*(Windows PowerShell 5.1 không hỗ trợ `&&`: dùng `mkdir build`, `cd build` trên từng dòng; README phải ghi chú điều này.)*

Vì lệnh chuẩn không truyền `CMAKE_BUILD_TYPE`, `CMakeLists.txt` phải **tự đặt mặc định `Release`** cho generator đơn cấu hình (Makefiles/Ninja) để benchmark không bị chạy ở Debug. Với generator đa cấu hình (Visual Studio) dùng `--config Release` / `ctest -C Release`.

**c) `CMakeLists.txt` đặt BÊN TRONG `lab2/`** và phải **tự đóng gói hoàn toàn** (self-contained):
- `cmake_minimum_required(VERSION 3.16)`, `project(lab2_aes LANGUAGES CXX)`, `CMAKE_CXX_STANDARD 17`, `CMAKE_CXX_STANDARD_REQUIRED ON`, `CMAKE_CXX_EXTENSIONS OFF`.
- **Không** tham chiếu `../` hay file nằm ngoài `lab2/`. Có thể build chỉ với thư mục `lab2/`.
- Cờ cảnh báo theo compiler (dùng generator expression hoặc `if(MSVC)`):
  - MSVC: `/W4 /permissive-` (+ `/utf-8`); định nghĩa `_CRT_SECURE_NO_WARNINGS` nếu cần.
  - GCC/Clang/MinGW: `-Wall -Wextra -Wpedantic`.
- **Binary dễ phân phối:**
  - MSVC: link runtime tĩnh (`CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"`) để `aestool.exe` chạy không cần cài VC++ Redistributable.
  - MinGW: `-static` (hoặc `-static-libgcc -static-libstdc++` + `-static`) để không phụ thuộc `libstdc++-6.dll`, `libgcc_s_seh-1.dll`, `libwinpthread-1.dll`.
  - Linux: có thể `-static-libstdc++ -static-libgcc`.
- Đặt thư mục output nhất quán (`CMAKE_RUNTIME_OUTPUT_DIRECTORY` = `${CMAKE_BINARY_DIR}/bin`); với generator đa cấu hình, đường dẫn sẽ có thêm `Release/` — README phải ghi chính xác đường dẫn binary cho từng toolchain.
- Targets: `aes` (static lib), `aestool` (CLI), `aes_bench` (benchmark), `aes_tests` (unit test), tùy chọn `AES_ENABLE_AESNI`.
- `enable_testing()` + `add_test` / `catch_discover_tests` (hoặc `gtest_discover_tests`) để `ctest` chạy được trên cả hai OS. Dùng `$<TARGET_FILE:...>` khi gọi binary trong test, **không** hard-code đường dẫn hay đuôi `.exe`.
- Thư viện test (Catch2/GoogleTest) lấy bằng `FetchContent` (hoặc `find_package` nếu đã có). Đây không phải thư viện mật mã nên được phép.
- Nếu `WIN32`: link `bcrypt` (cho `BCryptGenRandom`). Nếu compiler cũ cần `stdc++fs` thì thêm có điều kiện.
- Cung cấp thêm `CMakePresets.json` (tùy chọn) với preset `linux-gcc`, `linux-clang`, `windows-msvc`, `windows-mingw`.

**d) Quy tắc viết code portable**

1. **Cô lập mã phụ thuộc OS** trong lớp `platform`:
   - `include/aes/platform.hpp` khai báo: `secure_random(uint8_t*, size_t)`, `secure_zero(void*, size_t)`, `atomic_replace_file(tmp, dst)`.
   - `src/platform_posix.cpp` (dùng `getrandom()` hoặc `/dev/urandom`, `explicit_bzero`/volatile) và `src/platform_win.cpp` (dùng `BCryptGenRandom` với `BCRYPT_USE_SYSTEM_PREFERRED_RNG`, `SecureZeroMemory`), chọn trong CMake bằng `if(WIN32)`.
   - `#include <windows.h>` / `<unistd.h>` **chỉ** xuất hiện trong file platform tương ứng; trước khi include `<windows.h>` định nghĩa `NOMINMAX` và `WIN32_LEAN_AND_MEAN`.
2. **I/O nhị phân:** mở file bằng `std::ios::binary` — tuyệt đối không để Windows dịch `\n` ↔ `\r\n` làm hỏng key/IV/ciphertext. Test phải chứng minh byte `0x0A`, `0x0D`, `0x1A`, `0x00` đi qua nguyên vẹn.
3. **Kích thước 64-bit:** dùng `std::uint64_t`/`std::uintmax_t` cho độ dài file và số block. **Không** giả định `long` là 64-bit (trên Windows `long` = 32-bit). File 1 GiB phải chạy đúng trên cả hai OS.
4. **Không phụ thuộc endianness của máy chủ:** thao tác từng byte, không `reinterpret_cast` mảng byte thành `uint32_t/uint64_t` rồi giả định thứ tự byte (counter big-endian tính bằng từng byte).
5. **Chỉ dùng C++17 chuẩn:** không `__int128`, `__builtin_*`, `__attribute__`, VLA, `__declspec` ngoài lớp platform; không gọi `system()`; dùng `std::filesystem` cho đường dẫn/đổi tên/xóa file.
6. **Đường dẫn:** hỗ trợ đường dẫn có **dấu cách** và dấu phân cách `/` lẫn `\`. Có test dùng thư mục tạm có dấu cách.
7. **Đổi tên file nguyên tử:** `atomic_replace_file` phải ghi đè file đích nếu đã tồn tại trên cả POSIX lẫn Windows (`MoveFileExW` + `MOVEFILE_REPLACE_EXISTING`); xử lý lỗi rõ ràng → fail closed.
8. Các test CLI viết **không phụ thuộc shell** (bash/PowerShell): gọi hàm `aes::cli::run(args)` trực tiếp từ test (tách `main.cpp` mỏng + `cli.cpp`), hoặc dùng CMake script mode (`cmake -P`). Không dùng `.sh`/`.bat` trong `ctest` cốt lõi.
9. Thêm `.gitattributes`: `* text=auto`, `*.bin binary`, `*.sh text eol=lf`, `*.ps1 text eol=crlf` — tránh Git làm hỏng file nhị phân và vector.

**e) Xác minh trên cả hai OS**

- `ctest` phải xanh trên **Linux (GCC)**, **Windows (MSVC hoặc MinGW64)**; khuyến nghị thêm Linux (Clang) và cả MSVC lẫn MinGW.
- Khuyến nghị thêm CI: `.github/workflows/lab2-ci.yml` (đặt ở gốc repo, `working-directory: lab2`) với matrix `ubuntu-latest` + `windows-latest`, chạy đúng lệnh build chuẩn, `ctest`, `aestool --kat`, và upload binary làm artifact. CI này là cách tin cậy để lấy kết quả Windows nếu agent đang chạy trên Linux (và ngược lại).
- **Nếu agent chỉ có một OS:** build phần có thể build, thử cross-compile Windows bằng `x86_64-w64-mingw32-g++` (chạy thử qua `wine` nếu có), và **ghi rõ trong README nền tảng nào đã được xác minh thật, nền tảng nào chưa**. **Tuyệt đối không giả mạo kết quả test/benchmark của OS chưa chạy.**

---

## 2. Cấu trúc thư mục yêu cầu

```
<repo>/                          # repo có thể chứa nhiều lab (lab1, lab2, ...)
├── .github/workflows/
│   └── lab2-ci.yml              # (khuyến nghị) matrix ubuntu + windows
└── lab2/                        # ← THƯ MỤC GỐC CỦA BÀI LÀM
    ├── CMakeLists.txt           # ← nằm TRONG lab2/ (self-contained)
    ├── CMakePresets.json        # (tùy chọn)
    ├── .gitattributes
    ├── .gitignore               # build/, *.bin lớn, ...
    ├── README.md                # xem mục 7
    ├── agent.md                 # file này
    ├── include/aes/
    │   ├── aes128.hpp           # API lõi AES-128
    │   ├── ctr.hpp              # chế độ CTR
    │   ├── cli.hpp              # aes::cli::run(args) — để test không cần shell
    │   ├── platform.hpp         # CSPRNG, secure_zero, atomic_replace_file
    │   └── util.hpp             # hex, đọc/ghi file nhị phân
    ├── src/
    │   ├── aes128.cpp           # SubBytes, ShiftRows, MixColumns, AddRoundKey, KeyExpansion
    │   ├── sbox_table.cpp       # S-box dạng bảng tra
    │   ├── sbox_computed.cpp    # S-box tính bằng công thức (GF(2^8) inverse + affine)
    │   ├── ctr.cpp
    │   ├── util.cpp
    │   ├── platform_posix.cpp   # Linux/macOS
    │   ├── platform_win.cpp     # Windows
    │   ├── kat_runner.cpp       # chạy --kat vectors.json
    │   ├── cli.cpp
    │   └── main.cpp             # mỏng: gọi aes::cli::run
    ├── bench/
    │   └── aes_bench.cpp        # benchmark portable (std::chrono::steady_clock)
    ├── bonus/                   # chỉ tạo nếu làm bonus
    │   ├── aes_ext.cpp          # AES-192/256
    │   ├── xts.cpp              # AES-XTS
    │   └── aesni.cpp            # AES-NI (OFF mặc định)
    ├── tests/
    │   ├── CMakeLists.txt
    │   ├── test_aes_core.cpp    # KAT FIPS-197
    │   ├── test_ctr.cpp         # KAT NIST SP 800-38A + edge cases
    │   ├── test_negative.cpp    # key sai, iv sai, bit-flip, overflow, I/O error
    │   └── test_portability.cpp # byte 0x0A/0x0D/0x1A, đường dẫn có dấu cách, file > 2^31 byte (tùy chọn)
    ├── vectors/vectors.json     # test vectors cho --kat
    ├── scripts/
    │   └── cross_validate.py    # so khớp với `openssl enc -aes-128-ctr` (chạy được Win + Linux)
    ├── dist/                    # BINARY NỘP BÀI (xem mục 6)
    │   ├── linux-x86_64/aestool        (+ aestool.sha256)
    │   └── windows-x86_64/aestool.exe  (+ aestool.exe.sha256)
    └── docs/results/
        ├── linux/               # log benchmark, ctest, sysinfo
        └── windows/
```

> Toàn bộ lệnh trong README đều chạy từ `lab2/`: `cd lab2` → `mkdir build && cd build` → `cmake ..` → `cmake --build .`.

---

## 3. Đặc tả triển khai

### 3.1 Lõi AES-128 (FIPS-197) — 30 điểm

- Block 16 bytes, key 16 bytes, **10 vòng**, state dạng ma trận 4×4 **theo thứ tự cột (column-major)** đúng chuẩn.
- Tự viết 5 hàm, mỗi hàm có comment ghi rõ tham chiếu mục trong FIPS-197:
  1. `AddRoundKey` — XOR state với round key.
  2. `SubBytes` — thay từng byte qua S-box.
  3. `ShiftRows` — dịch vòng hàng i sang trái i byte.
  4. `MixColumns` — nhân ma trận cố định trên GF(2⁸), đa thức bất khả quy `x⁸ + x⁴ + x³ + x + 1` (0x11B). Dùng hàm `xtime`.
  5. `KeyExpansion` — sinh 11 round key (176 bytes) với `RotWord`, `SubWord`, `Rcon`.
- Chỉ cần chiều **mã hóa block** cho CTR. Nên cài thêm `InvCipher` nếu làm bonus/XTS hoặc để test đầy đủ, nhưng không bắt buộc.
- Hai bản S-box hoán đổi qua cấu hình (`SBoxMode::Table | Computed`) để benchmark:
  - **Table-based:** mảng 256 byte hằng.
  - **Computed:** tính nghịch đảo trong GF(2⁸) (0 ↦ 0) rồi áp phép affine `b ⊕ rotl(b,1) ⊕ rotl(b,2) ⊕ rotl(b,3) ⊕ rotl(b,4) ⊕ 0x63`. Ghi chú trong code rằng cài đặt này **chưa chắc constant-time** nếu có nhánh/lookup phụ thuộc dữ liệu; nếu có thể, viết nghịch đảo không rẽ nhánh theo bí mật (lũy thừa x²⁵⁴ bằng phép nhân GF không điều kiện).
- Hai bản S-box phải cho **kết quả giống hệt nhau** trên cả 256 giá trị (có unit test).

### 3.2 Chế độ CTR (NIST SP 800-38A) — 15 điểm

Công thức:

```
S_i = AES_K( CounterBlock_i )
C_i = P_i XOR S_i        P_i = C_i XOR S_i
```

Quyết định thiết kế **bắt buộc ghi vào README** (mục Endianness & Overflow):

- **IV = 16 bytes = CounterBlock khởi tạo** (Nonce ‖ Counter), phù hợp NIST SP 800-38A F.5.1 và `openssl enc -aes-128-ctr`.
- **Endianness:** bộ đếm tăng theo **big-endian** trên **toàn bộ 128 bit** (byte 15 là byte thấp nhất, carry lan lên byte 14, 13, …). Cài đặt từng byte nên kết quả **giống nhau trên mọi máy/OS**.
- **Counter overflow:** nếu tăng counter gây **carry ra khỏi bit 128** (đã dùng hết `0xFF…FF` mà vẫn còn dữ liệu) ⇒ **fail closed**: dừng, báo lỗi, xóa output. Không wrap về 0 âm thầm.
- **Block lẻ cuối cùng:** XOR với `min(16, còn lại)` byte đầu của keystream, **không padding**; ciphertext dài bằng plaintext.
- File rỗng (0 byte) ⇒ output rỗng, exit code 0.
- **Streaming** theo chunk (ví dụ 1 MiB) để file 1 GiB không cần nạp hết vào RAM.
- Encrypt và decrypt dùng chung hàm lõi; CLI vẫn phân biệt 2 lệnh.

### 3.3 CLI — `aestool`

```
aestool encrypt --mode ctr --key key.bin --iv iv.bin --in msg.bin --out ct.bin
aestool decrypt --mode ctr --key key.bin --iv iv.bin --in ct.bin  --out msg.bin
aestool --kat vectors/vectors.json
aestool keygen --out key.bin          # tùy chọn: 16 byte từ CSPRNG hệ điều hành
aestool ivgen  --out iv.bin           # tùy chọn: 16 byte từ CSPRNG hệ điều hành
aestool --help
```

- Mọi file là **nhị phân thô** (key và iv đúng 16 byte, không hex, không newline).
- Chỉ `--mode ctr` được hỗ trợ (và `xts` nếu làm bonus). Mode khác ⇒ lỗi.
- Exit code: `0` thành công; `1` lỗi tham số; `2` lỗi key/iv; `3` lỗi I/O; `4` counter overflow; `5` KAT thất bại. (Ghi trong README.) Mã thoát và thông báo lỗi phải **giống nhau trên Windows và Linux**.
- Cảnh báo trong `--help`: *không bao giờ dùng lại cùng một cặp (key, IV).*

### 3.4 `--kat vectors.json`

Tự viết parser JSON tối giản (không dùng thư viện ngoài) cho schema phẳng sau:

```json
{
  "aes128_block": [
    { "name": "FIPS-197 C.1",
      "key": "000102030405060708090a0b0c0d0e0f",
      "plaintext": "00112233445566778899aabbccddeeff",
      "ciphertext": "69c4e0d86a7b0430d8cdb78070b4c55a" },
    { "name": "FIPS-197 B",
      "key": "2b7e151628aed2a6abf7158809cf4f3c",
      "plaintext": "3243f6a8885a308d313198a2e0370734",
      "ciphertext": "3925841d02dc09fbdc118597196a0b32" }
  ],
  "aes128_ctr": [
    { "name": "NIST SP 800-38A F.5.1",
      "key": "2b7e151628aed2a6abf7158809cf4f3c",
      "iv":  "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
      "plaintext":  "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
      "ciphertext": "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee" }
  ]
}
```

> Các vector là vector chính thức từ FIPS-197 (App. B, C.1) và NIST SP 800-38A (F.5.1). **Đối chiếu lại** với bản gốc trước khi chốt. Thêm vector độ dài lẻ (cắt plaintext còn 1, 15, 17, 33 byte — ciphertext là tiền tố tương ứng).
> File `vectors.json` phải đọc đúng cả khi có `\r\n` (Windows checkout) — parser bỏ qua `\r`.

`--kat` in `PASS`/`FAIL` cho từng vector, exit `0` nếu tất cả pass, ≠ 0 nếu có bất kỳ fail.

---

## 4. Kiểm thử & Xác minh

### 4.1 Unit test (Catch2 hoặc GoogleTest) — chạy qua `ctest` trên **cả Windows lẫn Linux**

Lệnh chạy:

```
# Linux / MinGW (generator đơn cấu hình)
ctest --output-on-failure
# Windows MSVC (đa cấu hình)
ctest -C Release --output-on-failure
```

Test tối thiểu:

- KAT FIPS-197 (App. B, C.1); KeyExpansion kiểm tra round key theo FIPS-197 App. A.1.
- Từng biến đổi riêng lẻ (`SubBytes`, `ShiftRows`, `MixColumns`, `AddRoundKey`) với state đã biết.
- S-box table == S-box computed (256/256).
- CTR KAT NIST SP 800-38A F.5.1 (encrypt và decrypt).
- CTR độ dài: 0, 1, 15, 16, 17, 31, 32, 33 byte; biên chunk (1 MiB ± 1 byte).
- Round-trip `decrypt(encrypt(x)) == x` với dữ liệu giả ngẫu nhiên (PRNG tự viết kiểu SplitMix64/xorshift **chỉ để tạo dữ liệu test**, ghi chú rõ không phải mật mã).
- Carry counter: IV kết thúc `...00ff`, `...ffff`; tăng qua biên byte.
- **Overflow:** IV = `ff×16` + dữ liệu ≤ 16 byte ⇒ OK; > 16 byte ⇒ lỗi overflow, không có file output.
- **Portability:** dữ liệu chứa `0x0A 0x0D 0x1A 0x00` đi qua encrypt→decrypt nguyên vẹn; đường dẫn có dấu cách; ghi đè file output đã tồn tại.

### 4.2 Negative testing (kèm giải thích trong báo cáo)

| Kịch bản | Kỳ vọng |
| :--- | :--- |
| Key file ≠ 16 byte (0, 15, 17, 32) | Fail closed, exit ≠ 0, không tạo output |
| IV file ≠ 16 byte | Fail closed |
| File input không tồn tại / không đọc được | Fail closed |
| Output không ghi được (thư mục không tồn tại/read-only) | Fail closed |
| **Giải mã bằng key sai** | Không báo lỗi, ra rác (CTR không xác thực) |
| **Giải mã bằng IV sai** | Không báo lỗi, ra rác |
| **Lật 1 bit ciphertext** | Giải mã thành công; plaintext **chỉ lật đúng bit tương ứng** (malleability) — chứng minh bằng test |

### 4.3 Cross-validation (`scripts/cross_validate.py`)

- Script Python 3 chạy được trên cả Windows (`py` / `python`) lẫn Linux (`python3`), gọi `openssl` CLI qua `subprocess` (không `shell=True`, không phụ thuộc bash).
- Với nhiều kích thước (0, 1, 15, 16, 17, 1000, 1 MiB) và key/iv ngẫu nhiên (`os.urandom` — chỉ trong script test):
  ```
  openssl enc -aes-128-ctr -K <hex_key> -iv <hex_iv> -in msg.bin -out ref.bin
  aestool encrypt --mode ctr --key key.bin --iv iv.bin --in msg.bin --out ct.bin
  # so sánh byte-by-byte: ref.bin == ct.bin
  ```
- Yêu cầu **khớp 100%** trên **cả Windows và Linux**. Ghi lại phiên bản OpenSSL (`openssl version`) trên từng OS. Nếu Windows không có OpenSSL, dùng bản Git for Windows / MSYS2 / vcpkg, hoặc Crypto++/Python `cryptography` **chỉ trong script**, và nói rõ trong README.
- Đăng ký vào `ctest` qua `add_test` chỉ khi tìm được `python` và `openssl` (`find_program`); nếu thiếu thì test báo **SKIPPED có thông báo rõ ràng** (`SKIP_RETURN_CODE`), **không được âm thầm pass**.

---

## 5. Benchmark & Phân tích hiệu năng (gồm so sánh Windows vs Linux) — 10 điểm

### 5.1 Chương trình `aes_bench` (portable)

- Viết bằng C++17, dùng `std::chrono::steady_clock`; **không** dùng `time`, `dd`, PowerShell `Measure-Command` làm nguồn số liệu chính (để khỏi chênh lệch do công cụ).
- Tham số: `--sizes 1MiB,100MiB,1GiB --runs 5 --sbox table|computed|both --csv out.csv --workdir <dir>`.
- Tự tạo file thử nghiệm (dữ liệu giả ngẫu nhiên SplitMix64/xorshift — không phải mật mã), tự xóa sau khi đo. Không commit file lớn vào repo.
- Đo **hai chế độ**:
  1. **Compute-only (in-memory):** mã hóa buffer trong RAM → throughput thuần thuật toán.
  2. **End-to-end (file → file)** qua đúng đường code của CLI → gồm I/O, system calls, page cache.
- Mỗi cấu hình: 1 lần warm-up (bỏ), **≥ 5 lần đo**, báo cáo **trung vị, min, max**. Throughput = `bytes / (1024² × giây)` **MiB/s** (ghi rõ trong README là MiB/s hay MB/s và dùng nhất quán).
- Xuất CSV với cột: `os, compiler, compiler_version, build_type, sbox, mode(compute|e2e), size_bytes, run, seconds, mib_per_s`. Tên OS/compiler lấy từ macro (`_WIN32`, `__linux__`, `_MSC_VER`, `__GNUC__`, `__clang__`, `__MINGW64__`).

### 5.2 Quy trình đo trên từng OS

1. Build **Release** (`-O2` / `/O2`) trên mỗi OS/toolchain; ghi cờ biên dịch thực tế.
2. Lưu thông tin máy vào `docs/results/<os>/sysinfo.txt` (CPU model, số nhân, RAM, OS version, compiler version, loại ổ đĩa/filesystem, power plan hoặc CPU governor). Lệnh gợi ý: Linux `lscpu`, `free -h`, `lsb_release -a`; Windows `systeminfo`, `Get-CimInstance Win32_Processor`.
3. Lưu log thô + CSV vào `docs/results/linux/` và `docs/results/windows/`.
4. **Điều kiện công bằng:** cùng kích thước file, cùng buffer/chunk size, cùng `--runs`, cùng S-box; nếu có thể dùng **cùng một máy** (dual-boot) hoặc 2 máy cùng CPU. Nếu chạy trong VM/WSL/CI runner, **ghi rõ** (WSL2 và runner CI ≠ native). Với Windows nên đo **cả MSVC và MinGW64**; Linux đo **GCC (và Clang nếu có)** để tách ảnh hưởng của *compiler* khỏi ảnh hưởng của *OS*.
5. Đo thêm kịch bản "cold cache" vs "warm cache" cho chế độ e2e nếu khả thi (ghi rõ cách làm), hoặc ít nhất nêu rõ file nằm trong page cache hay không.
6. **TUYỆT ĐỐI KHÔNG BỊA SỐ.** Mọi con số trong README phải lấy từ lần chạy thật. Không chạy được (thiếu dung lượng cho 1 GiB, không có máy Windows…) ⇒ ghi "chưa đo" + lý do.

### 5.3 Nội dung phân tích bắt buộc trong báo cáo

- **Table S-box vs Computed S-box:** bảng throughput, giải thích vì sao bản tra bảng nhanh hơn (hoặc không) và đánh đổi về bảo mật (cache-timing).
- **So sánh Windows vs Linux:** bảng 3 kích thước × (Linux GCC, Windows MSVC, Windows MinGW64) × (compute-only, e2e), kèm tỉ lệ chênh lệch (%). Phân tích các yếu tố, **chỉ khẳng định những gì có bằng chứng từ số đo**:
  - **OS scheduling:** thời gian CPU bị ngắt/chuyển ngữ cảnh, độ dao động giữa các lần chạy (min–max), ảnh hưởng của tiến trình nền, mức ưu tiên, CPU governor (Linux) / power plan (Windows), turbo/thermal throttling.
  - **System calls & I/O:** `read`/`write` (Linux) vs `ReadFile`/`WriteFile` (Windows, qua lớp CRT/`std::fstream`), chi phí mỗi syscall, ảnh hưởng của kích thước chunk; buffering của C++ stream.
  - **Page cache / file system cache:** ext4 vs NTFS, hành vi write-back, khác biệt cold vs warm cache; antivirus real-time scanning (Windows Defender) có thể làm chậm I/O.
  - **Cache CPU & bộ nhớ:** L1/L2/L3, kích thước S-box 256 B nằm trọn trong L1, working set của buffer, alignment, hardware prefetch.
  - **Compiler/runtime:** khác biệt tối ưu hóa giữa GCC/Clang/MSVC (inline, unroll, vectorize), runtime tĩnh vs động.
- Kết luận: nút thắt là compute hay I/O ở từng kích thước; vì sao chênh lệch compute-only nhỏ trong khi e2e có thể lớn hơn.

---

## 6. Đóng gói & Nộp bài (binary cho cả hai OS)

Sản phẩm nộp **bắt buộc có file chạy đã biên dịch cho cả Windows và Linux**:

```
lab2/dist/
├── linux-x86_64/
│   ├── aestool                  # build trên Ubuntu LTS (ghi rõ phiên bản + GCC/Clang)
│   └── aestool.sha256
└── windows-x86_64/
    ├── aestool.exe              # build Release, runtime tĩnh (chạy không cần DLL phụ)
    └── aestool.exe.sha256
```

- Binary phải là bản **Release** build từ đúng mã nguồn nộp. Ghi trong README: OS/compiler/phiên bản/cờ biên dịch và checksum SHA-256 của từng binary.
- Windows binary phải chạy được trên máy Windows 10/11 sạch (kiểm tra bằng `dumpbin /dependents aestool.exe` hoặc `objdump -p aestool.exe | findstr "DLL Name"`; chỉ được phụ thuộc DLL hệ thống như `KERNEL32.dll`, `bcrypt.dll`, `msvcrt.dll`/`ucrtbase`/`api-ms-win-crt-*`).
- Linux binary: kiểm tra bằng `ldd aestool` (chỉ phụ thuộc `libc`, `libm`, và các lib hệ thống cơ bản).
- Có thể thêm target CMake `package` hoặc script `scripts/package_dist.py` để sao chép binary + tạo checksum.
- Gói nộp cuối (zip) gồm: mã nguồn, `CMakeLists.txt`, `README.md`, `vectors/`, `tests/`, `scripts/`, `dist/`, `docs/results/` — **không** gồm thư mục `build/` và file test lớn.
- Nếu agent không thể tự build binary của OS còn lại: **không** được tạo file giả; để trống thư mục kèm `dist/README_MISSING.txt` nêu lý do và hướng dẫn lệnh build, đồng thời đánh dấu ❌ trong Rubric Checklist (hoặc ⚠️ nếu build qua CI artifact đã xác minh).

---

## 7. Phân tích An toàn Mật mã (nội dung bắt buộc của báo cáo) — 20 điểm

README phải có phần riêng bàn luận sâu (không chỉ liệt kê), tối thiểu gồm:

1. **Rò rỉ kênh bên (side-channel):**
   - Timing leakage từ tra bảng S-box phụ thuộc dữ liệu bí mật (cache hit/miss).
   - Cache attacks (Prime+Probe, Flush+Reload, cache-collision) và **T-table** (4 bảng 1 KiB — vì sao AES phần mềm dễ bị tấn công).
   - Đánh giá bản của bạn: table-based **không constant-time**; computed S-box có cải thiện không và vì sao (hoặc vì sao chưa đủ).
   - Biện pháp giảm thiểu: bit-slicing, AES-NI, constant-time S-box, tránh truy cập bộ nhớ phụ thuộc bí mật.
2. **Vì sao CTR chỉ cung cấp bảo mật (confidentiality) chứ không cung cấp tính xác thực/toàn vẹn (authenticity):**
   - Malleability: lật bit ở ciphertext ⇒ lật đúng bit ở plaintext; kẻ tấn công có thể sửa có chủ đích nếu biết/đoán plaintext. Dẫn chứng từ negative test.
   - Không có thẻ xác thực ⇒ phía nhận không thể phát hiện sửa đổi.
   - Giải pháp: kết hợp MAC theo **Encrypt-then-MAC** (HMAC-SHA-256 hoặc CMAC) hoặc dùng AEAD (**AES-GCM**, ChaCha20-Poly1305). MAC dùng khóa riêng/dẫn xuất riêng và bao phủ cả IV + ciphertext.
3. **Hậu quả tái sử dụng (Key, IV):** `C1 ⊕ C2 = P1 ⊕ P2` — minh họa ngắn gọn (demo bằng 2 file nhỏ).
4. **Quản lý IV/Nonce:** sinh từ CSPRNG hoặc bộ đếm đảm bảo duy nhất; tránh va chạm; giới hạn số block/khóa.
5. **Endianness và Counter overflow:** nêu lựa chọn thiết kế (mục 3.2) và lý do fail closed; nhấn mạnh kết quả **không phụ thuộc endianness của máy** nên giống nhau trên Windows/Linux.
6. **CSPRNG đa nền tảng:** `getrandom()`/`/dev/urandom` vs `BCryptGenRandom`; vì sao không dùng `rand()`/`std::random_device`/`mt19937`.
7. **Fail-closed & xử lý lỗi:** vì sao không được xử lý tiếp dữ liệu không hợp lệ.
8. **Hạn chế còn tồn tại** (không có kiểm tra toàn vẹn, không constant-time, không có KDF cho key từ mật khẩu, …) — trung thực về giới hạn.

---

## 8. Yêu cầu nội dung `README.md` (map theo thang điểm)

README viết bằng **tiếng Việt**, rõ ràng, có mục lục. Cấu trúc bắt buộc (**13 mục**):

```
# Lab 2 — AES-128 (CTR Mode) bằng C++ thuần
## 1. Giới thiệu
## 2. Tính năng & Phạm vi
## 3. Ràng buộc & Quy tắc an toàn (Bans & Constraints)
## 4. Cấu trúc dự án
## 5. Yêu cầu hệ thống, Build & Chạy (Windows + Linux)
   ### 5.1 Yêu cầu hệ thống & ma trận nền tảng được hỗ trợ
   ### 5.2 Linux (Ubuntu LTS) — GCC/Clang
   ### 5.3 Windows — MSVC
   ### 5.4 Windows — MinGW-w64 (MSYS2)
   ### 5.5 Chạy nhanh: keygen → encrypt → decrypt → so sánh
   ### 5.6 Binary dựng sẵn (dist/), checksum và cách kiểm tra
## 6. Thiết kế & Triển khai
   ### 6.1 Lõi AES-128 (FIPS-197)
   ### 6.2 Chế độ CTR (NIST SP 800-38A)
   ### 6.3 Endianness & Counter overflow
   ### 6.4 CLI & Định dạng I/O
   ### 6.5 Thiết kế đa nền tảng (lớp platform, I/O nhị phân, CSPRNG)
## 7. Kiểm thử & Xác minh
   ### 7.1 KATs (--kat)
   ### 7.2 Cross-validation với OpenSSL/Crypto++
   ### 7.3 Negative testing
   ### 7.4 Unit test (ctest) — kết quả trên Linux và Windows
   ### 7.5 Ma trận xác minh nền tảng
## 8. Đánh giá hiệu năng
   ### 8.1 Phương pháp đo
   ### 8.2 Kết quả Linux
   ### 8.3 Kết quả Windows
   ### 8.4 So sánh Windows vs Linux & phân tích (scheduling, syscalls, cache…)
   ### 8.5 Table S-box vs Computed S-box
## 9. Thảo luận An toàn Mật mã
## 10. Bonus (nếu có)
## 11. Bảng đối chiếu thang điểm (Rubric Checklist)
## 12. Hạn chế & Hướng phát triển
## 13. Tài liệu tham khảo
```

### Chi tiết từng mục

**1. Giới thiệu** — Bối cảnh (AES là gì, chuẩn FIPS-197, vì sao cần chế độ vận hành, CTR biến block cipher thành stream cipher), mục tiêu lab, điểm nổi bật (tự cài đặt hoàn toàn, fail-closed, 2 kiểu S-box, **chạy trên cả Windows và Linux**). Có sơ đồ ASCII hoặc Mermaid của luồng CTR.

**3. Ràng buộc** — Liệt kê đủ 5 điều CẤM ở mục 1.1, nêu cách dự án tuân thủ từng điều (kèm vị trí trong code).

**5. Yêu cầu hệ thống, Build & Chạy** — phải có **lệnh riêng, đầy đủ cho từng nền tảng**, chạy từ `lab2/`:

Linux (Ubuntu LTS):
```bash
sudo apt update && sudo apt install -y build-essential cmake python3 openssl
cd lab2
mkdir build && cd build
cmake ..
cmake --build . -j
ctest --output-on-failure
./bin/aestool --kat ../vectors/vectors.json
```

Windows — MSVC (mở *x64 Native Tools Command Prompt for VS* hoặc *Developer PowerShell*; cần Visual Studio 2019/2022 với workload "Desktop development with C++" và CMake):
```bat
cd lab2
mkdir build && cd build
cmake ..
cmake --build . --config Release
ctest -C Release --output-on-failure
bin\Release\aestool.exe --kat ..\vectors\vectors.json
```

Windows — MinGW-w64 (MSYS2 UCRT64: `pacman -S mingw-w64-ucrt-x86_64-gcc mingw-w64-ucrt-x86_64-cmake mingw-w64-ucrt-x86_64-ninja`):
```bash
cd lab2
mkdir build && cd build
cmake .. -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release
cmake --build .
ctest --output-on-failure
./bin/aestool.exe --kat ../vectors/vectors.json
```

Ghi chú bắt buộc trong README: (i) PowerShell 5.1 không có `&&`; (ii) đường dẫn binary thực tế của từng toolchain; (iii) cách cài OpenSSL/Python cho cross-validation trên Windows; (iv) cách xử lý lỗi thường gặp (thiếu CMake, thiếu Developer prompt, không tải được Catch2/GoogleTest do mạng). Đã được kiểm tra thật hay chưa phải phản ánh trung thực ở mục 7.5.

**7.5 Ma trận xác minh nền tảng** — bảng *(chỉ đánh ✅ khi đã chạy thật)*:

| Nền tảng | Build | ctest | `--kat` | Cross-validation | Benchmark |
| :--- | :---: | :---: | :---: | :---: | :---: |
| Ubuntu LTS + GCC | | | | | |
| Ubuntu LTS + Clang | | | | | |
| Windows + MSVC | | | | | |
| Windows + MinGW-w64 | | | | | |

**8. Hiệu năng** — Theo mục 5: bảng throughput thật (3 kích thước × S-box × OS/compiler × compute/e2e), cấu hình máy, nhận xét và phân tích so sánh Windows vs Linux. **Chỉ điền số đo thật.**

**11. Rubric Checklist** — bảng có cột *Hạng mục · Điểm · Bằng chứng (file/test/log) · Trạng thái (✅/⚠️/❌)*:

| Hạng mục | Điểm |
| :--- | :--- |
| Lõi AES-128 chuẩn FIPS-197 chính xác | 30 |
| Chế độ CTR triển khai chính xác | 15 |
| Đạt KATs & Cross-validation với OpenSSL/Crypto++ | 15 |
| Chất lượng lập trình & Tài liệu hóa | 10 |
| Thực nghiệm & Phân tích hiệu năng (gồm so sánh Windows vs Linux) | 10 |
| Thảo luận An toàn Mật mã trong Báo cáo | 20 |
| Bonus A: AES-192 / AES-256 | +10 |
| Bonus B: AES-XTS | +5 |
| Bonus C: AES-NI / Bit-sliced | +5 |

Thêm một mục **"Điều kiện bắt buộc chung (không tính điểm riêng nhưng thiếu là không đạt)"**: CMake build trên Windows + Linux · `ctest` pass cả hai OS · binary Windows + Linux có trong `dist/` · README có hướng dẫn riêng cho từng OS · so sánh hiệu năng Windows vs Linux. Trạng thái phải **trung thực**, dựa trên kết quả chạy thật.

---

## 9. Bonus (làm sau khi phần bắt buộc đã xong và pass hết trên cả hai OS)

- **A — AES-192/256 (+10):** mở rộng KeyExpansion (Nk = 6/8; số vòng 12/14), key 24/32 byte; KAT FIPS-197 C.2, C.3; CLI `--bits 128|192|256` (mặc định 128); fail closed nếu độ dài key không khớp.
- **B — AES-XTS (+5):** theo IEEE 1619 / NIST SP 800-38E; key kép; ciphertext stealing cho block lẻ; KAT từ IEEE 1619; nhắc XTS dành cho mã hóa đĩa.
- **C — AES-NI / Bit-sliced (+5):** AES-NI qua intrinsics (`<wmmintrin.h>`) trong `bonus/aesni.cpp`, **portable giữa MSVC/GCC/Clang** (kiểm tra cờ `-maes -msse4.1` / `/arch:AVX` hoặc `__attribute__((target("aes")))` có điều kiện), chọn lúc runtime bằng CPUID (`__cpuid` trên MSVC, `<cpuid.h>` trên GCC/Clang); **bắt buộc** cho kết quả giống bản phần mềm (test so khớp); benchmark riêng trên cả hai OS.

Tất cả bonus nằm tách biệt để không vi phạm quy tắc "lõi chạy hoàn toàn bằng phần mềm"; build mặc định **không** chứa AES-NI.

---

## 10. Quy trình làm việc đề xuất cho Agent

1. **Khởi tạo** `lab2/`, `CMakeLists.txt` (trong `lab2/`), cấu trúc thư mục, `.gitignore`, `.gitattributes`, (khuyến nghị) CI matrix ubuntu + windows.
2. **Lớp platform** (`platform_posix.cpp` / `platform_win.cpp`) + I/O nhị phân + atomic replace.
3. **Lõi AES:** S-box (table), `KeyExpansion`, 4 phép biến đổi vòng, `encrypt_block`. Pass KAT FIPS-197 **trước khi** làm tiếp.
4. **S-box computed** + test tương đương với table.
5. **CTR** streaming + counter big-endian 128-bit + overflow fail-closed. Pass KAT NIST F.5.1.
6. **CLI** (`cli.cpp` + `main.cpp` mỏng) + exit code + fail-closed.
7. **`--kat`** + `vectors.json`.
8. **Unit test + negative + portability test**, đăng ký vào `ctest`.
9. **Build thử bằng lệnh chuẩn** (`mkdir build && cd build && cmake .. && cmake --build .`) trên mọi OS/compiler có thể; sửa warning/lỗi đặc thù compiler.
10. **Cross-validation** (`cross_validate.py`) trên mỗi OS; lưu log.
11. **`aes_bench`**: đo thật trên mỗi OS; lưu CSV + sysinfo vào `docs/results/<os>/`.
12. **Đóng gói `dist/`** (binary Windows + Linux, checksum, kiểm tra phụ thuộc DLL/so).
13. **Viết README** theo mục 8, điền số liệu thật, hoàn thiện ma trận nền tảng, phân tích Windows vs Linux và thảo luận an toàn.
14. **Bonus** (tùy chọn).
15. **Tự rà soát** bằng checklist mục 11.

Nếu một bước thất bại, **sửa và chạy lại** — không che giấu bằng cách bỏ test hoặc sửa vector cho khớp output sai.

---

## 11. Checklist hoàn thành (Definition of Done)

**Ràng buộc mật mã**
- [ ] `grep -r -i -E "openssl|cryptopp|crypto\+\+|sodium|mbedtls" src include bench` không thấy include/link thư viện mật mã (trừ comment).
- [ ] Không có `rand(`, `random_device`, `mt19937` trong luồng sinh key/IV.
- [ ] Không có AES-NI/intrinsics trong `src/` và `include/` (chỉ trong `bonus/`).
- [ ] Mọi kịch bản fail-closed (mục 4.2) dừng đúng và không để lại output dở.

**Đa nền tảng**
- [ ] `CMakeLists.txt` nằm trong `lab2/`, không tham chiếu ngoài thư mục `lab2/`.
- [ ] `mkdir build && cd build && cmake .. && cmake --build .` chạy được trên **Ubuntu (GCC)** và **Windows (MSVC và/hoặc MinGW64)**.
- [ ] `ctest` xanh 100% trên **cả Windows lẫn Linux**; `aestool --kat vectors/vectors.json` exit 0 trên cả hai.
- [ ] Không có `#include <windows.h>` / `<unistd.h>` ngoài file platform; không có `long` dùng cho kích thước file.
- [ ] Byte `0x0A/0x0D/0x1A` đi qua nguyên vẹn trên Windows (I/O nhị phân).
- [ ] Cross-validation khớp 100% trên cả hai OS (hoặc ghi rõ lý do chưa chạy).
- [ ] `dist/` có binary Linux **và** Windows + checksum; Windows binary không phụ thuộc DLL ngoài hệ thống.

**Hiệu năng & tài liệu**
- [ ] Mã hóa/giải mã file 1 GiB với bộ nhớ ổn định (streaming) trên cả hai OS.
- [ ] Có số đo thật cho 1 MiB / 100 MiB / 1 GiB, Table vs Computed, **Windows vs Linux**, kèm sysinfo.
- [ ] README đủ 13 mục, có hướng dẫn build riêng cho Windows và Linux, ma trận xác minh nền tảng trung thực, rubric checklist trung thực.
- [ ] Code có comment tham chiếu FIPS-197/SP 800-38A, build sạch không warning ở `/W4` và `-Wall -Wextra -Wpedantic`.

---

## 12. Quy tắc ứng xử của Agent

- **Trung thực tuyệt đối:** không bịa kết quả test, số benchmark hay trạng thái pass — đặc biệt với nền tảng bạn **chưa thực sự chạy**.
- **Không đi đường tắt vi phạm ràng buộc** (ví dụ gọi OpenSSL trong `aestool` "cho nhanh", hoặc dùng `#ifdef` rải rác thay cho lớp platform).
- Khi gặp mơ hồ, chọn phương án **an toàn hơn** (fail closed) và ghi lại quyết định trong README.
- Báo cáo cuối cùng cho người dùng: tóm tắt ngắn những gì đã làm, kết quả `ctest`/KAT/cross-validation **theo từng OS/compiler**, các hạng mục chưa hoàn thành hoặc chưa xác minh được.