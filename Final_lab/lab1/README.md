# aestool – Lab 1: Mã hóa đối xứng AES với Crypto++

Công cụ dòng lệnh C++17 hỗ trợ AES **ECB, CBC, OFB, CFB, CTR, XTS, CCM (AEAD), GCM (AEAD)**, có KAT runner (vector NIST), benchmark, kiểm tra chống dùng sai (ECB, IV/nonce, tái sử dụng nonce) và (tùy chọn) thư viện `.dll/.so/.a/.lib` + GUI Python.

> Hướng dẫn chạy từng bước trong terminal: xem **[GUIDE.md](GUIDE.md)**.

## 1. Dependency

| Thành phần | Phiên bản mục tiêu | Ghi chú |
|---|---|---|
| Crypto++ | ≥ 8.2 (khuyến nghị 8.6–8.9) | thư viện mật mã DUY NHẤT được dùng |
| CMake | ≥ 3.16 | bắt buộc |
| Trình biên dịch | GCC ≥ 9 (Ubuntu 20.04/22.04/24.04), MSVC 2019+ (VS 16/17), MinGW-w64 GCC ≥ 9 | cần C++17 + `<filesystem>` |
| Catch2 | 3.x | cho unit test; tự tải nếu thiếu (`AESTOOL_FETCH_DEPS=ON`) |
| Python | ≥ 3.8 (+ `matplotlib` cho vẽ đồ thị, `tkinter` cho GUI) | tùy chọn |

Không dùng OpenSSL, libsodium hay thư viện mật mã nào khác. Ngẫu nhiên chỉ dùng `AutoSeededRandomPool`.

## 2. Cài đặt dependency

**Ubuntu**
```bash
sudo apt update
sudo apt install -y build-essential cmake git libcrypto++-dev
```

**Windows – MSVC (vcpkg)**
```powershell
git clone https://github.com/microsoft/vcpkg C:\vcpkg
C:\vcpkg\bootstrap-vcpkg.bat
C:\vcpkg\vcpkg install cryptopp:x64-windows catch2:x64-windows
```

**Windows – MinGW64 (MSYS2, shell "MSYS2 MINGW64")**
```bash
pacman -S --needed mingw-w64-x86_64-gcc mingw-w64-x86_64-cmake mingw-w64-x86_64-ninja \
          mingw-w64-x86_64-crypto++ mingw-w64-x86_64-catch git
```

Nếu không tìm thấy Crypto++/Catch2 trên máy, CMake tự tải và build chúng (cần `git` + internet; tắt bằng `-DAESTOOL_FETCH_DEPS=OFF`).

## 3. Build (out-of-source)

**Ubuntu / MinGW**
```bash
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release        # MinGW: thêm -G Ninja
cmake --build . -j
ctest --output-on-failure
```

**Windows MSVC (Developer PowerShell for VS)**
```powershell
mkdir build; cd build
cmake .. -DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake
cmake --build . --config Release
ctest -C Release --output-on-failure
```

Kết quả nằm trong `build/bin/` (`aestool`, `aescore.dll`/`libaescore.so`, `aescore_tests`) và `build/lib/` (`aescore_static.a/.lib`).
Tuỳ chọn CMake: `-DAESTOOL_BUILD_TESTS=OFF`, `-DAESTOOL_BUILD_SHARED=OFF`, `-DAESTOOL_FETCH_DEPS=OFF`.

## 4. Ví dụ sử dụng

```bash
aestool keygen --bits 256 --out key.bin                       # sinh khóa (chmod 600 trên Linux)
aestool encrypt --mode gcm --key key.bin --in msg.txt --out ct.bin
aestool decrypt --mode gcm --key key.bin --in ct.bin  --out msg.txt
aestool encrypt --mode gcm --key key.bin --text "xin chào" --aad-text "v1" --out ct.bin --encode base64
aestool encrypt --mode ctr --key key.bin --in msg.txt --out ct.bin --sidecar ct.json   # IV/tag ở sidecar JSON
aestool decrypt --key key.bin --in ct.bin --sidecar ct.json --out msg.txt
aestool --kat vectors/nist_vectors.json                       # KAT runner: PASS/FAIL + bảng tổng kết
aestool bench --csv bench_linux.csv                           # benchmark đầy đủ
```
Danh sách đầy đủ tùy chọn: `aestool help`.

Mã thoát: `0` OK · `1` lỗi chung/KAT fail · `2` dùng sai bị từ chối (ECB, nonce reuse, độ dài IV/khóa…) · `3` lỗi mật mã (xác thực thất bại, file sai định dạng) – **fail closed**: không ghi file đầu ra, không trả plaintext.

## 5. Định dạng file

**Container nhị phân** (big-endian): `"AEST" | ver=1 | mode | key_len | flags(bit0=AEAD) | key_id(8) | iv_len | iv | aad_len(4) | aad | tag_len | tag | ct_len(8) | ciphertext`.
Header chứa thuật toán/mode, IV/nonce, AAD và tag (AEAD). `key_id` = 8 byte đầu của `SHA-256("aestool-keyid-v1"‖key)` – dùng để phát hiện tái sử dụng nonce mà không lộ khóa.
Parser kiểm tra chặt: magic, version, độ dài từng trường, độ dài ciphertext phải khớp đúng kích thước file; sai là từ chối.

**Sidecar JSON** (`--sidecar`): file đầu ra chỉ chứa ciphertext thô, metadata nằm trong JSON:
```json
{"format":"aestool-sidecar-v1","alg":"AES-256-GCM","mode":"gcm","key_len":32,
 "keyid":"…","iv":"…hex…","aad":"…hex…","tag":"…hex…"}
```

**File khóa/IV/AAD**: nhị phân thô, hoặc văn bản có dòng đầu `AESTOOL-HEX` rồi đến các chữ số hex.
Khóa: `--key FILE` hoặc `--key-hex HEX` (cách sau lộ khóa trong history/danh sách tiến trình).

## 6. Quy tắc chống dùng sai

| Hạng mục | Hành vi |
|---|---|
| ECB | In `WARNING`; từ chối dữ liệu > 16 KiB trừ khi có `--allow-ecb` |
| Độ dài IV | CBC/OFB/CFB/CTR/XTS: 16 B · GCM: 12 B · CCM: 7–13 B (mặc định 12) · ECB: không có IV. Sai độ dài → từ chối |
| Độ dài khóa | 16/24/32 B; XTS: 32 hoặc 64 B (2 khóa) |
| IV không cung cấp | Sinh bằng `AutoSeededRandomPool`, lưu trong header hoặc sidecar |
| AEAD | CCM/GCM luôn xác thực; tag sai → `AuthError`, plaintext bị hủy, không ghi file. `--aead` với mode không phải AEAD bị từ chối |
| Ghi file | Ghi vào `*.aestool.tmp` rồi đổi tên → không bao giờ để lại file hỏng |
| Khóa | Dùng bản sao tạm, xóa bằng ghi đè sau khi dùng; `keygen` không ghi đè file có sẵn, `chmod 600` trên Linux |

### Logic phát hiện tái sử dụng nonce (CTR, CCM, GCM)

Khi mã hóa, trước khi gọi Crypto++ (`ops.cpp: nonce_reused`):

1. Tính `key_id` của khóa đang dùng.
2. Nếu `--out` đã tồn tại và là file `AEST`: đọc **chỉ phần header** (≤ 1 MiB đầu), so sánh `(key_id, iv)`; trùng → **từ chối**.
3. Nếu `--sidecar` đã tồn tại: parse JSON, so sánh `(keyid, iv)`; trùng → từ chối.
4. Nếu có `--ledger FILE`: mỗi lần dùng được ghi một dòng `<keyid-hex> <nonce-hex>`; dòng đã có → từ chối. Ledger được cập nhật sau khi mã hóa thành công (nonce đã dùng thì coi như "cháy" kể cả khi bước ghi file sau đó lỗi).
5. Nonce do người dùng đưa vào (`--nonce`) mà trùng → lỗi `NONCE REUSE REFUSED` (mã thoát 2). Nonce tự sinh mà trùng (xác suất cực nhỏ) → sinh lại, tối đa 8 lần.

Giới hạn: phát hiện dựa trên file/ledger mà chương trình nhìn thấy; không bắt được tái sử dụng giữa các máy khác nhau hoặc khi header bị xóa. Với CTR, chỉ phát hiện nonce **trùng hoàn toàn**, không phát hiện các khối đếm chồng lấn.

## 7. Cấu trúc mã nguồn

```
src/aescore.{h,cpp}      lõi bọc Crypto++ (mode, kiểm tra tham số, random, key id)
src/container.{h,cpp}    header AEST + sidecar JSON
src/ops.{h,cpp}          pipeline encrypt/decrypt + chính sách ECB + phát hiện nonce reuse
src/kat.{h,cpp}          KAT runner (--kat)         src/minijson.h  parser JSON
src/bench.{h,cpp}        benchmark + thống kê       src/util.{h,cpp} hex/base64/UTF-8/file I/O
src/aescore_capi.*       C API cho .dll/.so         src/main.cpp    CLI
tests/test_aescore.cpp   unit test Catch2 (KAT, negative test, nonce reuse, ...)
vectors/nist_vectors.json  vector NIST SP 800-38A / GCM / SP 800-38C
scripts/plot_bench.py    vẽ đồ thị từ CSV           gui/aestool_gui.py  GUI Python (ctypes → thư viện)
```

## 8. Hạn chế đã biết

- Toàn bộ dữ liệu được đọc vào RAM (giới hạn 2 GiB/file); CCM giới hạn ~16 MB với nonce 12 B (đặc tả CCM).
- `--threads` được chấp nhận nhưng chưa dùng ở Lab 1.
- Nonce ngẫu nhiên 96-bit của GCM có giới hạn va chạm ~2³² thông điệp/khóa; nên đổi khóa trước đó.
- Mode/key_len trong header không được xác thực (chỉ AAD và dữ liệu được xác thực) – sửa header dẫn đến lỗi hoặc xác thực thất bại, không dẫn đến plaintext sai âm thầm ở mode AEAD.
- XTS không có tính toàn vẹn; cần ≥ 16 byte dữ liệu (dùng ciphertext stealing cho độ dài không chia hết 16).
- Khóa trong RAM được xóa ghi đè nhưng không `mlock`; không chống được swap/core dump.
- Đã build và chạy `ctest` thành công trên Ubuntu 24.04 (GCC 13, Crypto++ 8.9.0). Phần Windows (MSVC/MinGW) được viết theo cùng mã nguồn chuẩn C++17 nhưng chưa được biên dịch thử trong môi trường tạo ra mã; nếu gặp lỗi, xem GUIDE.md mục I.
- GUI cần `tkinter`; trên Windows với DLL Crypto++ động cần để DLL cạnh `aescore.dll` (hoặc dùng triplet tĩnh `x64-windows-static`).
