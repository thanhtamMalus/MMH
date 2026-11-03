# RUN – Hướng dẫn build, test và chạy aestool (Ubuntu)

Tài liệu này dành cho người vừa clone repo về. Tất cả lệnh chạy từ thư mục gốc của dự án (`lab1/`).

## 1. Cài công cụ (một lần)

```bash
sudo apt update
sudo apt install -y build-essential cmake git python3-tk
```

- Không cần cài `libcrypto++-dev`: repo có sẵn Crypto++ trong `crypto_libs/`. Nếu bản có sẵn không dùng được, CMake sẽ tự tải Crypto++ khi có mạng (`AESTOOL_FETCH_DEPS=ON`).
- `python3-tk` chỉ cần nếu dùng GUI.
- Cần CMake >= 3.14 và kết nối mạng ở lần build đầu (để tải Catch2 nếu máy chưa có).

## 2. Build và test

```bash
git clone <repo-url>
cd lab1
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
```

Kết quả mong đợi:

```
1/2 Test #1: nist_kat .... Passed
2/2 Test #2: unit_tests .. Passed
100% tests passed, 0 tests failed out of 2
```

Sau khi build, các file nằm trong `build/bin/`:

| File | Mô tả |
|---|---|
| `build/bin/aestool` | Chương trình dòng lệnh chính |
| `build/bin/aescore_tests` | File test Catch2 |
| `build/bin/libaescore.so` | Thư viện dùng chung (GUI gọi qua `ctypes`) |

> Nếu thư mục `build/` bị mang từ máy khác sang (ví dụ Windows) sẽ gặp lỗi `CMakeCache.txt directory is different`. Xóa đi và build lại: `rm -rf build`.

## 3. Đặt alias cho gõ ngắn

```bash
alias aestool=./build/bin/aestool
aestool help
```

Alias chỉ có hiệu lực trong cửa sổ terminal hiện tại. Mở terminal mới thì gõ lại.

## 4. Thử nhanh các chức năng

```bash
# Sinh khóa AES-256 (nhị phân 32 byte) và dạng hex
aestool keygen --bits 256 --out key.bin
aestool keygen --bits 256 --format hex --out key.hex

# Tạo file thử
echo "Xin chào, đây là thông điệp bí mật" > msg.txt

# Mã hóa / giải mã GCM (IV tự sinh, lưu trong header)
aestool encrypt --mode gcm --key key.bin --in msg.txt --out ct.bin
aestool decrypt --mode gcm --key key.bin --in ct.bin --out out.txt
cat out.txt

# Dùng --text, AAD, hiển thị Base64
aestool encrypt --mode gcm --key key.bin --text "hello" --aad-text "v1" --out ct.bin --encode base64
aestool decrypt --mode gcm --key key.bin --in ct.bin

# Không có --out: in hex ra màn hình, rồi giải mã lại từ chuỗi hex
aestool encrypt --mode ctr --key key.bin --text "abc" > ct.hex
aestool decrypt --key key.bin --text "$(cat ct.hex)"

# Thử các mode
for m in ecb cbc ofb cfb ctr ccm gcm; do
  aestool encrypt --mode $m --key key.bin --in msg.txt --out ct.$m
done
aestool keygen --bits 512 --out xts.key
aestool encrypt --mode xts --key xts.key --in msg.txt --out ct.xts

# Sidecar JSON
aestool encrypt --mode gcm --key key.bin --in msg.txt --out ct.raw --sidecar ct.json
aestool decrypt --key key.bin --in ct.raw --sidecar ct.json --out out.txt
```

Lưu ý: ECB bị từ chối với dữ liệu lớn hơn 16 KiB, phải thêm `--allow-ecb`.

## 5. Kiểm tra vector NIST (KAT)

```bash
aestool --kat vectors/nist_vectors.json
```

Mỗi case in `[PASS]` hoặc `[FAIL]`, cuối cùng có bảng tổng kết theo từng mode. Có sẵn một case âm (tag sai phải bị từ chối).

Thêm vector mới vào file JSON theo mẫu các trường: `name, mode, key, iv|nonce, aad, plaintext, ciphertext, tag, padding, expect`.

## 6. Negative test (chứng minh từ chối dữ liệu sai)

```bash
aestool keygen --bits 256 --out key2.bin
aestool encrypt --mode gcm --key key.bin --in msg.txt --out ct.bin

# Sai key -> AUTHENTICATION FAILED, mã thoát 3, không tạo file bad.txt
aestool decrypt --key key2.bin --in ct.bin --out bad.txt ; echo "exit=$?"

# Sai IV
aestool decrypt --key key.bin --in ct.bin --iv-hex 000000000000000000000000 --out bad.txt

# Sửa 1 byte ciphertext -> bị từ chối
cp ct.bin tampered.bin
printf '\x00' | dd of=tampered.bin bs=1 seek=$(( $(stat -c%s tampered.bin) - 1 )) conv=notrunc
aestool decrypt --key key.bin --in tampered.bin --out bad.txt

# IV sai độ dài -> mã thoát 2
aestool encrypt --mode gcm --key key.bin --in msg.txt --out x.bin --iv-hex 0011223344

# Non-AEAD (CBC): sai key cho ra rác hoặc lỗi padding, không có xác thực
aestool encrypt --mode cbc --key key.bin --in msg.txt --out cbc.bin
aestool decrypt --key key2.bin --in cbc.bin

# Dùng lại nonce -> lần thứ hai bị REFUSED
aestool encrypt --mode gcm --key key.bin --in msg.txt --out n.bin --nonce-hex 000102030405060708090a0b
aestool encrypt --mode gcm --key key.bin --in msg.txt --out n.bin --nonce-hex 000102030405060708090a0b

# ECB: cảnh báo + giới hạn 16 KiB
head -c 20000 /dev/urandom > big.bin
aestool encrypt --mode ecb --key key.bin --in big.bin --out e.bin               # REFUSED
aestool encrypt --mode ecb --key key.bin --in big.bin --out e.bin --allow-ecb   # cho phép
```

Các negative test này cũng nằm trong `aescore_tests`, nên `ctest` đã chạy chúng.

## 7. Benchmark và vẽ đồ thị

```bash
# (Tùy chọn) đặt CPU ở chế độ hiệu năng cao, cần quyền root
sudo cpupower frequency-set -g performance

aestool bench --quick                      # chạy thử vài chục giây
aestool bench --csv bench_linux.csv        # đầy đủ: 8 mode x 6 kích thước, 30 lần lặp, warm-up 1 s
aestool bench --runs 100 --warmup 2 --csv bench_100.csv
aestool bench --op decrypt --csv bench_dec.csv
aestool bench --with-io --csv bench_io.csv # thêm đọc/ghi file mỗi thao tác
aestool bench --modes gcm,ctr --sizes 1k,1m --runs 50

pip install matplotlib
python3 scripts/plot_bench.py bench_linux.csv --out plots
```

- Phải build **Release**. Bản Debug chậm hơn nhiều và được cảnh báo ở đầu kết quả.
- So sánh Windows/Linux: chạy cùng lệnh trên hai hệ điều hành rồi đưa cả hai CSV vào script:

  ```bash
  python3 scripts/plot_bench.py bench_linux.csv bench_windows.csv --out plots
  ```

- Mỗi hàng CSV gồm: trung bình, trung vị, độ lệch chuẩn, khoảng tin cậy 95% của thông lượng (MB/s, 1 MB = 10^6 B) và độ trễ (µs/op), cùng thông tin OS, compiler, phiên bản Crypto++, AES-NI.

## 8. Chạy GUI

```bash
python3 aestool_gui.py
```

GUI cần `build/bin/libaescore.so`. Nếu chưa có, script sẽ tự build lần đầu. Nếu không tìm thấy thư viện, chỉ đường dẫn tay:

```bash
AESCORE_LIB=$PWD/build/bin/libaescore.so python3 aestool_gui.py
```

GUI chỉ gọi thư viện đã biên dịch (qua `ctypes`), không cài lại thuật toán mật mã. Header C của thư viện: `src/aescore_capi.h`.

## 9. Chạy riêng test Catch2

```bash
./build/bin/aescore_tests              # chạy tất cả
./build/bin/aescore_tests -s           # in cả assertion thành công
./build/bin/aescore_tests --list-tests # liệt kê test case
./build/bin/aescore_tests "tên test"   # chạy một test case

ctest --test-dir build -R unit_tests -V     # chạy qua ctest, in chi tiết
ctest --test-dir build -R nist_kat -V
```

## 10. Cấu hình CMake

| Option | Mặc định | Ý nghĩa |
|---|---|---|
| `AESTOOL_BUILD_TESTS` | ON | Build test Catch2 và đăng ký ctest |
| `AESTOOL_BUILD_SHARED` | ON | Build thư viện chia sẻ `.so` / `.dll` có C API |
| `AESTOOL_FETCH_DEPS` | ON | Tự tải Crypto++ / Catch2 nếu máy chưa có (cần git và internet) |
| `AESTOOL_USE_LOCAL_CRYPTOPP` | ON | Dùng Crypto++ dựng sẵn trong `crypto_libs/` trước (Linux/macOS) |
| `AESTOOL_CRYPTOPP_PREFER_STATIC` | OFF | Ưu tiên `libcryptopp.a` thay vì `.so` (bản `.a` đi kèm bị crash khi chạy, nên giữ OFF) |

Ví dụ tắt test: `cmake -S . -B build -DAESTOOL_BUILD_TESTS=OFF`.

## 11. Xử lý sự cố

| Triệu chứng | Cách xử lý |
|---|---|
| `CMakeCache.txt directory is different` | `rm -rf build` rồi build lại (build đến từ máy khác) |
| `No such file or directory` khi chạy file | File nằm trong `build/bin/`, không phải `build/` |
| `Catch2 v3 not found` | Chỉ là cảnh báo, `nist_kat` vẫn chạy. Cần mạng để tự tải Catch2, hoặc cài Catch2 v3 |
| `Crypto++ was not found` | Giữ `AESTOOL_FETCH_DEPS=ON` và có mạng, hoặc `sudo apt install libcrypto++-dev` |
| Lỗi `cryptopp/xts.h` / `XTS_Mode` không tồn tại | Crypto++ quá cũ, cần >= 8.2 |
| `aestool` crash khi dùng `libcryptopp.a` | Giữ `AESTOOL_CRYPTOPP_PREFER_STATIC=OFF` |
| GUI báo `aescore library not found` | Build trước, hoặc đặt `AESCORE_LIB` |
| GUI báo thiếu tkinter | `sudo apt install python3-tk` |
| `AUTHENTICATION FAILED` (mã thoát 3) | Đúng thiết kế: sai khóa, nonce, AAD hoặc dữ liệu bị sửa; không tạo file đầu ra |

## 12. Lưu ý khi commit lên Git

- Thêm vào `.gitignore`: `build/`, `__pycache__/`, `*.pyc`.
- Nếu từng commit `build/`: `git rm -r --cached build`.
- Phải commit: `vectors/nist_vectors.json` (test `nist_kat` đọc file này) và `crypto_libs/` (nếu dùng Crypto++ đi kèm).