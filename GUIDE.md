# GUIDE – Chạy aestool trong terminal (Ubuntu & Windows)

## A. Ubuntu (20.04 / 22.04 / 24.04)

```bash
# 1) Cài công cụ + Crypto++
sudo apt update
sudo apt install -y build-essential cmake git libcrypto++-dev

# 2) Build + test
cd aestool
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build . -j
ctest --output-on-failure

# 3) Chạy
./bin/aestool help
```

## B. Windows – Cách 1: MSVC + vcpkg (PowerShell)

Mở **"Developer PowerShell for VS 2019/2022"**.
```powershell
git clone https://github.com/microsoft/vcpkg C:\vcpkg
C:\vcpkg\bootstrap-vcpkg.bat
C:\vcpkg\vcpkg install cryptopp:x64-windows catch2:x64-windows

cd aestool
mkdir build; cd build
cmake .. -DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake
cmake --build . --config Release
ctest -C Release --output-on-failure

.\bin\Release\aestool.exe help
```

## C. Windows – Cách 2: MinGW64 (MSYS2)

Mở shell **"MSYS2 MINGW64"**.
```bash
pacman -S --needed mingw-w64-x86_64-gcc mingw-w64-x86_64-cmake mingw-w64-x86_64-ninja \
                   mingw-w64-x86_64-crypto++ mingw-w64-x86_64-catch git
cd aestool
mkdir build && cd build
cmake .. -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build .
ctest --output-on-failure
./bin/aestool.exe help
```

> Từ đây các lệnh viết kiểu Linux (`./bin/aestool`). Trên Windows MSVC thay bằng `.\bin\Release\aestool.exe`.
> Để gõ ngắn, đặt alias: `alias aestool=./bin/aestool` (bash) hoặc `Set-Alias aestool .\bin\Release\aestool.exe` (PowerShell).

---

## D. Thử nhanh các chức năng

```bash
# Sinh khóa AES-256 (file nhị phân 32 byte) và khóa dạng hex có header
aestool keygen --bits 256 --out key.bin
aestool keygen --bits 256 --format hex --out key.hex

# Tạo file thử
echo "Xin chào, đây là thông điệp bí mật ✓" > msg.txt

# Mã hóa / giải mã GCM (IV tự sinh, lưu trong header)
aestool encrypt --mode gcm --key key.bin --in msg.txt --out ct.bin
aestool decrypt --mode gcm --key key.bin --in ct.bin  --out out.txt
cat out.txt            # Windows: type out.txt

# Dùng --text, AAD, hiển thị Base64
aestool encrypt --mode gcm --key key.bin --text "hello" --aad-text "v1" --out ct.bin --encode base64
aestool decrypt --mode gcm --key key.bin --in ct.bin           # in plaintext ra màn hình

# Không có --out: in thẳng ciphertext hex, rồi giải mã lại từ chuỗi hex
aestool encrypt --mode ctr --key key.bin --text "abc" > ct.hex
aestool decrypt --key key.bin --text "$(cat ct.hex)"           # PowerShell: (Get-Content ct.hex)

# Đủ 8 mode
for m in ecb cbc ofb cfb ctr ccm gcm; do aestool encrypt --mode $m --key key.bin --in msg.txt --out ct.$m; done
aestool keygen --bits 512 --out xts.key && aestool encrypt --mode xts --key xts.key --in msg.txt --out ct.xts

# Sidecar JSON
aestool encrypt --mode gcm --key key.bin --in msg.txt --out ct.raw --sidecar ct.json
aestool decrypt --key key.bin --in ct.raw --sidecar ct.json --out out.txt
```

## E. KAT (vector NIST)

```bash
aestool --kat vectors/nist_vectors.json
```
Mỗi case in `[PASS]`/`[FAIL]`, cuối cùng có bảng tổng kết theo mode. Có sẵn một case âm (tag sai phải bị từ chối). Bạn có thể thêm vector vào file JSON theo mẫu: `name, mode, key, iv|nonce, aad, plaintext, ciphertext, tag, padding, expect`.

## F. Chứng minh negative test (chạy tay)

```bash
aestool keygen --bits 256 --out key.bin && aestool keygen --bits 256 --out key2.bin
aestool encrypt --mode gcm --key key.bin --in msg.txt --out ct.bin

# Sai key -> xác thực thất bại, không có plaintext, mã thoát 3
aestool decrypt --key key2.bin --in ct.bin --out bad.txt ; echo "exit=$?"   # bad.txt không được tạo

# Sai IV
aestool decrypt --key key.bin --in ct.bin --iv-hex 000000000000000000000000 --out bad.txt

# Sửa 1 byte ciphertext (Linux)
cp ct.bin tampered.bin && printf '\x00' | dd of=tampered.bin bs=1 seek=$(( $(stat -c%s tampered.bin) - 1 )) conv=notrunc
aestool decrypt --key key.bin --in tampered.bin --out bad.txt

# IV sai độ dài -> bị từ chối (mã thoát 2)
aestool encrypt --mode gcm --key key.bin --in msg.txt --out x.bin --iv-hex 0011223344

# Non-AEAD: sai key cho ra rác / lỗi padding (không có xác thực)
aestool encrypt --mode cbc --key key.bin --in msg.txt --out cbc.bin
aestool decrypt --key key2.bin --in cbc.bin

# Tái sử dụng nonce -> bị từ chối
aestool encrypt --mode gcm --key key.bin --in msg.txt --out n.bin --nonce-hex 000102030405060708090a0b
aestool encrypt --mode gcm --key key.bin --in msg.txt --out n.bin --nonce-hex 000102030405060708090a0b   # REFUSED

# ECB: cảnh báo + giới hạn 16 KiB
head -c 20000 /dev/urandom > big.bin
aestool encrypt --mode ecb --key key.bin --in big.bin --out e.bin                  # REFUSED
aestool encrypt --mode ecb --key key.bin --in big.bin --out e.bin --allow-ecb      # cho phép
```
Các negative test cũng nằm trong `aescore_tests` (chạy bằng `ctest`).

## G. Benchmark + đồ thị

```bash
# Linux: đặt CPU governor hiệu năng cao (cần quyền root)
sudo cpupower frequency-set -g performance      # hoặc: echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
# Windows: Power Options -> High performance (hoặc Ultimate Performance)

aestool bench --quick                           # chạy thử ~ vài chục giây
aestool bench --csv bench_linux.csv             # đầy đủ: 8 mode x 6 kích thước, 30 lần lặp, warm-up 1 s
aestool bench --runs 100 --warmup 2 --csv bench_100.csv
aestool bench --op decrypt --csv bench_dec.csv
aestool bench --with-io --csv bench_io.csv      # thêm đọc/ghi file mỗi thao tác (đo overhead syscall)
aestool bench --modes gcm,ctr --sizes 1k,1m --runs 50

pip install matplotlib
python scripts/plot_bench.py bench_linux.csv bench_windows.csv --out plots
```
Phải build **Release**; bản Debug sẽ chậm hơn nhiều và được cảnh báo trong phần đầu kết quả. So sánh Windows/Linux: chạy cùng lệnh trên hai hệ điều hành và đưa cả hai CSV vào `plot_bench.py`.
Mỗi hàng CSV có: trung bình, trung vị, độ lệch chuẩn, khoảng tin cậy 95% của thông lượng (MB/s, 1 MB = 10⁶ B) và độ trễ (µs/op), cùng thông tin OS/compiler/phiên bản Crypto++/AES-NI.

## H. Thư viện `.dll/.so/.a/.lib` + GUI (điểm thưởng)

Sau khi build:
- Linux: `build/bin/libaescore.so`, `build/lib/libaescore_static.a`
- Windows: `build\bin\Release\aescore.dll`, `build\lib\Release\aescore_static.lib`
- Header C: `src/aescore_capi.h`

```bash
python3 gui/aestool_gui.py        # Windows: python gui\aestool_gui.py
# chỉ định thư viện thủ công:  AESCORE_LIB=/path/libaescore.so python3 gui/aestool_gui.py
```
Ubuntu cần: `sudo apt install python3-tk`. GUI chỉ gọi thư viện đã biên dịch (qua `ctypes`), không cài lại thuật toán mật mã.

## I. Xử lý sự cố

| Triệu chứng | Cách xử lý |
|---|---|
| `Crypto++ was not found` | Cài theo mục A/B/C; với vcpkg nhớ truyền `-DCMAKE_TOOLCHAIN_FILE=...`; hoặc để `AESTOOL_FETCH_DEPS=ON` + có internet |
| Lỗi `cryptopp/xts.h` hoặc `XTS_Mode` không tồn tại | Crypto++ quá cũ – cần ≥ 8.2 |
| `Catch2 v3 not found` | Bỏ qua (chỉ cảnh báo, `nist_kat` ctest vẫn chạy) hoặc `-DAESTOOL_BUILD_TESTS=OFF` |
| `ctest` báo "Test not available" trên MSVC | Thêm `-C Release` |
| Windows báo thiếu `cryptopp-dll.dll` khi chạy `.exe` | Dùng toolchain vcpkg (tự sao chép DLL), hoặc cài `cryptopp:x64-windows-static` |
| Console Windows hiện sai tiếng Việt | Dùng Windows Terminal; tool tự đặt code page UTF-8 |
| `AUTHENTICATION FAILED` (mã 3) | Đúng thiết kế: sai khóa/nonce/AAD hoặc dữ liệu bị sửa; không có file đầu ra |
