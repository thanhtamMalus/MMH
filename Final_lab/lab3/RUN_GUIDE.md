# RUN_GUIDE.md — Hướng dẫn tự chạy & thu kết quả Lab 3 (`rsatool`)

> Dành cho **bạn (người chạy)**. Bot/agent chỉ viết code; mọi lệnh terminal dưới đây do bạn chạy và lưu log vào thư mục `results/` để dán vào báo cáo.
> Gốc dự án: `lab3-rsatool/`. Các lệnh ví dụ coi như bạn đang đứng ở thư mục gốc đó.

---

## 0. Chuẩn bị thư mục kết quả

**Linux / Git Bash**
```bash
mkdir -p results report/figures testdata
```
**Windows PowerShell**
```powershell
New-Item -ItemType Directory -Force results, report\figures, testdata | Out-Null
```

---

## 1. Cài thư viện

### 1.1 Ubuntu LTS
```bash
sudo apt update
sudo apt install -y build-essential cmake ninja-build pkg-config git \
    libcrypto++-dev nlohmann-json3-dev catch2 \
    python3 python3-pip python3-venv
python3 -m venv .venv && source .venv/bin/activate
pip install pandas numpy scipy matplotlib
```
> Nếu `apt` cài Catch2 bản 2.x, CMake sẽ tự `FetchContent` bản 3.x (cần Internet). Không phải lỗi.

### 1.2 Windows (MSVC + vcpkg) — khuyến nghị
Cài trước: Visual Studio 2022 (Desktop development with C++), CMake, Git, Python 3.

```powershell
git clone https://github.com/microsoft/vcpkg C:\vcpkg
C:\vcpkg\bootstrap-vcpkg.bat
C:\vcpkg\vcpkg install cryptopp nlohmann-json catch2 --triplet x64-windows
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install pandas numpy scipy matplotlib
```

### 1.3 Windows (MinGW64 / MSYS2)
Mở **MSYS2 MINGW64**:
```bash
pacman -S --needed mingw-w64-x86_64-toolchain mingw-w64-x86_64-cmake mingw-w64-x86_64-ninja \
    mingw-w64-x86_64-crypto++ mingw-w64-x86_64-nlohmann-json mingw-w64-x86_64-catch \
    mingw-w64-x86_64-python mingw-w64-x86_64-python-pip
pip install pandas numpy scipy matplotlib
```

---

## 2. Build (out-of-source, bắt buộc)

### 2.1 Linux
```bash
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release 2>&1 | tee results/build_linux_configure.log
cmake --build build 2>&1 | tee results/build_linux.log
```
Executable: `build/bin/rsatool`, `build/bin/rsabench`, `build/bin/rsa_tests`.

### 2.2 Windows – MSVC
Dùng **x64 Native Tools Command Prompt** hoặc PowerShell thường:
```powershell
cmake -S . -B build-msvc -G "Visual Studio 17 2022" -A x64 `
  -DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake `
  -DVCPKG_TARGET_TRIPLET=x64-windows 2>&1 | Tee-Object results\build_msvc_configure.log
cmake --build build-msvc --config Release 2>&1 | Tee-Object results\build_msvc.log
```
Executable: `build-msvc\bin\Release\rsatool.exe` (hoặc `build-msvc\Release\`; xem đường dẫn thực tế trong log).

### 2.3 Windows – MinGW64 (trong MSYS2 MINGW64)
```bash
cmake -S . -B build-mingw -G Ninja -DCMAKE_BUILD_TYPE=Release 2>&1 | tee results/build_mingw_configure.log
cmake --build build-mingw 2>&1 | tee results/build_mingw.log
```

> **Nếu build lỗi**: copy nguyên log lỗi (`results/build_*.log`) gửi lại cho bot/agent để sửa. Bước build đã dùng `tee` nên log nằm sẵn trong `results/`.

Để ngắn gọn, phần dưới dùng biến:

```bash
# Linux
RT=build/bin/rsatool
BN=build/bin/rsabench
TS=build/bin/rsa_tests
```
```powershell
# Windows MSVC (PowerShell)
$RT = ".\build-msvc\bin\Release\rsatool.exe"
$BN = ".\build-msvc\bin\Release\rsabench.exe"
$TS = ".\build-msvc\bin\Release\rsa_tests.exe"
```
Ở các bước sau, lệnh Linux viết `$RT ...`; trên PowerShell dùng `& $RT ...`.

---

## 3. Chạy unit test (ctest)

**Linux**
```bash
ctest --test-dir build --output-on-failure -V 2>&1 | tee results/ctest_linux.log
$TS --reporter compact 2>&1 | tee results/catch2_linux.log   # tuỳ chọn, bảng test chi tiết
```
**Windows MSVC**
```powershell
ctest --test-dir build-msvc -C Release --output-on-failure -V 2>&1 | Tee-Object results\ctest_msvc.log
```
**Windows MinGW**
```bash
ctest --test-dir build-mingw --output-on-failure -V 2>&1 | tee results/ctest_mingw.log
```

✅ Cần thu: dòng `100% tests passed, 0 tests failed out of N` (chụp màn hình + log).
Danh sách test chi tiết (để chép tên test vào báo cáo):
```bash
$TS --list-tests > results/test_list.txt
```

---

## 4. Tạo dữ liệu thử

```bash
python scripts/make_testfiles.py
```
Kết quả trong `testdata/`: `msg_small.bin` (100 B), `msg_edge318.bin` (318 B), `msg_edge319.bin` (319 B), `msg_1KiB.bin`, `msg_1MiB.bin`, `msg_100MiB.bin`.

---

## 5. Demo CLI (thu log để dán báo cáo)

Mẹo: đặt tất cả lệnh demo vào 1 file log:

**Linux**
```bash
script -q -c "bash" results/demo_session_linux.txt   # (tuỳ chọn) ghi lại cả phiên; thoát bằng exit
```
Hoặc đơn giản: thêm `2>&1 | tee -a results/demo_linux.log` sau từng lệnh.

### 5.1 Sinh khóa
```bash
mkdir -p keys
$RT keygen --bits 3072 --pub keys/pub3072.pem --priv keys/priv3072.pem 2>&1 | tee -a results/demo_linux.log
$RT keygen --bits 4096 --pub keys/pub4096.pem --priv keys/priv4096.pem 2>&1 | tee -a results/demo_linux.log
# khóa "sai" để làm negative test
$RT keygen --bits 3072 --pub keys/pub_other.pem --priv keys/priv_other.pem

ls -l keys/ | tee -a results/demo_linux.log        # Windows: Get-ChildItem keys
cat keys/priv3072.meta.json | tee -a results/demo_linux.log
head -n 3 keys/pub3072.pem
```
✅ Cần thu: danh sách đủ `*.pem`, `*.der`, `*.meta.json`; nội dung metadata có `creation_time`, `modulus_bits`, `hash`.

(Tuỳ chọn, đối chiếu với OpenSSL nếu có sẵn:)
```bash
openssl pkey -in keys/priv3072.pem -noout -text | head -n 3
openssl pkey -pubin -in keys/pub3072.pem -noout -text | head -n 3
openssl pkey -inform DER -in keys/priv3072.der -noout -text | head -n 3
```

### 5.2 Mã hóa/giải mã — Direct (≤ 318 byte với RSA-3072)
```bash
$RT encrypt --in testdata/msg_small.bin --pub keys/pub3072.pem --out ct_small.bin --verbose
$RT decrypt --in ct_small.bin --priv keys/priv3072.pem --out dec_small.bin
sha256sum testdata/msg_small.bin dec_small.bin           # Linux
# Windows: Get-FileHash testdata\msg_small.bin, dec_small.bin -Algorithm SHA256
cmp testdata/msg_small.bin dec_small.bin && echo "MATCH"  # Windows: fc /b a b
```
Biên giới giới hạn:
```bash
$RT encrypt --in testdata/msg_edge318.bin --pub keys/pub3072.pem --out ct318.bin --verbose   # kỳ vọng: Direct
$RT encrypt --in testdata/msg_edge319.bin --pub keys/pub3072.pem --out ct319.bin --verbose   # kỳ vọng: Hybrid tự động
```
Label & định dạng:
```bash
$RT encrypt --in testdata/msg_small.bin --pub keys/pub3072.pem --out ct_label.b64 --label "lab3-demo" --encode base64
$RT decrypt --in ct_label.b64 --priv keys/priv3072.pem --out dec_label.bin --label "lab3-demo" --encode base64
$RT encrypt --in testdata/msg_small.bin --pub keys/pub3072.pem --out ct_label.hex --label "lab3-demo" --encode hex
```

### 5.3 Hybrid — 1 KiB / 1 MiB / 100 MiB
```bash
for f in 1KiB 1MiB 100MiB; do
  /usr/bin/time -v $RT encrypt --in testdata/msg_$f.bin --pub keys/pub3072.pem --out ct_$f.bin --verbose 2>&1 | tee -a results/demo_hybrid_$f.log
  /usr/bin/time -v $RT decrypt --in ct_$f.bin --priv keys/priv3072.pem --out dec_$f.bin 2>&1 | tee -a results/demo_hybrid_$f.log
  sha256sum testdata/msg_$f.bin dec_$f.bin | tee -a results/demo_hybrid_$f.log
done
```
Windows PowerShell:
```powershell
foreach ($f in "1KiB","1MiB","100MiB") {
  Measure-Command { & $RT encrypt --in testdata\msg_$f.bin --pub keys\pub3072.pem --out ct_$f.bin --verbose } | Tee-Object -Append results\demo_hybrid_$f.log
  Measure-Command { & $RT decrypt --in ct_$f.bin --priv keys\priv3072.pem --out dec_$f.bin }              | Tee-Object -Append results\demo_hybrid_$f.log
  Get-FileHash testdata\msg_$f.bin, dec_$f.bin -Algorithm SHA256 | Tee-Object -Append results\demo_hybrid_$f.log
}
```
Xem header JSON của envelope (để chụp hình cho báo cáo):
```bash
python - <<'EOF'
import struct, json
b = open("ct_1KiB.bin","rb").read()
assert b[:4]==b"RSAE"
n = struct.unpack(">I", b[5:9])[0]
print(json.dumps(json.loads(b[9:9+n]), indent=2))
EOF
```
Hybrid RSA-4096:
```bash
$RT encrypt --in testdata/msg_1MiB.bin --pub keys/pub4096.pem --out ct_1MiB_4096.bin --verbose
$RT decrypt --in ct_1MiB_4096.bin --priv keys/priv4096.pem --out dec_1MiB_4096.bin
cmp testdata/msg_1MiB.bin dec_1MiB_4096.bin && echo MATCH
```

---

## 6. Negative test thủ công (minh hoạ fail-closed)

Mỗi lệnh `decrypt` **phải thất bại**, in đúng `Error: decryption failed.`, exit code **3**, và **không tạo file output**.

```bash
mkdir -p neg && rm -f neg/*

# Tạo các file bị can thiệp từ envelope Hybrid hợp lệ (ct_1KiB.bin) và Direct (ct_small.bin)
python scripts/tamper.py --in ct_1KiB.bin  --out neg/flip_payload.bin      --mode flip-payload
python scripts/tamper.py --in ct_1KiB.bin  --out neg/flip_tag.bin          --mode flip-tag
python scripts/tamper.py --in ct_1KiB.bin  --out neg/flip_wrapped.bin      --mode flip-wrapped-key
python scripts/tamper.py --in ct_1KiB.bin  --out neg/header_iv.bin         --mode flip-header-iv
python scripts/tamper.py --in ct_1KiB.bin  --out neg/header_modulus.bin    --mode change-modulus
python scripts/tamper.py --in ct_1KiB.bin  --out neg/truncated.bin         --mode truncate
python scripts/tamper.py --in ct_small.bin --out neg/flip_direct.bin       --mode flip-direct

# Chạy và ghi lại exit code
for f in flip_payload flip_tag flip_wrapped header_iv header_modulus truncated flip_direct; do
  echo "== $f ==" | tee -a results/negative_tests.log
  $RT decrypt --in neg/$f.bin --priv keys/priv3072.pem --out neg/out_$f.bin 2>&1 | tee -a results/negative_tests.log
  echo "exit=${PIPESTATUS[0]}  output_exists=$([ -f neg/out_$f.bin ] && echo YES || echo no)" | tee -a results/negative_tests.log
done

# Sai khóa riêng
echo "== wrong private key (hybrid) ==" | tee -a results/negative_tests.log
$RT decrypt --in ct_1KiB.bin --priv keys/priv_other.pem --out neg/out_wrongkey.bin 2>&1 | tee -a results/negative_tests.log; echo "exit=${PIPESTATUS[0]}" | tee -a results/negative_tests.log
echo "== wrong private key (direct) ==" | tee -a results/negative_tests.log
$RT decrypt --in ct_small.bin --priv keys/priv_other.pem --out neg/out_wrongkey2.bin 2>&1 | tee -a results/negative_tests.log; echo "exit=${PIPESTATUS[0]}" | tee -a results/negative_tests.log

# Sai label
echo "== wrong label (direct) ==" | tee -a results/negative_tests.log
$RT decrypt --in ct_label.b64 --priv keys/priv3072.pem --out neg/out_wronglabel.bin --label "WRONG" --encode base64 2>&1 | tee -a results/negative_tests.log; echo "exit=${PIPESTATUS[0]}" | tee -a results/negative_tests.log
echo "== missing label ==" | tee -a results/negative_tests.log
$RT decrypt --in ct_label.b64 --priv keys/priv3072.pem --out neg/out_nolabel.bin --encode base64 2>&1 | tee -a results/negative_tests.log; echo "exit=${PIPESTATUS[0]}" | tee -a results/negative_tests.log
```
> Hybrid + sai label: tạo trước bằng `$RT encrypt --in testdata/msg_1KiB.bin --pub keys/pub3072.pem --out ct_1KiB_label.bin --label "abc"` rồi giải mã với `--label "xyz"` và ghi log tương tự.

Windows: thay `PIPESTATUS[0]` bằng `$LASTEXITCODE` và `[ -f ]` bằng `Test-Path`.

✅ Cần thu: `results/negative_tests.log` — mỗi trường hợp: thông báo lỗi chung, `exit=3`, `output_exists=no`.

---

## 7. Benchmark & thống kê

> Chạy khi máy **rảnh**: đóng trình duyệt, cắm điện, tắt chế độ tiết kiệm pin. Chạy trên bản **Release**. Nên chạy 2–3 lần và giữ lần ổn định nhất (ghi chú trong báo cáo).

### 7.1 Chạy bench đầy đủ
**Linux**
```bash
$BN --out results/bench_raw.csv --env-out results/bench_env.txt 2>&1 | tee results/bench_stdout.log
```
**Windows**
```powershell
& $BN --out results\bench_raw.csv --env-out results\bench_env.txt 2>&1 | Tee-Object results\bench_stdout.log
```
Chạy thử nhanh trước (vài phút → để kiểm tra không lỗi): thêm `--quick`.
> Keygen RSA-4096 và AES-GCM 100 MiB hơi lâu; tổng thể có thể vài chục phút tuỳ máy.

### 7.2 Phân tích & vẽ đồ thị
```bash
python scripts/analyze_bench.py --in results/bench_raw.csv --out-dir results --fig-dir report/figures
```
✅ Cần thu:
- `results/bench_summary.csv`, `results/bench_summary.md` (bảng mean/std/95% CI)
- `report/figures/latency_rsa_keygen.png`
- `report/figures/latency_rsa_encdec.png`
- `report/figures/throughput_aesgcm.png`
- `report/figures/latency_hybrid_total.png`
- `results/bench_env.txt` (CPU/OS/compiler/phiên bản Crypto++)

### 7.3 (Bonus tuỳ chọn) Thí nghiệm thời gian khi xác thực thất bại
```bash
$BN --timing-failure --out results/bench_authfail.csv
```
(Chỉ chạy nếu agent đã cài cờ này; xem `docs/BONUS_B_hybrid_analysis.md`.)

---

## 8. Checklist thu thập cho báo cáo

| # | Mục | File/Hình | Dán vào chương |
|---|---|---|---|
| 1 | Log build Linux / MSVC / MinGW | `results/build_*.log` | Build đa nền tảng |
| 2 | Kết quả ctest | `results/ctest_*.log` + ảnh chụp | Kiểm thử |
| 3 | Danh sách test | `results/test_list.txt` | Kiểm thử |
| 4 | Demo keygen & metadata | `results/demo_linux.log`, ảnh `ls keys/` | Quản lý khóa |
| 5 | Demo Direct + biên 318/319 | `results/demo_linux.log` | RSA-OAEP |
| 6 | Demo Hybrid 1KiB/1MiB/100MiB + hash khớp | `results/demo_hybrid_*.log` | Hybrid |
| 7 | Header JSON của envelope | ảnh chụp lệnh Python | Định dạng envelope |
| 8 | Negative tests | `results/negative_tests.log` | Fail-closed |
| 9 | Bảng thống kê | `results/bench_summary.md` | Hiệu năng |
| 10 | 4 đồ thị | `report/figures/*.png` | Hiệu năng |
| 11 | Môi trường đo | `results/bench_env.txt` | Hiệu năng |
| 12 | (Bonus A) test manual OAEP | trong `ctest` log | Bonus A |

Sau khi thu đủ, gửi lại cho bot: `bench_summary.md`, `ctest_*.log`, `negative_tests.log`, `bench_env.txt` để nó điền các `{{TODO}}` trong `report/REPORT_OUTLINE.md`.

---

## 9. Đóng gói nộp bài

Cấu trúc yêu cầu: **1 file duy nhất** `MSV.All6labs.zip` (hoặc `.rar`) chứa: mã nguồn C++, `CMakeLists.txt`, `README.md`, **file thực thi đã build cho cả Windows & Linux**, unit tests, báo cáo PDF/DOCX.

Gợi ý cho Lab 3 (đặt trong thư mục `Lab3/` của gói chung):
```bash
mkdir -p dist/linux dist/windows
cp build/bin/rsatool build/bin/rsabench build/bin/rsa_tests dist/linux/
# Windows: copy các .exe Release (+ DLL phụ thuộc nếu vcpkg dùng triplet động; hoặc build triplet x64-windows-static để khỏi cần DLL)
rm -rf build build-msvc build-mingw testdata keys neg *.bin *.b64 *.hex
```
> Đừng nộp khóa riêng/`keys/` thật. Giữ lại `results/` và `report/figures/`.

---

## 10. Xử lý sự cố thường gặp

| Triệu chứng | Cách xử lý |
|---|---|
| CMake không tìm thấy Crypto++ | Linux: `sudo apt install libcrypto++-dev`. Windows: kiểm tra `-DCMAKE_TOOLCHAIN_FILE=.../vcpkg.cmake` và triplet. |
| `unresolved external symbol` (MSVC) | Lệch runtime (MD/MT). Dùng đúng triplet `x64-windows` hoặc `x64-windows-static`, build lại sạch thư mục `build-msvc`. |
| Thiếu DLL khi chạy `.exe` | Dùng triplet static hoặc copy DLL từ `vcpkg\installed\x64-windows\bin`. |
| `FetchContent` lỗi mạng | Cài Catch2/nlohmann_json sẵn qua `apt`/`vcpkg`/`pacman`, hoặc bật Internet. |
| Python thiếu thư viện | `pip install pandas numpy scipy matplotlib` (trong venv đã kích hoạt). |
| Bench quá chậm | Chạy `--quick` để kiểm tra, rồi chạy đầy đủ khi máy rảnh. |
| Mọi lỗi giải mã đều ra cùng 1 câu | Đúng thiết kế (fail-closed, không rò rỉ). Để debug, dùng unit test, không đòi thông báo chi tiết. |