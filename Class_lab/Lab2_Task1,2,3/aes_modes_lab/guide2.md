# VAI TRÒ
Bạn là kỹ sư mật mã + build/DevOps. Hãy tối ưu và hoàn thành toàn bộ Lab 2 (NT219) trong thư mục dự án:
Gõ path vô
Môi trường: Windows 11. Trả lời/giải thích bằng tiếng Việt, code và comment bằng tiếng Anh.

# RÀNG BUỘC CỨNG
1. AES và các mode phải tự cài đặt bằng C/C++ chỉ với thư viện chuẩn (C++17 STL / libc). CẤM OpenSSL, Crypto++, mbedTLS, libsodium, Botan...
2. Được dùng intrinsics của compiler (AES-NI/PCLMUL) CHỈ như đường tối ưu tùy chọn, có runtime CPU detection và PHẢI có bản portable fallback. Mặc định build phải chạy đúng trên mọi CPU x86-64.
3. Không đổi public API đã có nếu không cần thiết; nếu đổi, ghi rõ trong báo cáo.
4. Mỗi phase phải qua "GATE" (kiểm chứng bằng lệnh thật) mới được sang phase sau. Không được tuyên bố hoàn thành nếu chưa chạy test và dán output thật.
5. Không xóa code cũ mà chưa có test chứng minh code mới tương đương.

# HIỆN TRẠNG tự kiểm tra
- Task 1 (AES core)
- Task 2 (modes NIST SP 800-38A/C/D)
- Task 3 (CMake + 3 compiler)
- Task 4 (Python PyQt6 + Docker)

# COMPILER (đường dẫn máy này)
- MSVC: ``
- GCC/G++: ` (cũng có bản ucrt64, ưu tiên mingw64)
- Clang/Clang++: ``

# CẤU TRÚC THƯ MỤC MỤC TIÊU
Lab-2/
├── Build_msvc/  Build_gcc/  Build_clang/     (out-of-source, không commit)
├── cmake/        (toolchain files, helper modules, CPU-feature detection)
├── src/          (aes core, modes, C API)
├── include/      (public headers)
├── test/         (test vectors NIST + unit tests + benchmark)
├── python/       (binding ctypes + GUI PyQt6)
├── CMakeLists.txt
├── CMakePresets.json
├── Dockerfile
├── .dockerignore
└── README.md
Nếu cấu trúc hiện tại khác, hãy đề xuất mapping và di chuyển file bằng git mv (hoặc ghi lại), không làm mất lịch sử.

---

# PHASE 0 — AUDIT (chưa sửa code)
1. Đọc toàn bộ src/, include/, test/, build script hiện có.
2. Xuất báo cáo ngắn gồm:
   - Danh sách file, hàm/class public, quy ước API.
   - Mode nào đã có, mode nào thiếu so với: SP 800-38A (ECB, CBC, CFB1, CFB8, CFB128, OFB, CTR), SP 800-38C (CCM), SP 800-38D (GCM, kể cả IV khác 96-bit và AAD).
   - Test nào đang có, test nào đang fail.
   - Điểm nghẽn hiệu năng, lỗi tiềm ẩn (UB, buffer overflow, endian, alignment, leak key, so sánh tag không constant-time, dùng memcmp`/`== cho tag).
3. Chạy build + test hiện tại bằng 1 compiler để lấy baseline.
GATE 0: có báo cáo audit + baseline (đúng/sai, throughput MB/s) trước khi sửa.

# PHASE 1 — TASK 1: TỐI ƯU AES CORE
1. Tạo test vector trước: FIPS-197 Appendix B/C (AES-128/192/256, encrypt + decrypt). Test phải pass trên code cũ để làm chuẩn.
2. Tối ưu theo thứ tự, đo benchmark sau MỖI bước (giữ bước nào có lợi):
   a. Key expansion tính một lần, lưu round keys dạng uint32_t[]; inverse key schedule (equivalent inverse cipher) cho decrypt.
   b. T-table (Te0..Te3, Td0..Td3) sinh lúc compile-time (constexpr) hoặc lúc khởi tạo, thay vì SubBytes/ShiftRows/MixColumns/xtime từng byte.
   c. Load/store 32-bit big-endian bằng hàm helper an toàn (không type-punning gây UB; dùng memcpy).
   d. Unroll vòng lặp theo số round (10/12/14), inline, tránh branch trong vòng chính.
   e. Xử lý nhiều block một lần (interleave 2–4 block) cho CTR/ECB/GCM.
   f. Tùy chọn: đường AES-NI (wmmintrin.h) bật bằng runtime detection (__cpuid`/cpuid.h`), cô lập trong file riêng với flag -maes chỉ áp cho file đó. Fallback portable luôn có.
   g. Tài liệu hóa rõ: T-table có nguy cơ cache-timing; bản portable là "educational", AES-NI là constant-time.
3. Dọn dẹp: secure_zero (không bị compiler tối ưu mất) cho key/round keys khi hủy; không để key trong stack buffer không xóa.
GATE 1: FIPS-197 pass trên 3 key size; benchmark trước/sau (MB/s ECB-encrypt, dữ liệu ≥ 64 MB); kết quả bản tối ưu === bản cũ trên 1 triệu block ngẫu nhiên (differential test, seed cố định).

# PHASE 2 — TASK 2: HOÀN THIỆN + TỐI ƯU MODES
1. Hoàn thiện mọi mode còn thiếu, bám đúng spec:
   - 38A: ECB, CBC, CFB1, CFB8, CFB128, OFB, CTR. Padding là tùy chọn riêng (PKCS#7) và KHÔNG nằm trong spec 38A; ECB/CBC không padding yêu cầu input bội số 16.
   - 38C: CCM đầy đủ, tham số tag length (4..16 chẵn), nonce length (7..13), L = 15 − n, định dạng B0, mã hóa độ dài AAD, CTR counter bắt đầu từ 1 cho payload và 0 cho tag.
   - 38D: GCM với IV 96-bit (J0 = IV||0^31||1) và IV bất kỳ độ dài (qua GHASH), AAD bất kỳ, tag 128/120/112/104/96 bit, inc32.
2. Test vector chính thức, bắt buộc pass 100%:
   - SP 800-38A Appendix F (tất cả mode, cả AES-128/192/256).
   - SP 800-38C Appendix C (4 ví dụ) .
   - SP 800-38D / GCM spec test cases 1–18 (McGrew–Viega).
   - Test âm: tag sai → decrypt trả lỗi và KHÔNG xuất plaintext; độ dài sai; nonce sai; input rỗng; input không bội số block.
3. Tối ưu:
   - GCM: GHASH bằng bảng 4-bit hoặc 8-bit Shoup (portable); tùy chọn PCLMULQDQ có runtime detection. Một lần precompute H-table cho mỗi key.
   - CTR/GCM/CCM: xử lý nhiều block song song, counter tăng không dùng vòng lặp byte chậm.
   - XOR theo từ 64-bit (dùng memcpy, không ép kiểu con trỏ vi phạm aliasing).
   - Tránh cấp phát heap trong đường xử lý chính; hỗ trợ streaming API (init/update/final) cho GCM/CTR/CBC bên cạnh API one-shot.
   - So sánh tag bằng hàm constant-time.
4. Mọi mode có API nhất quán: init(key) / encrypt / decrypt, trả mã lỗi rõ ràng (enum), không throw qua ranh giới C API.
GATE 2: bảng kết quả test theo từng mode (pass/fail), benchmark MB/s cho ECB/CBC/CTR/GCM/CCM trước–sau, chạy sạch với AddressSanitizer + UBSan (GCC/Clang) cho toàn bộ test.

# PHASE 3 — TASK 3: CMAKE + 3 COMPILER
1. CMakeLists.txt (cmake_minimum_required ≥ 3.21, C++17, C11 nếu có C):
   - Target: aes_core (static lib), aes_shared (shared lib cho Python, xuất qua C API), aes_tests, aes_bench, tùy chọn CLI demo.
   - Options: AES_ENABLE_AESNI (mặc định ON nhưng có runtime detection), AES_BUILD_TESTS, AES_BUILD_BENCH, AES_ENABLE_SANITIZERS.
   - Warning cao: MSVC /W4 /permissive-; GCC/Clang -Wall -Wextra -Wpedantic -Wconversion -Wshadow. Mặc định không để warning còn sót.
   - Release flags: MSVC /O2; GCC/Clang -O3. KHÔNG dùng -march=native cho bản phân phối (chỉ áp -maes -mpclmul -msse4.1 cho riêng file intrinsics).
   - Export symbol Windows: macro AES_API (__declspec(dllexport/dllimport)) + extern "C"; đặt WINDOWS_EXPORT_ALL_SYMBOLS KHÔNG thay thế C API sạch.
   - enable_testing() + add_test cho từng nhóm test để chạy bằng ctest.
2. Thư mục cmake/: toolchain file hoặc preset cho từng compiler với đường dẫn tuyệt đối ở trên:
   - Build_msvc: dùng generator Visual Studio phù hợp (kiểm tra bằng cmake --help xem tên generator cho VS 18, ví dụ "Visual Studio 18 2026") hoặc Ninja sau khi nạp vcvars64.bat. Chọn cách chạy được trên máy này và giải thích.
   - Build_gcc: Ninja hoặc MinGW Makefiles + C:\msys64\mingw64\bin\g++.exe.
   - Build_clang: Ninja + C:\msys64\mingw64\bin\clang++.exe.
   - Chú ý: khi chạy từ PowerShell/CMD thường, PATH phải có C:\msys64\mingw64\bin để DLL runtime tìm thấy; hoặc link static (-static) cho bản test. Xử lý và ghi rõ.
3. CMakePresets.json: preset msvc-release, msvc-debug, gcc-release, gcc-debug, clang-release, clang-debug (+ preset sanitizer cho gcc/clang), kèm build/test presets.
4. Script build_all.ps1: cấu hình + build + ctest lần lượt 3 compiler (Release), dừng và báo lỗi rõ khi một compiler fail, in bảng tổng kết cuối.
GATE 3: dán output ctest PASS 100% của cả 3 thư mục Build_msvc, Build_gcc, Build_clang; không còn warning; bảng benchmark so sánh 3 compiler. Nếu một compiler fail, sửa gốc rễ (không tắt warning/test để qua).

# PHASE 4 — TASK 4: DEPLOYMENT
## 4A. C API + Python binding
1. include/aes_c_api.h: API C thuần, opaque handle, không ném exception, không trả con trỏ nội bộ, buffer do caller cấp, trả int mã lỗi, có hàm aes_version() và aes_error_string(). Ví dụ: aes_ctx_new/free, aes_ecb/cbc/cfb/ofb/ctr_*, aes_ccm_encrypt/decrypt, aes_gcm_encrypt/decrypt.
2. python/aeslib.py: wrapper bằng ctypes (không dùng pybind11/SWIG để khỏi thêm phụ thuộc build):
   - Tự tìm aes_shared.dll / libaes_shared.so (biến môi trường AES_LIB_PATH, thư mục build, thư mục cài đặt).
   - Trên Windows dùng os.add_dll_directory cho C:\msys64\mingw64\bin nếu DLL build bằng MinGW.
   - Kiểm tra kiểu/độ dài đầu vào trước khi gọi native, chuyển mã lỗi thành exception Python.
   - Test pytest so khớp với vector NIST và với thư viện cryptography (chỉ dùng trong test để đối chiếu, không dùng trong lib).
## 4B. GUI PyQt6 (python/gui_app.py)
- Chọn mode (ECB/CBC/CFB1/CFB8/CFB128/OFB/CTR/CCM/GCM), key size 128/192/256.
- Nhập key/IV/nonce/AAD/tag length, định dạng Hex hoặc Text (UTF-8) chọn được; kiểm tra hợp lệ theo từng mode, báo lỗi rõ ràng ngay trên giao diện.
- Encrypt/Decrypt cho text và file (đọc/ghi file chạy ở `QThread`/worker để không treo UI, có progress bar).
- Hiển thị tag GCM/CCM, trạng thái "authentication failed" khi giải mã thất bại.
- Nút copy kết quả, nút sinh key/IV ngẫu nhiên bằng secrets, hiển thị thời gian xử lý và throughput.
- Tab "Self-test" chạy các test vector NIST ngay trong app.
- Code tách lớp: UI không chứa logic mật mã.
## 4C. Docker
- Dockerfile multi-stage:
  - Stage build: image Linux (ví dụ debian:bookworm-slim), cài build-essential clang cmake ninja-build python3; build bằng cả GCC và Clang, chạy ctest ngay trong build (fail thì build fail).
  - Stage runtime: image nhỏ, chạy user không phải root, chứa libaes_shared.so + python/ + Python deps (PyQt6 cài riêng cho GUI).
  - ENTRYPOINT mặc định chạy self-test + CLI Python (headless). Lệnh mẫu trong README.
- GUI trong Docker: ghi rõ cách chạy qua X11 forwarding (VcXsrv/WSLg) hoặc noVNC, nhưng bản chính phải chạy headless được.
- .dockerignore loại Build_*, .git, __pycache__.
GATE 4: docker build thành công và log hiển thị test pass; docker run chạy self-test ra PASS; pytest python/tests pass trên Windows với DLL từ ít nhất 1 compiler; GUI mở được và mã hóa/giải mã round-trip đúng GCM + CBC (chụp màn hình hoặc mô tả bước kiểm).

# PHASE 5 — README + BÁO CÁO
README.md gồm: tổng quan, cấu trúc, yêu cầu, lệnh build cho 3 compiler, cách chạy test/benchmark, API C và ví dụ Python, cách chạy GUI, cách dùng Docker, bảng benchmark trước/sau tối ưu, danh sách test vector đã pass, hạn chế bảo mật đã biết (timing T-table, không phải bản dùng production).
Cuối cùng xuất báo cáo: việc đã làm theo từng task, lệnh đã chạy, output test, bảng benchmark, các quyết định thiết kế, việc còn tồn đọng (nếu có).

# QUY TẮC LÀM VIỆC
- Làm tuần tự theo phase, sau mỗi phase tóm tắt 5–10 dòng + kết quả GATE rồi mới tiếp tục.
- Gặp mơ hồ không ảnh hưởng lớn: chọn phương án hợp lý, ghi giả định. Chỉ hỏi lại khi quyết định đó đổi API công khai hoặc mất dữ liệu.
- Commit nhỏ, thông điệp rõ theo phase (nếu dùng git).
- Không bịa kết quả test hoặc benchmark: mọi số liệu phải đến từ lệnh vừa chạy.