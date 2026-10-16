# AES Modes Benchmark & Visual Comparison

Bộ công cụ Python để **so sánh các chế độ hoạt động (mode) của AES** qua 3 bài thực nghiệm:

| Task | Nội dung | Kết quả |
|---|---|---|
| **Task 01** | Plaintext gồm 2 block giống nhau (block 1 = block 2), chạy encrypt/decrypt cho tất cả mode | Bảng so sánh ciphertext, phát hiện lộ pattern (ECB), kiểm tra giải mã, thời gian |
| **Task 02** | Mã hóa / giải mã một ảnh RGB do bạn chọn | Lưới ảnh so sánh trực quan, bảng thời gian, throughput, entropy, correlation |
| **Task 03** | Benchmark theo kích thước dữ liệu (10³ – 10⁶ byte) | Ảnh 4 subplot: Throughput, Encrypt latency, Decrypt latency, biểu đồ cột 1 MB, mặc định đo bằng **PyCryptodome** |

---

## Cấu trúc thư mục

```
.
├── AES_tasks_compare.py              # Script chính chạy 3 task
├── AES_project_all_modes_PyQt6.py    # Driver AES: các mode, CLI, GUI (PyQt6)
├── AESVisual_all_modes_rgb.py        # Mã hóa ảnh RGB + container .aesimg
├── mypackages/                       # Backend AES (modes.py, AES.py, key_expansion.py...)
├── requirements.txt
└── docs/                             # Ảnh minh họa kết quả
```

> `AES_tasks_compare.py` dùng lại backend AES và các hàm trong hai file driver ở trên, nên các file này phải nằm **cùng thư mục** với nhau.

---

## Cài đặt

Yêu cầu Python 3.9 trở lên.

```bash
pip install -r requirements.txt
```

Nội dung `requirements.txt`:

```
numpy
pillow
matplotlib
cryptography
pycryptodome
PyQt6          # chỉ cần nếu dùng giao diện --gui
```

Vai trò của từng thư viện:

- `numpy`, `pillow`, `matplotlib`: xử lý ảnh và vẽ biểu đồ.
- `cryptography`: backend đối chiếu (`--backend reference`).
- `pycryptodome`: Task 03, vì có đủ EAX, SIV, OCB.

---

## Cách chạy

```bash
python AES_tasks_compare.py                  # hiện menu chọn task
python AES_tasks_compare.py --task 1         # Task 01
python AES_tasks_compare.py --task 2         # Task 02 (sẽ hỏi đường dẫn ảnh)
python AES_tasks_compare.py --task 3         # Task 03
python AES_tasks_compare.py --task all       # chạy cả ba
```

### Task 02: nhập đường dẫn ảnh

Khi chạy Task 02, chương trình hỏi:

```
Nhap duong dan anh (dan path hoac keo-tha file vao terminal):
```

Bạn dán đường dẫn vào hoặc kéo-thả file vào terminal (dấu nháy và khoảng trắng đều được xử lý). Hoặc truyền sẵn:

```bash
python AES_tasks_compare.py --task 2 --image ~/Pictures/images.jpeg
```

Ảnh được **giữ nguyên kích thước và chất lượng**. Nếu muốn chạy nhanh hơn, có thể thu nhỏ bằng `--max-side 256`.

---

## Chi tiết từng task

### Task 01: 2 block giống nhau

- Plaintext = `block || block` (32 byte, mặc định `AES_BLOCK_16BYTE`).
- Chạy 12 mode: ECB, CBC, CFB, OFB, CTR, GCM, GMAC, CCM, GCM-SIV, XTS, KW, KWP.
- Cột `C1 == C2` cho biết ciphertext block 1 có bằng block 2 không. ECB cho kết quả bằng nhau (lộ pattern), các mode còn lại khác nhau.
- GMAC chỉ tạo tag (không mã hóa), KW/KWP bọc khóa, nên cột này ghi `N/A`.

### Task 02: ảnh

- Mode: ECB, CBC, CFB, OFB, CTR, GCM, CCM, GCM-SIV, XTS.
- Dùng trực tiếp các hàm của `AESVisual_all_modes_rgb.py`: `load_rgb_image`, `encrypt_image_bytes`, `decrypt_image_bytes`, `select_cipher_visual_bytes`, `save_container`.
- Các chỉ số trong bảng:
  - **Enc/Dec (ms), MB/s**: thời gian và thông lượng.
  - **Entropy**: càng gần 8,0 thì ciphertext càng ngẫu nhiên.
  - **Correlation**: tương quan giữa các pixel liền kề, càng gần 0 càng tốt.
  - **Round-trip**: ảnh giải mã có khớp ảnh gốc không.
- Nếu một mode của AESVisual bị lỗi, chương trình chạy lại mode đó bằng backend dự án và đánh dấu `*` (ví dụ `CBC*`). Chi tiết lỗi nằm trong `task2_errors.log`.

### Task 03: benchmark 4 subplot

Các mode: ECB, CBC, CFB, OFB, CTR, GCM, EAX, CCM, SIV, OCB.

| Subplot | Nội dung |
|---|---|
| (a) | AES Throughput (MB/s) vs Data Size, log-log |
| (b) | Encrypt Latency (µs) vs Data Size, log-log |
| (c) | Decrypt Latency (µs) vs Data Size, log-log |
| (d) | Biểu đồ cột Encrypt/Decrypt latency tại 1 MB |

Mỗi phép đo được lặp lại nhiều lần trong khoảng 0,25 giây rồi lấy trung bình. Chi phí khởi tạo cipher được tính vào thời gian, và ECB/CBC có thêm bước padding.

---

## Tùy chọn dòng lệnh

| Tham số | Mặc định | Ý nghĩa |
|---|---|---|
| `--task {1,2,3,all}` | hiện menu | Chọn task |
| `--image PATH` | hỏi khi chạy | Ảnh đầu vào cho Task 02 |
| `--backend {project,reference}` | `project` | `reference` dùng thư viện `cryptography` thay cho backend của bạn |
| `--project-module` | `AES_project_all_modes_PyQt6` | Tên module driver AES |
| `--visual-module` | `AESVisual_all_modes_rgb` | Tên module mã hóa ảnh |
| `--key-bits {128,192,256}` | `128` | Độ dài khóa AES |
| `--block TEXT` | `AES_BLOCK_16BYTE` | Block 16 byte cho Task 01 (text hoặc `hex:...`) |
| `--repeat1` | `100` | Số lần lặp mỗi phép đo, Task 01 |
| `--repeat2` | `1` | Số lần lặp mỗi phép đo, Task 02 |
| `--max-side` | `0` | Thu nhỏ ảnh nếu cạnh dài hơn giá trị này; `0` là giữ nguyên |
| `--sizes` | `1e3,1e4,1e5,1e6` | Kích thước dữ liệu cho Task 03 (byte) |
| `--bench-backend {pycryptodome,project}` | `pycryptodome` | Backend cho Task 03 |
| `--bench-repeat` | `1000` | Số lần lặp tối đa mỗi phép đo, Task 03 |
| `--out-dir` | `aes_output` | Thư mục lưu kết quả |
| `--no-show` | tắt | Chỉ lưu file, không mở cửa sổ đồ thị |

---

## Kết quả đầu ra

Tất cả nằm trong thư mục `aes_output/`:

```
aes_output/
├── task1_results.csv
├── task1_table.png
├── image_original.png
├── images_encrypted/<MODE>.png
├── images_decrypted/<MODE>.png
├── containers_aesimg/cipher_rgb_<mode>.aesimg
├── task2_visual_comparison.png
├── task2_table_and_time.png
├── task2_results.csv
├── task2_errors.log                  # chỉ có khi có mode bị lỗi
├── task3_benchmark.png
└── task3_results.csv
```

Các file `.aesimg` có thể giải mã lại bằng `AESVisual_all_modes_rgb.py`:

```bash
python AESVisual_all_modes_rgb.py --mode CBC --operation decrypt \
    --input-bin aes_output/containers_aesimg/cipher_rgb_cbc.aesimg
```

---

## Lưu ý

- **ECB** chỉ dùng để minh họa. Nó làm lộ cấu trúc ảnh (xem `task2_visual_comparison.png`) nên không an toàn cho dữ liệu thực.
- **CBC, CFB, OFB, CTR, XTS** chỉ bảo mật nội dung, không xác thực. Với dữ liệu thật, nên dùng GCM, CCM hoặc GCM-SIV.
- **CCM** dùng nonce 12 byte, vì nonce 13 byte chỉ cho phép tối đa 65 535 byte dữ liệu, không đủ cho ảnh thông thường.
- **SIV** (Task 03) dùng khóa gấp đôi, tức 32 byte cho AES-128, theo yêu cầu của PyCryptodome.
- Nếu backend AES là Python thuần, ảnh lớn không thu nhỏ có thể chạy rất lâu. Hãy xem dòng tiến trình `dang chay <mode> ...` để biết chương trình vẫn đang chạy.
- Số liệu benchmark phụ thuộc vào máy và tải CPU tại thời điểm đo.

**Đây là dự án phục vụ học tập và so sánh. Không dùng để bảo vệ dữ liệu thật.**

