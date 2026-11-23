# Hướng Dẫn Biên Dịch Và Chạy Dự Án (Installation & Execution Guide)

Tài liệu này hướng dẫn chi tiết cách cấu hình, biên dịch và chạy dự án trên cả hai hệ điều hành **Windows** và **Linux** (hoặc WSL), cũng như cách triển khai qua **Docker Container**.

---

## 🛠 Yêu cầu hệ thống (Prerequisites)

| Công cụ | Windows | Linux (Ubuntu/Debian) |
| :--- | :--- | :--- |
| **C++ Compiler** | MSVC (Visual Studio 2019/202s2) | GCC / G++ (`g++ >= 9`) |
| **Build System** | CMake >= 3.16 | CMake >= 3.16 |
| **Scripting** | Python 3.x | Python 3.x |
| **Container** | Docker Desktop | Docker Engine / Docker Desktop |

---

## 💻 1. Cài đặt và Chạy trên WINDOWS

### Bước 1: Khởi tạo thư mục Build
Mở **PowerShell** tại thư mục gốc `aes_modes_lab` và khởi tạo cấu hình CMake:

```powershell
cmake -S . -B build
```
### Bước 2: Biên dịch (Build)
Biên dịch dự án ở chế độ Debug để xuất ra thư viện tĩnh .lib, thư viện động .dll và file test thực thi:

```powershell
cmake --build build --config Debug
```
Các file thành phẩm sẽ nằm tại build\Debug\:
aes_modes.lib (Thư viện tĩnh)
aes_modes.dll (Thư viện động)
aes_tests.exe (File chạy test C++)

### Bước 3: Chạy Unit Test C++
```powershell
.\build\Debug\aes_tests.exe
```
### Bước 4: Kiểm tra Python Binding (gọi file .dll)
Chạy script Python để test import thư viện động C++:

```powershell
python python_binding/test_aes.py
```
## 🐧 2. Cài đặt và Chạy trên LINUX (Ubuntu / Debian / WSL)
### Bước 1: Cài đặt các công cụ cần thiết (nếu chưa có)
Mở Terminal (Bash) và chạy lệnh:

```
sudo apt update
sudo apt install -y build-essential cmake python3
```
### Bước 2: Khởi tạo cấu hình CMake
Tại thư mục gốc aes_modes_lab, chạy:

```
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
```
Bước 3: Biên dịch (Build)
Chạy Make để biên dịch dự án:

```
cmake --build build --parallel
```
Các file thành phẩm sẽ nằm tại build/:
libaes_modes.a (Thư viện tĩnh Linux)
libaes_modes.so (Thư viện động Linux)
aes_tests (File chạy test C++)

### Bước 4: Chạy Unit Test C++
```
./build/aes_tests
```
### Bước 5: Kiểm tra Python Binding (gọi file .so)
Cần khai báo đường dẫn chứa file .so cho hệ thống trước khi chạy Python:

```
export LD_LIBRARY_PATH=$(pwd)/build:$LD_LIBRARY_PATH
python3 python_binding/test_aes.py
```
## 🐳 3. Đóng gói và Chạy bằng DOCKER (Cross-Platform)
Cách này hoạt động giống hệt nhau trên cả Windows và Linux mà không cần cài đặt môi trường C++.

### Bước 1: Build Docker Image
Chạy lệnh đóng gói (Docker sẽ tự động biên dịch sang môi trường Linux và kiểm thử):

```
docker build -t aes-modes-lab .
```
### Bước 2: Chạy Container
```
docker run --rm aes-modes-lab
```
## 🧹 Dọn dẹp File rác (Clean Up)
Để xóa toàn bộ file tạm sinh ra trong quá trình build:

### Trên Windows (PowerShell):
```powershell
Remove-Item -Recurse -Force build -ErrorAction SilentlyContinue
```
### Trên Linux (Bash):
```
rm -rf build
```


