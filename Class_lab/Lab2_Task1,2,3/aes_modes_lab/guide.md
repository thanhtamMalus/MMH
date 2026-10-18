# Hướng dẫn biên dịch và chạy

Dự án yêu cầu trình biên dịch hỗ trợ C++17 và CMake 3.16 trở lên. Tất cả lệnh dưới đây giả sử terminal đang ở thư mục `aes_modes_lab`.

## Ubuntu / Linux

### 1. Cài công cụ cần thiết

```bash
sudo apt update
sudo apt install -y build-essential cmake g++
```

### 2. Tạo thư mục build và cấu hình CMake

```bash
mkdir -p build
cd build
cmake ..
```

Nếu muốn chỉ định trình biên dịch C++:

```bash
cmake -DCMAKE_CXX_COMPILER=g++ ..
```

### 3. Biên dịch

```bash
cmake --build . --parallel
```

### 4. Chạy bộ kiểm thử

```bash
./aes_tests
```

Hoặc chạy bằng CTest:

```bash
ctest --output-on-failure
```

## Windows

### Cách 1: PowerShell hoặc CMD với CMake và compiler native

Cài CMake và một compiler C++17. Có thể dùng MinGW-w64/GCC, Clang hoặc Visual Studio Build Tools/MSVC. Mở terminal trong thư mục `aes_modes_lab`, rồi tạo thư mục build:

```powershell
New-Item -ItemType Directory -Force build
Set-Location build
```

#### MinGW Makefiles (GCC)

```powershell
cmake -G "MinGW Makefiles" ..
cmake --build .
.\aes_tests.exe
```

Hoặc chạy test qua CTest:

```powershell
ctest --output-on-failure
```

#### Visual Studio / MSVC

```powershell
cmake ..
cmake --build . --config Release
.\Release\aes_tests.exe
```

Với generator MSVC một cấu hình khác, file thực thi có thể nằm trong `Debug`; chạy đúng cấu hình đã build, ví dụ `.\Debug\aes_tests.exe`. CTest vẫn có thể chạy từ thư mục build:

```powershell
ctest -C Release --output-on-failure
```

Nếu dùng Clang với generator MinGW, chỉ định compiler khi cấu hình (đảm bảo `clang++` đã nằm trong `PATH`):

```powershell
cmake -G "MinGW Makefiles" -DCMAKE_CXX_COMPILER=clang++ ..
cmake --build .
.\aes_tests.exe
```

### Cách 2: Windows Terminal với WSL (Ubuntu)

Cài WSL/Ubuntu nếu chưa có, mở Ubuntu từ Windows Terminal, rồi chuyển đến vị trí dự án trên ổ Windows. Ví dụ, nếu dự án ở `D:\work\aes_modes_lab`:

```bash
cd /mnt/d/work/aes_modes_lab
sudo apt update
sudo apt install -y build-essential cmake g++
mkdir -p build
cd build
cmake ..
cmake --build . --parallel
./aes_tests
```

Chạy toàn bộ kiểm thử bằng CTest:

```bash
ctest --output-on-failure
```

## Kết quả mong đợi

Khi thành công, executable in:

```text
All AES mode tests passed.
```

Nếu kiểm thử thất bại, chương trình in `Test failure:` cùng mô tả lỗi và trả mã thoát khác 0. `ctest --output-on-failure` sẽ hiển thị chẩn đoán tương ứng.
