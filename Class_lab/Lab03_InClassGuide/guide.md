# Hướng dẫn build Lab03 (CMake + MSYS2 MinGW + OpenSSL)

## TL;DR - Quy trình mỗi lần sửa code

```powershell
cd D:\GitHub\MMH\Class_lab\Lab03
cmake --build build        # biên dịch, tạo/cập nhật file .exe
.\task_b\task_b.exe        # chạy
```

**Không cần gõ `g++` nữa.** `cmake --build build` đã biên dịch và tạo luôn file `.exe`.

## Mỗi lần qua máy khác

1. Xóa cache của build cũ
Trước tiên, hãy xóa hoàn toàn thư mục build bị lỗi cũ để CMake nhận diện lại môi trường từ đầu:

```powershell
Remove-Item -Recurse -Force build
```
2. Chỉ định rõ Generator là MinGW Makefiles
Strawberry Perl thường chen ngang vào lệnh cmake. Bạn cần chỉ định rõ Generator của MSYS2 bằng tham số -G "MinGW Makefiles":

```powershell
cmake -B build -G "MinGW Makefiles"
cmake --build build
```
---

## 1. Cấu trúc thư mục

```
Lab03/
├── CMakeLists.txt
├── common.h              <- dùng chung, chỉ cần #include "common.h"
├── task_a/
│   ├── task_a_bignum.cpp
│   └── task_a.exe        <- do CMake tạo
├── task_b/
│   ├── task_b_rsa_keys.cpp
│   └── task_b.exe        <- do CMake tạo
└── build/                <- do CMake tạo, có thể xóa bất cứ lúc nào
```

File `.exe` nằm cạnh file `.cpp` (nhờ `RUNTIME_OUTPUT_DIRECTORY` trong `CMakeLists.txt`).

## 2. Cấu hình lần đầu (hoặc sau khi xóa `build/`)

Chạy trong PowerShell, tại thư mục `Lab03`:

```powershell
Remove-Item -Recurse -Force build
cmake -S . -B build -G "MinGW Makefiles" `
  -DCMAKE_CXX_COMPILER=C:/msys64/mingw64/bin/g++.exe `
  -DOPENSSL_ROOT_DIR=C:/msys64/mingw64
cmake --build build
```

Hai tham số bắt buộc:

- `-DCMAKE_CXX_COMPILER=...`: máy có 3 bản g++ trong PATH, phải chỉ rõ bản MSYS2.
- `-DOPENSSL_ROOT_DIR=...`: chỉ chỗ OpenSSL của MSYS2 (`include/openssl`, `lib/libcrypto.a`).

Chỉ phải chạy lại lệnh cấu hình này khi:

- thêm hoặc xóa task trong `CMakeLists.txt`
- đổi đường dẫn compiler / OpenSSL
- đã xóa thư mục `build/`

## 3. Build các lần sau

```powershell
cmake --build build                  # build tất cả task
cmake --build build --target task_b  # chỉ build task_b
```

Lưu ý:

- **Chạy từ thư mục `Lab03`.** Nếu đang đứng trong `task_b` thì `cd ..` trước, hoặc dùng `cmake --build ..\build`.
- CMake chỉ biên dịch lại phần đã đổi nên các lần sau nhanh hơn.
- **Nếu có lỗi biên dịch, `.exe` không được cập nhật** và chạy `.exe` sẽ chạy bản cũ. Luôn kiểm tra dòng cuối có `Built target ...` chưa.

## 4. Chạy chương trình

```powershell
.\task_b\task_b.exe          # mặc định
.\task_b\task_b.exe 512      # truyền số bit (edu-bits)
```

Các file `.pem` / `.der` được ghi vào **thư mục đang đứng khi chạy**.
Nếu đứng ở `Lab03` thì chúng nằm ở `Lab03`; muốn chúng nằm trong `task_b` thì `cd task_b` rồi chạy `.\task_b.exe`.

Nếu báo thiếu DLL (`libcrypto-3-x64.dll`), hãy chạy từ terminal
và kiểm tra `C:\msys64\mingw64\bin` có trong PATH.

## 5. Thêm task mới

1. Tạo thư mục `task_c/` và file `task_c/task_c_xxx.cpp`.
2. Thêm một dòng vào `CMakeLists.txt`:
   ```cmake
   add_task(task_c task_c/task_c_xxx.cpp)
   ```
3. Chạy lại lệnh cấu hình ở mục 2 (không cần xóa `build/`), rồi `cmake --build build`.

## 6. Build tay bằng g++ (chỉ khi không dùng CMake)

`common.h` nằm ở `Lab03` nên phải thêm `-I` trỏ tới nó.

Đứng ở `Lab03`:

```powershell
g++ -std=c++17 -Wall -Wextra -I. task_b/task_b_rsa_keys.cpp -o task_b/task_b -lcrypto
```

Đứng trong `task_b`:

```powershell
g++ -std=c++17 -Wall -Wextra -I.. task_b_rsa_keys.cpp -o task_b -lcrypto
```

Quên `-I` sẽ gặp lỗi `common.h: No such file or directory`.
Lỗi này **không phải do CMake**, mà do gõ g++ tay mà thiếu include path.

## 7. Lỗi thường gặp

| Lỗi | Nguyên nhân / cách sửa |
|---|---|
| `Could NOT find OpenSSL` | Thiếu `-DOPENSSL_ROOT_DIR`, hoặc CMake đang dùng generator Visual Studio. Xóa `build/` rồi chạy lại lệnh ở mục 2. |
| `Selecting Windows SDK...` | CMake đang chọn Visual Studio. Thêm `-G "MinGW Makefiles"`. |
| `common.h: No such file or directory` | Đang build tay bằng g++ mà thiếu `-I`. Dùng `cmake --build build`, hoặc xem mục 6. |
| `'cout' is not a member of 'std'` | Thiếu `#include <iostream>` (đã có sẵn trong `common.h`). |
| `missing terminating " character` | Chuỗi bị ngắt dòng khi copy/paste, hoặc lẫn ký tự lạ như `↩→`. Viết lại thành một dòng. |
| Chạy `.exe` mà kết quả không đổi sau khi sửa code | Build bị lỗi nên `.exe` là bản cũ. Đọc lỗi biên dịch trong terminal. |
| Không thấy `mingw32-make` | `pacman -S mingw-w64-x86_64-make` trong MSYS2 MINGW64, hoặc thêm `-DCMAKE_MAKE_PROGRAM=C:/msys64/mingw64/bin/mingw32-make.exe`. |
| Chưa cài OpenSSL | Trong MSYS2 MINGW64: `pacman -S mingw-w64-x86_64-openssl`. |

## 8. Mẹo

- Gặp lỗi lạ sau khi đổi cấu hình: xóa `build/` rồi cấu hình lại (mục 2).
- Dùng `CMakePresets.json` để khỏi gõ lệnh cấu hình dài:

```json
{
  "version": 3,
  "configurePresets": [
    {
      "name": "mingw",
      "generator": "MinGW Makefiles",
      "binaryDir": "${sourceDir}/build",
      "cacheVariables": {
        "OPENSSL_ROOT_DIR": "C:/msys64/mingw64",
        "CMAKE_CXX_COMPILER": "C:/msys64/mingw64/bin/g++.exe"
      }
    }
  ]
}
```

Khi có file preset này, mục 2 rút gọn thành:

```powershell
cmake --preset mingw
cmake --build build
```