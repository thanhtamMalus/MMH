import ctypes
import os
import platform

# Xác định đường dẫn file DLL / SO
base_dir = os.path.dirname(os.path.abspath(__file__))
if platform.system() == "Windows":
    lib_path = os.path.join(base_dir, "../Build_gcc/aes_modes.dll")
else:
    lib_path = os.path.join(base_dir, "../Build_gcc/libaes_modes.so")

# Nạp thư viện C++ vào Python
try:
    aes_lib = ctypes.CDLL(lib_path)
    print(" [Success] Nạp thư viện C++ vào Python thành công!")
except Exception as e:
    print(f" [Error] Không thể nạp thư viện: {e}")

# (Tùy chọn) Gọi một hàm C/C++ từ thư viện nếu có
# aes_lib.ten_ham_cua_ban()