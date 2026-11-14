cmake_minimum_required(VERSION 3.16)
project(aes_modes_lab LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

#Khai báo các file nguồn
set(SRC_FILES
    src/aes.cpp
    src/sp800_38a.cpp
    src/sp800_38c.cpp
    src/sp800_38d.cpp
)

#Thư viện tĩnh (.a / .lib)
add_library(aes_modes STATIC ${SRC_FILES})
target_include_directories(aes_modes PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

#Thư viện động (.so / .dll) - Phục vụ Import sang ngôn ngữ khác (Python/C#...)
add_library(aes_modes_shared SHARED ${SRC_FILES})
target_include_directories(aes_modes_shared PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
set_target_properties(aes_modes_shared PROPERTIES OUTPUT_NAME "aes_modes")

#Tự động xuất tất cả symbol trên Windows DLL (nếu không dùng extern "C")
if(WIN32)
    set_target_properties(aes_modes_shared PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS ON)
endif()

#File chạy Test
add_executable(aes_tests tests/main.cpp)
target_link_libraries(aes_tests PRIVATE aes_modes)

enable_testing()
add_test(NAME aes_tests COMMAND aes_tests)