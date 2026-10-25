cmake_minimum_required(VERSION 3.10)
project(Lab03_BIGNUM CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)

# Thư viện "ảo" chỉ chứa common.h + OpenSSL.
# Task nào link vào nó sẽ tự có include path, OpenSSL và các lib Windows.
add_library(common INTERFACE)
target_include_directories(common INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(common INTERFACE OpenSSL::Crypto)
if(WIN32)
    target_link_libraries(common INTERFACE ws2_32 gdi32 crypt32)
endif()

# Hàm thêm một task: tên target + file nguồn
function(add_task name)
    add_executable(${name} ${ARGN})
    target_link_libraries(${name} PRIVATE common)
    # Xuất file .exe ra cạnh file .cpp cho giống cách bạn đang để
    set_target_properties(${name} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/${name})
endfunction()

# Mỗi task chỉ cần một dòng
add_task(task_a task_a/task_a_bignum.cpp)
add_task(task_b task_b/task_b_rsa_keys.cpp)
# add_task(task_c task_c/task_c_xxx.cpp)