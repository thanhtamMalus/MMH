cmake_minimum_required(VERSION 3.20)
project(rsatool VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ── OpenSSL >= 4.0 (tự động dò, xem cmake/RsatoolOpenSSL.cmake) ──────────────
# Không hardcode đường dẫn. Thứ tự: -DOPENSSL_ROOT_DIR > biến môi trường >
# PATH/LD_LIBRARY_PATH > các thư mục cài đặt quen thuộc > (tuỳ chọn) tự build.
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(RsatoolOpenSSL)
rsatool_find_openssl4()

# ── Third-party deps via FetchContent ────────────────────────────────────────
include(FetchContent)

FetchContent_Declare(
    CLI11
    GIT_REPOSITORY https://github.com/CLIUtils/CLI11.git
    GIT_TAG        v2.4.2
)

FetchContent_Declare(
    nlohmann_json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG        v3.11.3
)

FetchContent_Declare(
    Catch2
    GIT_REPOSITORY https://github.com/catchorg/Catch2.git
    GIT_TAG        v3.6.0
)

FetchContent_MakeAvailable(CLI11 nlohmann_json Catch2)

# ── Compiler flags ────────────────────────────────────────────────────────────
if(MSVC)
    add_compile_options(/W4 /permissive- /utf-8 /EHsc)
    # Suppress C4996 for std::getenv (safe usage)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
else()
    add_compile_options(-Wall -Wextra -Wpedantic -Wconversion)
endif()

# ── Library: rsatool_lib ──────────────────────────────────────────────────────
add_library(rsatool_lib STATIC
    src/keys.cpp
    src/oaep.cpp
    src/hybrid.cpp
    src/envelope.cpp
    src/codec.cpp
    src/platform.cpp
)

target_include_directories(rsatool_lib PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# OpenSSL::Crypto đã mang theo include dir + (khi tĩnh) dl/pthread
target_link_libraries(rsatool_lib PUBLIC
    OpenSSL::Crypto
    nlohmann_json::nlohmann_json
)

# Windows: link thêm WinSock và các thư viện hệ thống
if(WIN32)
    target_link_libraries(rsatool_lib PUBLIC ws2_32 crypt32 advapi32 user32)
endif()

# ── Executable: rsatool ───────────────────────────────────────────────────────
add_executable(rsatool src/main.cpp)
target_link_libraries(rsatool PRIVATE rsatool_lib CLI11::CLI11)
rsatool_setup_runtime(rsatool)

# ── Tests ─────────────────────────────────────────────────────────────────────
enable_testing()

add_executable(test_rsatool
    tests/test_oaep.cpp
    tests/test_hybrid.cpp
    tests/test_negative.cpp
    #tests/test_codec.cpp
)
target_link_libraries(test_rsatool PRIVATE
    rsatool_lib
    Catch2::Catch2WithMain
)
rsatool_setup_runtime(test_rsatool)

include(CTest)
list(APPEND CMAKE_MODULE_PATH "${catch2_SOURCE_DIR}/extras")
include(Catch)
catch_discover_tests(test_rsatool)

# ── Benchmark ─────────────────────────────────────────────────────────────────
add_executable(bench_rsatool bench/bench.cpp)
target_link_libraries(bench_rsatool PRIVATE rsatool_lib)
rsatool_setup_runtime(bench_rsatool)

# ── Bonus: manual OAEP ───────────────────────────────────────────────────────
add_executable(oaep_manual src/bonus/oaep_manual.cpp)
target_link_libraries(oaep_manual PRIVATE rsatool_lib)
rsatool_setup_runtime(oaep_manual)
