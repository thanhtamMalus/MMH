cmake_minimum_required(VERSION 3.16)
project(rsatool LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Default build type
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# Disable in-source build
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_BINARY_DIR)
    message(FATAL_ERROR "In-source build is not allowed. Create a build directory.")
endif()

# ---- OpenSSL 4.x detection ----

# Allow user to override via -DOPENSSL_ROOT_DIR or -DCMAKE_PREFIX_PATH
find_package(OpenSSL 4.0 REQUIRED COMPONENTS Crypto)

message(STATUS "OpenSSL version: ${OPENSSL_VERSION}")
message(STATUS "OpenSSL include: ${OPENSSL_INCLUDE_DIR}")
message(STATUS "OpenSSL libs: ${OPENSSL_CRYPTO_LIBRARY}")

# Enforce OpenSSL >= 4.0
if(OPENSSL_VERSION VERSION_LESS 4.0)
    message(FATAL_ERROR "Cần OpenSSL >= 4.0 (tìm thấy ${OPENSSL_VERSION}). "
                  "Truyền -DOPENSSL_ROOT_DIR=<đường dẫn OpenSSL 4.x>. Xem RUN_GUIDE.md.")
endif()

# Define OPENSSL_NO_DEPRECATED for all targets (essential for OpenSSL 4.x)
target_compile_definitions(rsalab::openssl INTERFACE OPENSSL_NO_DEPRECATED)

# Create interface library for rsalab::openssl
add_library(rsalab::openssl INTERFACE)
target_link_libraries(rsalab::openssl INTERFACE OpenSSL::Crypto)
target_include_directories(rsalab::openssl INTERFACE ${OPENSSL_INCLUDE_DIR})

# ---- nlohmann_json detection ----

find_package(nlohmann_json CONFIG QUIET)
if(NOT nlohmann_json::nlohmann_json)
    # Fallback to FetchContent
    include(FetchContent)
    FetchContent_Declare(
        nlohmann_json
        GIT_TAG v3.11.3
    )
    FetchContent_MakeAvailable(nlohmann_json)
    set(nlohmann_json::nlohmann_json FALSE CACHE BOOL "") # suppress warning
endif()

# ---- Catch2 detection ----

find_package(Catch2 3 QUIET)
if(NOT Catch2::Catch2)
    # Fallback to FetchContent
    include(FetchContent)
    FetchContent_Declare(
        Catch2
        GIT_TAG v3.5.1
    )
    FetchContent_MakeAvailable(Catch2)
    set(Catch2::Catch2 FALSE CACHE BOOL "") # suppress warning
endif()

# ---- Source file definitions ----

# rsa_core: static library with all source files except main.cpp
# Sources: src/*.cpp excluding main.cpp
file(GLOB rsa_core_sources
    src/*.cpp
    EXCLUDE_FROM_ALL
    glob_Globs
)
# Actually, let me list them explicitly to exclude main.cpp properly
set(RSA_CORE_SOURCES
    src/cli.cpp
    src/encoding.cpp
    src/keyio.cpp
    src/rsa_oaep.cpp
    src/envelope.cpp
    src/hybrid.cpp
    src/oaep_manual.cpp
    src/util.cpp
)

add_library(rsa_core STATIC ${RSA_CORE_SOURCES})
target_link_libraries(rsa_core PRIVATE
    rsalab::openssl
    nlohmann_json::nlohmann_json
)

# rsatool: executable (CLI)
# Source: src/main.cpp
add_executable(rsatool src/main.cpp)
target_link_libraries(rsa_core PUBLIC)  # inherit rsa_core symbols/resources
target_link_libraries(rsatool PRIVATE
    rsalab::openssl
    rsa_core
)

# rsabench: benchmark executable
# Source: bench/bench_main.cpp
add_executable(rsabench bench/bench_main.cpp)
target_link_libraries(rsabench PRIVATE
    rsalab::openssl
)

# rsa_tests: test executable
# Sources: tests/*.cpp
set(RSA_TEST_SOURCES
    tests/test_main_or_catch.cpp
    tests/test_rsa_oaep.cpp
    tests/test_keyio.cpp
    tests/test_hybrid.cpp
    tests/test_negative.cpp
    tests/test_oaep_manual.cpp
)

add_executable(rsa_tests ${RSA_TEST_SOURCES})
target_link_libraries(rsa_tests PRIVATE
    rsalab::openssl
    rsa_core
    nlohmann_json::nlohmann_json
)

# Enable Catch2 tests
if(Catch2::Catch2)
    target_compile_definitions(rsa_tests PRIVATE Catch2_MAIN_REQUIRED)
    install(CODE "message(STATUS 'Catch2 available for testing')")
else()
    install(CODE "message(STATUS 'Catch2 not available, tests will be skipped')")
endif()

# Set output directory for executables
set(RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# ---- Compiler warnings ----

# GCC / Clang
if(NOT MSVC)
    target_compile_options(rsa_core PRIVATE -Wall -Wextra -Wpedantic)
    target_compile_options(rsatool PRIVATE -Wall -Wextra -Wpedantic)
    target_compile_options(rsabench PRIVATE -Wall -Wextra -Wpedantic)
    target_compile_options(rsa_tests PRIVATE -Wall -Wextra -Wpedantic)
endif()

# MSVC
if(MSVC)
    target_compile_options(rsa_core PRIVATE /W4 /permissive-)
    target_compile_options(rsatool PRIVATE /W4 /permissive-)
    target_compile_options(rsabench PRIVATE /W4 /permissive-)
    target_compile_options(rsa_tests PRIVATE /W4 /permissive-)
    target_compile_options(rsa_core PRIVATE /EHsc)
    target_compile_options(rsatool PRIVATE /EHsc)
    target_compile_options(rsabench PRIVATE /EHsc)
    target_compile_options(rsa_tests PRIVATE /EHsc)
    # Define _CRT_SECURE_NO_WARNINGS
    target_compile_definitions(rsa_core PRIVATE _CRT_SECURE_NO_WARNINGS)
    target_compile_definitions(rsatool PRIVATE _CRT_SECURE_NO_WARNINGS)
    target_compile_definitions(rsabench PRIVATE _CRT_SECURE_NO_WARNINGS)
    target_compile_definitions(rsa_tests PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()

# ---- Platform-specific linker options ----

# MinGW: link additional system libraries
if(MINGW)
    target_link_libraries(rsa_core PRIVATE -lws2_32 -lcrypt32)
    target_link_libraries(rsatool PRIVATE -lws2_32 -lcrypt32)
    target_link_libraries(rsabench PRIVATE -lws2_32 -lcrypt32)
    target_link_libraries(rsa_tests PRIVATE -lws2_32 -lcrypt32)
endif()

# Threads (may be needed for OpenSSL on some platforms)
if(UNIX AND NOT APPLE)
    find_package(Threads REQUIRED)
    target_link_libraries(rsa_core PRIVATE Threads::Threads)
    target_link_libraries(rsatool PRIVATE Threads::Threads)
    target_link_libraries(rsabench PRIVATE Threads::Threads)
    target_link_libraries(rsa_tests PRIVATE Threads::Threads)
endif()

# ---- Copy DLL for Windows (if using dynamic OpenSSL) ----

# If linking dynamic OpenSSL on Windows, DLL must be accessible
# This is handled by the user via OPENSSL_ROOT_DIR or PATH
# Optionally add post-build copy if DLL is found

option(OPENSSL_USE_STATIC_LIBS "Link OpenSSL tĩnh" OFF)
if(OPENSSL_USE_STATIC_LIBS)
    if(WIN32)
        target_link_libraries(rsa_core PRIVATE ws2_32 crypt32 user32 advapi32)
        target_link_libraries(rsatool PRIVATE ws2_32 crypt32 user32 advapi32)
        target_link_libraries(rsabench PRIVATE ws2_32 crypt32 user32 advapi32)
        target_link_libraries(rsa_tests PRIVATE ws2_32 crypt32 user32 advapi32)
    endif()
    message(STATUS "Linking OpenSSL statically")
endif()

message(STATUS "CMake configuration complete for rsatool")