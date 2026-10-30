cmake_minimum_required(VERSION 3.16)
project(lab2_aes LANGUAGES CXX)

# Enforce standard C++17 without compiler-specific extensions
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Default to Release build if no build type is specified (for single-config generators like Makefiles/Ninja)
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Choose the build type" FORCE)
endif()

# Unified binary output directory: <binary_dir>/bin
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")

# Option for Bonus C (AES-NI intrinsics, default OFF)
option(AES_ENABLE_AESNI "Enable hardware AES-NI acceleration (Bonus C)" OFF)

# Compiler warnings and standalone runtime linkage
if(MSVC)
    # Statically link MSVC CRT runtime so binary runs without VC++ Redistributable
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    add_compile_options(/W4 /permissive- /utf-8)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS -DNOMINMAX)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
    if(WIN32 AND MINGW)
        # Static linkage on MinGW to avoid DLL dependencies (libgcc, libstdc++, libwinpthread)
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static -static-libgcc -static-libstdc++")
    endif()
endif()

# Core static library
set(AES_SOURCES
    src/aes128.cpp
    src/sbox_table.cpp
    src/sbox_computed.cpp
    src/ctr.cpp
    src/util.cpp
    src/cli.cpp
    src/kat_runner.cpp
    bonus/aes_ext.cpp
)

if(WIN32)
    list(APPEND AES_SOURCES src/platform_win.cpp)
else()
    list(APPEND AES_SOURCES src/platform_posix.cpp)
endif()

if(AES_ENABLE_AESNI)
    list(APPEND AES_SOURCES bonus/aesni.cpp)
    add_definitions(-DAES_ENABLE_AESNI_IMPL)
    if(NOT MSVC)
        set_source_files_properties(bonus/aesni.cpp PROPERTIES COMPILE_FLAGS "-maes -msse4.1")
    endif()
endif()

add_library(aes STATIC ${AES_SOURCES})

target_include_directories(aes PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}
)

if(WIN32)
    target_link_libraries(aes PUBLIC bcrypt)
endif()

# CLI Executable (aestool)
add_executable(aestool
    src/main.cpp
)

target_link_libraries(aestool PRIVATE aes)

# Benchmark Executable (aes_bench)
add_executable(aes_bench
    bench/aes_bench.cpp
)

target_link_libraries(aes_bench PRIVATE aes)

# Testing
enable_testing()
add_subdirectory(tests)
