cmake_minimum_required(VERSION 3.20)
project(rsatool VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ── OpenSSL >= 4.0 ───────────────────────────────────────────────────────────
# Never hardcode paths. Use OPENSSL_ROOT_DIR from env/CLI or CMake discovery.
find_package(OpenSSL 4.0 REQUIRED)
message(STATUS "OpenSSL version : ${OPENSSL_VERSION}")
message(STATUS "OpenSSL include : ${OPENSSL_INCLUDE_DIR}")
message(STATUS "OpenSSL crypto  : ${OPENSSL_CRYPTO_LIBRARY}")

if(OPENSSL_VERSION VERSION_LESS "4.0")
    message(FATAL_ERROR
        "OpenSSL >= 4.0 is required, but found ${OPENSSL_VERSION}. "
        "Set -DOPENSSL_ROOT_DIR= to your OpenSSL 4 installation.")
endif()

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
    ${CMAKE_SOURCE_DIR}/include
    ${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(rsatool_lib PUBLIC
    OpenSSL::Crypto
    nlohmann_json::nlohmann_json
)

# Windows: also link WinSock and crypto support libs
if(WIN32)
    target_link_libraries(rsatool_lib PUBLIC ws2_32 crypt32 advapi32 user32)
endif()

# Linux RPATH so the binary finds a custom /opt/openssl4 at runtime
if(UNIX AND NOT APPLE)
    get_filename_component(OPENSSL_LIB_DIR "${OPENSSL_CRYPTO_LIBRARY}" DIRECTORY)
    set_target_properties(rsatool_lib PROPERTIES
        BUILD_RPATH "${OPENSSL_LIB_DIR}"
        INSTALL_RPATH "${OPENSSL_LIB_DIR}"
    )
endif()

# ── Executable: rsatool ───────────────────────────────────────────────────────
add_executable(rsatool src/main.cpp)
target_link_libraries(rsatool PRIVATE rsatool_lib CLI11::CLI11)

if(UNIX AND NOT APPLE)
    get_filename_component(OPENSSL_LIB_DIR "${OPENSSL_CRYPTO_LIBRARY}" DIRECTORY)
    set_target_properties(rsatool PROPERTIES
        BUILD_RPATH "${OPENSSL_LIB_DIR}"
        INSTALL_RPATH "${OPENSSL_LIB_DIR}"
    )
endif()

# Windows: copy libcrypto DLL next to executable
if(WIN32)
    add_custom_command(TARGET rsatool POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "$<TARGET_FILE:OpenSSL::Crypto>"
            "$<TARGET_FILE_DIR:rsatool>"
        COMMENT "Copying OpenSSL DLL to output directory"
    )
endif()

# ── Tests ─────────────────────────────────────────────────────────────────────
enable_testing()

add_executable(test_rsatool
    tests/test_oaep.cpp
    tests/test_hybrid.cpp
    tests/test_negative.cpp
    tests/test_codec.cpp
)

target_link_libraries(test_rsatool PRIVATE
    rsatool_lib
    Catch2::Catch2WithMain
)

if(UNIX AND NOT APPLE)
    get_filename_component(OPENSSL_LIB_DIR "${OPENSSL_CRYPTO_LIBRARY}" DIRECTORY)
    set_target_properties(test_rsatool PROPERTIES
        BUILD_RPATH "${OPENSSL_LIB_DIR}"
        INSTALL_RPATH "${OPENSSL_LIB_DIR}"
    )
endif()

if(WIN32)
    add_custom_command(TARGET test_rsatool POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "$<TARGET_FILE:OpenSSL::Crypto>"
            "$<TARGET_FILE_DIR:test_rsatool>"
        COMMENT "Copying OpenSSL DLL to test directory"
    )
endif()

include(CTest)
include(Catch)
catch_discover_tests(test_rsatool)

# ── Benchmark ─────────────────────────────────────────────────────────────────
add_executable(bench_rsatool bench/bench.cpp)
target_link_libraries(bench_rsatool PRIVATE rsatool_lib)

if(UNIX AND NOT APPLE)
    get_filename_component(OPENSSL_LIB_DIR "${OPENSSL_CRYPTO_LIBRARY}" DIRECTORY)
    set_target_properties(bench_rsatool PROPERTIES
        BUILD_RPATH "${OPENSSL_LIB_DIR}"
        INSTALL_RPATH "${OPENSSL_LIB_DIR}"
    )
endif()

if(WIN32)
    add_custom_command(TARGET bench_rsatool POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "$<TARGET_FILE:OpenSSL::Crypto>"
            "$<TARGET_FILE_DIR:bench_rsatool>"
        COMMENT "Copying OpenSSL DLL to bench directory"
    )
endif()

# ── Bonus: manual OAEP ───────────────────────────────────────────────────────
add_executable(oaep_manual src/bonus/oaep_manual.cpp)
target_link_libraries(oaep_manual PRIVATE rsatool_lib)

if(UNIX AND NOT APPLE)
    get_filename_component(OPENSSL_LIB_DIR "${OPENSSL_CRYPTO_LIBRARY}" DIRECTORY)
    set_target_properties(oaep_manual PROPERTIES
        BUILD_RPATH "${OPENSSL_LIB_DIR}"
        INSTALL_RPATH "${OPENSSL_LIB_DIR}"
    )
endif()

if(WIN32)
    add_custom_command(TARGET oaep_manual POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "$<TARGET_FILE:OpenSSL::Crypto>"
            "$<TARGET_FILE_DIR:oaep_manual>"
        COMMENT "Copying OpenSSL DLL to oaep_manual directory"
    )
endif()

