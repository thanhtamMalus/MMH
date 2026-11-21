cmake_minimum_required(VERSION 3.16)
project(hashtool VERSION 1.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release)
endif()

# OpenSSL >= 3.0 (EVP_MD_fetch / EVP_DigestInit_ex2). OpenSSL 4.x also works.
find_package(OpenSSL 3.0 REQUIRED)
message(STATUS "OpenSSL ${OPENSSL_VERSION} (${OPENSSL_CRYPTO_LIBRARY})")

add_executable(hashtool src/hashtool.cpp src/x509_tool.cpp)
target_include_directories(hashtool PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/common")
target_link_libraries(hashtool PRIVATE OpenSSL::Crypto)

if(MSVC)
  target_compile_options(hashtool PRIVATE /W4 /O2 /utf-8)
else()
  target_compile_options(hashtool PRIVATE -O2 -Wall -Wextra -Wpedantic)
endif()

# Always place the binary in <lab>/bin (also for multi-config generators such as Visual Studio)
set(BIN_DIR "${CMAKE_CURRENT_SOURCE_DIR}/bin")
set_target_properties(hashtool PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY "${BIN_DIR}"
  RUNTIME_OUTPUT_DIRECTORY_RELEASE "${BIN_DIR}"
  RUNTIME_OUTPUT_DIRECTORY_DEBUG "${BIN_DIR}"
  RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO "${BIN_DIR}"
  RUNTIME_OUTPUT_DIRECTORY_MINSIZEREL "${BIN_DIR}")

enable_testing()
add_test(NAME kat COMMAND hashtool --kat "${CMAKE_CURRENT_SOURCE_DIR}/vectors/vectors.json")
