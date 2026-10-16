cmake_minimum_required(VERSION 3.16)
project(aestool VERSION 1.0.0 LANGUAGES CXX)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(AESTOOL_BUILD_TESTS  "Build unit tests (Catch2) and register ctest tests" ON)
option(AESTOOL_BUILD_SHARED "Also build the shared library (.dll / .so) with C API" ON)
option(AESTOOL_FETCH_DEPS   "Download Crypto++ / Catch2 if not found on the system (needs git + internet)" ON)
set(AESTOOL_CRYPTOPP_TAG "CRYPTOPP_8_9_0" CACHE STRING "Crypto++ tag used by the download fallback")
set(AESTOOL_CRYPTOPP_CMAKE_TAG "CRYPTOPP_8_9_0" CACHE STRING "cryptopp-cmake tag used by the download fallback")

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")

# ---------------------------------------------------------------------------
# Locate Crypto++ (the only crypto library allowed by the lab)
#   1) CMake package config (vcpkg, cryptopp-cmake)
#   2) plain find_path / find_library (apt: libcrypto++-dev, MSYS2: crypto++)
#   3) download + build (fallback)
# ---------------------------------------------------------------------------
add_library(cryptopp_dep INTERFACE)
set(_cpp_ok FALSE)

find_package(cryptopp CONFIG QUIET)
foreach(_t cryptopp::cryptopp cryptopp::cryptopp-static cryptopp-static cryptopp::cryptopp-shared cryptopp-shared)
  if(NOT _cpp_ok AND TARGET ${_t})
    target_link_libraries(cryptopp_dep INTERFACE ${_t})
    set(_cpp_ok TRUE)
    message(STATUS "Crypto++: using CMake target ${_t}")
  endif()
endforeach()

if(NOT _cpp_ok)
  find_path(CRYPTOPP_INCLUDE_DIR NAMES cryptopp/aes.h crypto++/aes.h)
  find_library(CRYPTOPP_LIBRARY NAMES cryptopp crypto++ cryptlib)
  if(CRYPTOPP_INCLUDE_DIR AND CRYPTOPP_LIBRARY)
    target_include_directories(cryptopp_dep INTERFACE "${CRYPTOPP_INCLUDE_DIR}")
    target_link_libraries(cryptopp_dep INTERFACE "${CRYPTOPP_LIBRARY}")
    set(_cpp_ok TRUE)
    message(STATUS "Crypto++: ${CRYPTOPP_LIBRARY} (headers in ${CRYPTOPP_INCLUDE_DIR})")
  endif()
endif()

if(NOT _cpp_ok AND AESTOOL_FETCH_DEPS)
  message(STATUS "Crypto++ not found locally - downloading it (needs git + internet)")
  include(FetchContent)
  FetchContent_Declare(cryptopp_src
    GIT_REPOSITORY https://github.com/weidai11/cryptopp.git
    GIT_TAG ${AESTOOL_CRYPTOPP_TAG}
    GIT_SHALLOW TRUE)
  FetchContent_GetProperties(cryptopp_src)
  if(NOT cryptopp_src_POPULATED)
    FetchContent_Populate(cryptopp_src)
  endif()
  set(CRYPTOPP_SOURCES "${cryptopp_src_SOURCE_DIR}" CACHE PATH "" FORCE)
  set(CRYPTOPP_BUILD_TESTING OFF CACHE BOOL "" FORCE)
  set(CRYPTOPP_BUILD_DOCUMENTATION OFF CACHE BOOL "" FORCE)
  set(CRYPTOPP_INSTALL OFF CACHE BOOL "" FORCE)
  FetchContent_Declare(cryptopp_cmake
    GIT_REPOSITORY https://github.com/abdes/cryptopp-cmake.git
    GIT_TAG ${AESTOOL_CRYPTOPP_CMAKE_TAG}
    GIT_SHALLOW TRUE)
  FetchContent_MakeAvailable(cryptopp_cmake)
  foreach(_t cryptopp::cryptopp cryptopp-static cryptopp::cryptopp-static cryptopp-shared cryptopp)
    if(NOT _cpp_ok AND TARGET ${_t})
      target_link_libraries(cryptopp_dep INTERFACE ${_t})
      set(_cpp_ok TRUE)
      message(STATUS "Crypto++: built from source (target ${_t})")
    endif()
  endforeach()
endif()

if(NOT _cpp_ok)
  message(FATAL_ERROR
    "Crypto++ was not found.\n"
    "  Ubuntu : sudo apt install libcrypto++-dev\n"
    "  MSVC   : vcpkg install cryptopp:x64-windows  and pass -DCMAKE_TOOLCHAIN_FILE=<vcpkg>/scripts/buildsystems/vcpkg.cmake\n"
    "  MinGW  : pacman -S mingw-w64-x86_64-crypto++   (MSYS2 MINGW64 shell)\n"
    "or re-run with -DAESTOOL_FETCH_DEPS=ON (default) and internet access.")
endif()

if(WIN32)
  target_link_libraries(cryptopp_dep INTERFACE ws2_32 advapi32)
endif()

# ---------------------------------------------------------------------------
# Core library: object library -> static (.a/.lib) and shared (.so/.dll)
# ---------------------------------------------------------------------------
function(aestool_target_defaults tgt)
  if(MSVC)
    target_compile_options(${tgt} PRIVATE /W4 /utf-8 /EHsc)
  else()
    target_compile_options(${tgt} PRIVATE -Wall -Wextra)
  endif()
  if(WIN32)
    target_compile_definitions(${tgt} PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN _CRT_SECURE_NO_WARNINGS)
  endif()
endfunction()

set(AESCORE_SOURCES
  src/aescore.cpp
  src/util.cpp
  src/container.cpp
  src/ops.cpp
  src/kat.cpp
  src/bench.cpp
  src/aescore_capi.cpp)

add_library(aescore_obj OBJECT ${AESCORE_SOURCES})
target_include_directories(aescore_obj PUBLIC src)
target_link_libraries(aescore_obj PUBLIC cryptopp_dep)
target_compile_definitions(aescore_obj PRIVATE AESCORE_BUILDING)
set_target_properties(aescore_obj PROPERTIES POSITION_INDEPENDENT_CODE ON)
aestool_target_defaults(aescore_obj)

add_library(aescore_core STATIC $<TARGET_OBJECTS:aescore_obj>)
target_include_directories(aescore_core PUBLIC src)
target_link_libraries(aescore_core PUBLIC cryptopp_dep)
set_target_properties(aescore_core PROPERTIES OUTPUT_NAME aescore_static LINKER_LANGUAGE CXX)

if(AESTOOL_BUILD_SHARED)
  add_library(aescore_shared SHARED $<TARGET_OBJECTS:aescore_obj>)
  target_include_directories(aescore_shared PUBLIC src)
  target_link_libraries(aescore_shared PUBLIC cryptopp_dep)
  set_target_properties(aescore_shared PROPERTIES OUTPUT_NAME aescore LINKER_LANGUAGE CXX)
  if(MINGW)
    target_link_options(aescore_shared PRIVATE -static-libgcc -static-libstdc++)
  endif()
endif()

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
add_executable(aestool src/main.cpp)
target_link_libraries(aestool PRIVATE aescore_core)
aestool_target_defaults(aestool)
if(WIN32)
  target_link_libraries(aestool PRIVATE shell32)
endif()
if(MINGW)
  target_link_options(aestool PRIVATE -static-libgcc -static-libstdc++)
endif()

# ---------------------------------------------------------------------------
# Tests (ctest)
# ---------------------------------------------------------------------------
if(AESTOOL_BUILD_TESTS)
  enable_testing()
  add_test(NAME nist_kat COMMAND aestool --kat "${CMAKE_SOURCE_DIR}/vectors/nist_vectors.json")

  find_package(Catch2 3 QUIET)
  if(NOT Catch2_FOUND AND AESTOOL_FETCH_DEPS)
    include(FetchContent)
    FetchContent_Declare(Catch2
      GIT_REPOSITORY https://github.com/catchorg/Catch2.git
      GIT_TAG v3.5.4
      GIT_SHALLOW TRUE)
    FetchContent_MakeAvailable(Catch2)
  endif()
  if(TARGET Catch2::Catch2WithMain)
    add_executable(aescore_tests tests/test_aescore.cpp)
    target_link_libraries(aescore_tests PRIVATE aescore_core Catch2::Catch2WithMain)
    aestool_target_defaults(aescore_tests)
    if(MINGW)
      target_link_options(aescore_tests PRIVATE -static-libgcc -static-libstdc++)
    endif()
    add_test(NAME unit_tests COMMAND aescore_tests)
  else()
    message(WARNING "Catch2 v3 not found: unit tests are not built (the nist_kat ctest is still registered).")
  endif()
endif()

# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------
install(TARGETS aestool RUNTIME DESTINATION bin)
if(AESTOOL_BUILD_SHARED)
  install(TARGETS aescore_shared RUNTIME DESTINATION bin LIBRARY DESTINATION lib ARCHIVE DESTINATION lib)
endif()
install(TARGETS aescore_core ARCHIVE DESTINATION lib)
install(FILES src/aescore_capi.h DESTINATION include)
