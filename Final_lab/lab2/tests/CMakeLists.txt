cmake_minimum_required(VERSION 3.16)

add_executable(aes_tests
    test_main.cpp
    test_aes_core.cpp
    test_ctr.cpp
    test_negative.cpp
    test_portability.cpp
)

target_include_directories(aes_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
)

target_link_libraries(aes_tests PRIVATE aes)

# Register tests for ctest
add_test(NAME aes_core_and_ctr COMMAND $<TARGET_FILE:aes_tests>)
add_test(NAME aes_cli_kat COMMAND $<TARGET_FILE:aestool> --kat ${CMAKE_CURRENT_SOURCE_DIR}/../vectors/vectors.json)

# ---------------------------------------------------------------------------
# Cross-validation against the OpenSSL *CLI* (OpenSSL >= 4.0 by default).
# OpenSSL is NEVER linked or #included: no OpenSSL headers/libs are needed to
# build this project. The script auto-detects openssl(.exe) on PATH and in the
# usual install folders; override with -DAES_OPENSSL_EXECUTABLE=<path>.
# If no suitable OpenSSL is found the test is reported as SKIPPED (not passed).
# ---------------------------------------------------------------------------
set(AES_MIN_OPENSSL "4.0" CACHE STRING "Minimum OpenSSL CLI version for cross-validation")
set(AES_OPENSSL_EXECUTABLE "" CACHE FILEPATH "Path to openssl/openssl.exe (empty = auto-detect)")

find_program(PYTHON_EXECUTABLE NAMES python3 python py)

if(PYTHON_EXECUTABLE)
    set(_xval_args
        ${CMAKE_CURRENT_SOURCE_DIR}/../scripts/cross_validate.py
        --aestool $<TARGET_FILE:aestool>
        --min-version ${AES_MIN_OPENSSL})
    if(AES_OPENSSL_EXECUTABLE)
        list(APPEND _xval_args --openssl "${AES_OPENSSL_EXECUTABLE}")
    endif()
    add_test(NAME aes_cross_validation_openssl
             COMMAND ${PYTHON_EXECUTABLE} ${_xval_args})
    # Script exits 77 when OpenSSL >= AES_MIN_OPENSSL is missing -> "Skipped"
    set_tests_properties(aes_cross_validation_openssl PROPERTIES SKIP_RETURN_CODE 77)
else()
    message(STATUS "Python not found: aes_cross_validation_openssl test not registered")
endif()
