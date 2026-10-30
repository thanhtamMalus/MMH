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

# Check for Python & OpenSSL to register cross-validation test
find_program(PYTHON_EXECUTABLE NAMES python3 python py)
find_program(OPENSSL_EXECUTABLE NAMES openssl)

if(PYTHON_EXECUTABLE AND OPENSSL_EXECUTABLE)
    add_test(
        NAME aes_cross_validation_openssl
        COMMAND ${PYTHON_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/../scripts/cross_validate.py
                --aestool $<TARGET_FILE:aestool>
                --openssl ${OPENSSL_EXECUTABLE}
    )
endif()
