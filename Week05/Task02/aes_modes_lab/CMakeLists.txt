cmake_minimum_required(VERSION 3.16)
project(aes_modes_lab LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(aes_modes STATIC
    src/aes.cpp
    src/sp800_38a.cpp
    src/sp800_38c.cpp
    src/sp800_38d.cpp
)
target_include_directories(aes_modes PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

add_executable(aes_tests tests/main.cpp)
target_link_libraries(aes_tests PRIVATE aes_modes)

enable_testing()
add_test(NAME aes_tests COMMAND aes_tests)
