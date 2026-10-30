#include "test_harness.hpp"
#include <iostream>

int main(int argc, char* argv[]) {
    std::string filter = (argc > 1) ? argv[1] : "";
    auto& tests = aes_test::get_test_registry();

    std::cout << "==========================================\n";
    std::cout << "Running AES Test Suite (" << tests.size() << " test cases)\n";
    std::cout << "==========================================\n";

    size_t passed = 0;
    size_t failed = 0;

    for (const auto& tc : tests) {
        if (!filter.empty() && tc.name.find(filter) == std::string::npos) {
            continue;
        }

        std::cout << "[ RUN      ] " << tc.name << "\n";
        try {
            tc.func();
            std::cout << "[       OK ] " << tc.name << "\n";
            passed++;
        } catch (const std::exception& ex) {
            std::cerr << "[  FAILED  ] " << tc.name << "\n";
            std::cerr << "             " << ex.what() << "\n";
            failed++;
        } catch (...) {
            std::cerr << "[  FAILED  ] " << tc.name << " (Unknown exception)\n";
            failed++;
        }
    }

    std::cout << "==========================================\n";
    std::cout << "Passed: " << passed << " | Failed: " << failed << "\n";
    std::cout << "==========================================\n";

    return (failed == 0) ? 0 : 1;
}
