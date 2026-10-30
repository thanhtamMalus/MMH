#ifndef AES_TEST_HARNESS_HPP
#define AES_TEST_HARNESS_HPP

#include <iostream>
#include <string>
#include <vector>
#include <functional>
#include <stdexcept>
#include <cstdlib>

namespace aes_test {

struct TestFailure : public std::runtime_error {
    using std::runtime_error::runtime_error;
};

struct TestCase {
    std::string name;
    std::function<void()> func;
};

inline std::vector<TestCase>& get_test_registry() {
    static std::vector<TestCase> registry;
    return registry;
}

inline bool register_test(const std::string& name, std::function<void()> func) {
    get_test_registry().push_back({name, std::move(func)});
    return true;
}

inline void report_assertion(bool condition, const char* expr, const char* file, int line) {
    if (!condition) {
        std::string msg = std::string("Assertion failed: ") + expr + " at " + file + ":" + std::to_string(line);
        throw TestFailure(msg);
    }
}

} // namespace aes_test

#define AES_CONCAT_IMPL(x, y) x##y
#define AES_CONCAT(x, y) AES_CONCAT_IMPL(x, y)

#define TEST_CASE(name) \
    static void AES_CONCAT(test_func_, __LINE__)(); \
    static bool AES_CONCAT(reg_, __LINE__) = ::aes_test::register_test(name, AES_CONCAT(test_func_, __LINE__)); \
    static void AES_CONCAT(test_func_, __LINE__)()

#define REQUIRE(expr) ::aes_test::report_assertion((expr), #expr, __FILE__, __LINE__)
#define CHECK(expr)   ::aes_test::report_assertion((expr), #expr, __FILE__, __LINE__)

#endif // AES_TEST_HARNESS_HPP
