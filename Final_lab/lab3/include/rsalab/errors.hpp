#pragma once

#include <stdexcept>
#include <string>

namespace rsalab {

class UsageError : public std::runtime_error {
public:
    explicit UsageError(const std::string& msg) : std::runtime_error(msg) {}
};

class IoError : public std::runtime_error {
public:
    explicit IoError(const std::string& msg) : std::runtime_error(msg) {}
};

class CryptoFailure : public std::runtime_error {
public:
    explicit CryptoFailure(const std::string& msg) : std::runtime_error(msg) {}
};

} // namespace rsalab