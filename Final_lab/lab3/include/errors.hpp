// errors.hpp — Custom exception types for rsatool
// All crypto failures raise CryptoError; parse/format issues raise FormatError.
#pragma once
#include <stdexcept>
#include <string>

namespace rsatool {

/// Thrown for every cryptographic failure.
/// User-visible message is always generic to avoid oracle attacks.
class CryptoError : public std::runtime_error {
public:
    explicit CryptoError(const std::string& msg = "error: decryption failed")
        : std::runtime_error(msg) {}
};

/// Thrown for malformed input, bad envelope format, etc.
class FormatError : public std::runtime_error {
public:
    explicit FormatError(const std::string& msg)
        : std::runtime_error(msg) {}
};

/// Thrown for invalid arguments / unsupported parameters.
class UsageError : public std::runtime_error {
public:
    explicit UsageError(const std::string& msg)
        : std::runtime_error(msg) {}
};

} // namespace rsatool

