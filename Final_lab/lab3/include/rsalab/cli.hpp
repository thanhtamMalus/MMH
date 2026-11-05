#pragma once

#include <rsalab/util.hpp>
#include <rsalab/keyio.hpp>
#include <rsalab/rsa_oaep.hpp>
#include <rsalab/hybrid.hpp>
#include <rsalab/encoding.hpp>
#include <string>
#include <vector>
#include <cstddef>
#include <stdexcept>

namespace rsalab {

// CLI result types

struct CliResult {
    enum class Status { Ok, Usage, Error };
    Status status = Status::Ok;
    std::string message;
};

// Keygen command options
struct KeygenOptions {
    std::size_t bits = 0;
    std::string pub_path;
    std::string priv_path;
};

// Encrypt command options
struct EncryptOptions {
    std::string in_path;
    std::string out_path;
    std::string pub_path;
    std::string label;
    EncodeFormat encode_format = EncodeFormat::Raw;
    bool force_hybrid = false;
    Mode mode = Mode::Auto; // Auto, Direct, Hybrid
    std::string impl = "lib"; // "lib" or "manual"
};

// Decrypt command options
struct DecryptOptions {
    std::string in_path;
    std::string out_path;
    std::string priv_path;
    std::string label;
    EncodeFormat encode_format = EncodeFormat::Raw;
    Mode mode = Mode::Auto;
    std::string impl = "lib";
};

// Parse command-line arguments
// ReturnsCliResult with parsed options or error message
CliResult parse_keygen(int argc, const char* const* argv, KeygenOptions& opts);

CliResult parse_encrypt(int argc, const char* const* argv, EncryptOptions& opts);

CliResult parse_decrypt(int argc, const char* const* argv, DecryptOptions& opts);

// Print help message
void print_help();

// Parse encode format from string
EncodeFormat parse_encode_format(const std::string& str);

// Parse mode from string
Mode parse_mode(const std::string& str);

} // namespace rsalab