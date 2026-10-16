#pragma once
// Encoding + file helpers (no cryptography here).
#include <cstdint>
#include <string>

#include "aescore.h"

namespace util {

using aescore::Bytes;

constexpr uint64_t kMaxFileBytes = 2ull * 1024 * 1024 * 1024;

std::string to_hex(const uint8_t* d, size_t n);
inline std::string to_hex(const Bytes& b) { return to_hex(b.data(), b.size()); }
bool from_hex(const std::string& s, Bytes& out, bool allow_whitespace = false);   // strict

std::string to_base64(const Bytes& b);
bool from_base64(const std::string& s, Bytes& out, bool allow_whitespace = false); // strict

bool is_valid_utf8(const Bytes& b);
inline Bytes to_bytes(const std::string& s) { return Bytes(s.begin(), s.end()); }
inline std::string to_string(const Bytes& b) { return std::string(b.begin(), b.end()); }

bool file_exists(const std::string& path);
bool read_file(const std::string& path, Bytes& out, std::string& err, uint64_t max_bytes = kMaxFileBytes);
bool read_file_prefix(const std::string& path, Bytes& out, std::string& err, size_t max_bytes);
// Writes to "<path>.aestool.tmp" then renames: a failed run never leaves a half-written output.
bool write_file_atomic(const std::string& path, const Bytes& data, std::string& err, bool secret = false);
bool append_file(const std::string& path, const std::string& text, std::string& err);

// Key/IV/AAD file: raw binary, or text starting with the line "AESTOOL-HEX" followed by hex digits.
Bytes read_blob_file(const std::string& path, const char* what);
// Argument that is either an existing file or a hex string.
Bytes parse_blob_arg(const std::string& value, const char* what);

}  // namespace util
