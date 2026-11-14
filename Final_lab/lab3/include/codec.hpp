// codec.hpp — Encode/decode raw bytes as hex or base64
#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace rsatool::codec {

enum class Encoding { Raw, Hex, Base64 };

/// Parse encoding name ("raw", "hex", "base64"). Throws UsageError on unknown.
Encoding parse_encoding(const std::string& name);

/// Encode bytes according to enc. For Raw, returns a copy as a string of raw bytes.
std::string encode(const std::vector<uint8_t>& data, Encoding enc);
std::string encode(const uint8_t* data, std::size_t len, Encoding enc);

/// Decode bytes. Throws FormatError on invalid input.
std::vector<uint8_t> decode(const std::string& text, Encoding enc);
std::vector<uint8_t> decode(const std::vector<uint8_t>& raw_data, Encoding enc);

} // namespace rsatool::codec

