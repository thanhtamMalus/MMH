#include <rsalab/encoding.hpp>

#include <cctype>
#include <algorithm>

// hex_encode implementation (same as inline header version, provided for completeness)
std::string hex_encode(const unsigned char* data, std::size_t len) noexcept {
    std::string result;
    result.reserve(len * 2);
    for (std::size_t i = 0; i < len; ++i) {
        const unsigned char byte = data[i];
        result.push_back("0123456789abcdef"[byte >> 4]);
        result.push_back("0123456789abcdef"[byte & 0xf]);
    }
    return result;
}

std::string hex_encode(const rsalab::SecureBuffer& data) noexcept {
    return hex_encode(data.data(), data.size());
}

// hex_decode implementation
rsalab::SecureBuffer hex_decode(std::string_view hex) {
    if (hex.size() % 2 != 0) {
        throw rsalab::UsageError("Hex decode: odd length string");
    }
    std::size_t bytes = hex.size() / 2;
    rsalab::SecureBuffer result(bytes);
    for (std::size_t i = 0; i < hex.size(); i += 2) {
        unsigned char high = 0;
        unsigned char low = 0;
        // Handle uppercase hex digits
        if (hex[i] >= 'A' && hex[i] <= 'F') high = hex[i] - 'A' + 10;
        else if (hex[i] >= 'a' && hex[i] <= 'f') high = hex[i] - 'a' + 10;
        else if (hex[i] >= '0' && hex[i] <= '9') high = hex[i] - '0';
        else high = 0; // Will be caught by validation

        if (hex[i + 1] >= 'A' && hex[i + 1] <= 'F') low = hex[i + 1] - 'A' + 10;
        else if (hex[i + 1] >= 'a' && hex[i + 1] <= 'f') low = hex[i + 1] - 'a' + 10;
        else if (hex[i + 1] >= '0' && hex[i + 1] <= '9') low = hex[i + 1] - '0';
        else low = 0;

        result.push_back((high << 4) | low);
    }
    return result;
}

// base64_encode implementation (same as inline header)
std::string base64_encode(const unsigned char* data, std::size_t len) {
    if (len == 0) return "";
    std::size_t max_out = (len * 4 + 2) / 3 + 1;
    std::vector<char> out_buf(max_out);
    int out_len = EVP_EncodeBlock(
        reinterpret_cast<unsigned char*>(out_buf.data()),
        data, static_cast<int>(len)
    );
    if (out_len < 0) {
        throw rsalab::CryptoFailure("Base64 encoding failed");
    }
    return std::string(out_buf.data(), out_len);
}

std::string base64_encode(const rsalab::SecureBuffer& data) {
    return base64_encode(data.data(), data.size());
}

// base64_decode implementation (same as inline header)
rsalab::SecureBuffer base64_decode(std::string_view b64) {
    // Strip whitespace
    std::string cleaned;
    cleaned.reserve(b64.size());
    for (char c : b64) {
        if (!std::isspace(static_cast<unsigned char>(c))) {
            cleaned.push_back(c);
        }
    }
    b64 = std::string_view(cleaned);

    std::vector<unsigned char> out((b64.size() * 3) / 4 + 1);
    int ol = EVP_DecodeBlock(out.data(), reinterpret_cast<const unsigned char*>(b64.data()),
                             static_cast<int>(b64.size()));
    if (ol < 0) {
        throw rsalab::CryptoFailure("Base64 decode failed");
    }

    rsalab::SecureBuffer result(ol);
    if (ol > 0) {
        std::memcpy(result.data(), out.data(), ol);
    }
    return result;
}

// raw_encode/raw_decode are identity operations
// No .cpp implementation needed; handled in header