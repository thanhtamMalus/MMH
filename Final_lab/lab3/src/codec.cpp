// codec.cpp — Hex and Base64 encode/decode (strict, no whitespace tolerance)
#include "codec.hpp"
#include "errors.hpp"

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

namespace rsatool::codec {

Encoding parse_encoding(const std::string& name) {
    if (name == "raw")    return Encoding::Raw;
    if (name == "hex")    return Encoding::Hex;
    if (name == "base64") return Encoding::Base64;
    throw UsageError("unknown encoding '" + name + "': choose raw, hex, or base64");
}

// ── Hex ───────────────────────────────────────────────────────────────────────

static const char HEX_CHARS[] = "0123456789abcdef";

static std::string to_hex(const uint8_t* data, std::size_t len) {
    std::string out;
    out.reserve(len * 2);
    for (std::size_t i = 0; i < len; ++i) {
        out.push_back(HEX_CHARS[(data[i] >> 4) & 0xF]);
        out.push_back(HEX_CHARS[data[i] & 0xF]);
    }
    return out;
}

static std::vector<uint8_t> from_hex(const std::string& text) {
    if (text.size() % 2 != 0) {
        throw FormatError("error: malformed envelope (hex length must be even)");
    }
    std::vector<uint8_t> out;
    out.reserve(text.size() / 2);
    for (std::size_t i = 0; i < text.size(); i += 2) {
        auto parse_nibble = [](char c) -> uint8_t {
            if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
            if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(c - 'a' + 10);
            if (c >= 'A' && c <= 'F') return static_cast<uint8_t>(c - 'A' + 10);
            throw FormatError("error: malformed envelope (invalid hex character)");
            return 0; // unreachable
        };
        uint8_t hi = parse_nibble(text[i]);
        uint8_t lo = parse_nibble(text[i + 1]);
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return out;
}

// ── Base64 ────────────────────────────────────────────────────────────────────

static std::string to_base64(const uint8_t* data, std::size_t len) {
    // Use OpenSSL BIO chain for encoding
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* mem = BIO_new(BIO_s_mem());
    if (!b64 || !mem) {
        BIO_free(b64);
        BIO_free(mem);
        throw CryptoError("error: base64 encode failed");
    }
    // No newlines
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO* chain = BIO_push(b64, mem);

    if (BIO_write(chain, data, static_cast<int>(len)) < 0 ||
        BIO_flush(chain) <= 0) {
        BIO_free_all(chain);
        throw CryptoError("error: base64 encode failed");
    }

    BUF_MEM* bptr = nullptr;
    BIO_get_mem_ptr(chain, &bptr);

    std::string result(bptr->data, bptr->length);
    BIO_free_all(chain);
    return result;
}

// Strict RFC 4648 validation: alphabet only, length % 4 == 0,
// '=' only as 1-2 trailing characters. Returns the padding count.
static std::size_t validate_base64(const std::string& s) {
    if (s.size() % 4 != 0) {
        throw FormatError("error: malformed envelope (base64 length must be a multiple of 4)");
    }

    std::size_t pad = 0;
    for (std::size_t i = 0; i < s.size(); ++i) {
        const unsigned char c = static_cast<unsigned char>(s[i]);
        const bool is_data = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                             (c >= '0' && c <= '9') || c == '+' || c == '/';
        if (is_data) {
            if (pad != 0)
                throw FormatError("error: malformed envelope (base64 data after padding)");
        } else if (c == '=') {
            if (i + 2 < s.size())  // '=' allowed only in the last two positions
                throw FormatError("error: malformed envelope (base64 padding misplaced)");
            ++pad;
        } else {
            throw FormatError("error: malformed envelope (invalid base64 character)");
        }
    }
    return pad;
}

static std::vector<uint8_t> from_base64(const std::string& text) {
    // Strict: no whitespace allowed
    for (char c : text) {
        if (c == '\n' || c == '\r' || c == ' ' || c == '\t') {
            throw FormatError("error: malformed envelope (base64 must not contain whitespace)");
        }
    }
    if (text.empty()) return {};

    const std::size_t pad = validate_base64(text);

    std::vector<uint8_t> out((text.size() / 4) * 3);
    int n = EVP_DecodeBlock(out.data(),
                            reinterpret_cast<const unsigned char*>(text.data()),
                            static_cast<int>(text.size()));
    if (n < 0) {
        throw FormatError("error: malformed envelope (base64 decode failed)");
    }
    // EVP_DecodeBlock counts padding bytes in its result; strip them.
    const std::size_t decoded = static_cast<std::size_t>(n);
    if (decoded < pad) {
        throw FormatError("error: malformed envelope (base64 decode failed)");
    }
    out.resize(decoded - pad);
    return out;
}

// ── Public API ────────────────────────────────────────────────────────────────

std::string encode(const uint8_t* data, std::size_t len, Encoding enc) {
    switch (enc) {
    case Encoding::Raw: return std::string(reinterpret_cast<const char*>(data), len);
    case Encoding::Hex: return to_hex(data, len);
    case Encoding::Base64: return to_base64(data, len);
    }
    return {};
}

std::string encode(const std::vector<uint8_t>& data, Encoding enc) {
    return encode(data.data(), data.size(), enc);
}

std::vector<uint8_t> decode(const std::string& text, Encoding enc) {
    switch (enc) {
    case Encoding::Raw:
        return std::vector<uint8_t>(
            reinterpret_cast<const uint8_t*>(text.data()),
            reinterpret_cast<const uint8_t*>(text.data()) + text.size());
    case Encoding::Hex:
        return from_hex(text);
    case Encoding::Base64:
        return from_base64(text);
    }
    return {};
}

std::vector<uint8_t> decode(const std::vector<uint8_t>& raw_data, Encoding enc) {
    std::string s(reinterpret_cast<const char*>(raw_data.data()), raw_data.size());
    return decode(s, enc);
}

} // namespace rsatool::codec