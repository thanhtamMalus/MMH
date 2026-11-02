#include "aes/util.hpp"
#include <fstream>
#include <filesystem>
#include <system_error>

namespace aes {
namespace util {

namespace {

inline int hex_char_to_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

const char HEX_CHARS[] = "0123456789abcdef";

} // namespace

std::string to_hex(const uint8_t* data, size_t size) {
    if (!data || size == 0) return "";
    std::string hex_str;
    hex_str.reserve(size * 2);
    for (size_t i = 0; i < size; ++i) {
        hex_str.push_back(HEX_CHARS[(data[i] >> 4) & 0x0F]);
        hex_str.push_back(HEX_CHARS[data[i] & 0x0F]);
    }
    return hex_str;
}

bool from_hex(const std::string& hex, std::vector<uint8_t>& out) {
    if (hex.size() % 2 != 0) return false;
    out.clear();
    out.reserve(hex.size() / 2);

    for (size_t i = 0; i < hex.size(); i += 2) {
        int hi = hex_char_to_val(hex[i]);
        int lo = hex_char_to_val(hex[i + 1]);
        if (hi < 0 || lo < 0) {
            out.clear();
            return false;
        }
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return true;
}

bool read_binary_file(const std::string& filepath, std::vector<uint8_t>& out) {
    std::ifstream stream(filepath, std::ios::binary | std::ios::ate);
    if (!stream.is_open()) {
        return false;
    }

    std::streampos end_pos = stream.tellg();
    if (end_pos < 0) {
        return false;
    }

    size_t file_size = static_cast<size_t>(end_pos);
    stream.seekg(0, std::ios::beg);

    out.resize(file_size);
    if (file_size > 0) {
        stream.read(reinterpret_cast<char*>(out.data()), static_cast<std::streamsize>(file_size));
        if (!stream) {
            out.clear();
            return false;
        }
    }
    return true;
}

bool write_binary_file(const std::string& filepath, const uint8_t* data, size_t size) {
    std::ofstream stream(filepath, std::ios::binary | std::ios::trunc);
    if (!stream.is_open()) {
        return false;
    }

    if (size > 0 && data) {
        stream.write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(size));
        if (!stream) {
            return false;
        }
    }
    stream.flush();
    return stream.good();
}

bool file_exists(const std::string& filepath) {
    std::error_code ec;
    return std::filesystem::exists(filepath, ec);
}

bool get_file_size(const std::string& filepath, uint64_t& out_size) {
    std::error_code ec;
    auto sz = std::filesystem::file_size(filepath, ec);
    if (ec) {
        return false;
    }
    out_size = static_cast<uint64_t>(sz);
    return true;
}

} // namespace util
} // namespace aes
