#pragma once

#include <openssl/rand.h>
#include <rsalab/ossl_raii.hpp>
#include <string>
#include <vector>
#include <cstdint>
#include <string_view>
#include <system_error>
#include <fstream>

namespace rsalab {

#include <openssl/opensslv.h>
static_assert(OPENSSL_VERSION_MAJOR >= 4, "rsatool requires OpenSSL 4.x or newer");

// Byte types used throughout the library
using ByteVec = std::vector<unsigned char>;
using ByteView = std::string_view;

// Maximum plaintext length for RSA-OAEP
// mLen <= k - 2*hLen - 2 where k = modulus bytes, hLen = SHA-256 digest length = 32

inline std::size_t max_plaintext_len(std::size_t modulus_bits) noexcept {
    constexpr std::size_t hash_len = 32; // SHA-256
    std::size_t k = (modulus_bits + 7) / 8; // ceiling division
    return k - 2 * hash_len - 2;
}

// Read entire file into a SecureBuffer (binary mode)
// Throws IoError on failure
inline SecureBuffer read_file(const std::string& path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        throw IoError("Cannot open file for reading: " + path);
    }
    std::streamsize size = file.tellg();
    if (size < 0) {
        throw IoError("Cannot determine file size: " + path);
    }
    file.seekg(0, std::ios::beg);
    SecureBuffer buffer(static_cast<std::size_t>(size));
    if (size > 0) {
        file.read(reinterpret_cast<char*>(buffer.data()), size);
        if (static_cast<std::streamsize>(file.gcount()) != size) {
            throw IoError("Failed to read entire file: " + path);
        }
    }
    return buffer;
}

// Write SecureBuffer to file (binary mode)
// Atomically writes to temp file then renames (C++ level; OS rename for true atomicity)
inline bool write_file(const std::string& path, const SecureBuffer& data) {
    std::string tmp_path = path + ".tmp";
    std::ofstream file(tmp_path, std::ios::binary);
    if (!file.is_open()) {
        return false;
    }
    file.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    if (file.fail()) {
        file.close();
        std::remove(tmp_path.c_str());
        return false;
    }
    file.close();
    // Rename atomically
    // On Windows, use MoveFileEx with MOVEFILE_REPLACE_EXISTING
    // On Linux, use rename
    #ifdef _WIN32
    if (!MoveFileExA(tmp_path.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING)) {
        std::remove(tmp_path.c_str());
        return false;
    }
    #else
    if (std::rename(tmp_path.c_str(), path.c_str()) != 0) {
        std::remove(tmp_path.c_str());
        return false;
    }
    #endif
    return true;
}

// Generate cryptographically secure random bytes
// Wrapper around OpenSSL RAND_bytes - always checks return value == 1
inline void secure_rand_bytes(unsigned char* buf, std::size_t count) {
    if (count > 0) {
        if (RAND_bytes(buf, static_cast<int>(count)) != 1) {
            throw CryptoFailure("RAND_bytes failed");
        }
    }
}

// Write random bytes to SecureBuffer (uses OpenSSL CSPRNG)
inline void random_bytes(SecureBuffer& buf, std::size_t count) {
    buf.fill_random(count);
}

// Constant-time equality comparison for byte buffers
inline bool constant_time_eq(const unsigned char* a, std::size_t na,
                             const unsigned char* b, std::size_t nb) noexcept {
    return CRYPTO_memcmp(a, static_cast<int>(na), b, static_cast<int>(nb), 0) == 0;
}

// Constant-time less-than comparison
inline bool constant_time_lt(const unsigned char* a, std::size_t na,
                             const unsigned char* b, std::size_t nb) noexcept {
    if (na == 0) return false;
    if (nb == 0) return true;
    int cmp = CRYPTO_memcmp(a, static_cast<int>(na), b, static_cast<int>(nb), 0);
    return cmp < 0;
}

// AAD (Additional Authenticated Data) for AES-GCM hybrid envelope
// Format: "RSAE-AAD-v1|" + mode + "|" + rsa_modulus + "|" + hash + "|" + wrapped_key_b64 + "|" + iv_b64
inline SecureBuffer make_aad(const std::string& mode,
                              std::size_t modulus_bits,
                              const std::string& hash,
                              const std::string& wrapped_key_b64,
                              const std::string& iv_b64) {
    std::string aad = "RSAE-AAD-v1|" + mode + "|";
    aad += std::to_string(modulus_bits) + "|" + hash + "|" + wrapped_key_b64 + "|" + iv_b64;
    return SecureBuffer(
        reinterpret_cast<const unsigned char*>(aad.data()),
        aad.size()
    );
}

// Error category messages
inline const char* crypto_failure_msg() noexcept { return "Error: decryption failed."; }
inline const char* io_error_msg() noexcept { return "Error: I/O failure."; }
inline const char* usage_error_msg() noexcept { return "Error: usage."; }

} // namespace rsalab