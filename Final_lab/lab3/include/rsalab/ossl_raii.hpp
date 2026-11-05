#pragma once

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <memory>
#include <vector>
#include <cstddef>
#include <cstring>
#include <stdexcept>
#include <algorithm>

namespace rsalab {

// Constant-time comparison helper (wraps OpenSSL CRYPTO_memcmp)
inline int constant_time_compare(const unsigned char* a, std::size_t na,
                                 const unsigned char* b, std::size_t nb) noexcept {
    return CRYPTO_memcmp(a, static_cast<int>(na), b, static_cast<int>(nb), 0);
}

// RAII wrappers for OpenSSL 4.x
// All functions return 1 on success, 0 or NULL on error

inline void evp_pkey_deleter(EVP_PKEY* p) noexcept {
    if (p) EVP_PKEY_free(p);
}

inline void evp_pkey_ctx_deleter(EVP_PKEY_CTX* ctx) noexcept {
    if (ctx) EVP_PKEY_CTX_free(ctx);
}

inline void evp_cipher_ctx_deleter(EVP_CIPHER_CTX* ctx) noexcept {
    if (ctx) EVP_CIPHER_CTX_free(ctx);
}

inline void evp_md_ctx_deleter(EVP_MD_CTX* ctx) noexcept {
    if (ctx) EVP_MD_CTX_free(ctx);
}

inline void bio_free_all(BIO* bio) noexcept {
    if (bio) BIO_free_all(bio);
}

inline void evp_cipher_free_deleter(EVP_CIPHER* cipher) noexcept {
    if (cipher) EVP_CIPHER_free(cipher);
}

inline void evp_md_free_deleter(EVP_MD* md) noexcept {
    if (md) EVP_MD_free(md);
}

inline void ossl_encoder_ctx_free_deleter(OSSL_ENCODER_CTX* ctx) noexcept {
    if (ctx) OSSL_ENCODER_CTX_free(ctx);
}

inline void ossl_decoder_ctx_free_deleter(OSSL_DECODER_CTX* ctx) noexcept {
    if (ctx) OSSL_DECODER_CTX_free(ctx);
}

// STL-like unique_ptr wrappers

using PkeyPtr = std::unique_ptr<EVP_PKEY, decltype(&evp_pkey_deleter)>;
using PkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, decltype(&evp_pkey_ctx_deleter)>;
using CipherCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, decltype(&evp_cipher_ctx_deleter)>;
using MdCtxPtr = std::unique_ptr<EVP_MD_CTX, decltype(&evp_md_ctx_deleter)>;
using BioPtr = std::unique_ptr<BIO, decltype(&bio_free_all)>;
using EVP_CIPHERPtr = std::unique_ptr<EVP_CIPHER, decltype(&evp_cipher_free_deleter)>;
using EVP_MDPtr = std::unique_ptr<EVP_MD, decltype(&evp_md_free_deleter)>;
using OSSLEngCtxPtr = std::unique_ptr<OSSL_ENCODER_CTX, decltype(&ossl_encoder_ctx_free_deleter)>;
using OSSLDecCtxPtr = std::unique_ptr<OSSL_DECODER_CTX, decltype(&ossl_decoder_ctx_free_deleter)>;

// Secure buffer with automatic zeroization via OPENSSL_cleanse
// Intended for keys, plaintext temp storage, sensitive output data.

class SecureBuffer {
public:
    using value_type = unsigned char;
    using size_type = std::size_t;

    SecureBuffer() = default;

    explicit SecureBuffer(size_type n) : data_(n) {
        if (n > 0) {
            OPENSSL_cleanse(data_.data(), n);
        }
    }

    // Create with uninitialized memory then zeroize
    SecureBuffer(size_type n, std::nullptr_t) : data_(n) {
        if (n > 0) {
            OPENSSL_cleanse(data_.data(), n);
        }
    }

    ~SecureBuffer() noexcept {
        if (!data_.empty()) {
            OPENSSL_cleanse(data_.data(), data_.size());
        }
    }

    // Disable copy, enable move
    SecureBuffer(const SecureBuffer&) = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;
    SecureBuffer(SecureBuffer&& other) noexcept : data_(std::move(other.data_)) {}
    SecureBuffer& operator=(SecureBuffer&& other) noexcept {
        if (this != &other) {
            data_ = std::move(other.data_);
        }
        return *this;
    }

    // Reset and zeroize old data
    void reset() noexcept {
        if (!data_.empty()) {
            OPENSSL_cleanse(data_.data(), data_.size());
        }
        data_.clear();
    }

    // Assignment from raw buffer, zeroizes destination first
    void assign(const unsigned char* src, size_type n) {
        if (data_.size() != n) {
            data_.resize(n);
            if (n > 0) {
                OPENSSL_cleanse(data_.data(), n);
            }
        }
        if (src && n > 0) {
            std::memcpy(data_.data(), src, n);
        }
    }

    // Fill with cryptographically random bytes via RAND_bytes
    void fill_random(size_type n) {
        if (n > 0) {
            if (RAND_bytes(data_.data(), static_cast<int>(n)) != 1) {
                throw CryptoFailure("RAND_bytes failed");
            }
        }
    }

    // Resize buffer and zeroize new portion
    void resize(size_type n) {
        if (n > data_.size()) {
            data_.resize(n);
            OPENSSL_cleanse(data_.data() + data_.size(), n - data_.size());
        } else {
            data_.resize(n);
        }
    }

    // Basic container operations
    unsigned char& operator[](size_type i) { return data_[i]; }
    const unsigned char& operator[](size_type i) const { return data_[i]; }

    unsigned char* data() noexcept { return data_.data(); }
    const unsigned char* data() const noexcept { return data_.data(); }
    size_type size() const noexcept { return data_.size(); }
    bool empty() const noexcept { return data_.empty(); }

    // Append a byte
    void push_back(unsigned char c) { data_.push_back(c); }

    // Reserve capacity (prevents reallocation leaks)
    void reserve(size_type n) { data_.reserve(n); }

    // Equality comparison (constant-time)
    bool operator==(const SecureBuffer& other) const noexcept {
        if (data_.size() != other.data_.size()) return false;
        return constant_time_compare(data_.data(), data_.size(),
                                     other.data_.data(), other.data_.size()) == 0;
    }

    // Inequality
    bool operator!=(const SecureBuffer& other) const noexcept {
        return !(*this == other);
    }

    // Less-than for use in containers (memcmp-based, not constant-time but safe for ordering)
    bool operator<(const SecureBuffer& other) const noexcept {
        std::size_t n = std::min(data_.size(), other.data_.size());
        int cmp = constant_time_compare(data_.data(), n,
                                        other.data_.data(), n);
        if (cmp != 0) return cmp < 0;
        return data_.size() < other.data_.size();
    }

    // Get raw pointer
    const unsigned char* get() const noexcept { return data_.data(); }
    unsigned char* get() noexcept { return data_.data(); }

    // Exchange ownership (move)
    SecureBuffer exchange(SecureBuffer& other) noexcept {
        std::swap(data_, other.data_);
        return *this;
    }

    // Clear buffer without destroying
    void clear() noexcept {
        if (!data_.empty()) {
            OPENSSL_cleanse(data_.data(), data_.size());
        }
        data_.clear();
    }
};

// Convenience: read entire file into SecureBuffer (binary mode)
SecureBuffer read_file(const std::string& path);

// Convenience: write SecureBuffer to file (binary mode)
bool write_file(const std::string& path, const SecureBuffer& data);

// Convenience: byteswap constant-time
inline void secure_zero(void* ptr, std::size_t len) noexcept {
    if (ptr) OPENSSL_cleanse(ptr, len);
}

} // namespace rsalab