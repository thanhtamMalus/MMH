// secure.hpp — RAII SecureBuffer and OpenSSL unique_ptr wrappers
// Secrets are wiped with OPENSSL_cleanse on destruction.
#pragma once
#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>

// Compile-time OpenSSL version check (must be >= 4.0)
static_assert(OPENSSL_VERSION_MAJOR >= 4,
              "OpenSSL >= 4.0 required. Set OPENSSL_ROOT_DIR to your OpenSSL 4 installation.");

namespace rsatool {

// ── SecureBuffer ─────────────────────────────────────────────────────────────
/// A std::vector<uint8_t> that wipes its contents on destruction.
class SecureBuffer {
public:
    using value_type = uint8_t;

    SecureBuffer() = default;
    explicit SecureBuffer(std::size_t size, uint8_t fill = 0)
        : data_(size, fill) {}

    SecureBuffer(const uint8_t* ptr, std::size_t len)
        : data_(ptr, ptr + len) {}

    ~SecureBuffer() { wipe(); }

    // Non-copyable (would leak secret bytes in copy semantics)
    SecureBuffer(const SecureBuffer&) = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;

    // Movable
    SecureBuffer(SecureBuffer&&) noexcept = default;
    SecureBuffer& operator=(SecureBuffer&&) noexcept = default;

    uint8_t*       data()       noexcept { return data_.data(); }
    const uint8_t* data() const noexcept { return data_.data(); }
    std::size_t    size() const noexcept { return data_.size(); }
    bool           empty() const noexcept { return data_.empty(); }

    void resize(std::size_t n) { data_.resize(n); }
    void assign(const uint8_t* ptr, std::size_t len) {
        data_.assign(ptr, ptr + len);
    }

    uint8_t& operator[](std::size_t i) { return data_[i]; }
    const uint8_t& operator[](std::size_t i) const { return data_[i]; }

    uint8_t* begin() noexcept { return data_.data(); }
    uint8_t* end()   noexcept { return data_.data() + data_.size(); }

    void wipe() noexcept {
        if (!data_.empty()) {
            OPENSSL_cleanse(data_.data(), data_.size());
        }
    }

private:
    std::vector<uint8_t> data_;
};

// ── OpenSSL unique_ptr helpers ────────────────────────────────────────────────

struct EVPPKEYDeleter { void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); } };
struct EVPPKEYCTXDeleter { void operator()(EVP_PKEY_CTX* p) const { EVP_PKEY_CTX_free(p); } };
struct EVPCIPHERCTXDeleter { void operator()(EVP_CIPHER_CTX* p) const { EVP_CIPHER_CTX_free(p); } };
struct EVPMDCTXDeleter { void operator()(EVP_MD_CTX* p) const { EVP_MD_CTX_free(p); } };
struct BIODeleter { void operator()(BIO* p) const { BIO_free_all(p); } };

using UniqueEVPPKEY     = std::unique_ptr<EVP_PKEY,       EVPPKEYDeleter>;
using UniqueEVPPKEYCTX  = std::unique_ptr<EVP_PKEY_CTX,   EVPPKEYCTXDeleter>;
using UniqueEVPCIPHERCTX = std::unique_ptr<EVP_CIPHER_CTX, EVPCIPHERCTXDeleter>;
using UniqueEVPMDCTX    = std::unique_ptr<EVP_MD_CTX,     EVPMDCTXDeleter>;
using UniqueBIO         = std::unique_ptr<BIO,            BIODeleter>;

// Helper: throw CryptoError and drain OpenSSL error queue
[[noreturn]] inline void throwCryptoError(const char* msg = "error: decryption failed") {
    ERR_clear_error();
    throw rsatool::CryptoError(msg);  // forward declare; include errors.hpp first
}

} // namespace rsatool

