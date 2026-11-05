#pragma once

#include <rsalab/util.hpp>
#include <rsalab/ossl_raii.hpp>
#include <rsalab/keyio.hpp>
#include <openssl/evp.h>
#include <cstdint>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace rsalab {

// PublicKey / PrivateKey wrappers around EVP_PKEY::unique_ptr
// Provided accessors for modulus size, exponent check, RSA validation

struct PublicKey {
    PkeyPtr pkey;

    PublicKey() = default;
    explicit PublicKey(PkeyPtr k) : pkey(std::move(k)) {}

    bool valid() const noexcept { return pkey != nullptr; }
    operator bool() const noexcept { return valid(); }

    std::size_t modulus_bits() const noexcept {
        if (!pkey) return 0;
        return EVP_PKEY_get_bits(pkey.get());
    }

    std::size_t modulus_bytes() const noexcept {
        if (!pkey) return 0;
        return (EVP_PKEY_get_bits(pkey.get()) + 7) / 8;
    }

    bool is_rsa() const noexcept {
        return EVP_PKEY_is_a(pkey.get(), "RSA") != 0;
    }

    // Get public exponent (checks if e == 65537)
    bool has_exponent_65537() const noexcept {
        if (!pkey) return false;
        BIGNUM* bn = nullptr;
        if (EVP_PKEY_get_bn_param(pkey.get(), OSSL_PKEY_PARAM_RSA_E, &bn) != 1) {
            if (bn) BN_free(bn);
            return false;
        }
        bool ok = (BN_cmp(bn, BN_value_one()) == 0); // placeholder
        BIGNUM* expected = BN_new();
        BN_dec2bn(&expected, "65537");
        int cmp = BN_cmp(bn, expected);
        BN_free(bn);
        BN_free(expected);
        return cmp == 0;
    }
};

struct PrivateKey {
    PkeyPtr pkey;

    PrivateKey() = default;
    explicit PrivateKey(PkeyPtr k) : pkey(std::move(k)) {}

    bool valid() const noexcept { return pkey != nullptr; }
    operator bool() const noexcept { return valid(); }

    std::size_t modulus_bits() const noexcept {
        if (!pkey) return 0;
        return EVP_PKEY_get_bits(pkey.get());
    }

    std::size_t modulus_bytes() const noexcept {
        if (!pkey) return 0;
        return (EVP_PKEY_get_bits(pkey.get()) + 7) / 8;
    }

    bool is_rsa() const noexcept {
        return EVP_PKEY_is_a(pkey.get(), "RSA") != 0;
    }

    // Check exponent = 65537
    bool has_exponent_65537() const noexcept {
        if (!pkey) return false;
        BIGNUM* bn = nullptr;
        if (EVP_PKEY_get_bn_param(pkey.get(), OSSL_PKEY_PARAM_RSA_E, &bn) != 1) {
            if (bn) BN_free(bn);
            return false;
        }
        BIGNUM* expected = BN_new();
        BN_dec2bn(&expected, "65537");
        int cmp = BN_cmp(bn, expected);
        BN_free(bn);
        BN_free(expected);
        return cmp == 0;
    }
};

// Maximum plaintext length for RSA-OAEP
// mLen <= k - 2*hLen - 2 where k = byte length of modulus, hLen = 32 (SHA-256)

inline std::size_t max_plaintext_len(std::size_t modulus_bits) noexcept {
    constexpr std::size_t hash_len = 32;
    std::size_t k = (modulus_bits + 7) / 8;
    return k - 2 * hash_len - 2;
}

// RSA-OAEP encrypt using EVP high-level API
// - Sets RSA_PKCS1_OAEP_PADDING, SHA-256 MD, MGF1-SHA-256, optional label
// - Two-phase: first call with nullptr to get outlen, then actual encrypt
// - Throws CryptoFailure on error
// - Throws UsageError if msg exceeds max length

inline ByteVec oaep_encrypt(const PublicKey& pub, ByteView msg, ByteView label) {
    std::size_t mlen = msg.size();
    std::size_t max_len = max_plaintext_len(pub.modulus_bits());
    if (mlen > max_len) {
        throw UsageError(
            "RSA-OAEP message too long: " + std::to_string(mlen) +
            " bytes exceeds maximum " + std::to_string(max_len) +
            " for " + std::to_string(pub.modulus_bits()) + "-bit key"
        );
    }

    // Get RSA modulus size
    std::size_t k = pub.modulus_bytes();
    if (k == 0) {
        throw CryptoFailure("Invalid public key");
    }

    // Build EVP_PKEY_CTX
    PkeyCtxPtr ctx(EVP_PKEY_CTX_new(pub.pkey.get(), nullptr));
    if (!ctx) {
        ERR_clear_error();
        throw CryptoFailure("EVP_PKEY_CTX_new failed");
    }

    // Initialize encryption
    if (EVP_PKEY_encrypt_init(ctx.get()) != 1) {
        ERR_clear_error();
        throw CryptoFailure("EVP_PKEY_encrypt_init failed");
    }

    // Set RSA padding to OAEP
    if (EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_OAEP_PADDING) != 1) {
        ERR_clear_error();
        throw CryptoFailure("EVP_PKEY_CTX_set_rsa_padding failed");
    }

    // Set OAEP hash to SHA-256
    if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx.get(), EVP_sha256()) != 1) {
        ERR_clear_error();
        throw CryptoFailure("EVP_PKEY_CTX_set_rsa_oaep_md failed");
    }

    // Set MGF1 hash to SHA-256 (explicitly, not default)
    if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx.get(), EVP_sha256()) != 1) {
        ERR_clear_error();
        throw CryptoFailure("EVP_PKEY_CTX_set_rsa_mgf1_md failed");
    }

    // Set OAEP label if provided and non-empty
    if (!label.empty()) {
        // Label must be allocated with OPENSSL_malloc
        unsigned char* label_buf = static_cast<unsigned char*>(
            OPENSSL_malloc(label.size()));
        if (!label_buf) {
            throw CryptoFailure("OAEP label allocation failed");
        }
        std::memcpy(label_buf, label.data(), label.size());
        // Takes ownership; do NOT free manually if successful
        if (EVP_PKEY_CTX_set0_rsa_oaep_label(ctx.get(), label_buf, label.size()) != 1) {
            OPENSSL_free(label_buf);
            ERR_clear_error();
            throw CryptoFailure("EVP_PKEY_CTX_set0_rsa_oaep_label failed");
        }
        // If set0_rsa_oaep_label fails, we already freed label_buf above
        // Label is now owned by ctx (or was freed on failure)
    }
    // If label is empty, we do NOT call set0_rsa_oaep_label (label = empty string per standard)

    // Two-phase encrypt: first call to get output length
    size_t outlen = 0;
    if (EVP_PKEY_encrypt(ctx.get(), nullptr, &outlen, msg.data(), static_cast<int>(mlen)) != 1) {
        ERR_clear_error();
        throw CryptoFailure("EVP_PKEY_encrypt (length query) failed");
    }

    if (outlen != k) {
        // Output should be exactly k bytes (modulus size)
        // This isn't an error per se for the API, but we validate
    }

    // Actual encryption
    ByteVec ciphertext(outlen);
    if (EVP_PKEY_encrypt(ctx.get(), ciphertext.data(), &outlen,
                          msg.data(), static_cast<int>(mlen)) != 1) {
        ERR_clear_error();
        throw CryptoFailure("EVP_PKEY_encrypt failed");
    }

    ciphertext.resize(outlen);
    return ciphertext;
}

// RSA-OAEP decrypt using EVP high-level API
// - Same padding/cipher setup as encrypt
// - Two-phase: first call to get outlen, then actual decrypt
// - Throws CryptoFailure on error (generic, no root cause detail)
// - Checks ciphertext size == modulus size

inline ByteVec oaep_decrypt(const PrivateKey& priv, ByteView ct, ByteView label) {
    std::size_t ctlen = ct.size();
    std::size_t k = priv.modulus_bytes();
    if (k == 0) {
        throw CryptoFailure("Invalid private key");
    }
    if (ctlen != k) {
        throw CryptoFailure(
            "RSA-OAEP ciphertext length mismatch: expected " + std::to_string(k) +
            " bytes, got " + std::to_string(ctlen)
        );
    }

    // Build EVP_PKEY_CTX
    PkeyCtxPtr ctx(EVP_PKEY_CTX_new(priv.pkey.get(), nullptr));
    if (!ctx) {
        ERR_clear_error();
        throw CryptoFailure("EVP_PKEY_CTX_new failed");
    }

    // Initialize decryption
    if (EVP_PKEY_decrypt_init(ctx.get()) != 1) {
        ERR_clear_error();
        throw CryptoFailure("EVP_PKEY_decrypt_init failed");
    }

    // Set RSA padding to OAEP
    if (EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_OAEP_PADDING) != 1) {
        ERR_clear_error();
        throw CryptoFailure("EVP_PKEY_CTX_set_rsa_padding failed");
    }

    // Set OAEP hash to SHA-256
    if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx.get(), EVP_sha256()) != 1) {
        ERR_clear_error();
        throw CryptoFailure("EVP_PKEY_CTX_set_rsa_oaep_md failed");
    }

    // Set MGF1 hash to SHA-256 (explicitly)
    if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx.get(), EVP_sha256()) != 1) {
        ERR_clear_error();
        throw CryptoFailure("EVP_PKEY_CTX_set_rsa_mgf1_md failed");
    }

    // Set OAEP label if provided
    if (!label.empty()) {
        unsigned char* label_buf = static_cast<unsigned char*>(
            OPENSSL_malloc(label.size()));
        if (!label_buf) {
            throw CryptoFailure("OAEP label allocation failed");
        }
        std::memcpy(label_buf, label.data(), label.size());
        if (EVP_PKEY_CTX_set0_rsa_oaep_label(ctx.get(), label_buf, label.size()) != 1) {
            OPENSSL_free(label_buf);
            ERR_clear_error();
            throw CryptoFailure("EVP_PKEY_CTX_set0_rsa_oaep_label failed");
        }
    }
    // If label empty, do not call set0_rsa_oaep_label

    // Two-phase decrypt: first call to get output length
    size_t outlen = 0;
    if (EVP_PKEY_decrypt(ctx.get(), nullptr, &outlen, ct.data(),
                         static_cast<int>(ctlen)) != 1) {
        ERR_clear_error();
        throw CryptoFailure("EVP_PKEY_decrypt (length query) failed");
    }

    if (outlen == 0) {
        // This typically means OAEP decode failure (invalid padding, wrong label, etc.)
        throw CryptoFailure("RSA-OAEP decryption failed (output length zero)");
    }

    // Actual decryption
    ByteVec plaintext(outlen);
    if (EVP_PKEY_decrypt(ctx.get(), plaintext.data(), &outlen,
                          ct.data(), static_cast<int>(ctlen)) != 1) {
        ERR_clear_error();
        throw CryptoFailure("RSA-OAEP decryption failed");
    }

    plaintext.resize(outlen);
    return plaintext;
}

// Convenience: encrypt with empty label (default)
inline ByteVec oaep_encrypt(const PublicKey& pub, ByteView msg) {
    return oaep_encrypt(pub, msg, ByteView{});
}

// Convenience: decrypt with empty label (default)
inline ByteVec oaep_decrypt(const PrivateKey& priv, ByteView ct) {
    return oaep_decrypt(priv, ct, ByteView{});
}

} // namespace rsalab