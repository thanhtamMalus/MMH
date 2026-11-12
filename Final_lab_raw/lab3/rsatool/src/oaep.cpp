// oaep.cpp — RSA-OAEP encrypt/decrypt using EVP_PKEY_CTX (high-level API only)
// SHA-256 for both OAEP hash and MGF1. No RSA_* functions.
#include <rsatool/oaep.hpp>
#include <rsatool/errors.hpp>
#include <rsatool/keys.hpp>

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/err.h>

#include <cstring>
#include <vector>

namespace rsatool::oaep {

std::vector<uint8_t> encrypt(
    const EVP_PKEY*  pub_key,
    const uint8_t*   plaintext,
    std::size_t      plaintext_len,
    const std::string& label)
{
    ERR_clear_error();

    // Validate key size
    int bits = keys::key_bits(pub_key);
    std::size_t mLen = max_plaintext_len(bits);

    if (plaintext_len > mLen) {
        throw UsageError(
            "error: plaintext too long for direct RSA-OAEP (" +
            std::to_string(plaintext_len) + " > " + std::to_string(mLen) +
            " bytes). Use --mode hybrid.");
    }

    UniqueEVPPKEYCTX ctx(
        EVP_PKEY_CTX_new_from_pkey(nullptr, const_cast<EVP_PKEY*>(pub_key), nullptr));
    if (!ctx) throw CryptoError("error: EVP_PKEY_CTX_new_from_pkey failed");

    if (EVP_PKEY_encrypt_init(ctx.get()) <= 0)
        throw CryptoError();

    // Set RSA-OAEP padding
    if (EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_OAEP_PADDING) <= 0)
        throw CryptoError();

    // Set OAEP hash to SHA-256
    if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx.get(), EVP_sha256()) <= 0)
        throw CryptoError();

    // Set MGF1 hash to SHA-256
    if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx.get(), EVP_sha256()) <= 0)
        throw CryptoError();

    // Set optional OAEP label (OpenSSL takes ownership of OPENSSL_malloc'd buffer)
    if (!label.empty()) {
        // Must use OPENSSL_malloc — OpenSSL will free it
        unsigned char* lbuf = static_cast<unsigned char*>(
            OPENSSL_malloc(label.size()));
        if (!lbuf) throw CryptoError();
        std::memcpy(lbuf, label.data(), label.size());

        if (EVP_PKEY_CTX_set0_rsa_oaep_label(ctx.get(), lbuf,
                                               static_cast<int>(label.size())) <= 0) {
            OPENSSL_free(lbuf);
            throw CryptoError();
        }
        // OpenSSL now owns lbuf; do not free it
    }

    // Determine output length
    std::size_t out_len = 0;
    if (EVP_PKEY_encrypt(ctx.get(), nullptr, &out_len, plaintext,
                          plaintext_len) <= 0)
        throw CryptoError();

    std::vector<uint8_t> ciphertext(out_len);
    if (EVP_PKEY_encrypt(ctx.get(), ciphertext.data(), &out_len,
                          plaintext, plaintext_len) <= 0)
        throw CryptoError();

    ciphertext.resize(out_len);
    return ciphertext;
}

SecureBuffer decrypt(
    const EVP_PKEY*  priv_key,
    const uint8_t*   ciphertext,
    std::size_t      ciphertext_len,
    const std::string& label)
{
    ERR_clear_error();

    UniqueEVPPKEYCTX ctx(
        EVP_PKEY_CTX_new_from_pkey(nullptr, const_cast<EVP_PKEY*>(priv_key), nullptr));
    if (!ctx) throw CryptoError();

    if (EVP_PKEY_decrypt_init(ctx.get()) <= 0)
        throw CryptoError();

    // RSA-OAEP padding
    if (EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_OAEP_PADDING) <= 0)
        throw CryptoError();

    // OAEP hash SHA-256
    if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx.get(), EVP_sha256()) <= 0)
        throw CryptoError();

    // MGF1 hash SHA-256
    if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx.get(), EVP_sha256()) <= 0)
        throw CryptoError();

    // Optional label
    if (!label.empty()) {
        unsigned char* lbuf = static_cast<unsigned char*>(
            OPENSSL_malloc(label.size()));
        if (!lbuf) throw CryptoError();
        std::memcpy(lbuf, label.data(), label.size());

        if (EVP_PKEY_CTX_set0_rsa_oaep_label(ctx.get(), lbuf,
                                               static_cast<int>(label.size())) <= 0) {
            OPENSSL_free(lbuf);
            throw CryptoError();
        }
    }

    // Determine output length
    std::size_t out_len = 0;
    if (EVP_PKEY_decrypt(ctx.get(), nullptr, &out_len, ciphertext,
                          ciphertext_len) <= 0)
        throw CryptoError();  // Generic "error: decryption failed"

    SecureBuffer plaintext(out_len);
    if (EVP_PKEY_decrypt(ctx.get(), plaintext.data(), &out_len,
                          ciphertext, ciphertext_len) <= 0) {
        ERR_clear_error();
        throw CryptoError();  // Generic message, no oracle info
    }

    plaintext.resize(out_len);
    return plaintext;
}

} // namespace rsatool::oaep

