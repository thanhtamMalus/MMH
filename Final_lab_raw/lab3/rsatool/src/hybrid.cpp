// hybrid.cpp — AES-256-GCM streaming encrypt/decrypt
// Fresh 32-byte key + 12-byte IV per call. Single GCM tag over whole stream.
// Decrypt-then-release: plaintext not written until tag verifies.
#include <rsatool/hybrid.hpp>
#include <rsatool/errors.hpp>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#include <cstring>
#include <istream>
#include <ostream>
#include <stdexcept>
#include <vector>

namespace rsatool::hybrid {

// ── Random bytes ─────────────────────────────────────────────────────────────

static void rand_bytes(uint8_t* buf, std::size_t len) {
    if (RAND_bytes(buf, static_cast<int>(len)) != 1) {
        ERR_clear_error();
        throw CryptoError("error: RAND_bytes failed");
    }
}

// ── Encrypt (memory) ──────────────────────────────────────────────────────────

EncryptResult encrypt_mem(
    const uint8_t* plaintext,
    std::size_t    plaintext_len,
    const std::vector<uint8_t>& aad)
{
    ERR_clear_error();

    // Generate fresh random key and IV
    SecureBuffer key(AES_KEY_BYTES);
    rand_bytes(key.data(), AES_KEY_BYTES);

    std::vector<uint8_t> iv(AES_IV_BYTES);
    rand_bytes(iv.data(), AES_IV_BYTES);

    // Set up AES-256-GCM context
    UniqueEVPCIPHERCTX ctx(EVP_CIPHER_CTX_new());
    if (!ctx) throw CryptoError("error: EVP_CIPHER_CTX_new failed");

    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) <= 0)
        throw CryptoError();

    // Set IV length (12 bytes = 96 bits)
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN,
                             static_cast<int>(AES_IV_BYTES), nullptr) <= 0)
        throw CryptoError();

    // Set key and IV
    if (EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr,
                            key.data(), iv.data()) <= 0)
        throw CryptoError();

    // Set AAD
    if (!aad.empty()) {
        int aad_len_out = 0;
        if (EVP_EncryptUpdate(ctx.get(), nullptr, &aad_len_out,
                               aad.data(), static_cast<int>(aad.size())) <= 0)
            throw CryptoError();
    }

    // Encrypt in chunks
    std::vector<uint8_t> ciphertext(plaintext_len + AES_TAG_BYTES);
    std::size_t offset = 0;
    std::size_t remaining = plaintext_len;

    while (remaining > 0) {
        std::size_t chunk = (remaining > CHUNK_SIZE) ? CHUNK_SIZE : remaining;
        int out_len = 0;
        if (EVP_EncryptUpdate(ctx.get(),
                               ciphertext.data() + offset, &out_len,
                               plaintext + (plaintext_len - remaining),
                               static_cast<int>(chunk)) <= 0)
            throw CryptoError();
        offset += static_cast<std::size_t>(out_len);
        remaining -= chunk;
    }

    // Finalize
    int final_len = 0;
    if (EVP_EncryptFinal_ex(ctx.get(), ciphertext.data() + offset, &final_len) <= 0)
        throw CryptoError();
    offset += static_cast<std::size_t>(final_len);
    ciphertext.resize(offset);

    // Get authentication tag
    std::vector<uint8_t> tag(AES_TAG_BYTES);
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG,
                             static_cast<int>(AES_TAG_BYTES), tag.data()) <= 0)
        throw CryptoError();

    return EncryptResult{
        std::move(key),
        std::move(iv),
        std::move(tag),
        std::move(ciphertext)
    };
}

// ── Decrypt (memory) — decrypt-then-release ───────────────────────────────────

SecureBuffer decrypt_mem(
    const uint8_t* ciphertext,
    std::size_t    ciphertext_len,
    const uint8_t* key,
    const uint8_t* iv,
    const uint8_t* tag,
    const std::vector<uint8_t>& aad)
{
    ERR_clear_error();

    UniqueEVPCIPHERCTX ctx(EVP_CIPHER_CTX_new());
    if (!ctx) throw CryptoError();

    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) <= 0)
        throw CryptoError();

    // Set IV length
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN,
                             static_cast<int>(AES_IV_BYTES), nullptr) <= 0)
        throw CryptoError();

    // Set key and IV
    if (EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key, iv) <= 0)
        throw CryptoError();

    // Set expected tag BEFORE Final (required by OpenSSL)
    // Cast away const is required by OpenSSL API signature
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_TAG,
                             static_cast<int>(AES_TAG_BYTES),
                             const_cast<uint8_t*>(tag)) <= 0)
        throw CryptoError();

    // Set AAD
    if (!aad.empty()) {
        int aad_len_out = 0;
        if (EVP_DecryptUpdate(ctx.get(), nullptr, &aad_len_out,
                               aad.data(), static_cast<int>(aad.size())) <= 0)
            throw CryptoError();
    }

    // Decrypt into a temporary SecureBuffer (decrypt-then-release)
    SecureBuffer plaintext(ciphertext_len);
    std::size_t offset = 0;
    std::size_t remaining = ciphertext_len;

    while (remaining > 0) {
        std::size_t chunk = (remaining > CHUNK_SIZE) ? CHUNK_SIZE : remaining;
        int out_len = 0;
        if (EVP_DecryptUpdate(ctx.get(),
                               plaintext.data() + offset, &out_len,
                               ciphertext + (ciphertext_len - remaining),
                               static_cast<int>(chunk)) <= 0)
            throw CryptoError();
        offset += static_cast<std::size_t>(out_len);
        remaining -= chunk;
    }

    // Final: tag verification happens here (constant-time by OpenSSL)
    int final_len = 0;
    if (EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + offset, &final_len) <= 0) {
        ERR_clear_error();
        // Wipe partial plaintext before throwing
        plaintext.wipe();
        throw CryptoError();  // Generic "error: decryption failed"
    }
    offset += static_cast<std::size_t>(final_len);
    plaintext.resize(offset);

    return plaintext;
}

// ── Stream variants ───────────────────────────────────────────────────────────

EncryptResult encrypt_stream(
    std::istream& in,
    const std::vector<uint8_t>& aad)
{
    // Read all input into memory (file already validated to exist)
    std::vector<uint8_t> data(
        (std::istreambuf_iterator<char>(in)),
        std::istreambuf_iterator<char>());
    return encrypt_mem(data.data(), data.size(), aad);
}

void decrypt_stream(
    const uint8_t* ciphertext,
    std::size_t    ciphertext_len,
    const uint8_t* key,
    const uint8_t* iv,
    const uint8_t* tag,
    const std::vector<uint8_t>& aad,
    std::ostream& out)
{
    // Decrypt entirely first (decrypt-then-release)
    SecureBuffer plaintext = decrypt_mem(ciphertext, ciphertext_len, key, iv, tag, aad);
    // Only write if tag verified (decrypt_mem throws on failure)
    out.write(reinterpret_cast<const char*>(plaintext.data()),
               static_cast<std::streamsize>(plaintext.size()));
}

} // namespace rsatool::hybrid

