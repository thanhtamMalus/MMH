#include <rsalab/hybrid.hpp>
#include <rsalab/rsa_oaep.hpp>
#include <rsalab/encoding.hpp>
#include <rsalab/ossl_raii.hpp>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string>
#include <vector>
#include <cstdint>
#include <stdexcept>
#include <algorithm>

namespace rsalab {

// Helper: Base64 encode a byte range
static std::string b64_encode(ByteView data) {
    if (data.size() == 0) return "";
    std::vector<char> out((data.size() * 4 + 2) / 3 + 1);
    int ol = EVP_EncodeBlock(
        reinterpret_cast<unsigned char*>(out.data()),
        reinterpret_cast<const unsigned char*>(data.data()),
        static_cast<int>(data.size())
    );
    if (ol < 0) throw CryptoFailure("Base64 encode failed");
    return std::string(out.data(), ol);
}

// Helper: Base64 decode a string (strip whitespace, handle padding)
static SecureBuffer b64_decode(std::string_view b64) {
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
    if (ol < 0) throw CryptoFailure("Base64 decode failed");

    SecureBuffer result(ol);
    if (ol > 0) {
        std::memcpy(result.data(), out.data(), ol);
    }
    return result;
}

// Encrypt hybrid: RSA-OAEP wrap AES key + AES-256-GCM encrypt data
// Returns: envelope container bytes (binary)
ByteVec encrypt_hybrid_impl(const PublicKey& pub,
                            const ByteVec& plaintext,
                            const HybridConfig& cfg) {
    std::size_t mlen = plaintext.size();
    std::size_t max_direct = max_plaintext_len(pub.modulus_bits());

    bool use_hybrid = false;
    if (cfg.mode == Mode::Auto) {
        use_hybrid = (mlen > max_direct);
    } else if (cfg.mode == Mode::Hybrid) {
        use_hybrid = true;
    } else {
        use_hybrid = false; // Direct
    }

    if (!use_hybrid) {
        // Direct RSA-OAEP
        ByteVec ciphertext = oaep_encrypt(pub, plaintext, cfg.label);
        // Build direct envelope
        EnvelopeHeader header;
        header.mode = "RSA-OAEP";
        header.rsa_modulus = pub.modulus_bits();
        header.hash = "SHA-256";
        SecureBuffer payload = ciphertext;
        return envelope::make_direct_envelope(ciphertext, pub.modulus_bits());
    }

    // ---- Hybrid mode ----

    // 1. Generate random AES-256 key (32 bytes)
    SecureBuffer aes_key(32);
    if (RAND_bytes(aes_key.data(), 32) != 1) {
        throw CryptoFailure("RAND_bytes failed for AES key");
    }

    // 2. Generate random IV (12 bytes)
    SecureBuffer iv(12);
    if (RAND_bytes(iv.data(), 12) != 1) {
        throw CryptoFailure("RAND_bytes failed for IV");
    }

    // 3. RSA-OAEP encrypt the AES key
    ByteVec wrapped_key = oaep_encrypt(pub, aes_key.data(), 32, cfg.label);

    // 4. Base64-encode wrapped key and IV
    std::string wrapped_key_b64 = b64_encode(ByteView(wrapped_key));
    std::string iv_b64 = b64_encode(ByteView(iv));

    // 5. Build AAD for GCM
    // Format: "RSAE-AAD-v1|" + mode + "|" + rsa_modulus + "|" + hash + "|" + wrapped_key_b64 + "|" + iv_b64
    std::string aad_str = "RSAE-AAD-v1|RSA-OAEP-AES-GCM|" +
                          std::to_string(pub.modulus_bits()) + "|SHA-256|" +
                          wrapped_key_b64 + "|" + iv_b64;
    SecureBuffer aad(
        reinterpret_cast<const unsigned char*>(aad_str.data()),
        aad_str.size()
    );

    // 6. AES-256-GCM encrypt
    // Use EVP_CIPHER_CTX RAII wrapper
    CipherCtxPtr ctx(EVP_CIPHER_CTX_new());
    if (!ctx) throw CryptoFailure("EVP_CIPHER_CTX_new failed");

    if (EVP_EncryptInit_ex2(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        throw CryptoFailure("EVP_EncryptInit_ex2 failed");
    }

    // Set IV length
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr) != 1) {
        throw CryptoFailure("EVP_CTRL_AEAD_SET_IVLEN failed");
    }

    // Set key and IV
    if (EVP_EncryptInit_ex2(ctx.get(), nullptr, aes_key.data(), iv.data(), nullptr) != 1) {
        throw CryptoFailure("EVP_EncryptInit_ex2 key/iv failed");
    }

    // Provide AAD
    std::size_t aad_len = aad.size();
    if (aad_len > 0) {
        if (EVP_EncryptUpdate(ctx.get(), nullptr, &aad_len, aad.data(), static_cast<int>(aad_len)) != 1) {
            throw CryptoFailure("EVP_EncryptUpdate AAD failed");
        }
    }

    // Encrypt plaintext
    // For block ciphers in GCM mode, ciphertext is same length as plaintext (no padding)
    std::size_t buf_size = plaintext.size() + 16; // add extra for safety
    std::vector<unsigned char> cipher_buf(buf_size);
    int out_len = 0;

    if (EVP_EncryptUpdate(ctx.get(), cipher_buf.data(), &out_len,
                          plaintext.data(), static_cast<int>(plaintext.size())) != 1) {
        throw CryptoFailure("EVP_EncryptUpdate plaintext failed");
    }

    int final_len = 0;
    if (EVP_EncryptFinal_ex(ctx.get(), cipher_buf.data() + out_len, &final_len) != 1) {
        throw CryptoFailure("EVP_EncryptFinal_ex failed");
    }

    std::size_t ciphertext_len = static_cast<std::size_t>(out_len) + static_cast<std::size_t>(final_len);
    std::vector<unsigned char> ciphertext(ciphertext_len);
    std::memcpy(ciphertext.data(), cipher_buf.data(), ciphertext_len);

    // Get GCM tag (16 bytes) - must be called after EncryptFinal_ex? 
    // Actually, per OpenSSL docs, GET_TAG can be called after Final or before Final.
    // The spec says: "lấy tag: EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag)"
    // And: "đặt tag trước Final" for decryption. For encryption, we get tag after.

    SecureBuffer tag(16);
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_GET_TAG, 16, tag.data()) != 1) {
        throw CryptoFailure("EVP_CTRL_AEAD_GET_TAG failed");
    }

    EVP_CIPHER_CTX_free(ctx.release()); // unique_ptr frees it

    // 7. Build header JSON
    // {"mode":"RSA-OAEP-AES-GCM","rsa_modulus":3072,"hash":"SHA-256",
    //  "wrapped_key":"<base64>","iv":"<base64>","tag":"<base64>"}
    std::string tag_b64 = b64_encode(ByteView(tag));
    std::string header_json = "{\"mode\":\"RSA-OAEP-AES-GCM\","
        "\"rsa_modulus\":" + std::to_string(pub.modulus_bits()) +
        ",\"hash\":\"SHA-256\",\"wrapped_key\":\"" + wrapped_key_b64 +
        "\",\"iv\":\"" + iv_b64 + "\",\"tag\":\"" + tag_b64 + "\"}";

    // 8. Build payload (ciphertext only, no tag)
    SecureBuffer payload(ciphertext.data(), ciphertext_len);

    // 9. Build envelope
    EnvelopeHeader env_header;
    env_header.mode = "RSA-OAEP-AES-GCM";
    env_header.rsa_modulus = pub.modulus_bits();
    env_header.hash = "SHA-256";
    env_header.wrapped_key = wrapped_key_b64;
    env_header.iv = iv_b64;
    env_header.tag = tag_b64;

    return envelope::build_envelope(env_header, payload);
}

// Decrypt hybrid: RSA-OAEP unwrap AES key + AES-256-GCM decrypt data
// Fail-closed: on error, throw CryptoFailure, do not return plaintext if auth fails
ByteVec decrypt_hybrid_impl(const PrivateKey& priv,
                            const ByteVec& envelope_data,
                            const HybridConfig& cfg) {
    // 1. Parse envelope
    if (envelope_data.size() < 9) {
        throw CryptoFailure("Envelope too short");
    }
    if (envelope_data[0] != 'R' || envelope_data[1] != 'S' ||
        envelope_data[2] != 'A' || envelope_data[3] != 'E') {
        throw CryptoFailure("Invalid envelope magic");
    }

    auto [header, payload] = envelope::parse_envelope(ByteView(
        reinterpret_cast<const char*>(envelope_data.data()), envelope_data.size()
    ));

    if (!header.is_hybrid()) {
        throw CryptoFailure("Not a hybrid envelope");
    }

    // 2. Base64-decode wrapped key
    SecureBuffer wrapped_key = b64_decode(header.wrapped_key);
    if (wrapped_key.size() != 32) {
        throw CryptoFailure("Wrapped key length is not 32 bytes");
    }

    // 3. Base64-decode IV
    SecureBuffer iv = b64_decode(header.iv);
    if (iv.size() != 12) {
        throw CryptoFailure("IV length is not 12 bytes");
    }

    // 4. Base64-decode tag
    SecureBuffer tag = b64_decode(header.tag);
    if (tag.size() != 16) {
        throw CryptoFailure("Tag length is not 16 bytes");
    }

    // 5. RSA-OAEP unwrap the AES key
    ByteVec aes_key = oaep_decrypt(priv, wrapped_key, header.label);

    // 6. AES-256-GCM decrypt
    CipherCtxPtr ctx(EVP_CIPHER_CTX_new());
    if (!ctx) throw CryptoFailure("EVP_CIPHER_CTX_new failed");

    if (EVP_DecryptInit_ex2(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        throw CryptoFailure("EVP_DecryptInit_ex2 failed");
    }

    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr) != 1) {
        throw CryptoFailure("EVP_CTRL_AEAD_SET_IVLEN failed");
    }

    // IMPORTANT: Set tag BEFORE decrypt update (per spec: tag must be set for auth check)
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_TAG, 16, tag.data()) != 1) {
        throw CryptoFailure("EVP_CTRL_AEAD_SET_TAG failed");
    }

    // Set key and IV
    if (EVP_DecryptInit_ex2(ctx.get(), nullptr, aes_key.data(), iv.data(), nullptr) != 1) {
        throw CryptoFailure("EVP_DecryptInit_ex2 key/iv failed");
    }

    // Provide AAD
    // Need to reconstruct AAD from header fields
    std::string aad_str = "RSAE-AAD-v1|RSA-OAEP-AES-GCM|" +
                          std::to_string(priv.modulus_bits()) + "|SHA-256|" +
                          header.wrapped_key + "|" + header.iv;
    SecureBuffer aad(
        reinterpret_cast<const unsigned char*>(aad_str.data()),
        aad_str.size()
    );

    std::size_t aad_len = aad.size();
    if (aad_len > 0) {
        if (EVP_DecryptUpdate(ctx.get(), nullptr, &aad_len, aad.data(), static_cast<int>(aad_len)) != 1) {
            throw CryptoFailure("EVP_DecryptUpdate AAD failed");
        }
    }

    // Decrypt ciphertext
    // Ciphertext length = payload size (same as plaintext since GCM has no padding)
    std::size_t plaintext_len = payload.size();
    std::vector<unsigned char> plain_buf(plaintext_len);

    int out_len = 0;
    if (EVP_DecryptUpdate(ctx.get(), plain_buf.data(), &out_len,
                          payload.data(), static_cast<int>(payload.size())) != 1) {
        throw CryptoFailure("EVP_DecryptUpdate failed");
    }

    int final_len = 0;
    // EVP_DecryptFinal_ex will verify the tag and return > 0 on success, 0 on failure
    if (EVP_DecryptFinal_ex(ctx.get(), plain_buf.data() + out_len, &final_len) != 1) {
        throw CryptoFailure("AES-GCM decryption failed (tag authentication error)");
    }

    // If we get here, authentication succeeded
    std::size_t plaintext_size = static_cast<std::size_t>(out_len) + static_cast<std::size_t>(final_len);
    std::vector<unsigned char> plaintext(plaintext_size);
    std::memcpy(plaintext.data(), plain_buf.data(), plaintext_size);

    EVP_CIPHER_CTX_free(ctx.release());

    return ByteVec(plaintext.data(), plaintext.data() + plaintext_size);
}

// Public interface wrappers (declared in hybrid.hpp)

ByteVec encrypt_hybrid(const PublicKey& pub,
                      const ByteVec& plaintext,
                      const HybridConfig& cfg) {
    return encrypt_hybrid_impl(pub, plaintext, cfg);
}

ByteVec decrypt_hybrid(const PrivateKey& priv,
                       const ByteVec& ciphertext,
                       const HybridConfig& cfg) {
    return decrypt_hybrid_impl(priv, ciphertext, cfg);
}

} // namespace rsalab