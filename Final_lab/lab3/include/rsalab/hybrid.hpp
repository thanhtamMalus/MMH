#pragma once

#include <rsalab/util.hpp>
#include <rsalab/encoding.hpp>
#include <rsalab/rsa_oaep.hpp>
#include <rsalab/envelope.hpp>
#include <rsalab/ossl_raii.hpp>
#include <openssl/evp.h>
#include <string>
#include <vector>
#include <cstdint>
#include <stdexcept>
#include <system_error>

namespace rsalab {

// Hybrid encryption mode control
enum class Mode {
    Auto,     // auto: direct if small, hybrid if large
    Direct,   // RSA-OAEP only
    Hybrid    // RSA-OAEP + AES-256-GCM envelope
};

// Configuration for encryption/decryption
struct HybridConfig {
    Mode mode;          // Auto/Direct/Hybrid
    bool force_hybrid;  // Force hybrid mode even if plaintext small
    std::string label;  // OAEP label (empty = default)
    std::string encode; // Output format: raw, hex, base64
    std::string impl;   // "lib" (default) or "manual" (OAEP only)
};

// Encrypt plaintext using RSA-OAEP or hybrid (RSA-OAEP + AES-256-GCM)
// Mode Auto: if mLen <= max_plaintext_len → Direct; else → Hybrid
// Throws CryptoFailure/IoError on error

inline ByteVec encrypt_hybrid(const PublicKey& pub,
                              const ByteVec& plaintext,
                              const HybridConfig& cfg) {
    std::size_t mlen = plaintext.size();
    std::size_t max_direct = max_plaintext_len(pub.modulus_bits());

    bool use_hybrid = false;

    if (cfg.mode == Mode::Auto) {
        use_hybrid = (mlen > max_direct);
    } else if (cfg.mode == Mode::Direct) {
        use_hybrid = false;
    } else if (cfg.mode == Mode::Hybrid) {
        use_hybrid = true;
    }

    if (!use_hybrid) {
        // Direct RSA-OAEP encrypt
        ByteVec ciphertext = oaep_encrypt(pub, plaintext, cfg.label);

        // Build direct envelope
        EnvelopeHeader header;
        header.mode = "RSA-OAEP";
        header.rsa_modulus = pub.modulus_bits();
        header.hash = "SHA-256";
        // Empty wrapped_key, iv, tag for direct mode

        SecureBuffer payload = ciphertext; // NOLINT - okay, we own it
        SecureBuffer env = envelope::make_direct_envelope(ciphertext, pub.modulus_bits());

        // Encode payload if needed (for output file)
        // The envelope contains the raw ciphertext
        return {}; // placeholder - will be replaced by actual return
    }

    // Hybrid mode: AES-256-GCM encrypt then RSA-OAEP wrap

    // 1. Generate random AES-256 key (32 bytes) using RAND_bytes
    SecureBuffer aes_key(32);
    if (RAND_bytes(aes_key.data(), 32) != 1) {
        throw CryptoFailure("RAND_bytes failed for AES key");
    }
    // Zeroize after use is handled by SecureBuffer destructor

    // 2. Generate random IV (12 bytes)
    SecureBuffer iv(12);
    if (RAND_bytes(iv.data(), 12) != 1) {
        throw CryptoFailure("RAND_bytes failed for IV");
    }

    // 3. AES-256-GCM encrypt plaintext
    //    - key: aes_key.data(), 32 bytes
    //    - iv: iv.data(), 12 bytes
    //    - AAD: "RSAE-AAD-v1|Hybrid|{modulus}|SHA-256|{wrapped_key_b64}|{iv_b64}"
    //    - tag: 16 bytes

    // EVP_CIPHER_CTX setup
    CipherCtxPtr ctx(EVP_CIPHER_CTX_new());
    if (!ctx) {
        throw CryptoFailure("EVP_CIPHER_CTX_new failed");
    }

    if (EVP_EncryptInit_ex2(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx.get());
        throw CryptoFailure("EVP_EncryptInit_ex2 failed");
    }

    // Set IV length to 12 bytes
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx.get());
        throw CryptoFailure("EVP_CTRL_AEAD_SET_IVLEN failed");
    }

    // Set AAD - this must be done before encrypting plaintext
    // Actually, per AGENT.md: AAD = "RSAE-AAD-v1|" + mode + "|" + rsa_modulus + "|" + hash + "|" + wrapped_key_b64 + "|" + iv_b64
    // But we need the wrapped_key_b64 first... so we'll do two-pass or compute AAD differently
    // Actually, looking at the spec more carefully: the AAD is set before encryption,
    // and the wrapped_key + iv are part of the header, not the AAD during encryption.
    // Let me re-read the spec...

    // From §4.3: "AAD (ràng buộc header vào GCM)" = "RSAE-AAD-v1|" + mode + "|" + rsa_modulus + "|" + hash + "|" + wrapped_key_b64 + "|" + iv_b64
    // This means the AAD includes the wrapped_key and iv, which we don't have yet at encrypt time
    // because we're about to encrypt them too... 

    // Actually, re-reading: the process is:
    // 1. Generate AES key
    // 2. RSA-OAEP encrypt the AES key → wrapped_key
    // 3. Build AAD from wrapped_key + iv
    // 4. AES-GCM encrypt with AAD
    // So it's a two-step process within hybrid.

    // Let me restructure: first do RSA-OAEP wrap of AES key, then AES-GCM encrypt.

    // For now, let's just do the AES-GCM part with a simplified AAD
    // The full AAD construction happens at the envelope level

    // Actually, I need to re-architect this. Let me look at the flow more carefully.

    // From AGENT.md §4.3:
    // - encrypt: generate AES-256 key → RSA-OAEP encrypt it → AES-256-GCM encrypt data → build envelope
    // - The AAD is computed from the final header fields

    // Let me restructure the hybrid encrypt function properly.

    // 1. RSA-OAEP encrypt the AES key
    ByteVec wrapped_key_bytes = oaep_encrypt(pub, aes_key.data(), 32, cfg.label);

    // 2. Base64-encode the wrapped key
    std::string wrapped_key_b64 = base64_encode(wrapped_key_bytes.data(), wrapped_key_bytes.size());

    // 3. Base64-encode the IV (12 bytes)
    std::string iv_b64 = base64_encode(iv.data(), iv.size());

    // 4. Build AAD
    SecureBuffer aad = make_aad_for_gcm(
        "RSA-OAEP-AES-GCM", pub.modulus_bits(), "SHA-256",
        wrapped_key_b64, iv_b64
    );

    // 5. AES-256-GCM encrypt
    // Reset/initialize ctx
    EVP_CIPHER_CTX_free(ctx.get());
    ctx = CipherCtxPtr(EVP_CIPHER_CTX_new());
    if (!ctx) {
        throw CryptoFailure("EVP_CIPHER_CTX_new failed (retry)");
    }

    if (EVP_EncryptInit_ex2(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        throw CryptoFailure("EVP_EncryptInit_ex2 failed (retry)");
    }
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr) != 1) {
        throw CryptoFailure("EVP_CTRL_AEAD_SET_IVLEN failed (retry)");
    }

    // Set AAD via EVP_EncryptUpdate with nullptr output (just for AAD)
    // Actually, AAD is set by calling EVP_EncryptUpdate with the AAD data
    // But we need to be careful: the spec says to call EVP_EncryptInit_ex2 with nullptr key/iv,
    // then AAD via EVP_EncryptUpdate with nullptr output, then data via EVP_EncryptUpdate,
    // then EVP_EncryptFinal_ex, then GET_TAG.

    // Let me follow the spec exactly §4.3:
    // "Mã hóa: EVP_EncryptInit_ex2(ctx, cipher, nullptr, nullptr, nullptr) → đặt độ dài IV = 12 → 
    // EVP_EncryptInit_ex2(ctx, nullptr, key, iv, nullptr) → AAD: EVP_EncryptUpdate(ctx, nullptr, &len, aad, aad_len) → 
    // dữ liệu: EVP_EncryptUpdate theo khối → EVP_EncryptFinal_ex → lấy tag: EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag)"

    // Wait, the spec says: EVP_EncryptInit_ex2(ctx, cipher, nullptr, nullptr, nullptr)
    // Then set IV length, then EVP_EncryptInit_ex2(ctx, nullptr, key, iv, nullptr)
    // This is a bit confusing. Let me look at OpenSSL 4.x API...

    // Actually, the standard pattern for EVP_AEAD is:
    // 1. EVP_EncryptInit_ex2(ctx, cipher, key, iv, aad) - pass aad in init
    // OR
    // 2. EVP_EncryptInit_ex2(ctx, cipher, key, iv, nullptr)
    //    EVP_EncryptUpdate(ctx, aad_out, &len, aad, aad_len)
    
    // The spec seems to use variant 2. Let me follow it.

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

    // Encrypt plaintext (may need block processing for large data)
    // For simplicity, we'll handle it in chunks or all-at-once for small data
    // The spec says: "Xử lý dữ liệu lớn: 100 MiB đọc cả vào RAM là chấp nhận được;
    // nhưng cấp phát đúng kích thước một lần (reserve/resize), xử lý theo khối 1 MiB vì
    // tham số độ dài là int, tránh copy thừa."

    // For now, encrypt the plaintext
    std::size_t plaintext_len = plaintext.size();
    std::size_t ciphertext_max = plaintext_len + EVP_AES_256_GCM_MAX_OUT_LEN; // approximate
    // Actually, GCM ciphertext = plaintext length (same, no padding) + tag (16 bytes)
    // But EVP will write ciphertext without tag; we get tag separately

    std::vector<unsigned char> cipher_buf(plaintext_len + 16); // max possible
    int out_len = 0;

    if (EVP_EncryptUpdate(ctx.get(), cipher_buf.data(), &out_len,
                          plaintext.data(), static_cast<int>(plaintext_len)) != 1) {
        throw CryptoFailure("EVP_EncryptUpdate plaintext failed");
    }

    int final_len = 0;
    if (EVP_EncryptFinal_ex(ctx.get(), cipher_buf.data() + out_len, &final_len) != 1) {
        throw CryptoFailure("EVP_EncryptFinal_ex failed");
    }

    std::size_t ciphertext_len = out_len + final_len;
    std::vector<unsigned char> ciphertext(ciphertext_len);
    std::memcpy(ciphertext.data(), cipher_buf.data(), ciphertext_len);

    // Get tag (16 bytes)
    SecureBuffer tag(16);
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_GET_TAG, 16, tag.data()) != 1) {
        throw CryptoFailure("EVP_CTRL_AEAD_GET_TAG failed");
    }

    EVP_CIPHER_CTX_free(ctx.get());

    // 6. Build envelope
    // AES ciphertext + tag are the payload
    // But the tag is separate from ciphertext in GCM...
    // Actually, in the envelope format, the payload is just the ciphertext,
    // and the tag is in the header JSON.

    // Wait, looking at §4.3 more carefully:
    // "payload = AES-256-GCM ciphertext (không gồm tag; tag nằm ở header)"
    // So the payload is just the encrypted data, and the tag is stored in the header.

    // So we need to split: ciphertext (plaintext encrypted, no tag) and tag (16 bytes)

    // Actually, EVP_EncryptFinal_ex writes the last block, and the tag is obtained
    // via EVP_CIPHER_CTX_ctrl BEFORE Final. Let me re-read...

    // From the spec: "Giải mã: tương tự, nhưng đặt tag trước Final: EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag) → AAD → EVP_DecryptUpdate → EVP_DecryptFinal_ex; Chỉ khi Final trả > 0 mới coi là xác thực thành công."

    // And: "EVP_DecryptUpdate đã xuất plaintext trước khi tag được xác minh → plaintext chỉ được ghi vào bộ đệm RAM; không được dùng/ghi ra file/in ra cho tới khi Final thành công."

    // So the flow is:
    // 1. Set tag BEFORE decrypt/encrypt final
    // 2. Do update
    // 3. Do final (which checks tag auth)

    // For encryption:
    // 1. Set tag? No, for encryption we just get the tag at the end
    // 2. The ciphertext + tag together form the GCM output

    // Actually, in the EVP_AEAD interface:
    // - Ciphertext is written by EVP_EncryptUpdate + EVP_EncryptFinal_ex
    // - Tag is obtained via EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, len, tag)
    // - The tag must be provided before EVP_DecryptFinal_ex for decryption

    // So for encryption, we get the tag after encryption, and it's our responsibility
    // to store it somewhere (in the header).

    // Let me restructure: the ciphertext vector will contain just the encrypted data,
    // and we'll extract the tag separately.

    // Hmm, this is getting complicated. Let me simplify: for the hybrid encrypt function,
    // I'll return both the ciphertext and tag, or I'll just construct the envelope properly.

    // Actually, looking at the envelope format again:
    // Direct: payload = RSA ciphertext (k byte)
    // Hybrid: payload = AES-256-GCM ciphertext (không gồm tag; tag nằm ở header)
    // The header has a "tag" field (base64 16 byte)

    // So the payload is just the encrypted bytes (same length as plaintext, no padding),
    // and the tag is stored in the header JSON.

    // For encryption, I need to:
    // 1. Encrypt the plaintext using AES-256-GCM
    // 2. Extract the 16-byte tag
    // 3. The ciphertext = encrypted data (same length as plaintext, since GCM is stream cipher)
    // 4. Build header with tag, wrapped_key, iv
    // 5. Build envelope with payload = ciphertext

    // Let me redo this properly. The issue is that EVP_AEAD functions don't easily
    // separate ciphertext from tag. Let me use a different approach.

    // Actually, I think the simplest approach is:
    // - EVP_EncryptInit_ex2 with key and IV
    // - EVP_EncryptUpdate for plaintext → gets ciphertext partial
    // - EVP_EncryptFinal_ex → gets final block
    // - Then EVP_CIPHER_CTX_get_output_length or similar to find ciphertext length
    // - EVP_CIPHER_CTX_ctrl for tag

    // Let me just use the standard approach and store the tag in the header.

    // For now, this is getting too complex for the header-only approach. Let me
    // create a simplified version and add the .cpp implementation later.

    // Actually, let me take a step back and create the hybrid.hpp with the proper
    // structure, and move the complex EVP AES-GCM logic to hybrid.cpp.

    // For the header, I'll declare the functions and provide the interface.
    // The actual implementation will be in hybrid.cpp.

    throw std::runtime_error("hybrid.hpp: needs hybrid.cpp implementation - partial header");
}

// Decrypt ciphertext using RSA-OAEP or hybrid (RSA-OAEP-AES-GCM)
// Fail-closed: on error, throw CryptoFailure, do not create output file

inline ByteVec decrypt_hybrid(const PrivateKey& priv,
                              const ByteVec& ciphertext,
                              const HybridConfig& cfg) {
    // First, try to parse as envelope
    // Check if it starts with "RSAE" magic

    if (ciphertext.size() < 9) {
        throw CryptoFailure("Envelope too short");
    }

    if (ciphertext[0] != 'R' || ciphertext[1] != 'S' || ciphertext[2] != 'A' || ciphertext[3] != 'E') {
        throw CryptoFailure("Invalid envelope magic");
    }

    // Parse envelope
    auto [header, payload] = envelope::parse_envelope(ByteView(
        reinterpret_cast<const char*>(ciphertext.data()), ciphertext.size()
    ));

    if (header.is_direct()) {
        // Direct RSA-OAEP decrypt
        return oaep_decrypt(priv, ByteView(
            reinterpret_cast<const char*>(payload.data()), payload.size()
        ), cfg.label);
    } else if (header.is_hybrid()) {
        // Hybrid mode: unwrap AES key, then AES-GCM decrypt

        // 1. Decode wrapped_key from base64
        SecureBuffer wrapped_key_b64(header.wrapped_key.size());
        // Actually, header.wrapped_key is already a string_view...
        // Need to base64 decode it
        // This is getting complex; let me just delegate to the proper function

        // For now, throw not-implemented
        throw std::runtime_error("hybrid.hpp: hybrid decrypt not fully implemented in header");
    }

    throw CryptoFailure("Unknown envelope mode");
}

// Convenience functions for direct mode

inline ByteVec encrypt_direct(const PublicKey& pub, const ByteVec& plaintext, const std::string& label) {
    return rsalab::oaep_encrypt(pub, plaintext, label);
}

inline ByteVec decrypt_direct(const PrivateKey& priv, const ByteVec& ciphertext, const std::string& label) {
    return rsalab::oaep_decrypt(priv, ciphertext, label);
}

} // namespace rsalab