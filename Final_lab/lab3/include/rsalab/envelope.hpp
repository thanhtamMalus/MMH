#pragma once

#include <rsalab/util.hpp>
#include <rsalab/encoding.hpp>
#include <rsalab/keyio.hpp>
#include <openssl/evp.h>
#include <string>
#include <vector>
#include <cstdint>
#include <stdexcept>
#include <array>
#include <algorithm>

namespace rsalab {

// Container magic and version
static constexpr std::array<unsigned char, 4> CONTAINER_MAGIC = {'R', 'S', 'A', 'E'};
static constexpr unsigned char CONTAINER_VERSION = 0x01;

// Header length field size (u32 big-endian)
static constexpr std::size_t HEADER_LEN_SIZE = 4;

// Direct mode header: {"mode":"RSA-OAEP","rsa_modulus":3072,"hash":"SHA-256"}
static constexpr const char* DIRECT_HEADER_JSON =
    "{\"mode\":\"RSA-OAEP\",\"rsa_modulus\":3072,\"hash\":\"SHA-256\"}";

// Hybrid mode header JSON template
// {"mode":"RSA-OAEP-AES-GCM","rsa_modulus":3072,"hash":"SHA-256",
//  "wrapped_key":"<base64 32-byte key>","iv":"<base64 12-byte>","tag":"<base64 16-byte>"}

struct EnvelopeHeader {
    std::string mode;          // "RSA-OAEP" or "RSA-OAEP-AES-GCM"
    std::size_t rsa_modulus;   // 3072 or 4096
    std::string hash;          // "SHA-256"
    std::string wrapped_key;   // base64-encoded wrapped AES key
    std::string iv;            // base64-encoded IV (12 bytes for GCM)
    std::string tag;           // base64-encoded tag (16 bytes for GCM, empty for direct)

    bool is_hybrid() const noexcept {
        return mode == "RSA-OAEP-AES-GCM";
    }
    bool is_direct() const noexcept {
        return mode == "RSA-OAEP";
    }
};

// Parse envelope container from raw bytes
// Returns: {header, payload} or throws IoError/CryptoFailure
inline std::pair<EnvelopeHeader, SecureBuffer> parse_envelope(ByteView data) {
    EnvelopeHeader header;

    // Minimum size: 4 (magic) + 1 (version) + 4 (header_len) = 9
    if (data.size() < 9) {
        throw IoError("Envelope too short: minimum 9 bytes required");
    }

    // Check magic "RSAE"
    if (data.subview(0, 4) != ByteView(
            reinterpret_cast<const char*>(CONTAINER_MAGIC.data()), 4)) {
        throw IoError("Invalid envelope magic: expected 'RSAE'");
    }

    // Check version = 0x01
    if (data[4] != CONTAINER_VERSION) {
        throw IoError("Invalid envelope version: expected 0x01, got 0x" +
                      std::to_string(data[4]));
    }

    // Read header length (u32 big-endian at bytes 5-8)
    std::size_t header_len = static_cast<std::size_t>(
        (static_cast<uint32_t>(data[5]) << 24) |
        (static_cast<uint32_t>(data[6]) << 16) |
        (static_cast<uint32_t>(data[7]) << 8) |
        static_cast<uint32_t>(data[8])
    );

    if (data.size() < 9 + header_len) {
        throw IoError("Envelope truncated: declared header_len=" + std::to_string(header_len) +
                      " but data size is " + std::to_string(data.size()));
    }

    // Parse JSON header
    std::string header_str(reinterpret_cast<const char*>(data.data() + 9), header_len);
    // Simple JSON parsing - extract fields
    // We'll look for key-value pairs

    // Parse mode
    std::size_t mode_pos = header_str.find("\"mode\"");
    if (mode_pos != std::string::npos) {
        std::size_t colon_pos = header_str.find(':', mode_pos);
        if (colon_pos != std::string::npos) {
            std::size_t val_start = header_str.find_first_of("\"", colon_pos + 1);
            if (val_start != std::string::npos) {
                std::size_t val_end = header_str.find_last_of("\"");
                if (val_end > val_start) {
                    header.mode = header_str.substr(val_start + 1, val_end - val_start - 1);
                }
            }
        }
    }

    // Parse rsa_modulus
    std::size_t modulus_pos = header_str.find("\"rsa_modulus\"");
    if (modulus_pos != std::string::npos) {
        std::size_t colon_pos = header_str.find(':', modulus_pos);
        if (colon_pos != std::string::npos) {
            std::size_t val_start = header_str.find_first_of("0123456789", colon_pos + 1);
            if (val_start != std::string::npos) {
                std::size_t val_end = header_str.find_first_not_of("0123456789", val_start);
                if (val_end == std::string::npos) val_end = header_str.size();
                header.rsa_modulus = std::stoul(header_str.substr(val_start, val_end - val_start));
            }
        }
    }

    // Parse hash
    std::size_t hash_pos = header_str.find("\"hash\"");
    if (hash_pos != std::string::npos) {
        std::size_t colon_pos = header_str.find(':', hash_pos);
        if (colon_pos != std::string::npos) {
            std::size_t val_start = header_str.find_first_of("\"", colon_pos + 1);
            if (val_start != std::string::npos) {
                std::size_t val_end = header_str.find_last_of("\"");
                if (val_end > val_start) {
                    header.hash = header_str.substr(val_start + 1, val_end - val_start - 1);
                }
            }
        }
    }

    // Parse wrapped_key (base64)
    std::size_t wk_pos = header_str.find("\"wrapped_key\"");
    if (wk_pos != std::string::npos) {
        std::size_t colon_pos = header_str.find(':', wk_pos);
        if (colon_pos != std::string::npos) {
            std::size_t val_start = header_str.find_first_of("\"", colon_pos + 1);
            if (val_start != std::string::npos) {
                std::size_t val_end = header_str.find_last_of("\"");
                if (val_end > val_start) {
                    header.wrapped_key = header_str.substr(val_start + 1, val_end - val_start - 1);
                }
            }
        }
    }

    // Parse iv (base64)
    std::size_t iv_pos = header_str.find("\"iv\"");
    if (iv_pos != std::string::npos) {
        std::size_t colon_pos = header_str.find(':', iv_pos);
        if (colon_pos != std::string::npos) {
            std::size_t val_start = header_str.find_first_of("\"", colon_pos + 1);
            if (val_start != std::string::npos) {
                std::size_t val_end = header_str.find_last_of("\"");
                if (val_end > val_start) {
                    header.iv = header_str.substr(val_start + 1, val_end - val_start - 1);
                }
            }
        }
    }

    // Parse tag (base64, empty for direct)
    std::size_t tag_pos = header_str.find("\"tag\"");
    if (tag_pos != std::string::npos) {
        std::size_t colon_pos = header_str.find(':', tag_pos);
        if (colon_pos != std::string::npos) {
            std::size_t val_start = header_str.find_first_of("\"", colon_pos + 1);
            if (val_start != std::string::npos) {
                std::size_t val_end = header_str.find_last_of("\"");
                if (val_end > val_start) {
                    header.tag = header_str.substr(val_start + 1, val_end - val_start - 1);
                }
            }
        }
    }

    // Extract payload (after header)
    std::size_t payload_offset = 9 + header_len;
    if (payload_offset > data.size()) {
        throw IoError("Envelope payload offset exceeds data size");
    }
    SecureBuffer payload(data.size() - payload_offset);
    if (payload_offset < data.size()) {
        std::memcpy(payload.data(), data.data() + payload_offset, data.size() - payload_offset);
    }

    return {header, payload};
}

// Build envelope container from header + payload
// Returns: raw container bytes (magic + version + header_len + header_json + payload)
inline SecureBuffer build_envelope(const EnvelopeHeader& header, const SecureBuffer& payload) {
    // Build JSON header string
    std::string json_header;
    if (header.is_direct()) {
        json_header = DIRECT_HEADER_JSON;
        // Direct: wrapped_key, iv, tag are omitted/empty
        // But we still need valid JSON with the three fields
    } else if (header.is_hybrid()) {
        json_header = "{\"mode\":\"RSA-OAEP-AES-GCM\",\"rsa_modulus\":"
                      + std::to_string(header.rsa_modulus) +
                      ",\"hash\":\"" + header.hash +
                      "\",\"wrapped_key\":\"" + header.wrapped_key +
                      "\",\"iv\":\"" + header.iv +
                      "\",\"tag\":\"" + header.tag + "\"}";
    } else {
        throw IoError("Unknown envelope mode: " + header.mode);
    }

    // Calculate sizes
    std::size_t json_size = json_header.size();
    std::size_t payload_size = payload.size();
    std::size_t total_size = 4 + 1 + HEADER_LEN_SIZE + json_size + payload_size;

    SecureBuffer container(total_size);

    // Write magic "RSAE" (4 bytes)
    std::memcpy(container.data(), CONTAINER_MAGIC.data(), 4);

    // Write version 0x01 (1 byte)
    container[4] = CONTAINER_VERSION;

    // Write header length (u32 big-endian, bytes 5-8)
    container[5] = static_cast<unsigned char>((json_size >> 24) & 0xFF);
    container[6] = static_cast<unsigned char>((json_size >> 16) & 0xFF);
    container[7] = static_cast<unsigned char>((json_size >> 8) & 0xFF);
    container[8] = static_cast<unsigned char>(json_size & 0xFF);

    // Write JSON header
    std::memcpy(container.data() + 9, json_header.data(), json_size);

    // Write payload
    std::size_t payload_offset = 9 + json_size;
    std::memcpy(container.data() + payload_offset, payload.data(), payload_size);

    return container;
}

// Generate Additional Authenticated Data (AAD) for AES-GCM
// Format: "RSAE-AAD-v1|" + mode + "|" + rsa_modulus + "|" + hash + "|" + wrapped_key_b64 + "|" + iv_b64
inline SecureBuffer make_aad_for_gcm(const std::string& mode,
                                      std::size_t rsa_modulus,
                                      const std::string& hash,
                                      const std::string& wrapped_key_b64,
                                      const std::string& iv_b64) {
    std::string aad = "RSAE-AAD-v1|" + mode + "|";
    aad += std::to_string(rsa_modulus) + "|" + hash + "|" + wrapped_key_b64 + "|" + iv_b64;
    return SecureBuffer(
        reinterpret_cast<const unsigned char*>(aad.data()),
        aad.size()
    );
}

// Convenience: create direct envelope (RSA-OAEP only)
// payload is the RSA ciphertext (exactly modulus_bytes bytes)
inline SecureBuffer make_direct_envelope(const ByteVec& rsa_ciphertext,
                                         std::size_t modulus_bits) {
    EnvelopeHeader header;
    header.mode = "RSA-OAEP";
    header.rsa_modulus = modulus_bits;
    header.hash = "SHA-256";
    // wrapped_key, iv, tag are empty for direct mode
    // Actually for direct mode, the header only has mode, rsa_modulus, hash
    // But our EnvelopeHeader always has all fields; we'll just set them minimally

    SecureBuffer payload = SecureBuffer(rsa_ciphertext.data(),
                                         rsa_ciphertext.size()); // copy

    return build_envelope(header, payload);
}

// Convenience: create hybrid envelope (RSA-OAEP-AES-GCM)
// wrapped_key: base64-encoded 32-byte AES key
// iv: base64-encoded 12-byte IV
// tag: base64-encoded 16-byte GCM tag
inline SecureBuffer make_hybrid_envelope(const ByteVec& aes_ciphertext,
                                          const std::string& wrapped_key_b64,
                                          const std::string& iv_b64,
                                          const std::string& tag_b64,
                                          std::size_t modulus_bits) {
    EnvelopeHeader header;
    header.mode = "RSA-OAEP-AES-GCM";
    header.rsa_modulus = modulus_bits;
    header.hash = "SHA-256";
    header.wrapped_key = wrapped_key_b64;
    header.iv = iv_b64;
    header.tag = tag_b64;

    SecureBuffer payload = aes_ciphertext; // assume already SecureBuffer or convert

    return build_envelope(header, payload);
}

} // namespace rsalab