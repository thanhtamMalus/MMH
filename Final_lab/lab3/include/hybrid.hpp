// hybrid.hpp — AES-256-GCM symmetric encryption for the hybrid envelope
// Fresh 32-byte key and 12-byte IV per encryption. Single GCM tag over whole stream.
#pragma once
#include <cstdint>
#include <filesystem>
#include <vector>
#include "secure.hpp"

namespace rsatool::hybrid {

/// AES-256-GCM parameters
inline constexpr std::size_t AES_KEY_BYTES  = 32;  // 256-bit key
inline constexpr std::size_t AES_IV_BYTES   = 12;  // 96-bit IV (GCM spec)
inline constexpr std::size_t AES_TAG_BYTES  = 16;  // 128-bit authentication tag
inline constexpr std::size_t CHUNK_SIZE     = 1024 * 1024;  // 1 MiB streaming chunk

/// Result of AES-GCM encryption
struct EncryptResult {
    SecureBuffer key;        // 32-byte AES key (must be RSA-wrapped)
    std::vector<uint8_t> iv;         // 12-byte IV
    std::vector<uint8_t> tag;        // 16-byte authentication tag
    std::vector<uint8_t> ciphertext; // encrypted payload
};

/// Encrypt data from memory with AES-256-GCM.
/// aad: Additional Authenticated Data (the canonical header bytes).
/// Generates a fresh key and IV. Returns EncryptResult.
EncryptResult encrypt_mem(
    const uint8_t* plaintext,
    std::size_t    plaintext_len,
    const std::vector<uint8_t>& aad);

/// Decrypt data from memory with AES-256-GCM.
/// Must supply the correct key, iv, tag, and aad.
/// Returns plaintext. Throws CryptoError if tag verification fails.
SecureBuffer decrypt_mem(
    const uint8_t* ciphertext,
    std::size_t    ciphertext_len,
    const uint8_t* key,
    const uint8_t* iv,
    const uint8_t* tag,
    const std::vector<uint8_t>& aad);

/// Encrypt a file stream into a ciphertext buffer.
EncryptResult encrypt_stream(
    std::istream& in,
    const std::vector<uint8_t>& aad);

/// Decrypt a ciphertext buffer into a file stream.
void decrypt_stream(
    const uint8_t* ciphertext,
    std::size_t    ciphertext_len,
    const uint8_t* key,
    const uint8_t* iv,
    const uint8_t* tag,
    const std::vector<uint8_t>& aad,
    std::ostream& out);

} // namespace rsatool::hybrid

