// oaep.hpp — RSA-OAEP direct encrypt/decrypt (EVP_PKEY_CTX)
// SHA-256 for both OAEP hash and MGF1 hash. No low-level RSA_* functions.
#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <rsatool/secure.hpp>

namespace rsatool::oaep {

/// Maximum plaintext length for RSA-OAEP with SHA-256:
///   mLen = k - 2*hLen - 2 = modulus_bytes - 66
inline constexpr std::size_t max_plaintext_len(int modulus_bits) {
    return static_cast<std::size_t>(modulus_bits / 8) - 2 * 32 - 2;
}

/// Encrypt plaintext with RSA-OAEP (SHA-256 / MGF1-SHA-256).
/// label may be empty. Returns ciphertext (length == modulus bytes).
/// Throws CryptoError / UsageError.
std::vector<uint8_t> encrypt(
    const EVP_PKEY*  pub_key,
    const uint8_t*   plaintext,
    std::size_t      plaintext_len,
    const std::string& label = "");

/// Decrypt RSA-OAEP ciphertext.
/// Returns plaintext. Throws CryptoError on any failure (generic message).
SecureBuffer decrypt(
    const EVP_PKEY*  priv_key,
    const uint8_t*   ciphertext,
    std::size_t      ciphertext_len,
    const std::string& label = "");

} // namespace rsatool::oaep

