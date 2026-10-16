#pragma once
// aescore: thin, strict wrapper around Crypto++ AES modes.
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

namespace aescore {

using Bytes = std::vector<uint8_t>;

// Error hierarchy. Everything derives from CryptoError so callers can fail closed.
class CryptoError : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};
class AuthError : public CryptoError {     // authentication tag mismatch
 public:
  using CryptoError::CryptoError;
};
class FormatError : public CryptoError {   // malformed container / sidecar / tag
 public:
  using CryptoError::CryptoError;
};
class UsageError : public CryptoError {    // refused misuse (bad lengths, ECB limit, nonce reuse...)
 public:
  using CryptoError::CryptoError;
};

enum class Mode : uint8_t { ECB = 1, CBC, OFB, CFB, CTR, XTS, CCM, GCM };

const char* mode_name(Mode m);          // "gcm"
std::string mode_name_upper(Mode m);    // "GCM"
bool parse_mode(const std::string& s, Mode& out);   // case-insensitive
bool is_aead(Mode m);
bool uses_iv(Mode m);                   // false only for ECB
size_t default_iv_len(Mode m);
size_t default_tag_len(Mode m);         // 16 for AEAD, 0 otherwise
bool valid_key_len(Mode m, size_t n);   // XTS: 32/64, others 16/24/32
bool valid_iv_len(Mode m, size_t n, bool lenient = false);
bool valid_tag_len(Mode m, size_t n, bool lenient = false);
std::string iv_requirement_text(Mode m);
std::string algorithm_name(Mode m, size_t key_len);   // e.g. "AES-256-GCM"

struct CipherParams {
  Mode mode = Mode::GCM;
  Bytes key;
  Bytes iv;            // IV / nonce / XTS tweak
  Bytes aad;           // AEAD only
  size_t tag_len = 0;  // 0 => default (16)
  bool padding = true; // PKCS#7 for ECB/CBC (KAT uses false)
  bool lenient = false;// accept non-recommended IV/tag lengths (KAT only, never the CLI)
};

struct EncResult {
  Bytes ct;   // ciphertext (same length as plaintext, except ECB/CBC with padding)
  Bytes tag;  // AEAD only
};

// Raw primitives (no header). Throw UsageError / AuthError / CryptoError.
EncResult encrypt_raw(const CipherParams& p, const Bytes& plaintext);
Bytes decrypt_raw(const CipherParams& p, const Bytes& ciphertext, const Bytes& tag);

// Cryptographically secure random bytes (Crypto++ AutoSeededRandomPool).
Bytes random_bytes(size_t n);
// 8-byte key identifier = SHA-256("aestool-keyid-v1" || key)[0..8). Not reversible.
Bytes key_id(const Bytes& key);
void secure_wipe(Bytes& b);
std::string crypto_library_version();
bool hardware_aes_available();

}  // namespace aescore
