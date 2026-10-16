#pragma once
// High-level encrypt/decrypt pipeline with all misuse-prevention checks.
#include <string>
#include <vector>

#include "aescore.h"

namespace aescore {

constexpr size_t kEcbMaxBytes = 16 * 1024;   // default ECB size limit (16 KiB)

const char* ecb_warning_text();
void check_ecb_policy(size_t size, bool allow_ecb);   // throws UsageError

// Nonce-reuse detection for CTR/CCM/GCM (returns false for other modes).
// Looks at: header of existing output file, existing sidecar JSON, optional ledger file.
bool nonce_reused(Mode mode, const Bytes& key_id, const Bytes& iv, const std::string& out_path,
                  const std::string& sidecar_path, const std::string& ledger_path, std::string* where);

struct EncryptOptions {
  Mode mode = Mode::GCM;
  Bytes key;
  Bytes iv;
  bool has_iv = false;
  Bytes aad;
  size_t tag_len = 0;
  bool allow_ecb = false;
  std::string out_path;       // inspected for nonce reuse (may be empty)
  std::string sidecar_path;   // non-empty => sidecar mode (output = raw ciphertext only)
  std::string ledger_path;    // optional global nonce ledger
};

struct EncryptResult {
  Bytes output;           // container, or raw ciphertext in sidecar mode
  std::string sidecar;    // JSON text in sidecar mode
  Bytes iv;
  Bytes tag;
  std::string alg;
  bool iv_generated = false;
};

EncryptResult encrypt_buffer(const EncryptOptions& o, const Bytes& plaintext);

struct DecryptOptions {
  bool has_mode = false;
  Mode mode = Mode::GCM;
  Bytes key;
  bool has_iv = false;    // overrides IV from header (used for negative tests)
  Bytes iv;
  bool has_aad = false;   // overrides AAD from header
  Bytes aad;
  bool allow_ecb = false;
  bool sidecar_mode = false;
  std::string sidecar_json;
};

struct DecryptResult {
  Bytes plaintext;
  std::string alg;
  std::vector<std::string> warnings;
};

// Fail closed: throws (AuthError/FormatError/UsageError/CryptoError) and returns no plaintext.
DecryptResult decrypt_buffer(const DecryptOptions& o, const Bytes& input);

}  // namespace aescore
