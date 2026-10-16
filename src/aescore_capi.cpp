#include "aescore_capi.h"

#include <cstdlib>
#include <cstring>
#include <string>

#include "aescore.h"
#include "ops.h"

using namespace aescore;

namespace {

void set_err(char* err, size_t n, const std::string& m) {
  if (!err || n == 0) return;
  std::strncpy(err, m.c_str(), n - 1);
  err[n - 1] = '\0';
}

int hand_over(const Bytes& b, uint8_t** out, size_t* out_len, char* err, size_t err_len) {
  uint8_t* p = static_cast<uint8_t*>(std::malloc(b.empty() ? 1 : b.size()));
  if (!p) {
    set_err(err, err_len, "out of memory");
    return 3;
  }
  if (!b.empty()) std::memcpy(p, b.data(), b.size());
  *out = p;
  *out_len = b.size();
  return 0;
}

}  // namespace

extern "C" {

const char* aescore_version(void) {
  static std::string v;
  v = "aescore 1.0 / Crypto++ " + crypto_library_version();
  return v.c_str();
}

int aescore_encrypt(const char* mode, const uint8_t* key, size_t key_len, const uint8_t* iv, size_t iv_len,
                    const uint8_t* aad, size_t aad_len, const uint8_t* in, size_t in_len, int allow_ecb,
                    uint8_t** out, size_t* out_len, char* err, size_t err_len) {
  try {
    if (!out || !out_len || !key) {
      set_err(err, err_len, "null argument");
      return 1;
    }
    *out = nullptr;
    *out_len = 0;
    EncryptOptions o;
    if (!mode || !parse_mode(mode, o.mode)) {
      set_err(err, err_len, "unknown mode");
      return 1;
    }
    o.key.assign(key, key + key_len);
    if (iv && iv_len) {
      o.iv.assign(iv, iv + iv_len);
      o.has_iv = true;
    }
    if (aad && aad_len) o.aad.assign(aad, aad + aad_len);
    o.allow_ecb = allow_ecb != 0;
    Bytes pt;
    if (in && in_len) pt.assign(in, in + in_len);
    const EncryptResult r = encrypt_buffer(o, pt);
    secure_wipe(o.key);
    return hand_over(r.output, out, out_len, err, err_len);
  } catch (const AuthError& e) {
    set_err(err, err_len, e.what());
    return 2;
  } catch (const UsageError& e) {
    set_err(err, err_len, e.what());
    return 1;
  } catch (const FormatError& e) {
    set_err(err, err_len, e.what());
    return 1;
  } catch (const std::exception& e) {
    set_err(err, err_len, e.what());
    return 3;
  }
}

int aescore_decrypt(const char* mode, const uint8_t* key, size_t key_len, const uint8_t* aad, size_t aad_len,
                    const uint8_t* in, size_t in_len, int allow_ecb, uint8_t** out, size_t* out_len, char* err,
                    size_t err_len) {
  try {
    if (!out || !out_len || !key || !in) {
      set_err(err, err_len, "null argument");
      return 1;
    }
    *out = nullptr;
    *out_len = 0;
    DecryptOptions o;
    if (mode && *mode) {
      if (!parse_mode(mode, o.mode)) {
        set_err(err, err_len, "unknown mode");
        return 1;
      }
      o.has_mode = true;
    }
    o.key.assign(key, key + key_len);
    if (aad && aad_len) {
      o.aad.assign(aad, aad + aad_len);
      o.has_aad = true;
    }
    o.allow_ecb = allow_ecb != 0;
    const Bytes ct(in, in + in_len);
    const DecryptResult r = decrypt_buffer(o, ct);
    secure_wipe(o.key);
    return hand_over(r.plaintext, out, out_len, err, err_len);
  } catch (const AuthError& e) {
    set_err(err, err_len, e.what());
    return 2;
  } catch (const UsageError& e) {
    set_err(err, err_len, e.what());
    return 1;
  } catch (const FormatError& e) {
    set_err(err, err_len, e.what());
    return 1;
  } catch (const std::exception& e) {
    set_err(err, err_len, e.what());
    return 3;
  }
}

int aescore_random(uint8_t* buf, size_t n) {
  try {
    if (!buf) return 1;
    const Bytes b = random_bytes(n);
    if (n) std::memcpy(buf, b.data(), n);
    return 0;
  } catch (...) {
    return 3;
  }
}

void aescore_free(uint8_t* p) { std::free(p); }

}  // extern "C"
