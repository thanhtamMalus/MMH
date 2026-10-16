#include "aescore.h"

#include <cctype>
#include <cstring>

#include "cryptopp_headers.h"

namespace cp = CryptoPP;

namespace aescore {
namespace {

const char* const kNames[8] = {"ecb", "cbc", "ofb", "cfb", "ctr", "xts", "ccm", "gcm"};
inline size_t idx(Mode m) { return static_cast<size_t>(m) - 1; }

using Pad = cp::StreamTransformationFilter::BlockPaddingScheme;

void run_stf(cp::StreamTransformation& c, const Bytes& in, Pad pad, std::string& out) {
  cp::StreamTransformationFilter f(c, new cp::StringSink(out), pad);
  if (!in.empty()) f.Put(in.data(), in.size());
  f.MessageEnd();
}

Bytes crypt_ecb(bool enc, const Bytes& key, const Bytes& in, Pad pad) {
  std::string out;
  if (enc) {
    cp::ECB_Mode<cp::AES>::Encryption c;
    c.SetKey(key.data(), key.size());
    run_stf(c, in, pad, out);
  } else {
    cp::ECB_Mode<cp::AES>::Decryption c;
    c.SetKey(key.data(), key.size());
    run_stf(c, in, pad, out);
  }
  return Bytes(out.begin(), out.end());
}

template <class M>
Bytes crypt_iv(bool enc, const Bytes& key, const Bytes& iv, const Bytes& in, Pad pad) {
  std::string out;
  if (enc) {
    typename M::Encryption c;
    c.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());
    run_stf(c, in, pad, out);
  } else {
    typename M::Decryption c;
    c.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());
    run_stf(c, in, pad, out);
  }
  return Bytes(out.begin(), out.end());
}

std::string key_len_text(Mode m) { return m == Mode::XTS ? "32 or 64" : "16, 24 or 32"; }

// Validates every parameter; returns the effective tag length.
size_t validate(const CipherParams& p) {
  if (!valid_key_len(p.mode, p.key.size()))
    throw UsageError("invalid key length " + std::to_string(p.key.size()) + " bytes for " +
                     mode_name_upper(p.mode) + " (expected " + key_len_text(p.mode) + " bytes)");
  if (!valid_iv_len(p.mode, p.iv.size(), p.lenient))
    throw UsageError("invalid IV/nonce length " + std::to_string(p.iv.size()) + " bytes for " +
                     mode_name_upper(p.mode) + " (expected " + iv_requirement_text(p.mode) + ")");
  if (!is_aead(p.mode)) {
    if (!p.aad.empty()) throw UsageError("AAD is only supported by AEAD modes (ccm, gcm)");
    return 0;
  }
  const size_t tl = p.tag_len ? p.tag_len : default_tag_len(p.mode);
  if (!valid_tag_len(p.mode, tl, p.lenient))
    throw UsageError("invalid tag length " + std::to_string(tl) + " for " + mode_name_upper(p.mode));
  return tl;
}

void check_block_input(const CipherParams& p, const Bytes& in) {
  if ((p.mode == Mode::ECB || p.mode == Mode::CBC) && !p.padding && in.size() % 16 != 0)
    throw UsageError("padding disabled but data length is not a multiple of 16");
  if (p.mode == Mode::XTS && in.size() < 16)
    throw UsageError("XTS needs at least 16 bytes of data");
}

Bytes run_nonaead(bool enc, const CipherParams& p, const Bytes& in) {
  check_block_input(p, in);
  const Pad pad = p.padding ? cp::StreamTransformationFilter::PKCS_PADDING
                            : cp::StreamTransformationFilter::NO_PADDING;
  const Pad dflt = cp::StreamTransformationFilter::DEFAULT_PADDING;
  switch (p.mode) {
    case Mode::ECB: return crypt_ecb(enc, p.key, in, pad);
    case Mode::CBC: return crypt_iv<cp::CBC_Mode<cp::AES> >(enc, p.key, p.iv, in, pad);
    case Mode::OFB: return crypt_iv<cp::OFB_Mode<cp::AES> >(enc, p.key, p.iv, in, dflt);
    case Mode::CFB: return crypt_iv<cp::CFB_Mode<cp::AES> >(enc, p.key, p.iv, in, dflt);
    case Mode::CTR: return crypt_iv<cp::CTR_Mode<cp::AES> >(enc, p.key, p.iv, in, dflt);
    case Mode::XTS: return crypt_iv<cp::XTS_Mode<cp::AES> >(enc, p.key, p.iv, in, dflt);
    default: break;
  }
  throw CryptoError("internal: not a non-AEAD mode");
}

void aead_enc(cp::AuthenticatedSymmetricCipher& e, const Bytes& aad, const Bytes& pt, int tl,
              Bytes& ct, Bytes& tag) {
  std::string out;
  cp::AuthenticatedEncryptionFilter f(e, new cp::StringSink(out), false, tl);
  if (!aad.empty()) f.ChannelPut(cp::AAD_CHANNEL, aad.data(), aad.size());
  f.ChannelMessageEnd(cp::AAD_CHANNEL);
  if (!pt.empty()) f.ChannelPut(cp::DEFAULT_CHANNEL, pt.data(), pt.size());
  f.ChannelMessageEnd(cp::DEFAULT_CHANNEL);
  if (out.size() != pt.size() + static_cast<size_t>(tl))
    throw CryptoError("internal: unexpected AEAD output size");
  ct.assign(out.begin(), out.begin() + static_cast<std::ptrdiff_t>(pt.size()));
  tag.assign(out.begin() + static_cast<std::ptrdiff_t>(pt.size()), out.end());
}

// Plaintext stays inside `out` until the tag is verified; on failure it is discarded.
Bytes aead_dec(cp::AuthenticatedSymmetricCipher& d, const Bytes& aad, const Bytes& ct,
               const Bytes& tag, int tl) {
  std::string out;
  cp::AuthenticatedDecryptionFilter f(d, new cp::StringSink(out),
                                      cp::AuthenticatedDecryptionFilter::DEFAULT_FLAGS, tl);
  if (!aad.empty()) f.ChannelPut(cp::AAD_CHANNEL, aad.data(), aad.size());
  f.ChannelMessageEnd(cp::AAD_CHANNEL);
  if (!ct.empty()) f.ChannelPut(cp::DEFAULT_CHANNEL, ct.data(), ct.size());
  f.ChannelPut(cp::DEFAULT_CHANNEL, tag.data(), tag.size());
  f.ChannelMessageEnd(cp::DEFAULT_CHANNEL);
  if (!f.GetLastResult()) {
    out.assign(out.size(), '\0');
    throw AuthError("authentication failed");
  }
  return Bytes(out.begin(), out.end());
}

template <int T>
void ccm_enc_t(const CipherParams& p, const Bytes& pt, EncResult& r) {
  typename cp::CCM<cp::AES, T>::Encryption e;
  e.SetKeyWithIV(p.key.data(), p.key.size(), p.iv.data(), p.iv.size());
  e.SpecifyDataLengths(p.aad.size(), pt.size(), 0);
  aead_enc(e, p.aad, pt, T, r.ct, r.tag);
}

template <int T>
Bytes ccm_dec_t(const CipherParams& p, const Bytes& ct, const Bytes& tag) {
  typename cp::CCM<cp::AES, T>::Decryption d;
  d.SetKeyWithIV(p.key.data(), p.key.size(), p.iv.data(), p.iv.size());
  d.SpecifyDataLengths(p.aad.size(), ct.size(), 0);
  return aead_dec(d, p.aad, ct, tag, T);
}

}  // namespace

// ---------------------------------------------------------------- mode info
const char* mode_name(Mode m) { return kNames[idx(m)]; }

std::string mode_name_upper(Mode m) {
  std::string s = mode_name(m);
  for (size_t i = 0; i < s.size(); ++i) s[i] = static_cast<char>(std::toupper(static_cast<unsigned char>(s[i])));
  return s;
}

bool parse_mode(const std::string& s, Mode& out) {
  std::string t;
  for (size_t i = 0; i < s.size(); ++i) t.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(s[i]))));
  for (size_t i = 0; i < 8; ++i)
    if (t == kNames[i]) {
      out = static_cast<Mode>(i + 1);
      return true;
    }
  return false;
}

bool is_aead(Mode m) { return m == Mode::CCM || m == Mode::GCM; }
bool uses_iv(Mode m) { return m != Mode::ECB; }

size_t default_iv_len(Mode m) {
  switch (m) {
    case Mode::ECB: return 0;
    case Mode::CCM:
    case Mode::GCM: return 12;
    default: return 16;
  }
}

size_t default_tag_len(Mode m) { return is_aead(m) ? 16 : 0; }

bool valid_key_len(Mode m, size_t n) {
  if (m == Mode::XTS) return n == 32 || n == 64;
  return n == 16 || n == 24 || n == 32;
}

bool valid_iv_len(Mode m, size_t n, bool lenient) {
  switch (m) {
    case Mode::ECB: return n == 0;
    case Mode::CCM: return n >= 7 && n <= 13;
    case Mode::GCM: return lenient ? (n >= 1 && n <= 1024) : n == 12;
    default: return n == 16;
  }
}

bool valid_tag_len(Mode m, size_t n, bool lenient) {
  if (m == Mode::GCM) return lenient ? (n >= 4 && n <= 16) : (n >= 12 && n <= 16);
  if (m == Mode::CCM) return n >= 4 && n <= 16 && n % 2 == 0;
  return n == 0;
}

std::string iv_requirement_text(Mode m) {
  switch (m) {
    case Mode::ECB: return "none - ECB takes no IV";
    case Mode::CCM: return "7 to 13 bytes (12 recommended)";
    case Mode::GCM: return "12 bytes";
    case Mode::XTS: return "16 bytes (tweak)";
    default: return "16 bytes";
  }
}

std::string algorithm_name(Mode m, size_t key_len) {
  const size_t bits = (m == Mode::XTS ? key_len / 2 : key_len) * 8;
  return "AES-" + std::to_string(bits) + "-" + mode_name_upper(m);
}

// ---------------------------------------------------------------- primitives
EncResult encrypt_raw(const CipherParams& p, const Bytes& pt) {
  const size_t tl = validate(p);
  EncResult r;
  try {
    if (!is_aead(p.mode)) {
      r.ct = run_nonaead(true, p, pt);
      return r;
    }
    if (p.mode == Mode::GCM) {
      cp::GCM<cp::AES>::Encryption e;
      e.SetKeyWithIV(p.key.data(), p.key.size(), p.iv.data(), p.iv.size());
      aead_enc(e, p.aad, pt, static_cast<int>(tl), r.ct, r.tag);
      return r;
    }
    switch (tl) {  // CCM: tag size is a compile-time parameter in Crypto++
      case 4: ccm_enc_t<4>(p, pt, r); break;
      case 6: ccm_enc_t<6>(p, pt, r); break;
      case 8: ccm_enc_t<8>(p, pt, r); break;
      case 10: ccm_enc_t<10>(p, pt, r); break;
      case 12: ccm_enc_t<12>(p, pt, r); break;
      case 14: ccm_enc_t<14>(p, pt, r); break;
      case 16: ccm_enc_t<16>(p, pt, r); break;
      default: throw UsageError("invalid CCM tag length");
    }
    return r;
  } catch (const cp::Exception& e) {
    throw CryptoError(std::string("encryption failed: ") + e.what());
  }
}

Bytes decrypt_raw(const CipherParams& p, const Bytes& ct, const Bytes& tag) {
  const size_t tl = validate(p);
  try {
    if (!is_aead(p.mode)) {
      if (!tag.empty()) throw FormatError("unexpected authentication tag for a non-AEAD mode");
      return run_nonaead(false, p, ct);
    }
    if (tag.size() != tl) throw FormatError("authentication tag has the wrong length");
    if (p.mode == Mode::GCM) {
      cp::GCM<cp::AES>::Decryption d;
      d.SetKeyWithIV(p.key.data(), p.key.size(), p.iv.data(), p.iv.size());
      return aead_dec(d, p.aad, ct, tag, static_cast<int>(tl));
    }
    switch (tl) {
      case 4: return ccm_dec_t<4>(p, ct, tag);
      case 6: return ccm_dec_t<6>(p, ct, tag);
      case 8: return ccm_dec_t<8>(p, ct, tag);
      case 10: return ccm_dec_t<10>(p, ct, tag);
      case 12: return ccm_dec_t<12>(p, ct, tag);
      case 14: return ccm_dec_t<14>(p, ct, tag);
      case 16: return ccm_dec_t<16>(p, ct, tag);
      default: throw UsageError("invalid CCM tag length");
    }
  } catch (const cp::HashVerificationFilter::HashVerificationFailed&) {
    throw AuthError("authentication failed: wrong key/nonce/AAD or the data or tag was modified");
  } catch (const cp::Exception& e) {
    throw CryptoError(std::string("decryption failed (wrong key/IV, bad padding or corrupted data): ") + e.what());
  }
}

// ---------------------------------------------------------------- helpers
Bytes random_bytes(size_t n) {
  Bytes b(n);
  if (n) {
    try {
      cp::AutoSeededRandomPool prng;
      prng.GenerateBlock(b.data(), n);
    } catch (const cp::Exception& e) {
      throw CryptoError(std::string("system RNG failure: ") + e.what());
    }
  }
  return b;
}

Bytes key_id(const Bytes& key) {
  static const char dom[] = "aestool-keyid-v1";
  cp::SHA256 h;
  h.Update(reinterpret_cast<const uint8_t*>(dom), sizeof(dom) - 1);
  if (!key.empty()) h.Update(key.data(), key.size());
  uint8_t digest[cp::SHA256::DIGESTSIZE];
  h.Final(digest);
  return Bytes(digest, digest + 8);
}

void secure_wipe(Bytes& b) {
  volatile uint8_t* p = b.data();
  for (size_t i = 0; i < b.size(); ++i) p[i] = 0;
  b.clear();
}

std::string crypto_library_version() {
  const int v = CRYPTOPP_VERSION;
  return std::to_string(v / 100) + "." + std::to_string((v / 10) % 10) + "." + std::to_string(v % 10);
}

bool hardware_aes_available() {
#if CRYPTOPP_BOOL_X86 || CRYPTOPP_BOOL_X32 || CRYPTOPP_BOOL_X64
  return cp::HasAESNI();
#elif CRYPTOPP_BOOL_ARM32 || CRYPTOPP_BOOL_ARMV8
  return cp::HasAES();
#else
  return false;
#endif
}

}  // namespace aescore
