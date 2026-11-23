#include "ops.h"

#include <sstream>

#include "container.h"
#include "util.h"

namespace aescore {
namespace {

bool tracks_nonce(Mode m) { return m == Mode::CTR || m == Mode::CCM || m == Mode::GCM; }

bool same_pair(const container::Header& h, const Bytes& kid, const Bytes& iv) {
  if (h.iv != iv) return false;
  if (h.key_id.empty()) return true;   // unknown key id: be conservative, compare nonce only
  return h.key_id == kid;
}

}  // namespace

const char* ecb_warning_text() {
  return "ECB mode is NOT secure: identical plaintext blocks produce identical ciphertext blocks "
         "and there is no integrity protection. Prefer GCM or CCM.";
}

void check_ecb_policy(size_t size, bool allow) {
  if (size > kEcbMaxBytes && !allow)
    throw UsageError("ECB refused: data is " + std::to_string(size) +
                     " bytes, above the default 16 KiB limit. Use --allow-ecb only if you really must.");
}

bool nonce_reused(Mode mode, const Bytes& kid, const Bytes& iv, const std::string& out_path,
                  const std::string& sidecar_path, const std::string& ledger_path, std::string* where) {
  if (!tracks_nonce(mode)) return false;
  std::string err;

  // 1) header of an existing output file
  if (!out_path.empty() && util::file_exists(out_path)) {
    Bytes prefix;
    if (util::read_file_prefix(out_path, prefix, err, 1u << 20)) {
      container::Header h;
      size_t hl = 0;
      uint64_t cl = 0;
      std::string e2;
      if (container::parse_header_prefix(prefix, h, hl, cl, e2) && same_pair(h, kid, iv)) {
        if (where) *where = "same key + nonce found in the header of existing output file '" + out_path + "'";
        return true;
      }
    }
  }

  // 2) existing sidecar JSON
  if (!sidecar_path.empty() && util::file_exists(sidecar_path)) {
    Bytes js;
    if (util::read_file(sidecar_path, js, err, 1u << 20)) {
      container::Header h;
      if (container::parse_sidecar_json(util::to_string(js), h, err) && same_pair(h, kid, iv)) {
        if (where) *where = "same key + nonce found in existing sidecar '" + sidecar_path + "'";
        return true;
      }
    }
  }

  // 3) ledger: one line per use, "<keyid-hex> <nonce-hex>"
  if (!ledger_path.empty() && util::file_exists(ledger_path)) {
    Bytes lb;
    if (!util::read_file(ledger_path, lb, err, 64u << 20))
      throw CryptoError("cannot read nonce ledger (failing closed): " + err);
    const std::string needle = util::to_hex(kid) + " " + util::to_hex(iv);
    std::istringstream in(util::to_string(lb));
    std::string line;
    while (std::getline(in, line)) {
      while (!line.empty() && (line.back() == '\r' || line.back() == ' ')) line.pop_back();
      if (line == needle) {
        if (where) *where = "same key + nonce recorded in ledger '" + ledger_path + "'";
        return true;
      }
    }
  }
  return false;
}

EncryptResult encrypt_buffer(const EncryptOptions& o, const Bytes& pt) {
  EncryptResult r;

  if (o.mode == Mode::ECB) {
    if (o.has_iv) throw UsageError("ECB does not use an IV/nonce");
    check_ecb_policy(pt.size(), o.allow_ecb);
  }
  if (!is_aead(o.mode) && !o.aad.empty()) throw UsageError("AAD is only supported by AEAD modes (ccm, gcm)");
  if (!valid_key_len(o.mode, o.key.size()))
    throw UsageError("invalid key length " + std::to_string(o.key.size()) + " bytes for " + mode_name_upper(o.mode) +
                     (o.mode == Mode::XTS ? " (expected 32 or 64)" : " (expected 16, 24 or 32)"));

  const bool track = tracks_nonce(o.mode);
  const Bytes kid = key_id(o.key);
  Bytes iv;

  if (uses_iv(o.mode)) {
    if (o.has_iv) {
      iv = o.iv;
      if (!valid_iv_len(o.mode, iv.size(), false))
        throw UsageError("invalid IV/nonce length " + std::to_string(iv.size()) + " bytes for " +
                         mode_name_upper(o.mode) + " (expected " + iv_requirement_text(o.mode) + ")");
      std::string where;
      if (track && nonce_reused(o.mode, kid, iv, o.out_path, o.sidecar_path, o.ledger_path, &where))
        throw UsageError("NONCE REUSE REFUSED: " + where + ". Reusing a nonce with the same key breaks " +
                         mode_name_upper(o.mode) + ". Omit --nonce to generate a fresh random one.");
    } else {
      r.iv_generated = true;
      for (int attempt = 0;; ++attempt) {
        iv = random_bytes(default_iv_len(o.mode));
        if (!track || !nonce_reused(o.mode, kid, iv, o.out_path, o.sidecar_path, o.ledger_path, nullptr)) break;
        if (attempt >= 8) throw CryptoError("could not generate a fresh nonce");
      }
    }
  }

  CipherParams p;
  p.mode = o.mode;
  p.key = o.key;
  p.iv = iv;
  p.aad = o.aad;
  p.tag_len = o.tag_len;
  EncResult e = encrypt_raw(p, pt);

  container::Header h;
  h.mode = o.mode;
  h.key_len = static_cast<uint8_t>(o.key.size());
  h.key_id = kid;
  h.iv = iv;
  h.aad = o.aad;
  h.tag = e.tag;

  if (!o.sidecar_path.empty()) {
    r.output = e.ct;
    r.sidecar = container::make_sidecar_json(h);
  } else {
    r.output = container::pack(h, e.ct);
  }
  r.iv = iv;
  r.tag = e.tag;
  r.alg = algorithm_name(o.mode, o.key.size());

  if (track && !o.ledger_path.empty()) {
    std::string err;
    if (!util::append_file(o.ledger_path, util::to_hex(kid) + " " + util::to_hex(iv) + "\n", err))
      throw CryptoError("cannot update nonce ledger: " + err);
  }
  return r;
}

DecryptResult decrypt_buffer(const DecryptOptions& o, const Bytes& in) {
  DecryptResult r;
  container::Header h;
  Bytes ct;
  std::string err;

  if (o.sidecar_mode) {
    if (!container::parse_sidecar_json(o.sidecar_json, h, err)) throw FormatError("bad sidecar: " + err);
    ct = in;
  } else {
    container::Parsed ps;
    if (!container::parse(in, ps, err)) throw FormatError("malformed ciphertext file: " + err);
    h = ps.h;
    ct.assign(in.begin() + static_cast<std::ptrdiff_t>(ps.ct_offset), in.end());
  }

  const Mode mode = h.mode;
  if (o.has_mode && o.mode != mode)
    throw UsageError(std::string("--mode ") + mode_name(o.mode) + " does not match the file (" + mode_name(mode) + ")");
  if (h.key_len != 0 && h.key_len != o.key.size())
    throw UsageError("key length (" + std::to_string(o.key.size()) + " bytes) does not match the file (" +
                     std::to_string(h.key_len) + " bytes)");
  if (mode == Mode::ECB) check_ecb_policy(ct.size(), o.allow_ecb);

  Bytes iv = h.iv;
  if (o.has_iv) {
    if (!o.has_iv || o.iv != h.iv) r.warnings.push_back("IV/nonce from the command line overrides the one stored in the file");
    iv = o.iv;
  }
  if (!valid_iv_len(mode, iv.size(), false))
    throw UsageError("invalid IV/nonce length " + std::to_string(iv.size()) + " bytes for " + mode_name_upper(mode) +
                     " (expected " + iv_requirement_text(mode) + ")");

  Bytes aad = h.aad;
  if (o.has_aad) {
    if (!is_aead(mode)) throw UsageError("AAD given for a non-AEAD mode");
    if (o.aad != h.aad) r.warnings.push_back("AAD from the command line overrides the one stored in the file");
    aad = o.aad;
  }

  CipherParams p;
  p.mode = mode;
  p.key = o.key;
  p.iv = iv;
  p.aad = aad;
  p.tag_len = h.tag.size();
  r.plaintext = decrypt_raw(p, ct, h.tag);   // throws on any failure: nothing is returned
  r.alg = algorithm_name(mode, o.key.size());
  return r;
}

}  // namespace aescore
