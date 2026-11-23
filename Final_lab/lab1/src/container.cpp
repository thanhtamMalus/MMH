#include "container.h"

#include <cstring>
#include <sstream>

#include "minijson.h"
#include "util.h"

using namespace aescore;

namespace container {
namespace {

const uint8_t kMagic[4] = {'A', 'E', 'S', 'T'};
const uint8_t kVersion = 1;

void put_u32(Bytes& o, uint32_t v) {
  for (int i = 3; i >= 0; --i) o.push_back(static_cast<uint8_t>(v >> (8 * i)));
}
void put_u64(Bytes& o, uint64_t v) {
  for (int i = 7; i >= 0; --i) o.push_back(static_cast<uint8_t>(v >> (8 * i)));
}
uint32_t get_u32(const Bytes& d, size_t pos) {
  uint32_t v = 0;
  for (int i = 0; i < 4; ++i) v = (v << 8) | d[pos + static_cast<size_t>(i)];
  return v;
}
uint64_t get_u64(const Bytes& d, size_t pos) {
  uint64_t v = 0;
  for (int i = 0; i < 8; ++i) v = (v << 8) | d[pos + static_cast<size_t>(i)];
  return v;
}

}  // namespace

Bytes pack(const Header& h, const Bytes& ct) {
  if (h.iv.size() > 255 || h.tag.size() > 16 || h.aad.size() > 0xFFFFFFFFull)
    throw CryptoError("header field too large");
  Bytes o;
  o.reserve(32 + h.iv.size() + h.aad.size() + h.tag.size() + ct.size());
  o.insert(o.end(), kMagic, kMagic + 4);
  o.push_back(kVersion);
  o.push_back(static_cast<uint8_t>(h.mode));
  o.push_back(h.key_len);
  o.push_back(is_aead(h.mode) ? 1 : 0);
  Bytes kid = h.key_id;
  kid.resize(8, 0);
  o.insert(o.end(), kid.begin(), kid.end());
  o.push_back(static_cast<uint8_t>(h.iv.size()));
  o.insert(o.end(), h.iv.begin(), h.iv.end());
  put_u32(o, static_cast<uint32_t>(h.aad.size()));
  o.insert(o.end(), h.aad.begin(), h.aad.end());
  o.push_back(static_cast<uint8_t>(h.tag.size()));
  o.insert(o.end(), h.tag.begin(), h.tag.end());
  put_u64(o, ct.size());
  o.insert(o.end(), ct.begin(), ct.end());
  return o;
}

bool parse_header_prefix(const Bytes& d, Header& h, size_t& header_len, uint64_t& ct_len, std::string& err) {
  size_t pos = 0;
  auto need = [&](size_t n) { return d.size() - pos >= n; };
  Header t;
  if (d.size() < 4 + 1 + 1 + 1 + 1 + 8 + 1) { err = "file too short for an aestool header"; return false; }
  if (std::memcmp(d.data(), kMagic, 4) != 0) { err = "bad magic: not an aestool ciphertext"; return false; }
  pos = 4;
  if (d[pos++] != kVersion) { err = "unsupported container version"; return false; }
  const uint8_t m = d[pos++];
  if (m < 1 || m > 8) { err = "unknown mode id in header"; return false; }
  t.mode = static_cast<Mode>(m);
  t.key_len = d[pos++];
  const uint8_t flags = d[pos++];
  if ((flags & ~1u) != 0) { err = "unknown flags in header"; return false; }
  if (((flags & 1) != 0) != is_aead(t.mode)) { err = "AEAD flag does not match mode"; return false; }
  if (!valid_key_len(t.mode, t.key_len)) { err = "invalid key length recorded in header"; return false; }
  t.key_id.assign(d.begin() + static_cast<std::ptrdiff_t>(pos), d.begin() + static_cast<std::ptrdiff_t>(pos + 8));
  pos += 8;
  const size_t ivl = d[pos++];
  if (!need(ivl)) { err = "truncated IV"; return false; }
  if (!valid_iv_len(t.mode, ivl, false)) { err = "invalid IV/nonce length in header"; return false; }
  t.iv.assign(d.begin() + static_cast<std::ptrdiff_t>(pos), d.begin() + static_cast<std::ptrdiff_t>(pos + ivl));
  pos += ivl;
  if (!need(4)) { err = "truncated header"; return false; }
  const size_t aadl = get_u32(d, pos);
  pos += 4;
  if (!need(aadl)) { err = "truncated AAD"; return false; }
  if (!is_aead(t.mode) && aadl != 0) { err = "AAD present for a non-AEAD mode"; return false; }
  t.aad.assign(d.begin() + static_cast<std::ptrdiff_t>(pos), d.begin() + static_cast<std::ptrdiff_t>(pos + aadl));
  pos += aadl;
  if (!need(1)) { err = "truncated header"; return false; }
  const size_t tl = d[pos++];
  if (is_aead(t.mode)) {
    if (!valid_tag_len(t.mode, tl, false)) { err = "invalid tag length in header"; return false; }
  } else if (tl != 0) {
    err = "tag present for a non-AEAD mode";
    return false;
  }
  if (!need(tl)) { err = "truncated tag"; return false; }
  t.tag.assign(d.begin() + static_cast<std::ptrdiff_t>(pos), d.begin() + static_cast<std::ptrdiff_t>(pos + tl));
  pos += tl;
  if (!need(8)) { err = "truncated header"; return false; }
  ct_len = get_u64(d, pos);
  pos += 8;
  h = t;
  header_len = pos;
  return true;
}

bool parse(const Bytes& d, Parsed& out, std::string& err) {
  size_t pos = 0;
  uint64_t ctl = 0;
  Header h;
  if (!parse_header_prefix(d, h, pos, ctl, err)) return false;
  if (ctl != static_cast<uint64_t>(d.size() - pos)) {
    err = "ciphertext length field does not match file size (truncated file or trailing data)";
    return false;
  }
  out.h = h;
  out.ct_offset = pos;
  out.ct_len = static_cast<size_t>(ctl);
  return true;
}

std::string make_sidecar_json(const Header& h) {
  std::ostringstream o;
  o << "{\n"
    << "  \"format\": \"aestool-sidecar-v1\",\n"
    << "  \"alg\": \"" << algorithm_name(h.mode, h.key_len) << "\",\n"
    << "  \"mode\": \"" << mode_name(h.mode) << "\",\n"
    << "  \"key_len\": " << static_cast<int>(h.key_len) << ",\n"
    << "  \"keyid\": \"" << util::to_hex(h.key_id) << "\",\n"
    << "  \"iv\": \"" << util::to_hex(h.iv) << "\",\n"
    << "  \"aad\": \"" << util::to_hex(h.aad) << "\",\n"
    << "  \"tag\": \"" << util::to_hex(h.tag) << "\"\n"
    << "}\n";
  return o.str();
}

bool parse_sidecar_json(const std::string& text, Header& h, std::string& err) {
  minijson::Value root;
  if (!minijson::parse(text, root, err)) return false;
  if (root.type != minijson::Value::Object) { err = "sidecar root must be a JSON object"; return false; }

  auto str = [&](const char* k, bool req, std::string& out) -> bool {
    const minijson::Value* v = root.get(k);
    if (!v) {
      if (req) { err = std::string("missing field '") + k + "'"; return false; }
      out.clear();
      return true;
    }
    if (v->type != minijson::Value::String) { err = std::string("field '") + k + "' must be a string"; return false; }
    out = v->s;
    return true;
  };

  std::string mode_s, iv_s, aad_s, tag_s, kid_s;
  if (!str("mode", true, mode_s) || !str("iv", true, iv_s) || !str("aad", false, aad_s) ||
      !str("tag", false, tag_s) || !str("keyid", false, kid_s))
    return false;

  Header t;
  if (!parse_mode(mode_s, t.mode)) { err = "unknown mode '" + mode_s + "'"; return false; }
  if (!util::from_hex(iv_s, t.iv, true)) { err = "iv is not valid hex"; return false; }
  if (!util::from_hex(aad_s, t.aad, true)) { err = "aad is not valid hex"; return false; }
  if (!util::from_hex(tag_s, t.tag, true)) { err = "tag is not valid hex"; return false; }
  if (!util::from_hex(kid_s, t.key_id, true)) { err = "keyid is not valid hex"; return false; }
  if (!t.key_id.empty() && t.key_id.size() != 8) { err = "keyid must be 8 bytes"; return false; }
  const minijson::Value* kl = root.get("key_len");
  if (kl && kl->type == minijson::Value::Number) {
    if (kl->n < 16 || kl->n > 64) { err = "key_len out of range"; return false; }
    t.key_len = static_cast<uint8_t>(kl->n);
  }
  if (!valid_iv_len(t.mode, t.iv.size(), false)) { err = "invalid IV/nonce length for mode"; return false; }
  if (is_aead(t.mode)) {
    if (!valid_tag_len(t.mode, t.tag.size(), false)) { err = "missing or invalid authentication tag"; return false; }
  } else if (!t.tag.empty() || !t.aad.empty()) {
    err = "tag/aad not allowed for a non-AEAD mode";
    return false;
  }
  h = t;
  return true;
}

}  // namespace container
