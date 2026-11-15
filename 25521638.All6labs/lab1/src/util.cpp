#include "util.h"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>

namespace fs = std::filesystem;

namespace util {
namespace {

fs::path P(const std::string& s) { return fs::u8path(s); }

int hv(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

int b64val(char c) {
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  if (c == '+') return 62;
  if (c == '/') return 63;
  return -1;
}

std::string strip_ws(const std::string& s, bool allow) {
  if (!allow) return s;
  std::string t;
  t.reserve(s.size());
  for (size_t i = 0; i < s.size(); ++i)
    if (!std::isspace(static_cast<unsigned char>(s[i]))) t.push_back(s[i]);
  return t;
}

}  // namespace

std::string to_hex(const uint8_t* d, size_t n) {
  static const char* k = "0123456789abcdef";
  std::string s;
  s.reserve(n * 2);
  for (size_t i = 0; i < n; ++i) {
    s.push_back(k[d[i] >> 4]);
    s.push_back(k[d[i] & 15]);
  }
  return s;
}

bool from_hex(const std::string& s, Bytes& out, bool allow_ws) {
  const std::string t = strip_ws(s, allow_ws);
  if (t.size() % 2 != 0) return false;
  Bytes r;
  r.reserve(t.size() / 2);
  for (size_t i = 0; i < t.size(); i += 2) {
    const int a = hv(t[i]), b = hv(t[i + 1]);
    if (a < 0 || b < 0) return false;
    r.push_back(static_cast<uint8_t>((a << 4) | b));
  }
  out.swap(r);
  return true;
}

std::string to_base64(const Bytes& d) {
  static const char* T = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string o;
  o.reserve((d.size() + 2) / 3 * 4);
  size_t i = 0;
  for (; i + 3 <= d.size(); i += 3) {
    const uint32_t x = (uint32_t(d[i]) << 16) | (uint32_t(d[i + 1]) << 8) | d[i + 2];
    o.push_back(T[(x >> 18) & 63]);
    o.push_back(T[(x >> 12) & 63]);
    o.push_back(T[(x >> 6) & 63]);
    o.push_back(T[x & 63]);
  }
  const size_t rem = d.size() - i;
  if (rem == 1) {
    const uint32_t x = uint32_t(d[i]) << 16;
    o.push_back(T[(x >> 18) & 63]);
    o.push_back(T[(x >> 12) & 63]);
    o += "==";
  } else if (rem == 2) {
    const uint32_t x = (uint32_t(d[i]) << 16) | (uint32_t(d[i + 1]) << 8);
    o.push_back(T[(x >> 18) & 63]);
    o.push_back(T[(x >> 12) & 63]);
    o.push_back(T[(x >> 6) & 63]);
    o.push_back('=');
  }
  return o;
}

bool from_base64(const std::string& s, Bytes& out, bool allow_ws) {
  const std::string t = strip_ws(s, allow_ws);
  const size_t n = t.size();
  if (n % 4 != 0) return false;
  Bytes r;
  r.reserve(n / 4 * 3);
  for (size_t i = 0; i < n; i += 4) {
    int v[4];
    int pad = 0;
    for (int j = 0; j < 4; ++j) {
      const char c = t[i + j];
      if (c == '=') {
        if (i + 4 != n || j < 2) return false;
        v[j] = 0;
        ++pad;
      } else {
        if (pad) return false;
        const int d = b64val(c);
        if (d < 0) return false;
        v[j] = d;
      }
    }
    const uint32_t x = (uint32_t(v[0]) << 18) | (uint32_t(v[1]) << 12) | (uint32_t(v[2]) << 6) | uint32_t(v[3]);
    r.push_back(static_cast<uint8_t>(x >> 16));
    if (pad < 2) r.push_back(static_cast<uint8_t>((x >> 8) & 255));
    if (pad < 1) r.push_back(static_cast<uint8_t>(x & 255));
  }
  out.swap(r);
  return true;
}

bool is_valid_utf8(const Bytes& b) {
  size_t i = 0;
  const size_t n = b.size();
  while (i < n) {
    const uint8_t c = b[i];
    if (c < 0x80) {
      ++i;
      continue;
    }
    size_t len;
    uint32_t cp;
    if ((c & 0xE0) == 0xC0) { len = 2; cp = c & 0x1F; }
    else if ((c & 0xF0) == 0xE0) { len = 3; cp = c & 0x0F; }
    else if ((c & 0xF8) == 0xF0) { len = 4; cp = c & 0x07; }
    else return false;
    if (i + len > n) return false;
    for (size_t k = 1; k < len; ++k) {
      if ((b[i + k] & 0xC0) != 0x80) return false;
      cp = (cp << 6) | (b[i + k] & 0x3F);
    }
    if ((len == 2 && cp < 0x80) || (len == 3 && cp < 0x800) || (len == 4 && cp < 0x10000)) return false;
    if (cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) return false;
    i += len;
  }
  return true;
}

bool file_exists(const std::string& path) {
  std::error_code ec;
  return fs::exists(P(path), ec);
}

bool read_file_prefix(const std::string& path, Bytes& out, std::string& err, size_t max_bytes) {
  std::error_code ec;
  const fs::path p = P(path);
  if (!fs::exists(p, ec)) { err = "file not found: " + path; return false; }
  if (!fs::is_regular_file(p, ec)) { err = "not a regular file: " + path; return false; }
  const uint64_t sz = fs::file_size(p, ec);
  if (ec) { err = "cannot get size of " + path; return false; }
  const size_t n = static_cast<size_t>(std::min<uint64_t>(sz, max_bytes));
  std::ifstream f(p, std::ios::binary);
  if (!f) { err = "cannot open " + path; return false; }
  Bytes b(n);
  if (n) {
    f.read(reinterpret_cast<char*>(b.data()), static_cast<std::streamsize>(n));
    if (static_cast<size_t>(f.gcount()) != n) { err = "read error on " + path; return false; }
  }
  out.swap(b);
  return true;
}

bool read_file(const std::string& path, Bytes& out, std::string& err, uint64_t max_bytes) {
  std::error_code ec;
  const fs::path p = P(path);
  if (!fs::exists(p, ec)) { err = "file not found: " + path; return false; }
  if (!fs::is_regular_file(p, ec)) { err = "not a regular file: " + path; return false; }
  const uint64_t sz = fs::file_size(p, ec);
  if (ec) { err = "cannot get size of " + path; return false; }
  if (sz > max_bytes) {
    err = "file too large (" + std::to_string(sz) + " bytes, limit " + std::to_string(max_bytes) + "): " + path;
    return false;
  }
  return read_file_prefix(path, out, err, static_cast<size_t>(sz));
}

bool write_file_atomic(const std::string& path, const Bytes& data, std::string& err, bool secret) {
  const fs::path p = P(path);
  const fs::path tmp = P(path + ".aestool.tmp");
  {
    std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
    if (!f) { err = "cannot create output file: " + path; return false; }
#ifndef _WIN32
    if (secret) {
      std::error_code pe;
      fs::permissions(tmp, fs::perms::owner_read | fs::perms::owner_write, fs::perm_options::replace, pe);
    }
#else
    (void)secret;
#endif
    if (!data.empty()) f.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    f.flush();
    if (!f) {
      f.close();
      std::error_code re;
      fs::remove(tmp, re);
      err = "write error on " + path;
      return false;
    }
  }
  std::error_code ec;
  fs::remove(p, ec);
  ec.clear();
  fs::rename(tmp, p, ec);
  if (ec) {
    std::error_code re;
    fs::remove(tmp, re);
    err = "cannot replace output file " + path + ": " + ec.message();
    return false;
  }
  return true;
}

bool append_file(const std::string& path, const std::string& text, std::string& err) {
  std::ofstream f(P(path), std::ios::binary | std::ios::app);
  if (!f) { err = "cannot open " + path + " for append"; return false; }
  f.write(text.data(), static_cast<std::streamsize>(text.size()));
  f.flush();
  if (!f) { err = "write error on " + path; return false; }
  return true;
}

Bytes read_blob_file(const std::string& path, const char* what) {
  Bytes raw;
  std::string err;
  if (!read_file(path, raw, err, 1u << 20)) throw aescore::UsageError(std::string(what) + ": " + err);
  size_t off = 0;
  if (raw.size() >= 3 && raw[0] == 0xEF && raw[1] == 0xBB && raw[2] == 0xBF) off = 3;
  static const std::string hdr = "AESTOOL-HEX";
  if (raw.size() - off >= hdr.size() && std::equal(hdr.begin(), hdr.end(), raw.begin() + static_cast<std::ptrdiff_t>(off))) {
    std::string text(raw.begin() + static_cast<std::ptrdiff_t>(off + hdr.size()), raw.end());
    aescore::secure_wipe(raw);
    const size_t nl = text.find('\n');
    text = (nl == std::string::npos) ? std::string() : text.substr(nl + 1);
    Bytes out;
    if (!from_hex(text, out, true)) throw aescore::UsageError(std::string(what) + ": invalid hex body after AESTOOL-HEX header");
    return out;
  }
  return raw;
}

Bytes parse_blob_arg(const std::string& value, const char* what) {
  std::error_code ec;
  if (fs::is_regular_file(P(value), ec)) return read_blob_file(value, what);
  Bytes b;
  if (from_hex(value, b, false)) return b;
  throw aescore::UsageError(std::string(what) + ": '" + value + "' is neither a readable file nor a valid hex string");
}

}  // namespace util
