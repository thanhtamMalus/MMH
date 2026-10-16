#include "kat.h"

#include <cstdio>
#include <iostream>
#include <map>
#include <stdexcept>

#include "aescore.h"
#include "minijson.h"
#include "util.h"

using namespace aescore;
using minijson::Value;

namespace {

struct Counter {
  int total = 0, pass = 0, fail = 0;
};

std::string get_s(const Value& t, const char* k, bool req) {
  const Value* v = t.get(k);
  if (!v) {
    if (req) throw std::runtime_error(std::string("missing field '") + k + "'");
    return std::string();
  }
  if (v->type != Value::String) throw std::runtime_error(std::string("field '") + k + "' must be a string");
  return v->s;
}

Bytes get_hex(const Value& t, const char* k, bool req) {
  const std::string s = get_s(t, k, req);
  Bytes b;
  if (!util::from_hex(s, b, true)) throw std::runtime_error(std::string("field '") + k + "' is not valid hex");
  return b;
}

// Throws std::runtime_error with the reason when the case fails.
void run_case(const Value& t, Mode mode) {
  CipherParams p;
  p.mode = mode;
  p.key = get_hex(t, "key", true);
  p.iv = t.get("iv") ? get_hex(t, "iv", true) : get_hex(t, "nonce", false);
  p.aad = get_hex(t, "aad", false);
  p.lenient = true;
  const Value* pv = t.get("padding");
  p.padding = pv && pv->type == Value::Bool && pv->b;   // NIST 38A vectors are unpadded
  const Bytes pt = get_hex(t, "plaintext", false);
  const Bytes ct = get_hex(t, "ciphertext", false);
  const Bytes tag = get_hex(t, "tag", false);
  if (is_aead(mode)) p.tag_len = tag.size();

  std::string expect = get_s(t, "expect", false);
  if (expect.empty()) expect = "pass";
  if (expect != "pass" && expect != "auth_fail") throw std::runtime_error("'expect' must be \"pass\" or \"auth_fail\"");

  if (expect == "auth_fail") {
    try {
      decrypt_raw(p, ct, tag);
    } catch (const AuthError&) {
      return;   // correct: rejected
    }
    throw std::runtime_error("expected authentication failure, but decryption succeeded");
  }

  const EncResult e = encrypt_raw(p, pt);
  if (e.ct != ct)
    throw std::runtime_error("ciphertext mismatch: expected " + util::to_hex(ct) + " got " + util::to_hex(e.ct));
  if (is_aead(mode) && e.tag != tag)
    throw std::runtime_error("tag mismatch: expected " + util::to_hex(tag) + " got " + util::to_hex(e.tag));
  const Bytes d = decrypt_raw(p, ct, tag);
  if (d != pt) throw std::runtime_error("decryption mismatch: got " + util::to_hex(d));
}

}  // namespace

int run_kat(const std::string& path, bool verbose) {
  Bytes raw;
  std::string err;
  if (!util::read_file(path, raw, err, 64u << 20)) {
    std::cerr << "KAT: " << err << "\n";
    return 1;
  }
  Value root;
  if (!minijson::parse(util::to_string(raw), root, err)) {
    std::cerr << "KAT: cannot parse " << path << ": " << err << "\n";
    return 1;
  }
  const Value* list = nullptr;
  if (root.type == Value::Array) list = &root;
  else if (root.type == Value::Object) list = root.get("tests");
  if (!list || list->type != Value::Array || list->arr.empty()) {
    std::cerr << "KAT: file must contain a non-empty \"tests\" array\n";
    return 1;
  }

  std::map<std::string, Counter> per_mode;
  Counter all;
  int idx = 0;
  for (const Value& t : list->arr) {
    ++idx;
    std::string name = "case#" + std::to_string(idx);
    std::string mode_label = "?";
    std::string reason;
    bool ok = false;
    try {
      if (t.type != Value::Object) throw std::runtime_error("test case must be an object");
      const std::string n = get_s(t, "name", false);
      if (!n.empty()) name = n;
      const std::string ms = get_s(t, "mode", true);
      Mode mode;
      if (!parse_mode(ms, mode)) throw std::runtime_error("unknown mode '" + ms + "'");
      mode_label = mode_name(mode);
      run_case(t, mode);
      ok = true;
    } catch (const std::exception& e) {   // malformed case => FAIL, never a crash
      reason = e.what();
    }
    Counter& c = per_mode[mode_label];
    ++c.total;
    ++all.total;
    if (ok) {
      ++c.pass;
      ++all.pass;
      std::cout << "[PASS] " << name << " (" << mode_label << ")\n";
    } else {
      ++c.fail;
      ++all.fail;
      std::cout << "[FAIL] " << name << " (" << mode_label << "): " << reason << "\n";
    }
    if (verbose && ok) std::cout << "       ok\n";
  }

  std::cout << "\n==== KAT summary ====\n";
  std::printf("%-8s %7s %7s %7s\n", "Mode", "Total", "Pass", "Fail");
  for (const auto& kv : per_mode)
    std::printf("%-8s %7d %7d %7d\n", kv.first.c_str(), kv.second.total, kv.second.pass, kv.second.fail);
  std::printf("%-8s %7d %7d %7d\n", "TOTAL", all.total, all.pass, all.fail);
  std::cout << (all.fail == 0 ? "RESULT: ALL PASS\n" : "RESULT: FAILURES PRESENT\n");
  return all.fail == 0 ? 0 : 1;
}
