// aestool - AES command line tool (Lab 1) built on Crypto++ via the aescore library.
#include <cctype>
#include <cstdio>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <vector>

#include "aescore.h"
#include "bench.h"
#include "kat.h"
#include "ops.h"
#include "util.h"

#ifdef _WIN32
#include <windows.h>
#include <shellapi.h>
#include <fcntl.h>
#include <io.h>
#endif

using namespace aescore;

namespace {

struct CliError : std::runtime_error {
  using std::runtime_error::runtime_error;
};

const char* kUsage =
    "aestool - AES encryption tool (Crypto++), modes: ecb cbc ofb cfb ctr xts ccm gcm\n"
    "\n"
    "Usage:\n"
    "  aestool encrypt --mode MODE (--key FILE | --key-hex HEX) (--in FILE | --text STR) [--out FILE]\n"
    "                  [--iv FILE|HEX | --nonce FILE|HEX] [--aad FILE | --aad-text STR] [--aead]\n"
    "                  [--tag-len N] [--encode hex|base64|raw] [--sidecar FILE.json] [--ledger FILE]\n"
    "                  [--allow-ecb] [--verbose]\n"
    "  aestool decrypt [--mode MODE] (--key FILE | --key-hex HEX) (--in FILE | --text ENCODED) [--out FILE]\n"
    "                  [--iv ..] [--nonce ..] [--aad ..] [--encode hex|base64] [--sidecar FILE.json]\n"
    "                  [--allow-ecb] [--verbose]\n"
    "  aestool keygen  [--bits 128|192|256|512] [--format raw|hex] [--out FILE] [--force]\n"
    "  aestool --kat vectors.json [--verbose]\n"
    "  aestool bench   [--modes gcm,ctr,...] [--sizes 1k,4k,16k,256k,1m,8m] [--runs 1000] [--warmup 1.0]\n"
    "                  [--bits 256] [--dir enc|dec|both] [--with-io] [--csv FILE] [--quick]\n"
    "  aestool version | help\n"
    "\n"
    "Key/IV/AAD files: raw binary, or text with first line 'AESTOOL-HEX' followed by hex digits.\n"
    "CCM and GCM always authenticate (--aead is accepted as an explicit assertion).\n"
    "Exit codes: 0 ok, 1 error, 2 usage/refused misuse, 3 crypto failure (auth/format) - fail closed.\n";

const std::set<std::string> kFlags = {"aead", "allow-ecb", "verbose", "help", "version",
                                      "quick", "with-io", "force"};
const std::set<std::string> kValues = {"mode", "key", "key-hex", "in", "text", "out", "iv", "iv-hex",
                                       "nonce", "nonce-hex", "aad", "aad-text", "encode", "sidecar",
                                       "ledger", "tag-len", "threads", "kat", "bits", "format", "sizes",
                                       "modes", "runs", "warmup", "batch-mb", "max-ops", "csv", "dir", "tmpdir"};

struct Args {
  std::string command;
  std::map<std::string, std::string> kv;
  std::set<std::string> flags;
  bool has(const std::string& k) const { return kv.count(k) != 0; }
  bool flag(const std::string& k) const { return flags.count(k) != 0; }
  std::string get(const std::string& k, const std::string& d = std::string()) const {
    auto it = kv.find(k);
    return it == kv.end() ? d : it->second;
  }
};

struct KeyGuard {
  Bytes& b;
  explicit KeyGuard(Bytes& x) : b(x) {}
  ~KeyGuard() { secure_wipe(b); }
};

Args parse_args(const std::vector<std::string>& v) {
  Args a;
  size_t i = 1;
  if (v.size() > 1 && v[1].compare(0, 2, "--") != 0 && v[1] != "-h") {
    a.command = v[1];
    i = 2;
  }
  for (; i < v.size(); ++i) {
    std::string tok = v[i];
    if (tok == "-h") tok = "--help";
    if (tok.compare(0, 2, "--") != 0) throw CliError("unexpected argument: " + tok);
    std::string name = tok.substr(2), val;
    bool has_eq = false;
    const size_t eq = name.find('=');
    if (eq != std::string::npos) {
      val = name.substr(eq + 1);
      name = name.substr(0, eq);
      has_eq = true;
    }
    if (kFlags.count(name)) {
      if (has_eq) throw CliError("--" + name + " does not take a value");
      a.flags.insert(name);
    } else if (kValues.count(name)) {
      if (!has_eq) {
        if (i + 1 >= v.size()) throw CliError("--" + name + " needs a value");
        val = v[++i];
      }
      if (a.kv.count(name)) throw CliError("--" + name + " given more than once");
      a.kv[name] = val;
    } else {
      throw CliError("unknown option --" + name);
    }
  }
  return a;
}

size_t parse_size(const std::string& s, const std::string& what) {
  if (s.empty() || s.find_first_not_of("0123456789") != std::string::npos || s.size() > 18)
    throw CliError(what + " must be a non-negative integer");
  return static_cast<size_t>(std::stoull(s));
}

double parse_double(const std::string& s, const std::string& what) {
  try {
    size_t pos = 0;
    const double d = std::stod(s, &pos);
    if (pos != s.size() || d < 0) throw std::invalid_argument("x");
    return d;
  } catch (const std::exception&) {
    throw CliError(what + " must be a non-negative number");
  }
}

std::vector<std::string> split(const std::string& s, char d) {
  std::vector<std::string> r;
  std::string cur;
  for (char c : s) {
    if (c == d) {
      r.push_back(cur);
      cur.clear();
    } else cur.push_back(c);
  }
  r.push_back(cur);
  return r;
}

size_t parse_size_token(std::string t) {
  if (t.empty()) throw CliError("empty size in --sizes");
  size_t mult = 1;
  const char suf = static_cast<char>(std::tolower(static_cast<unsigned char>(t.back())));
  if (suf == 'k') { mult = 1024; t.pop_back(); }
  else if (suf == 'm') { mult = 1024 * 1024; t.pop_back(); }
  const size_t n = parse_size(t, "--sizes") * mult;
  if (n == 0) throw CliError("size must be > 0");
  return n;
}

Mode need_mode(const Args& a) {
  if (!a.has("mode")) throw CliError("--mode is required (ecb|cbc|ofb|cfb|ctr|xts|ccm|gcm)");
  Mode m;
  if (!parse_mode(a.get("mode"), m)) throw CliError("unknown mode '" + a.get("mode") + "'");
  return m;
}

Bytes load_key(const Args& a) {
  const bool k = a.has("key"), kh = a.has("key-hex");
  if (k == kh) throw CliError("exactly one of --key FILE or --key-hex HEX is required");
  if (kh) {
    Bytes b;
    if (!util::from_hex(a.get("key-hex"), b, false)) throw CliError("--key-hex is not valid hex");
    std::cerr << "NOTE: --key-hex exposes the key in shell history and the process list; prefer --key FILE.\n";
    return b;
  }
  return util::read_blob_file(a.get("key"), "key file");
}

bool pick_iv(const Args& a, Bytes& iv) {
  static const char* names[] = {"iv", "iv-hex", "nonce", "nonce-hex"};
  int cnt = 0;
  std::string chosen;
  for (const char* n : names)
    if (a.has(n)) { ++cnt; chosen = n; }
  if (cnt == 0) return false;
  if (cnt > 1) throw CliError("give only one of --iv / --iv-hex / --nonce / --nonce-hex");
  const std::string v = a.get(chosen);
  if (chosen == "iv-hex" || chosen == "nonce-hex") {
    if (!util::from_hex(v, iv, false)) throw CliError("--" + chosen + " is not valid hex");
  } else {
    iv = util::parse_blob_arg(v, "IV/nonce");
  }
  return true;
}

bool pick_aad(const Args& a, Bytes& aad) {
  const bool f = a.has("aad"), t = a.has("aad-text");
  if (f && t) throw CliError("give only one of --aad FILE or --aad-text STRING");
  if (f) {
    std::string err;
    if (!util::read_file(a.get("aad"), aad, err, 64u << 20)) throw UsageError("AAD file: " + err);
    return true;
  }
  if (t) {
    aad = util::to_bytes(a.get("aad-text"));
    return true;
  }
  return false;
}

std::string check_encode(const Args& a, bool allow_raw) {
  const std::string e = a.get("encode", "hex");
  if (e != "hex" && e != "base64" && !(allow_raw && e == "raw"))
    throw CliError(std::string("--encode must be hex or base64") + (allow_raw ? " or raw" : ""));
  return e;
}

std::string encode_bytes(const Bytes& b, const std::string& enc) {
  return enc == "base64" ? util::to_base64(b) : util::to_hex(b);
}

void read_input_file(const std::string& path, Bytes& out) {
  std::string err;
  if (!util::read_file(path, out, err, util::kMaxFileBytes)) throw UsageError("input: " + err);
}

// ------------------------------------------------------------------ commands
int cmd_encrypt(const Args& a) {
  const Mode mode = need_mode(a);
  if (a.flag("aead") && !is_aead(mode))
    throw CliError(std::string("--aead needs --mode ccm or gcm; '") + mode_name(mode) + "' has no authentication");
  const std::string enc = check_encode(a, true);
  const std::string out = a.get("out"), sidecar = a.get("sidecar");
  if (out.empty() && !sidecar.empty()) throw CliError("--sidecar needs --out");
  if (out.empty() && enc == "raw") throw CliError("--encode raw needs --out FILE (binary is never printed)");
  if (a.has("threads")) std::cerr << "NOTE: --threads is accepted for CLI compatibility but unused in Lab 1.\n";
  if (a.has("in") == a.has("text")) throw CliError("exactly one of --in FILE or --text STRING is required");

  Bytes key = load_key(a);
  KeyGuard kg(key);
  Bytes pt;
  if (a.has("in")) read_input_file(a.get("in"), pt);
  else pt = util::to_bytes(a.get("text"));

  EncryptOptions o;
  o.mode = mode;
  o.key = key;
  o.has_iv = pick_iv(a, o.iv);
  pick_aad(a, o.aad);
  if (a.has("tag-len")) o.tag_len = parse_size(a.get("tag-len"), "--tag-len");
  o.allow_ecb = a.flag("allow-ecb");
  o.out_path = out;
  o.sidecar_path = sidecar;
  o.ledger_path = a.get("ledger");

  if (mode == Mode::ECB) std::cerr << "WARNING: " << ecb_warning_text() << "\n";
  const EncryptResult r = encrypt_buffer(o, pt);

  std::string err;
  if (!out.empty()) {
    if (!sidecar.empty() && !util::write_file_atomic(sidecar, util::to_bytes(r.sidecar), err, false))
      throw CryptoError(err);
    if (!util::write_file_atomic(out, r.output, err, false)) throw CryptoError(err);
  }

  std::ostream& info = out.empty() ? std::cerr : std::cout;
  info << "Encrypted " << pt.size() << " bytes with " << r.alg << (out.empty() ? "" : " -> " + out) << "\n";
  if (uses_iv(mode))
    info << "  IV/nonce : " << util::to_hex(r.iv)
         << (r.iv_generated ? (sidecar.empty() ? "  (random, stored in file header)" : "  (random, stored in sidecar)")
                            : "  (user supplied)")
         << "\n";
  if (is_aead(mode)) info << "  tag      : " << util::to_hex(r.tag) << "\n";
  if (!sidecar.empty()) info << "  sidecar  : " << sidecar << "\n";
  if (a.flag("verbose")) info << "  key id   : " << util::to_hex(key_id(key)) << "\n";

  if (enc != "raw") {
    const std::string s = encode_bytes(r.output, enc);
    if (out.empty()) {
      std::cout << s << "\n";
    } else if (a.has("encode") || r.output.size() <= 256) {
      std::cout << "  ciphertext (" << enc << "): " << s << "\n";
    } else {
      Bytes head(r.output.begin(), r.output.begin() + 64);
      std::cout << "  ciphertext (" << enc << ", first 64 of " << r.output.size()
                << " bytes; pass --encode to print all): " << encode_bytes(head, enc) << "...\n";
    }
  }
  return 0;
}

int cmd_decrypt(const Args& a) {
  const std::string enc = check_encode(a, false);
  const std::string out = a.get("out");
  if (a.has("threads")) std::cerr << "NOTE: --threads is accepted for CLI compatibility but unused in Lab 1.\n";
  if (a.has("in") == a.has("text")) throw CliError("exactly one of --in FILE or --text ENCODED is required");

  Bytes key = load_key(a);
  KeyGuard kg(key);

  Bytes input;
  DecryptOptions o;
  if (a.has("text")) {
    if (a.has("sidecar")) throw CliError("--sidecar needs --in (raw ciphertext file)");
    const bool ok = enc == "hex" ? util::from_hex(a.get("text"), input, true) : util::from_base64(a.get("text"), input, true);
    if (!ok) throw FormatError("--text is not valid " + enc);
  } else {
    read_input_file(a.get("in"), input);
  }
  if (a.has("sidecar")) {
    Bytes js;
    std::string err;
    if (!util::read_file(a.get("sidecar"), js, err, 1u << 20)) throw UsageError("sidecar: " + err);
    o.sidecar_mode = true;
    o.sidecar_json = util::to_string(js);
  }
  if (a.has("mode")) {
    o.mode = need_mode(a);
    o.has_mode = true;
    if (o.mode == Mode::ECB) std::cerr << "WARNING: " << ecb_warning_text() << "\n";
  }
  o.key = key;
  o.has_iv = pick_iv(a, o.iv);
  o.has_aad = pick_aad(a, o.aad);
  o.allow_ecb = a.flag("allow-ecb");

  const DecryptResult r = decrypt_buffer(o, input);   // throws => nothing is written (fail closed)
  for (const std::string& w : r.warnings) std::cerr << "WARNING: " << w << "\n";

  std::ostream& info = out.empty() ? std::cerr : std::cout;
  info << "Decrypted " << r.plaintext.size() << " bytes (" << r.alg << ")\n";

  if (!out.empty()) {
    std::string err;
    if (!util::write_file_atomic(out, r.plaintext, err, false)) throw CryptoError(err);
    std::cout << "  written to " << out << "\n";
  } else if (util::is_valid_utf8(r.plaintext)) {
    std::cout.write(reinterpret_cast<const char*>(r.plaintext.data()), static_cast<std::streamsize>(r.plaintext.size()));
    std::cout << std::flush;
    std::cerr << "\n";
  } else {
    std::cerr << "NOTE: plaintext is not valid UTF-8 (wrong key/IV for an unauthenticated mode?). Showing hex.\n";
    std::cout << util::to_hex(r.plaintext) << "\n";
  }
  return 0;
}

int cmd_keygen(const Args& a) {
  const size_t bits = parse_size(a.get("bits", "256"), "--bits");
  if (bits != 128 && bits != 192 && bits != 256 && bits != 512)
    throw CliError("--bits must be 128, 192, 256 (AES) or 512 (AES-256-XTS key pair)");
  const std::string fmt = a.get("format", "raw");
  if (fmt != "raw" && fmt != "hex") throw CliError("--format must be raw or hex");
  Bytes key = random_bytes(bits / 8);
  KeyGuard kg(key);
  if (a.has("out")) {
    const std::string out = a.get("out");
    if (util::file_exists(out) && !a.flag("force"))
      throw UsageError("refusing to overwrite existing file '" + out + "' (use --force)");
    Bytes file = key;
    if (fmt == "hex") file = util::to_bytes("AESTOOL-HEX\n" + util::to_hex(key) + "\n");
    std::string err;
    const bool ok = util::write_file_atomic(out, file, err, true);
    secure_wipe(file);
    if (!ok) throw CryptoError(err);
    std::cout << "Key (" << bits << " bits, " << fmt << ") written to " << out << "\n"
              << "  key id: " << util::to_hex(key_id(key)) << "\n"
              << "  Protect this file (Linux: chmod 600 applied; Windows: restrict the folder ACL).\n";
  } else {
    std::cout << util::to_hex(key) << "\n";
  }
  return 0;
}

int cmd_bench(const Args& a) {
  BenchConfig c;
  c.modes = bench_all_modes();
  c.sizes = bench_default_sizes();
  if (a.has("modes")) {
    c.modes.clear();
    for (const std::string& s : split(a.get("modes"), ',')) {
      Mode m;
      if (!parse_mode(s, m)) throw CliError("unknown mode '" + s + "' in --modes");
      c.modes.push_back(m);
    }
  }
  if (a.has("sizes")) {
    c.sizes.clear();
    for (const std::string& s : split(a.get("sizes"), ',')) c.sizes.push_back(parse_size_token(s));
  }
  if (a.flag("quick")) {
    c.runs = 20;
    c.warmup_sec = 0.2;
  }
  if (a.has("runs")) c.runs = static_cast<int>(parse_size(a.get("runs"), "--runs"));
  if (a.has("warmup")) c.warmup_sec = parse_double(a.get("warmup"), "--warmup");
  if (a.has("batch-mb")) c.batch_bytes = parse_size(a.get("batch-mb"), "--batch-mb") * 1024 * 1024;
  if (a.has("max-ops")) c.max_ops = parse_size(a.get("max-ops"), "--max-ops");
  if (a.has("bits")) c.key_bits = parse_size(a.get("bits"), "--bits");
  if (c.key_bits != 128 && c.key_bits != 192 && c.key_bits != 256) throw CliError("--bits for bench must be 128, 192 or 256");
  if (c.runs < 2) throw CliError("--runs must be >= 2");
  if (c.max_ops == 0 || c.batch_bytes == 0) throw CliError("--max-ops and --batch-mb must be > 0");
  const std::string dir = a.get("dir", "both");
  if (dir != "enc" && dir != "dec" && dir != "both") throw CliError("--dir must be enc, dec or both");
  c.do_enc = dir != "dec";
  c.do_dec = dir != "enc";
  c.with_io = a.flag("with-io");
  c.csv_path = a.get("csv");
  c.tmp_dir = a.get("tmpdir");
  c.verbose = a.flag("verbose");
  return run_bench(c);
}

std::vector<std::string> get_args(int argc, char** argv) {
  std::vector<std::string> v;
#ifdef _WIN32
  (void)argc;
  (void)argv;
  int n = 0;
  LPWSTR* w = CommandLineToArgvW(GetCommandLineW(), &n);   // real UTF-16 args -> UTF-8
  if (w) {
    for (int i = 0; i < n; ++i) {
      const int len = WideCharToMultiByte(CP_UTF8, 0, w[i], -1, nullptr, 0, nullptr, nullptr);
      std::string s(len > 1 ? static_cast<size_t>(len - 1) : 0, '\0');
      if (len > 1) WideCharToMultiByte(CP_UTF8, 0, w[i], -1, &s[0], len, nullptr, nullptr);
      v.push_back(s);
    }
    LocalFree(w);
  }
#else
  for (int i = 0; i < argc; ++i) v.push_back(argv[i]);
#endif
  return v;
}

}  // namespace

int main(int argc, char** argv) {
#ifdef _WIN32
  SetConsoleOutputCP(CP_UTF8);
  SetConsoleCP(CP_UTF8);
  _setmode(_fileno(stdout), _O_BINARY);   // no CRLF translation of plaintext
#endif
  try {
    const Args a = parse_args(get_args(argc, argv));
    if (a.flag("help") || a.command == "help") {
      std::cout << kUsage;
      return 0;
    }
    if (a.flag("version") || a.command == "version") {
      std::cout << "aestool 1.0.0 (Crypto++ " << crypto_library_version() << ")\n";
      return 0;
    }
    if (a.has("kat")) return run_kat(a.get("kat"), a.flag("verbose"));
    if (a.command == "encrypt") return cmd_encrypt(a);
    if (a.command == "decrypt") return cmd_decrypt(a);
    if (a.command == "keygen") return cmd_keygen(a);
    if (a.command == "bench") return cmd_bench(a);
    std::cerr << (a.command.empty() ? "ERROR: no command given\n" : "ERROR: unknown command '" + a.command + "'\n")
              << kUsage;
    return 2;
  } catch (const CliError& e) {
    std::cerr << "ERROR: " << e.what() << "\n(see 'aestool help')\n";
    return 2;
  } catch (const AuthError& e) {
    std::cerr << "AUTHENTICATION FAILED: " << e.what() << "\nNo plaintext was produced and no output file was written.\n";
    return 3;
  } catch (const UsageError& e) {
    std::cerr << "ERROR: " << e.what() << "\n";
    return 2;
  } catch (const CryptoError& e) {
    std::cerr << "ERROR (fail closed, nothing written): " << e.what() << "\n";
    return 3;
  } catch (const std::exception& e) {
    std::cerr << "ERROR: " << e.what() << "\n";
    return 1;
  }
}
