// hashtool.cpp - Lab 4: Hashing suite (SHA-2, SHA-3, SHAKE), KAT, streaming/mmap I/O,
// benchmark harness and X.509 analysis. Uses the OpenSSL EVP API (3.0+ and 4.x).
#include "common.hpp"
#include "x509_tool.hpp"

#include <fstream>
#include <map>

#include <openssl/crypto.h>
#include <openssl/err.h>

#ifndef _WIN32
#  include <fcntl.h>
#  include <sys/mman.h>
#  include <sys/stat.h>
#  include <unistd.h>
#endif

namespace {

// ------------------------------------------------------------------ algorithms
struct Algo {
  std::string name;   // canonical CLI name
  const char* ossl;   // OpenSSL fetch name
  bool xof;
  size_t def_len;     // default output length in bytes
};

const Algo kAlgos[] = {
  {"sha224", "SHA224", false, 28},   {"sha256", "SHA256", false, 32},
  {"sha384", "SHA384", false, 48},   {"sha512", "SHA512", false, 64},
  {"sha3-224", "SHA3-224", false, 28}, {"sha3-256", "SHA3-256", false, 32},
  {"sha3-384", "SHA3-384", false, 48}, {"sha3-512", "SHA3-512", false, 64},
  {"shake128", "SHAKE128", true, 32}, {"shake256", "SHAKE256", true, 64},
};

// Accept "SHA256", "sha-256", "SHA3_256", ... ; unknown -> nullptr (fail closed)
const Algo* find_algo(const std::string& in) {
  std::string k;
  for (char c : in) if (c != '-' && c != '_') k += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  for (const Algo& a : kAlgos) {
    std::string n;
    for (char c : a.name) if (c != '-') n += c;
    if (n == k) return &a;
  }
  return nullptr;
}

const size_t kMaxXofLen = 16u * 1024 * 1024;

class Hasher {
 public:
  Hasher(const Algo& a, size_t outlen) : algo_(a), outlen_(outlen) {
    md_ = EVP_MD_fetch(nullptr, a.ossl, nullptr);
    ctx_ = EVP_MD_CTX_new();
    if (!md_ || !ctx_) throw std::runtime_error(std::string("OpenSSL cannot provide ") + a.ossl);
  }
  ~Hasher() { EVP_MD_CTX_free(ctx_); EVP_MD_free(md_); }
  Hasher(const Hasher&) = delete;
  Hasher& operator=(const Hasher&) = delete;

  void reset() {
    if (EVP_DigestInit_ex2(ctx_, md_, nullptr) != 1) throw std::runtime_error("EVP_DigestInit_ex2 failed");
  }
  void update(const uint8_t* p, size_t n) {
    const size_t step = size_t(1) << 28;  // 256 MiB per call
    while (n) {
      size_t c = n < step ? n : step;
      if (EVP_DigestUpdate(ctx_, p, c) != 1) throw std::runtime_error("EVP_DigestUpdate failed");
      p += c; n -= c;
    }
  }
  std::vector<uint8_t> finish() {
    std::vector<uint8_t> out(outlen_);
    if (algo_.xof) {
      if (EVP_DigestFinalXOF(ctx_, out.data(), outlen_) != 1) throw std::runtime_error("EVP_DigestFinalXOF failed");
    } else {
      unsigned int l = 0;
      std::vector<uint8_t> tmp(EVP_MAX_MD_SIZE);
      if (EVP_DigestFinal_ex(ctx_, tmp.data(), &l) != 1) throw std::runtime_error("EVP_DigestFinal_ex failed");
      out.assign(tmp.begin(), tmp.begin() + l);
    }
    return out;
  }
 private:
  const Algo& algo_;
  size_t outlen_;
  EVP_MD* md_ = nullptr;
  EVP_MD_CTX* ctx_ = nullptr;
};

// ------------------------------------------------------------------ input sources
enum class Mode { Auto, Memory, Stream, Mmap };

uint64_t file_size(const std::string& path) {
  std::ifstream f(path, std::ios::binary | std::ios::ate);
  if (!f) throw IoError("Cannot open input file: " + path);
  std::streamoff s = f.tellg();
  if (s < 0) throw IoError("Cannot determine size of: " + path);
  return static_cast<uint64_t>(s);
}

class MappedFile {
 public:
  ~MappedFile() { close(); }
  void open(const std::string& path) {
    close();
#ifdef _WIN32
    hf_ = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                      FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (hf_ == INVALID_HANDLE_VALUE) throw IoError("Cannot open input file: " + path);
    LARGE_INTEGER li;
    if (!GetFileSizeEx(hf_, &li)) throw IoError("Cannot stat: " + path);
    size_ = static_cast<uint64_t>(li.QuadPart);
    if (size_ == 0) return;
    hm_ = CreateFileMappingA(hf_, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!hm_) throw IoError("CreateFileMapping failed: " + path);
    data_ = static_cast<const uint8_t*>(MapViewOfFile(hm_, FILE_MAP_READ, 0, 0, 0));
    if (!data_) throw IoError("MapViewOfFile failed (file too large for this process?): " + path);
#else
    fd_ = ::open(path.c_str(), O_RDONLY);
    if (fd_ < 0) throw IoError("Cannot open input file: " + path);
    struct stat st;
    if (fstat(fd_, &st) != 0) throw IoError("Cannot stat: " + path);
    size_ = static_cast<uint64_t>(st.st_size);
    if (size_ == 0) return;
    void* m = mmap(nullptr, static_cast<size_t>(size_), PROT_READ, MAP_PRIVATE, fd_, 0);
    if (m == MAP_FAILED) throw IoError("mmap failed: " + path);
    data_ = static_cast<const uint8_t*>(m);
    madvise(const_cast<uint8_t*>(data_), static_cast<size_t>(size_), MADV_SEQUENTIAL);
#endif
  }
  void close() {
#ifdef _WIN32
    if (data_) UnmapViewOfFile(data_);
    if (hm_) CloseHandle(hm_);
    if (hf_ != INVALID_HANDLE_VALUE) CloseHandle(hf_);
    hm_ = nullptr; hf_ = INVALID_HANDLE_VALUE;
#else
    if (data_) munmap(const_cast<uint8_t*>(data_), static_cast<size_t>(size_));
    if (fd_ >= 0) ::close(fd_);
    fd_ = -1;
#endif
    data_ = nullptr; size_ = 0;
  }
  const uint8_t* data() const { return data_; }
  uint64_t size() const { return size_; }
 private:
  const uint8_t* data_ = nullptr;
  uint64_t size_ = 0;
#ifdef _WIN32
  HANDLE hf_ = INVALID_HANDLE_VALUE, hm_ = nullptr;
#else
  int fd_ = -1;
#endif
};

class Input {
 public:
  Input(Mode m, const std::string& path, const std::string* text) : mode_(m), path_(path) {
    if (text) {
      if (m == Mode::Stream || m == Mode::Mmap) throw UsageError("--text cannot be combined with --stream/--mmap");
      mem_.assign(text->begin(), text->end());
      mode_ = Mode::Memory; size_ = mem_.size(); return;
    }
    size_ = file_size(path);
    if (mode_ == Mode::Auto) mode_ = (size_ <= (256ull << 20)) ? Mode::Memory : Mode::Stream;
    if (mode_ == Mode::Memory) {
      try {
        mem_.resize(static_cast<size_t>(size_));
      } catch (const std::bad_alloc&) {
        throw IoError("File too large for in-memory mode; use --stream or --mmap");
      }
      std::ifstream f(path, std::ios::binary);
      if (!f) throw IoError("Cannot open input file: " + path);
      if (size_ && !f.read(reinterpret_cast<char*>(mem_.data()), static_cast<std::streamsize>(size_)))
        throw IoError("Read error on: " + path);
    } else if (mode_ == Mode::Stream) {
      buf_.resize(1u << 20);  // 1 MiB chunks
    }
  }
  Mode mode() const { return mode_; }
  uint64_t size() const { return size_; }
  const char* mode_name() const {
    return mode_ == Mode::Memory ? "memory" : mode_ == Mode::Stream ? "stream" : "mmap";
  }

  // One full pass over the data; returns the digest.
  std::vector<uint8_t> run(Hasher& h) {
    h.reset();
    if (mode_ == Mode::Memory) {
      h.update(mem_.data(), mem_.size());
    } else if (mode_ == Mode::Stream) {
      std::ifstream f(path_, std::ios::binary);
      if (!f) throw IoError("Cannot open input file: " + path_);
      uint64_t total = 0;
      while (f) {
        f.read(reinterpret_cast<char*>(buf_.data()), static_cast<std::streamsize>(buf_.size()));
        std::streamsize got = f.gcount();
        if (got > 0) { h.update(buf_.data(), static_cast<size_t>(got)); total += static_cast<uint64_t>(got); }
      }
      if (f.bad() || total != size_) throw IoError("Read error / size changed while hashing: " + path_);
    } else {
      MappedFile mf;
      mf.open(path_);
      h.update(mf.data(), static_cast<size_t>(mf.size()));
    }
    return h.finish();
  }
 private:
  Mode mode_;
  std::string path_;
  uint64_t size_ = 0;
  std::vector<uint8_t> mem_, buf_;
};

// ------------------------------------------------------------------ KAT
// Minimal tolerant scanner for vectors.json: walks "key": value pairs in document order.
struct KatCounters { int pass = 0, fail = 0; };

void kat_run_one(KatCounters& c, const std::string& algo_name, const std::string& desc,
                 const std::string& in_hex, unsigned long long repeat, const std::string& exp_hex) {
  const Algo* a = find_algo(algo_name);
  std::vector<uint8_t> in, exp;
  std::string label = algo_name + " | " + desc;
  if (!a) { std::cout << "[FAIL] " << label << "  (unknown algorithm)\n"; ++c.fail; return; }
  if (!hex_to_bytes(in_hex, in) || !hex_to_bytes(exp_hex, exp) || exp.empty()) {
    std::cout << "[FAIL] " << label << "  (malformed hex in vector)\n"; ++c.fail; return;
  }
  if (!a->xof && exp.size() != a->def_len) {
    std::cout << "[FAIL] " << label << "  (expected length mismatch)\n"; ++c.fail; return;
  }
  Hasher h(*a, exp.size());
  h.reset();
  if (!in.empty() && repeat > 0) {
    size_t k = std::max<size_t>(1, 65536 / in.size());
    std::vector<uint8_t> block;
    for (size_t i = 0; i < k; ++i) block.insert(block.end(), in.begin(), in.end());
    for (unsigned long long i = 0; i < repeat / k; ++i) h.update(block.data(), block.size());
    for (unsigned long long i = 0; i < repeat % k; ++i) h.update(in.data(), in.size());
  }
  std::vector<uint8_t> got = h.finish();
  if (got == exp) { std::cout << "[PASS] " << label << "\n"; ++c.pass; }
  else {
    std::cout << "[FAIL] " << label << "\n       expected: " << exp_hex
              << "\n       got:      " << bytes_to_hex(got.data(), got.size()) << "\n";
    ++c.fail;
  }
}

int run_kat(const std::string& path) {
  std::ifstream f(path, std::ios::binary);
  if (!f) throw IoError("Cannot open vectors file: " + path);
  std::ostringstream ss; ss << f.rdbuf();
  const std::string s = ss.str();

  KatCounters c;
  std::string algo, desc, in_hex;
  unsigned long long repeat = 1;
  std::cout << "=== KAT RESULTS (" << path << ") ===\n";
  size_t i = 0, n = s.size();
  auto skip_ws = [&] { while (i < n && std::isspace(static_cast<unsigned char>(s[i]))) ++i; };
  auto read_str = [&](std::string& out) {  // s[i] == '"'
    out.clear(); ++i;
    while (i < n && s[i] != '"') { if (s[i] == '\\' && i + 1 < n) ++i; out += s[i++]; }
    if (i < n) ++i;
  };
  while (i < n) {
    if (s[i] != '"') { ++i; continue; }
    std::string key; read_str(key); skip_ws();
    if (i >= n || s[i] != ':') continue;       // string that is an array element, not a key
    ++i; skip_ws();
    std::string sval; unsigned long long nval = 0; bool is_str = false;
    if (i < n && s[i] == '"') { read_str(sval); is_str = true; }
    else if (i < n && std::isdigit(static_cast<unsigned char>(s[i]))) {
      while (i < n && std::isdigit(static_cast<unsigned char>(s[i]))) nval = nval * 10 + (s[i++] - '0');
    } else continue;                           // object/array value: keep scanning inside it
    if (key == "name" && is_str) algo = sval;
    else if (key == "description" && is_str) { desc = sval; in_hex.clear(); repeat = 1; }
    else if (key == "input_hex" && is_str) in_hex = sval;
    else if (key == "repeat" && !is_str) repeat = nval;
    else if (key == "expected_output" && is_str) kat_run_one(c, algo, desc, in_hex, repeat, sval);
  }
  int total = c.pass + c.fail;
  std::cout << "Total: " << c.pass << "/" << total << " passed\n";
  if (total == 0) { std::cout << "No test vectors found -> FAIL (fail closed)\n"; return 1; }
  return c.fail == 0 ? 0 : 1;
}

// ------------------------------------------------------------------ misc
unsigned long long parse_uint(const std::string& s, const char* what) {
  if (s.empty() || s.find_first_not_of("0123456789") != std::string::npos)
    throw UsageError(std::string("Invalid number for ") + what + ": '" + s + "'");
  try { return std::stoull(s); } catch (...) { throw UsageError(std::string("Number out of range for ") + what); }
}

void print_help() {
  std::cout <<
"hashtool - Lab 4 hashing suite (OpenSSL EVP)\n\n"
"Hashing:\n"
"  hashtool --algo ALGO (--in FILE | --text STR) [--stream | --mmap] [--outlen N]\n"
"           [--out FILE] [--encode hex|base64|raw]\n"
"  ALGO: sha224 sha256 sha384 sha512 sha3-224 sha3-256 sha3-384 sha3-512 shake128 shake256\n"
"  --outlen N     output bytes, SHAKE only (default 32 / 64); other algorithms reject it\n"
"  --stream       read in 1 MiB chunks (multi-GB files, constant RAM)\n"
"  --mmap         memory-mapped I/O\n"
"  (default)      whole file in RAM if <= 256 MiB, otherwise streaming\n"
"  Console always prints hex; --out writes hex (default), base64 or raw binary.\n\n"
"Benchmark:\n"
"  hashtool --algo sha256 --in FILE [--stream|--mmap] --bench N\n\n"
"Known Answer Tests:\n"
"  hashtool --kat [vectors/vectors.json]\n\n"
"X.509:\n"
"  hashtool --algo x509 --in cert.pem [--issuer ca.pem] [--out report.txt] [--no-time-check]\n\n"
"Other: --version, --help\n"
"Exit codes: 0 ok, 1 verification/KAT failure, 2 usage error, 3 I/O error\n";
}

int do_bench(const Algo& a, size_t outlen, Input& in, unsigned long long runs) {
  if (runs < 2 || runs > 10000) throw UsageError("--bench N requires 2 <= N <= 10000");
  Hasher h(a, outlen);
  std::vector<uint8_t> ref = in.run(h);  // warm-up (also fills the page cache)
  std::vector<double> mbps, secs;
  double cpu0 = process_cpu_seconds();
  Timer wall_total; wall_total.start();
  for (unsigned long long r = 0; r < runs; ++r) {
    Timer t; t.start();
    std::vector<uint8_t> d = in.run(h);
    t.stop();
    if (d != ref) throw std::runtime_error("digest changed between runs (file modified?)");
    secs.push_back(t.seconds());
    mbps.push_back(t.seconds() > 0 ? (static_cast<double>(in.size()) / 1e6) / t.seconds() : 0.0);
  }
  wall_total.stop();
  double cpu = process_cpu_seconds() - cpu0;
  std::vector<double> ms; for (double s : secs) ms.push_back(s * 1000.0);
  Stats st_t, st_l; st_t.compute(mbps); st_l.compute(ms);

  std::cout << "=== BENCHMARK RESULTS (" << a.name << ", " << in.size() << " bytes, mode=" << in.mode_name()
            << ", " << runs << " runs) ===\n";
  std::cout << format_stats_line("Throughput (MB/s)", st_t) << "\n";
  std::cout << format_stats_line("Latency per op (ms)", st_l, 3) << "\n";
  double util = wall_total.seconds() > 0 ? 100.0 * cpu / wall_total.seconds() : 0.0;
  std::cout << std::fixed << std::setprecision(1) << "CPU utilization (%): " << util
            << "  (process CPU time / wall time; 1 MB = 10^6 bytes)\n";
  std::cout << "Digest: " << bytes_to_hex(ref.data(), ref.size()) << "\n";
  std::cout << "# run,seconds,MB_per_s\n";
  for (size_t i = 0; i < secs.size(); ++i)
    std::cout << (i + 1) << "," << std::fixed << std::setprecision(6) << secs[i] << ","
              << std::setprecision(2) << mbps[i] << "\n";
  std::cout << "===\n";
  return 0;
}

void write_file(const std::string& path, const std::string& data) {
  std::ofstream o(path, std::ios::binary | std::ios::trunc);
  if (!o) throw IoError("Cannot write output file: " + path);
  o.write(data.data(), static_cast<std::streamsize>(data.size()));
  if (!o) throw IoError("Write error: " + path);
}

} // namespace

// ------------------------------------------------------------------ main
int main(int argc, char** argv) {
  try {
    if (argc < 2) { print_help(); return 0; }

    std::string algo_s, in_file, out_file, issuer, text, kat_path;
    std::string encode = "hex";
    bool has_text = false, stream = false, use_mmap = false, do_kat = false, time_check = true;
    bool has_outlen = false, has_bench = false;
    unsigned long long outlen_v = 0, bench_n = 0;

    for (int i = 1; i < argc; ++i) {
      std::string a = argv[i];
      auto val = [&](const char* opt) -> std::string {
        if (i + 1 >= argc) throw UsageError(std::string("Missing value for ") + opt);
        return argv[++i];
      };
      if (a == "--help" || a == "-h") { print_help(); return 0; }
      else if (a == "--version") {
        std::cout << "hashtool 1.1 (Lab 4), " << OpenSSL_version(OPENSSL_VERSION) << "\n"; return 0;
      }
      else if (a == "--algo") algo_s = val("--algo");
      else if (a == "--in") in_file = val("--in");
      else if (a == "--out") out_file = val("--out");
      else if (a == "--issuer") issuer = val("--issuer");
      else if (a == "--text") { text = val("--text"); has_text = true; }
      else if (a == "--encode") {
        encode = val("--encode");
        if (encode != "hex" && encode != "base64" && encode != "raw")
          throw UsageError("--encode must be hex, base64 or raw");
      }
      else if (a == "--outlen") { outlen_v = parse_uint(val("--outlen"), "--outlen"); has_outlen = true; }
      else if (a == "--bench") { bench_n = parse_uint(val("--bench"), "--bench"); has_bench = true; }
      else if (a == "--stream") stream = true;
      else if (a == "--mmap") use_mmap = true;
      else if (a == "--no-time-check") time_check = false;
      else if (a == "--kat") {
        do_kat = true;
        kat_path = (i + 1 < argc && std::string(argv[i + 1]).rfind("--", 0) != 0) ? argv[++i]
                                                                                    : "vectors/vectors.json";
      }
      else throw UsageError("Unknown option: " + a);
    }

    if (do_kat) return run_kat(kat_path);

    if (stream && use_mmap) throw UsageError("--stream and --mmap are mutually exclusive");
    if (algo_s.empty()) throw UsageError("Missing --algo");

    // ---- X.509 mode ----
    std::string lower;
    for (char c : algo_s) lower += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    if (lower == "x509") {
      if (in_file.empty()) throw UsageError("--algo x509 requires --in CERT");
      std::string report;
      int rc = x509_analyze(in_file, issuer, time_check, report);
      std::cout << report;
      if (!out_file.empty()) write_file(out_file, report);
      return rc;
    }

    // ---- hash modes ----
    const Algo* algo = find_algo(algo_s);
    if (!algo) throw UsageError("Unsupported algorithm '" + algo_s + "'. See --help for the list.");
    if (in_file.empty() == !has_text) throw UsageError("Provide exactly one of --in FILE or --text STR");

    size_t outlen = algo->def_len;
    if (has_outlen) {
      if (!algo->xof) throw UsageError("--outlen is only valid for shake128/shake256");
      if (outlen_v < 1 || outlen_v > kMaxXofLen) throw UsageError("--outlen must be in 1.." + std::to_string(kMaxXofLen));
      outlen = static_cast<size_t>(outlen_v);
    }

    Mode mode = stream ? Mode::Stream : use_mmap ? Mode::Mmap : Mode::Auto;
    Input input(mode, in_file, has_text ? &text : nullptr);

    if (has_bench) return do_bench(*algo, outlen, input, bench_n);

    Hasher h(*algo, outlen);
    std::vector<uint8_t> d = input.run(h);
    std::string hex = bytes_to_hex(d.data(), d.size());

    if (!out_file.empty()) {
      if (encode == "raw") write_file(out_file, std::string(reinterpret_cast<const char*>(d.data()), d.size()));
      else if (encode == "base64") write_file(out_file, base64_encode(d.data(), d.size()) + "\n");
      else write_file(out_file, hex + "\n");
    }
    std::cout << algo->name << "(" << (has_text ? "<text>" : in_file) << ")= " << hex << "\n";
    return 0;
  } catch (const UsageError& e) {
    std::cerr << "Error: " << e.what() << "\n"; return 2;
  } catch (const IoError& e) {
    std::cerr << "I/O error: " << e.what() << "\n"; return 3;
  } catch (const std::exception& e) {
    std::cerr << "Error: " << e.what() << "\n"; return 1;
  }
}
