#include "bench.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <thread>

#include "util.h"

using namespace aescore;

namespace {

volatile uint64_t g_sink = 0;   // prevents the optimizer from discarding results
using Clock = std::chrono::steady_clock;

double secs_since(Clock::time_point t0) {
  return std::chrono::duration<double>(Clock::now() - t0).count();
}

// ---------------------------------------------------------------- statistics
double stat_mean(const std::vector<double>& v) {
  if (v.empty()) return 0;
  double sum = 0;
  for (double x : v) sum += x;
  return sum / static_cast<double>(v.size());
}

double stat_median(std::vector<double> v) {
  const size_t n = v.size();
  if (n == 0) return 0;
  std::sort(v.begin(), v.end());
  return (n % 2) ? v[n / 2] : 0.5 * (v[n / 2 - 1] + v[n / 2]);
}

// sample standard deviation (n-1)
double stat_stddev(const std::vector<double>& v, double mean) {
  const size_t n = v.size();
  if (n < 2) return 0;
  double sq = 0;
  for (double x : v) sq += (x - mean) * (x - mean);
  return std::sqrt(sq / static_cast<double>(n - 1));
}

// two-sided 95% critical value of Student's t (normal approximation for large df)
double tcrit95(size_t df) {
  static const double T[30] = {12.706, 4.303, 3.182, 2.776, 2.571, 2.447, 2.365, 2.306, 2.262, 2.228,
                               2.201,  2.179, 2.160, 2.145, 2.131, 2.120, 2.110, 2.101, 2.093, 2.086,
                               2.080,  2.074, 2.069, 2.064, 2.060, 2.056, 2.052, 2.048, 2.045, 2.042};
  if (df == 0) return 0;
  if (df <= 30) return T[df - 1];
  return 1.96 + 2.4 / static_cast<double>(df);
}

// half-width of the 95% confidence interval of the mean: mean +/- ci95
double stat_ci95(const std::vector<double>& v, double sd) {
  const size_t n = v.size();
  if (n < 2) return 0;
  return tcrit95(n - 1) * sd / std::sqrt(static_cast<double>(n));
}

struct Stats {
  double mean = 0, median = 0, sd = 0, ci95 = 0;
};

Stats summarize(const std::vector<double>& v) {
  Stats s;
  s.mean = stat_mean(v);
  s.median = stat_median(v);
  s.sd = stat_stddev(v, s.mean);
  s.ci95 = stat_ci95(v, s.sd);
  return s;
}

struct Row {
  Mode mode;
  bool decrypt;
  size_t size;
  size_t ops;
  int runs;
  Stats thr;   // MB/s (1 MB = 10^6 bytes)
  Stats lat;   // microseconds per operation
};

std::string os_name() {
#if defined(_WIN32)
  return "Windows";
#elif defined(__APPLE__)
  return "macOS";
#elif defined(__linux__)
  return "Linux";
#else
  return "Unknown";
#endif
}

std::string compiler_name() {
#if defined(__clang__)
  std::string c = std::string("clang ") + __clang_version__;
#elif defined(_MSC_VER)
  std::string c = "MSVC " + std::to_string(_MSC_VER);
#elif defined(__GNUC__)
  std::string c = std::string("GCC ") + __VERSION__;
#else
  std::string c = "unknown";
#endif
#if defined(__MINGW32__)
  c += " (MinGW-w64)";
#endif
  return c;
}

std::string first_line_with(const char* path, const char* key) {
  std::ifstream f(path);
  std::string line;
  const std::string k = key;
  while (std::getline(f, line))
    if (line.compare(0, k.size(), k) == 0) {
      const size_t c = line.find(':');
      if (c != std::string::npos) return line.substr(c + 2 <= line.size() ? c + 2 : c + 1);
    }
  return std::string();
}

std::string cpu_model() {
#if defined(_WIN32)
  const char* e = std::getenv("PROCESSOR_IDENTIFIER");
  return e ? e : "unknown";
#else
  const std::string m = first_line_with("/proc/cpuinfo", "model name");
  return m.empty() ? "unknown" : m;
#endif
}

std::string governor() {
  std::ifstream f("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor");
  std::string g;
  if (f && std::getline(f, g)) return g;
  return "n/a";
}

std::string build_type() {
#ifdef NDEBUG
  return "Release (NDEBUG)";
#else
  return "Debug (no NDEBUG) - results are NOT representative";
#endif
}

std::string size_label(size_t b) {
  if (b >= 1024 * 1024 && b % (1024 * 1024) == 0) return std::to_string(b / (1024 * 1024)) + "MiB";
  if (b >= 1024 && b % 1024 == 0) return std::to_string(b / 1024) + "KiB";
  return std::to_string(b) + "B";
}

Row bench_one(const BenchConfig& c, Mode m, bool decrypt, size_t size) {
  const size_t klen = (c.key_bits / 8) * (m == Mode::XTS ? 2 : 1);
  CipherParams p;
  p.mode = m;
  p.key = random_bytes(klen);
  p.iv.assign(default_iv_len(m), 0);
  const Bytes pt = random_bytes(size);

  const bool io = c.with_io && !decrypt;
  std::string in_path, out_path;
  if (io) {
    const std::filesystem::path dir = c.tmp_dir.empty() ? std::filesystem::temp_directory_path()
                                                        : std::filesystem::u8path(c.tmp_dir);
    in_path = (dir / "aestool_bench_in.bin").u8string();
    out_path = (dir / "aestool_bench_out.bin").u8string();
    std::string err;
    if (!util::write_file_atomic(in_path, pt, err, false)) throw CryptoError("bench: " + err);
  }

  EncResult pre;
  if (decrypt) pre = encrypt_raw(p, pt);   // fixed ciphertext, prepared outside the timed region

  uint64_t counter = 0;
  auto bump_iv = [&]() {
    ++counter;   // unique nonce per operation, like a real AEAD user
    for (size_t i = 0; i < 8 && i < p.iv.size(); ++i)
      p.iv[p.iv.size() - 1 - i] = static_cast<uint8_t>((counter >> (8 * i)) & 0xFF);
  };

  auto op = [&]() {
    if (decrypt) {
      Bytes o = decrypt_raw(p, pre.ct, pre.tag);
      g_sink = g_sink + (o.empty() ? 0 : o[0]);
    } else if (io) {
      std::string err;
      Bytes in;
      if (!util::read_file(in_path, in, err, util::kMaxFileBytes)) throw CryptoError("bench: " + err);
      bump_iv();
      EncResult e = encrypt_raw(p, in);
      Bytes outb = e.ct;
      outb.insert(outb.end(), e.tag.begin(), e.tag.end());
      if (!util::write_file_atomic(out_path, outb, err, false)) throw CryptoError("bench: " + err);
      g_sink = g_sink + (e.ct.empty() ? 0 : e.ct[0]);
    } else {
      bump_iv();
      EncResult e = encrypt_raw(p, pt);
      g_sink = g_sink + (e.ct.empty() ? 0 : e.ct[0]) + e.tag.size();
    }
  };

  const size_t ops = std::max<size_t>(1, std::min(c.max_ops, c.batch_bytes / std::max<size_t>(size, 1)));

  const Clock::time_point w0 = Clock::now();   // warm-up
  do { op(); } while (secs_since(w0) < c.warmup_sec);

  std::vector<double> thr, lat;
  for (int r = 0; r < c.runs; ++r) {
    const Clock::time_point t0 = Clock::now();
    for (size_t i = 0; i < ops; ++i) op();
    const double el = secs_since(t0);
    thr.push_back(static_cast<double>(size) * static_cast<double>(ops) / 1e6 / el);
    lat.push_back(el / static_cast<double>(ops) * 1e6);
  }

  if (io) {
    std::error_code ec;
    std::filesystem::remove(std::filesystem::u8path(in_path), ec);
    std::filesystem::remove(std::filesystem::u8path(out_path), ec);
  }

  Row row;
  row.mode = m;
  row.decrypt = decrypt;
  row.size = size;
  row.ops = ops;
  row.runs = c.runs;
  row.thr = summarize(thr);
  row.lat = summarize(lat);
  return row;
}

}  // namespace

std::vector<Mode> bench_all_modes() {
  return {Mode::ECB, Mode::CBC, Mode::OFB, Mode::CFB, Mode::CTR, Mode::XTS, Mode::CCM, Mode::GCM};
}

std::vector<size_t> bench_default_sizes() {
  return {1024, 4 * 1024, 16 * 1024, 256 * 1024, 1024 * 1024, 8 * 1024 * 1024};
}

// ---------------------------------------------------------------- CSV
static const char* kCsvHeader =
    "mode,dir,size_bytes,ops_per_block,runs,thr_mean_MBps,thr_median_MBps,thr_sd,thr_ci95,"
    "lat_mean_us,lat_median_us,lat_sd,lat_ci95\n";

static std::string csv_row(const Row& r) {
  std::ostringstream o;
  o.precision(10);
  o << mode_name(r.mode) << "," << (r.decrypt ? "dec" : "enc") << "," << r.size << "," << r.ops << "," << r.runs
    << "," << r.thr.mean << "," << r.thr.median << "," << r.thr.sd << "," << r.thr.ci95 << "," << r.lat.mean << ","
    << r.lat.median << "," << r.lat.sd << "," << r.lat.ci95 << "\n";
  return o.str();
}

// Order: for each mode -> all sizes with dir=enc, then all sizes with dir=dec
// (6 sizes x 2 directions = 12 tasks per mode), then the next mode.
// Every size is measured with `runs` timed blocks (default 1000). The CSV is written
// incrementally so a long run never loses finished tasks.
int run_bench(const BenchConfig& c) {
  std::cout << "==== System ====\n"
            << "OS            : " << os_name() << "\n"
            << "CPU           : " << cpu_model() << "\n"
            << "Logical cores : " << std::thread::hardware_concurrency() << "\n"
            << "CPU governor  : " << governor() << " (set to 'performance' for stable results)\n"
            << "Compiler      : " << compiler_name() << "\n"
            << "Build         : " << build_type() << "\n"
            << "Crypto++      : " << crypto_library_version() << ", AES hardware accel: "
            << (hardware_aes_available() ? "yes" : "no") << "\n"
            << "Config        : runs=" << c.runs << " warmup=" << c.warmup_sec << "s ops_per_block<=" << c.max_ops
            << " (" << (c.batch_bytes >> 20) << " MiB/block), key=AES-" << c.key_bits << "\n\n";

  std::vector<bool> dirs;   // false = enc, true = dec
  if (c.do_enc) dirs.push_back(false);
  if (c.do_dec) dirs.push_back(true);
  const size_t total = c.modes.size() * dirs.size() * c.sizes.size();

  std::string err;
  if (!c.csv_path.empty() && !util::write_file_atomic(c.csv_path, util::to_bytes(kCsvHeader), err, false)) {
    std::cerr << "cannot write CSV: " << err << "\n";
    return 1;
  }

  std::printf("%-5s %-4s %-8s %6s %6s %11s %10s %12s %10s\n", "Mode", "Dir", "Size", "Ops", "Runs", "MB/s(mean)",
              "+-CI95", "us/op(mean)", "sd(us)");
  size_t done = 0;
  for (Mode m : c.modes) {
    for (bool dec : dirs) {
      for (size_t sz : c.sizes) {
        const Row r = bench_one(c, m, dec, sz);
        ++done;
        std::printf("%-5s %-4s %-8s %6zu %6d %11.2f %10.2f %12.2f %10.2f   [%zu/%zu]\n",
                    mode_name_upper(r.mode).c_str(), dec ? "dec" : "enc", size_label(r.size).c_str(), r.ops, r.runs,
                    r.thr.mean, r.thr.ci95, r.lat.mean, r.lat.sd, done, total);
        std::fflush(stdout);
        if (!c.csv_path.empty() && !util::append_file(c.csv_path, csv_row(r), err)) {
          std::cerr << "cannot append to CSV: " << err << "\n";
          return 1;
        }
      }
    }
  }
  if (!c.csv_path.empty()) std::cout << "\nCSV written to " << c.csv_path << "\n";
  return 0;
}
