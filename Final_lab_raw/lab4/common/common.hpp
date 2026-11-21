// common.hpp - shared helpers for Lab 4 hashtool (ASCII-only on purpose, see run_all.ps1 notes)
#ifndef COMMON_HPP
#define COMMON_HPP

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#ifdef _WIN32
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#else
#  include <time.h>
#endif

#include <openssl/evp.h>

// ---- Errors -> exit codes (fail closed) ----
struct UsageError : std::runtime_error { using std::runtime_error::runtime_error; }; // exit 2
struct IoError    : std::runtime_error { using std::runtime_error::runtime_error; }; // exit 3

// ---- Hex ----
inline int from_hex_char(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

inline std::string bytes_to_hex(const uint8_t* data, size_t len) {
  static const char hex_chars[] = "0123456789abcdef";
  std::string out;
  out.reserve(len * 2);
  for (size_t i = 0; i < len; ++i) {
    out += hex_chars[(data[i] >> 4) & 0xF];
    out += hex_chars[data[i] & 0xF];
  }
  return out;
}

// Strict decode: odd length or non-hex character -> false
inline bool hex_to_bytes(const std::string& hex, std::vector<uint8_t>& out) {
  out.clear();
  if (hex.size() % 2 != 0) return false;
  out.reserve(hex.size() / 2);
  for (size_t i = 0; i < hex.size(); i += 2) {
    int hi = from_hex_char(hex[i]), lo = from_hex_char(hex[i + 1]);
    if (hi < 0 || lo < 0) return false;
    out.push_back(static_cast<uint8_t>((hi << 4) | lo));
  }
  return true;
}

inline std::string base64_encode(const uint8_t* data, size_t len) {
  std::string out(((len + 2) / 3) * 4 + 1, '\0');
  int n = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(&out[0]), data, static_cast<int>(len));
  out.resize(static_cast<size_t>(n < 0 ? 0 : n));
  return out;
}

// ---- Timing ----
struct Timer {
  using clock = std::chrono::steady_clock;
  clock::time_point t0, t1;
  void start() { t0 = clock::now(); }
  void stop()  { t1 = clock::now(); }
  double seconds() const { return std::chrono::duration<double>(t1 - t0).count(); }
};

// CPU time (user + kernel) of this process, in seconds
inline double process_cpu_seconds() {
#ifdef _WIN32
  FILETIME c, e, k, u;
  if (!GetProcessTimes(GetCurrentProcess(), &c, &e, &k, &u)) return 0.0;
  auto to_s = [](const FILETIME& f) {
    ULARGE_INTEGER i; i.LowPart = f.dwLowDateTime; i.HighPart = f.dwHighDateTime;
    return static_cast<double>(i.QuadPart) * 1e-7;
  };
  return to_s(k) + to_s(u);
#else
  timespec ts;
  if (clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts) != 0) return 0.0;
  return static_cast<double>(ts.tv_sec) + static_cast<double>(ts.tv_nsec) * 1e-9;
#endif
}

// ---- Statistics: mean, median, sample stddev, 95% CI with Student-t ----
inline double t_critical_975(size_t df) {
  static const double t[] = {0, 12.706, 4.303, 3.182, 2.776, 2.571, 2.447, 2.365, 2.306, 2.262,
    2.228, 2.201, 2.179, 2.160, 2.145, 2.131, 2.120, 2.110, 2.101, 2.093, 2.086, 2.080,
    2.074, 2.069, 2.064, 2.060, 2.056, 2.052, 2.048, 2.045, 2.042};
  if (df == 0) return 0.0;
  if (df <= 30) return t[df];
  if (df <= 40) return 2.021;
  if (df <= 60) return 2.000;
  if (df <= 120) return 1.980;
  return 1.960;
}

struct Stats {
  double mean = 0, median = 0, stddev = 0, ci_lo = 0, ci_hi = 0;
  size_t n = 0;
  void compute(const std::vector<double>& v) {
    n = v.size();
    if (n == 0) return;
    double sum = 0;
    for (double x : v) sum += x;
    mean = sum / static_cast<double>(n);
    std::vector<double> s = v;
    std::sort(s.begin(), s.end());
    median = (n % 2 == 0) ? (s[n / 2 - 1] + s[n / 2]) / 2.0 : s[n / 2];
    if (n > 1) {
      double sq = 0;
      for (double x : v) sq += (x - mean) * (x - mean);
      stddev = std::sqrt(sq / static_cast<double>(n - 1));
      double margin = t_critical_975(n - 1) * stddev / std::sqrt(static_cast<double>(n));
      ci_lo = mean - margin;
      ci_hi = mean + margin;
    } else {
      ci_lo = ci_hi = mean;
    }
  }
};

// Line format is parsed by scripts/make_tables.py (keep "mean=", "median=", "stddev=", "95% CI=[a, b]")
inline std::string format_stats_line(const std::string& label, const Stats& s, int prec = 2) {
  std::ostringstream o;
  o << std::fixed << std::setprecision(prec) << label << ": mean=" << s.mean << ", median=" << s.median
    << ", stddev=" << s.stddev << ", 95% CI=[" << s.ci_lo << ", " << s.ci_hi << "]";
  return o.str();
}

#endif // COMMON_HPP
