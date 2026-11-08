// bench.cpp — Benchmarks for RSA keygen, OAEP encrypt/decrypt, AES-GCM throughput
// Outputs CSV to bench/results/. Build in Release (-O2).
// Warm-up: 3 reps. Main: >= 30 reps for fast ops, >= 10 for slow (RSA keygen/100MiB).
#include <rsatool/keys.hpp>
#include <rsatool/oaep.hpp>
#include <rsatool/hybrid.hpp>
#include <rsatool/envelope.hpp>
#include <rsatool/secure.hpp>
#include <rsatool/errors.hpp>
#include <rsatool/envelope.hpp>

#include <openssl/rand.h>

#include <chrono>
#include <cmath>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <numeric>
#include <string>
#include <vector>

using namespace rsatool;   // keys::, oaep::, hybrid::, envelope::

using Clock = std::chrono::steady_clock;
using Dur   = std::chrono::duration<double, std::micro>;  // microseconds

// ── Stats helpers ─────────────────────────────────────────────────────────────
static double mean(const std::vector<double>& v) {
    return std::accumulate(v.begin(), v.end(), 0.0) / static_cast<double>(v.size());
}

static double variance(const std::vector<double>& v, double m) {
    double s = 0.0;
    for (auto x : v) s += (x - m) * (x - m);
    return s / static_cast<double>(v.size() - 1);
}

// Student t 95% CI half-width: t_{n-1,0.975} * stddev / sqrt(n)
// Using conservative t=2.045 for n=30, good enough for n>10
static double ci95(const std::vector<double>& v, double m) {
    if (v.size() < 2) return 0.0;
    double sd = std::sqrt(variance(v, m));
    double t  = 2.045;  // 95% CI, df=29
    return t * sd / std::sqrt(static_cast<double>(v.size()));
}

static std::vector<uint8_t> rand_vec(std::size_t n) {
    std::vector<uint8_t> v(n);
    RAND_bytes(v.data(), static_cast<int>(n));
    return v;
}

// ── CSV writer ────────────────────────────────────────────────────────────────
struct CSV {
    std::ofstream f;
    explicit CSV(const std::string& path) : f(path) {
        f << "benchmark,size_bytes,bits,mean_us,ci95_us,throughput_MiB_s\n";
    }
    void write(const std::string& name, std::size_t size, int bits,
               double m_us, double ci_us) {
        double tp = (m_us > 0 && size > 0)
                    ? (static_cast<double>(size) / (1024.0 * 1024.0)) / (m_us / 1e6)
                    : 0.0;
        f << name << "," << size << "," << bits << ","
          << std::fixed << std::setprecision(3) << m_us << ","
          << ci_us << "," << tp << "\n";
    }
};

// ── Benchmark runners ─────────────────────────────────────────────────────────

template<typename F>
std::vector<double> run_bench(F&& fn, int warmup, int reps) {
    for (int i = 0; i < warmup; ++i) fn();
    std::vector<double> times;
    times.reserve(static_cast<std::size_t>(reps));
    for (int i = 0; i < reps; ++i) {
        auto t0 = Clock::now();
        fn();
        auto t1 = Clock::now();
        times.push_back(Dur(t1 - t0).count());
    }
    return times;
}

int main() {
    namespace fs = std::filesystem;

    // Ensure results directory exists (relative to executable location)
    fs::path results_dir = fs::path("bench") / "results";
    fs::create_directories(results_dir);
    std::string csv_path = (results_dir / "bench_results.csv").string();

    CSV csv(csv_path);
    std::cout << "rsatool benchmark — writing results to " << csv_path << "\n\n";

    // ── RSA key generation ────────────────────────────────────────────────────
    for (int bits : {3072, 4096}) {
        std::cout << "RSA-" << bits << " keygen (100 reps, slow)...\n";
        auto times = run_bench([&]{ keys::generate_key(bits); }, 1, 100);
        double m = mean(times), ci = ci95(times, m);
        csv.write("keygen", 0, bits, m, ci);
        std::cout << "  mean=" << m/1000.0 << " ms  CI95±" << ci/1000.0 << " ms\n";
    }

    // ── RSA-OAEP encrypt & decrypt ────────────────────────────────────────────
    for (int bits : {3072, 4096}) {
        std::cout << "\nRSA-" << bits << " OAEP encrypt/decrypt (100 reps)...\n";
        auto key = keys::generate_key(bits);
        auto pt  = rand_vec(32);  // small plaintext

        // Encrypt
        auto enc_times = run_bench([&]{
            oaep::encrypt(key.get(), pt.data(), pt.size());
        }, 3, 100);
        double em = mean(enc_times), eci = ci95(enc_times, em);
        csv.write("oaep_encrypt", pt.size(), bits, em, eci);
        std::cout << "  encrypt: mean=" << em << " µs  CI95±" << eci << " µs\n";

        // Pre-encrypt for decrypt benchmark
        auto ct = oaep::encrypt(key.get(), pt.data(), pt.size());

        // Decrypt
        auto dec_times = run_bench([&]{
            oaep::decrypt(key.get(), ct.data(), ct.size());
        }, 3, 100);
        double dm = mean(dec_times), dci = ci95(dec_times, dm);
        csv.write("oaep_decrypt", pt.size(), bits, dm, dci);
        std::cout << "  decrypt: mean=" << dm << " µs  CI95±" << dci << " µs\n";
        std::cout << "  decrypt/encrypt ratio: " << dm/em << "x (private exp is slower)\n";
    }

    // ── AES-256-GCM throughput ────────────────────────────────────────────────
    struct SizeCase { const char* label; std::size_t bytes; int reps; };
    SizeCase cases[] = {
        {"aes_gcm_1KiB",   1024,                100},
        {"aes_gcm_1MiB",   1024*1024,            100},
        {"aes_gcm_100MiB", 100ull*1024*1024,     100},
    };

    std::vector<uint8_t> aad = {0xAA, 0xBB, 0xCC};

    for (auto& c : cases) {
        std::cout << "\nAES-256-GCM encrypt " << c.label << " (" << c.reps << " reps)...\n";
        auto data = rand_vec(c.bytes);

        auto enc_times = run_bench([&]{
            hybrid::encrypt_mem(data.data(), data.size(), aad);
        }, 2, c.reps);

        double em = mean(enc_times), eci = ci95(enc_times, em);
        double tp = (static_cast<double>(c.bytes) / (1024.0*1024.0)) / (em / 1e6);
        csv.write(c.label, c.bytes, 256, em, eci);
        std::cout << "  mean=" << em/1000.0 << " ms  " << tp << " MiB/s  CI95±"
                  << eci/1000.0 << " ms\n";
    }

    // ── Hybrid total time ─────────────────────────────────────────────────────
    struct HybridCase { const char* label; std::size_t bytes; int reps; };
    HybridCase hcases[] = {
        {"hybrid_1KiB",   1024,            100},
        {"hybrid_1MiB",   1024*1024,       100},
        {"hybrid_100MiB", 100ull*1024*1024, 100},
    };

    auto key3072 = keys::generate_key(3072);
    // We need pub/priv PEM files for envelope; use temp files
    auto tmpdir = fs::temp_directory_path() / "rsatool_bench";
    fs::create_directories(tmpdir);
    auto pub_pem  = tmpdir / "pub.pem";
    auto priv_pem = tmpdir / "priv.pem";
    keys::write_public_pem(key3072.get(),  pub_pem);
    keys::write_private_pem(key3072.get(), priv_pem);

    for (auto& c : hcases) {
        std::cout << "\nHybrid encrypt+decrypt " << c.label << " (" << c.reps << " reps)...\n";

        auto data = rand_vec(c.bytes);
        auto in_f  = tmpdir / "in.bin";
        auto ct_f  = tmpdir / "ct.bin";
        auto out_f = tmpdir / "out.bin";

        {
            std::ofstream ofs(in_f, std::ios::binary);
            ofs.write(reinterpret_cast<const char*>(data.data()),
                       static_cast<std::streamsize>(data.size()));
        }

        auto times = run_bench([&]{
            rsatool::envelope::encrypt_file(in_f, ct_f, pub_pem, "", "raw", "hybrid");
            rsatool::envelope::decrypt_file(ct_f, out_f, priv_pem, "", "raw");
        }, 1, c.reps);

        double m = mean(times), ci = ci95(times, m);
        csv.write(c.label, c.bytes, 3072, m, ci);
        double tp = (static_cast<double>(c.bytes) / (1024.0*1024.0)) / (m / 1e6);
        std::cout << "  mean=" << m/1000.0 << " ms  " << tp << " MiB/s  CI95±"
                  << ci/1000.0 << " ms\n";
    }

    fs::remove_all(tmpdir);

    std::cout << "\nDone. Results written to " << csv_path << "\n";
    return 0;
}

