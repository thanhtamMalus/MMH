#include "aes/aes128.hpp"
#include "aes/ctr.hpp"
#include "aes/platform.hpp"
#include "aes/util.hpp"
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <chrono>
#include <algorithm>
#include <numeric>
#include <cstring>
#include <filesystem>
#include <sstream>
#include <iomanip>

namespace {

// Fast pseudo-random generator for generating benchmark test data (SplitMix64)
// NOT FOR CRYPTOGRAPHIC USE!
struct SplitMix64 {
    uint64_t state;
    explicit SplitMix64(uint64_t seed = 0x853c49e6748fea9bULL) : state(seed) {}
    uint64_t next() {
        uint64_t z = (state += 0x9e3779b97f4a7c15ULL);
        z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
        z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
        return z ^ (z >> 31);
    }
    void fill(uint8_t* buf, size_t len) {
        size_t words = len / 8;
        for (size_t i = 0; i < words; ++i) {
            uint64_t val = next();
            std::memcpy(buf + i * 8, &val, 8);
        }
        size_t rem = len % 8;
        if (rem > 0) {
            uint64_t val = next();
            std::memcpy(buf + words * 8, &val, rem);
        }
    }
};

std::string get_os_name() {
#if defined(_WIN32)
    return "Windows";
#elif defined(__linux__)
    return "Linux";
#elif defined(__APPLE__)
    return "macOS";
#else
    return "Unknown_OS";
#endif
}

std::string get_compiler_info(std::string& comp_version) {
#if defined(_MSC_VER)
    comp_version = std::to_string(_MSC_VER);
    return "MSVC";
#elif defined(__clang__)
    comp_version = std::to_string(__clang_major__) + "." + std::to_string(__clang_minor__) + "." + std::to_string(__clang_patchlevel__);
    return "Clang";
#elif defined(__GNUC__)
    comp_version = std::to_string(__GNUC__) + "." + std::to_string(__GNUC_MINOR__) + "." + std::to_string(__GNUC_PATCHLEVEL__);
#if defined(__MINGW64__)
    return "MinGW-w64_GCC";
#elif defined(__MINGW32__)
    return "MinGW_GCC";
#else
    return "GCC";
#endif
#else
    comp_version = "Unknown";
    return "Unknown_Compiler";
#endif
}

std::string get_build_type() {
#if defined(NDEBUG)
    return "Release";
#else
    return "Debug";
#endif
}

uint64_t parse_size(const std::string& str) {
    if (str.empty()) return 0;
    std::string s = str;
    uint64_t mult = 1;
    if (s.size() > 3 && s.substr(s.size() - 3) == "GiB") {
        mult = 1024ULL * 1024ULL * 1024ULL;
        s = s.substr(0, s.size() - 3);
    } else if (s.size() > 3 && s.substr(s.size() - 3) == "MiB") {
        mult = 1024ULL * 1024ULL;
        s = s.substr(0, s.size() - 3);
    } else if (s.size() > 3 && s.substr(s.size() - 3) == "KiB") {
        mult = 1024ULL;
        s = s.substr(0, s.size() - 3);
    } else if (s.size() > 2 && (s.substr(s.size() - 2) == "GB" || s.substr(s.size() - 2) == "gb")) {
        mult = 1000ULL * 1000ULL * 1000ULL;
        s = s.substr(0, s.size() - 2);
    } else if (s.size() > 2 && (s.substr(s.size() - 2) == "MB" || s.substr(s.size() - 2) == "mb")) {
        mult = 1000ULL * 1000ULL;
        s = s.substr(0, s.size() - 2);
    } else if (s.size() > 2 && (s.substr(s.size() - 2) == "KB" || s.substr(s.size() - 2) == "kb")) {
        mult = 1000ULL;
        s = s.substr(0, s.size() - 2);
    }
    return std::stoull(s) * mult;
}

std::vector<uint64_t> parse_size_list(const std::string& arg) {
    std::vector<uint64_t> res;
    std::stringstream ss(arg);
    std::string item;
    while (std::getline(ss, item, ',')) {
        if (!item.empty()) {
            res.push_back(parse_size(item));
        }
    }
    return res;
}

struct RunResult {
    int run_index;
    double seconds;
    double mib_per_s;
};

void run_compute_benchmark(
    uint64_t size_bytes,
    int runs,
    aes::SBoxMode sbox_mode,
    const std::string& sbox_str,
    const std::string& os_name,
    const std::string& compiler_name,
    const std::string& comp_version,
    const std::string& build_type,
    std::ofstream& csv_file
) {
    std::cout << ">>> Running Compute-Only (in-memory) | S-Box: " << sbox_str
              << " | Size: " << (size_bytes / (1024 * 1024)) << " MiB (" << size_bytes << " bytes) <<<\n";

    // Allocate buffer
    std::vector<uint8_t> in_buf(size_bytes);
    std::vector<uint8_t> out_buf(size_bytes);
    SplitMix64 rng(0x12345678ULL + size_bytes);
    rng.fill(in_buf.data(), size_bytes);

    uint8_t key[16] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
    uint8_t iv[16]  = {0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9,0xfa,0xfb,0xfc,0xfd,0xfe,0xff};

    // Warm-up run (discarded)
    std::cout << "  [Warm-up] ... " << std::flush;
    aes::ctr_crypt_buffer(in_buf.data(), out_buf.data(), size_bytes, key, iv, sbox_mode, 128);
    std::cout << "Done.\n";

    std::vector<double> times;
    std::vector<RunResult> results;

    for (int r = 1; r <= runs; ++r) {
        auto t0 = std::chrono::steady_clock::now();
        aes::ctr_crypt_buffer(in_buf.data(), out_buf.data(), size_bytes, key, iv, sbox_mode, 128);
        auto t1 = std::chrono::steady_clock::now();

        double sec = std::chrono::duration<double>(t1 - t0).count();
        double mib_s = (static_cast<double>(size_bytes) / (1024.0 * 1024.0)) / sec;

        times.push_back(sec);
        results.push_back({r, sec, mib_s});

        std::cout << "  Run " << r << "/" << runs << ": "
                  << std::fixed << std::setprecision(4) << sec << " s | "
                  << std::setprecision(2) << mib_s << " MiB/s\n";

        if (csv_file.is_open()) {
            csv_file << os_name << "," << compiler_name << "," << comp_version << ","
                     << build_type << "," << sbox_str << ",compute,"
                     << size_bytes << "," << r << "," << sec << "," << mib_s << "\n";
            csv_file.flush();
        }
    }

    std::sort(times.begin(), times.end());
    double median_sec = times[times.size() / 2];
    double min_sec = times.front();
    double max_sec = times.back();

    double median_mib = (static_cast<double>(size_bytes) / (1024.0 * 1024.0)) / median_sec;
    double max_mib = (static_cast<double>(size_bytes) / (1024.0 * 1024.0)) / min_sec;
    double min_mib = (static_cast<double>(size_bytes) / (1024.0 * 1024.0)) / max_sec;

    std::cout << "  Summary Compute: Median: " << std::setprecision(2) << median_mib
              << " MiB/s | Min: " << min_mib << " MiB/s | Max: " << max_mib << " MiB/s\n\n";
}

void run_e2e_benchmark(
    uint64_t size_bytes,
    int runs,
    aes::SBoxMode sbox_mode,
    const std::string& sbox_str,
    const std::string& workdir,
    const std::string& os_name,
    const std::string& compiler_name,
    const std::string& comp_version,
    const std::string& build_type,
    std::ofstream& csv_file
) {
    std::cout << ">>> Running End-to-End (file -> file) | S-Box: " << sbox_str
              << " | Size: " << (size_bytes / (1024 * 1024)) << " MiB (" << size_bytes << " bytes) <<<\n";

    std::filesystem::path dir(workdir);
    if (!std::filesystem::exists(dir)) {
        std::filesystem::create_directories(dir);
    }

    std::string key_file = (dir / "bench_key.bin").string();
    std::string iv_file  = (dir / "bench_iv.bin").string();
    std::string in_file  = (dir / "bench_in.bin").string();
    std::string out_file = (dir / "bench_out.bin").string();

    uint8_t key[16] = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
    uint8_t iv[16]  = {0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9,0xfa,0xfb,0xfc,0xfd,0xfe,0xff};
    aes::util::write_binary_file(key_file, key, 16);
    aes::util::write_binary_file(iv_file, iv, 16);

    // Create input file with fast streaming
    std::cout << "  Creating test file (" << (size_bytes / (1024 * 1024)) << " MiB) ... " << std::flush;
    {
        std::ofstream stream(in_file, std::ios::binary | std::ios::trunc);
        SplitMix64 rng(0xCAFEBABEULL + size_bytes);
        const size_t chunk_sz = 1024 * 1024;
        std::vector<uint8_t> chunk(chunk_sz);
        uint64_t written = 0;
        while (written < size_bytes) {
            size_t to_write = static_cast<size_t>(std::min(static_cast<uint64_t>(chunk_sz), size_bytes - written));
            rng.fill(chunk.data(), to_write);
            stream.write(reinterpret_cast<const char*>(chunk.data()), to_write);
            written += to_write;
        }
        stream.flush();
    }
    std::cout << "Done.\n";

    // Warm-up run (discarded)
    std::cout << "  [Warm-up] ... " << std::flush;
    aes::ctr_crypt_file(in_file, out_file, key_file, iv_file, sbox_mode, 128);
    std::cout << "Done.\n";

    std::vector<double> times;
    std::vector<RunResult> results;

    for (int r = 1; r <= runs; ++r) {
        auto t0 = std::chrono::steady_clock::now();
        aes::CtrStatus st = aes::ctr_crypt_file(in_file, out_file, key_file, iv_file, sbox_mode, 128);
        auto t1 = std::chrono::steady_clock::now();

        if (st != aes::CtrStatus::Success) {
            std::cerr << "  Error during e2e crypt: " << aes::ctr_status_to_string(st) << "\n";
            break;
        }

        double sec = std::chrono::duration<double>(t1 - t0).count();
        double mib_s = (static_cast<double>(size_bytes) / (1024.0 * 1024.0)) / sec;

        times.push_back(sec);
        results.push_back({r, sec, mib_s});

        std::cout << "  Run " << r << "/" << runs << ": "
                  << std::fixed << std::setprecision(4) << sec << " s | "
                  << std::setprecision(2) << mib_s << " MiB/s\n";

        if (csv_file.is_open()) {
            csv_file << os_name << "," << compiler_name << "," << comp_version << ","
                     << build_type << "," << sbox_str << ",e2e,"
                     << size_bytes << "," << r << "," << sec << "," << mib_s << "\n";
            csv_file.flush();
        }
    }

    // Clean up test files immediately
    std::error_code ec;
    std::filesystem::remove(in_file, ec);
    std::filesystem::remove(out_file, ec);
    std::filesystem::remove(key_file, ec);
    std::filesystem::remove(iv_file, ec);

    if (!times.empty()) {
        std::sort(times.begin(), times.end());
        double median_sec = times[times.size() / 2];
        double min_sec = times.front();
        double max_sec = times.back();

        double median_mib = (static_cast<double>(size_bytes) / (1024.0 * 1024.0)) / median_sec;
        double max_mib = (static_cast<double>(size_bytes) / (1024.0 * 1024.0)) / min_sec;
        double min_mib = (static_cast<double>(size_bytes) / (1024.0 * 1024.0)) / max_sec;

        std::cout << "  Summary E2E: Median: " << std::setprecision(2) << median_mib
                  << " MiB/s | Min: " << min_mib << " MiB/s | Max: " << max_mib << " MiB/s\n\n";
    }
}

} // namespace

int main(int argc, char* argv[]) {
    std::vector<uint64_t> sizes = {1024 * 1024, 100 * 1024 * 1024}; // default 1MiB, 100MiB
    int runs = 5;
    std::string sbox_opt = "both";
    std::string csv_path = "";
    std::string workdir = "./bench_workdir";

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--sizes" && i + 1 < argc) {
            sizes = parse_size_list(argv[++i]);
        } else if (arg == "--runs" && i + 1 < argc) {
            runs = std::max(1, std::stoi(argv[++i]));
        } else if (arg == "--sbox" && i + 1 < argc) {
            sbox_opt = argv[++i];
        } else if (arg == "--csv" && i + 1 < argc) {
            csv_path = argv[++i];
        } else if (arg == "--workdir" && i + 1 < argc) {
            workdir = argv[++i];
        } else if (arg == "--help" || arg == "-h") {
            std::cout << "Usage: aes_bench [--sizes 1MiB,100MiB,1GiB] [--runs 5] [--sbox table|computed|both] [--csv out.csv] [--workdir <dir>]\n";
            return 0;
        }
    }

    std::string comp_version;
    std::string compiler_name = get_compiler_info(comp_version);
    std::string os_name = get_os_name();
    std::string build_type = get_build_type();

    std::cout << "========================================================\n"
              << "AES-128 CTR Mode Benchmark Suite\n"
              << "OS: " << os_name << " | Compiler: " << compiler_name << " " << comp_version
              << " | Build Type: " << build_type << "\n"
              << "Runs: " << runs << " | Working Dir: " << workdir << "\n"
              << "========================================================\n\n";

    std::ofstream csv_file;
    if (!csv_path.empty()) {
        bool write_header = !std::filesystem::exists(csv_path) || std::filesystem::file_size(csv_path) == 0;
        csv_file.open(csv_path, std::ios::app);
        if (write_header) {
            csv_file << "os,compiler,compiler_version,build_type,sbox,mode,size_bytes,run,seconds,mib_per_s\n";
        }
    }

    std::vector<std::pair<aes::SBoxMode, std::string>> sbox_modes;
    if (sbox_opt == "table" || sbox_opt == "both") {
        sbox_modes.push_back({aes::SBoxMode::Table, "table"});
    }
    if (sbox_opt == "computed" || sbox_opt == "both") {
        sbox_modes.push_back({aes::SBoxMode::Computed, "computed"});
    }

    for (const auto& sb : sbox_modes) {
        for (uint64_t sz : sizes) {
            run_compute_benchmark(sz, runs, sb.first, sb.second, os_name, compiler_name, comp_version, build_type, csv_file);
            run_e2e_benchmark(sz, runs, sb.first, sb.second, workdir, os_name, compiler_name, comp_version, build_type, csv_file);
        }
    }

    if (csv_file.is_open()) {
        csv_file.close();
        std::cout << "Results saved to: " << csv_path << "\n";
    }

    return 0;
}
