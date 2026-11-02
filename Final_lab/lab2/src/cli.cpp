#include "aes/cli.hpp"
#include "aes/ctr.hpp"
#include "aes/platform.hpp"
#include "aes/util.hpp"
#include <iostream>
#include <string>
#include <vector>

namespace aes {
int run_kat_from_file(const std::string& filepath);

namespace cli {

void print_help(const char* prog_name) {
    std::cout << "Lab 2: Pure C++ AES-128 (CTR Mode) - FIPS-197 & NIST SP 800-38A Compliant\n"
              << "Usage:\n"
              << "  " << prog_name << " encrypt --mode ctr --key <key.bin> --iv <iv.bin> --in <in.bin> --out <out.bin> [--sbox table|computed] [--bits 128|192|256]\n"
              << "  " << prog_name << " decrypt --mode ctr --key <key.bin> --iv <iv.bin> --in <in.bin> --out <out.bin> [--sbox table|computed] [--bits 128|192|256]\n"
              << "  " << prog_name << " --kat <vectors.json>\n"
              << "  " << prog_name << " keygen --out <key.bin> [--bits 128|192|256]\n"
              << "  " << prog_name << " ivgen --out <iv.bin>\n"
              << "  " << prog_name << " --help / -h\n\n"
              << "Exit Codes:\n"
              << "  0: Success\n"
              << "  1: Argument error\n"
              << "  2: Key / IV error (invalid size or format)\n"
              << "  3: I/O error (cannot read/write file)\n"
              << "  4: Counter overflow (128-bit counter overflowed)\n"
              << "  5: KAT failure\n\n"
              << "================================== SECURITY WARNING ==================================\n"
              << "CRITICAL: NEVER REUSE THE SAME (KEY, IV) PAIR TO ENCRYPT MULTIPLE MESSAGES!\n"
              << "Reusing (Key, IV) in CTR mode produces identical keystreams (two-time pad vulnerability).\n"
              << "An attacker intercepting C1 and C2 can compute C1 ^ C2 = P1 ^ P2 and recover plaintexts.\n"
              << "======================================================================================\n";
}

int run(const std::vector<std::string>& args) {
    if (args.empty()) {
        std::cerr << "Error: No command specified.\n";
        print_help("aestool");
        return 1;
    }

    const std::string& cmd = args[0];

    if (cmd == "--help" || cmd == "-h" || cmd == "help") {
        print_help("aestool");
        return 0;
    }

    if (cmd == "--kat") {
        if (args.size() < 2) {
            std::cerr << "Error: Missing path to vectors.json for --kat.\n";
            return 1;
        }
        return run_kat_from_file(args[1]);
    }

    if (cmd == "keygen") {
        std::string out_file;
        size_t bits = 128;
        for (size_t i = 1; i < args.size(); ++i) {
            if (args[i] == "--out" && i + 1 < args.size()) {
                out_file = args[++i];
            } else if (args[i] == "--bits" && i + 1 < args.size()) {
                bits = static_cast<size_t>(std::stoi(args[++i]));
            } else {
                std::cerr << "Error: Unknown argument for keygen: " << args[i] << "\n";
                return 1;
            }
        }
        if (out_file.empty()) {
            std::cerr << "Error: --out is required for keygen.\n";
            return 1;
        }
        if (bits != 128 && bits != 192 && bits != 256) {
            std::cerr << "Error: Key length must be 128, 192, or 256 bits.\n";
            return 1;
        }
        size_t key_len = bits / 8;
        std::vector<uint8_t> key_buf(key_len);
        if (!platform::secure_random(key_buf.data(), key_len)) {
            std::cerr << "Error: OS CSPRNG failed to generate random key.\n";
            platform::secure_zero(key_buf.data(), key_len);
            return 2;
        }
        if (!util::write_binary_file(out_file, key_buf.data(), key_len)) {
            std::cerr << "Error: Failed to write key to " << out_file << "\n";
            platform::secure_zero(key_buf.data(), key_len);
            return 3;
        }
        platform::secure_zero(key_buf.data(), key_len);
        return 0;
    }

    if (cmd == "ivgen") {
        std::string out_file;
        for (size_t i = 1; i < args.size(); ++i) {
            if (args[i] == "--out" && i + 1 < args.size()) {
                out_file = args[++i];
            } else {
                std::cerr << "Error: Unknown argument for ivgen: " << args[i] << "\n";
                return 1;
            }
        }
        if (out_file.empty()) {
            std::cerr << "Error: --out is required for ivgen.\n";
            return 1;
        }
        uint8_t iv_buf[16];
        if (!platform::secure_random(iv_buf, 16)) {
            std::cerr << "Error: OS CSPRNG failed to generate random IV.\n";
            platform::secure_zero(iv_buf, 16);
            return 2;
        }
        if (!util::write_binary_file(out_file, iv_buf, 16)) {
            std::cerr << "Error: Failed to write IV to " << out_file << "\n";
            platform::secure_zero(iv_buf, 16);
            return 3;
        }
        platform::secure_zero(iv_buf, 16);
        return 0;
    }

    if (cmd == "encrypt" || cmd == "decrypt") {
        std::string mode_str;
        std::string key_file;
        std::string iv_file;
        std::string in_file;
        std::string out_file;
        std::string sbox_str = "table";
        size_t key_bits = 128;

        for (size_t i = 1; i < args.size(); ++i) {
            if (args[i] == "--mode" && i + 1 < args.size()) {
                mode_str = args[++i];
            } else if (args[i] == "--key" && i + 1 < args.size()) {
                key_file = args[++i];
            } else if (args[i] == "--iv" && i + 1 < args.size()) {
                iv_file = args[++i];
            } else if (args[i] == "--in" && i + 1 < args.size()) {
                in_file = args[++i];
            } else if (args[i] == "--out" && i + 1 < args.size()) {
                out_file = args[++i];
            } else if (args[i] == "--sbox" && i + 1 < args.size()) {
                sbox_str = args[++i];
            } else if (args[i] == "--bits" && i + 1 < args.size()) {
                key_bits = static_cast<size_t>(std::stoi(args[++i]));
            } else {
                std::cerr << "Error: Unknown argument: " << args[i] << "\n";
                return 1;
            }
        }

        if (mode_str != "ctr") {
            std::cerr << "Error: Only '--mode ctr' is supported.\n";
            return 1;
        }
        if (key_file.empty() || iv_file.empty() || in_file.empty() || out_file.empty()) {
            std::cerr << "Error: Missing required arguments (--key, --iv, --in, --out).\n";
            return 1;
        }

        SBoxMode sbox_mode = (sbox_str == "computed") ? SBoxMode::Computed : SBoxMode::Table;
        if (sbox_str != "table" && sbox_str != "computed") {
            std::cerr << "Error: Invalid sbox mode '" << sbox_str << "'. Use 'table' or 'computed'.\n";
            return 1;
        }

        CtrStatus status = ctr_crypt_file(in_file, out_file, key_file, iv_file, sbox_mode, key_bits);
        if (status != CtrStatus::Success) {
            std::cerr << "Error: " << ctr_status_to_string(status) << "\n";
            return static_cast<int>(status);
        }
        return 0;
    }

    std::cerr << "Error: Unknown command '" << cmd << "'.\n";
    print_help("aestool");
    return 1;
}

int run(int argc, char* argv[]) {
    std::vector<std::string> args;
    for (int i = 1; i < argc; ++i) {
        args.emplace_back(argv[i]);
    }
    return run(args);
}

} // namespace cli
} // namespace aes
