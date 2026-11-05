#include <rsalab/cli.hpp>
#include <rsalab/encoding.hpp>
#include <rsalab/util.hpp>
#include <iostream>
#include <string>
#include <vector>
#include <cstdlib>

namespace rsalab {

CliResult parse_keygen(int argc, const char* const* argv, KeygenOptions& opts) {
    CliResult result;

    // keygen --bits <n> --pub <path> --priv <path>
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--bits" && i + 1 < argc) {
            try {
                opts.bits = std::stoul(argv[++i]);
            } catch (...) {
                result.status = CliResult::Status::Usage;
                result.message = "Invalid --bits value";
                return result;
            }
            if (opts.bits < 3072) {
                result.status = CliResult::Status::Usage;
                result.message = "Key size must be >= 3072 (use --allow-weak-for-test to override)";
                return result;
            }
        } else if (arg == "--pub" && i + 1 < argc) {
            opts.pub_path = argv[++i];
        } else if (arg == "--priv" && i + 1 < argc) {
            opts.priv_path = argv[++i];
        } else {
            result.status = CliResult::Status::Usage;
            result.message = "Unknown keygen argument: " + arg;
            return result;
        }
    }

    // Validate required arguments
    if (opts.bits == 0) {
        result.status = CliResult::Status::Usage;
        result.message = "Missing --bits argument for keygen";
        return result;
    }
    if (opts.pub_path.empty()) {
        result.status = CliResult::Status::Usage;
        result.message = "Missing --pub argument for keygen";
        return result;
    }
    if (opts.priv_path.empty()) {
        result.status = CliResult::Status::Usage;
        result.message = "Missing --priv argument for keygen";
        return result;
    }

    return result;
}

CliResult parse_encrypt(int argc, const char* const* argv, EncryptOptions& opts) {
    CliResult result;

    // encrypt --in <file> --pub <file> --out <file> [--label TEXT] [--encode raw|hex|base64] [--force-hybrid] [--impl lib|manual]
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--in" && i + 1 < argc) {
            opts.in_path = argv[++i];
        } else if (arg == "--pub" && i + 1 < argc) {
            opts.pub_path = argv[++i];
        } else if (arg == "--out" && i + 1 < argc) {
            opts.out_path = argv[++i];
        } else if (arg == "--label" && i + 1 < argc) {
            opts.label = argv[++i];
        } else if (arg == "--encode" && i + 1 < argc) {
            opts.encode_format = parse_encode_format(argv[++i]);
        } else if (arg == "--force-hybrid") {
            opts.force_hybrid = true;
        } else if (arg == "--impl" && i + 1 < argc) {
            opts.impl = argv[++i];
        } else {
            result.status = CliResult::Status::Usage;
            result.message = "Unknown encrypt argument: " + arg;
            return result;
        }
    }

    // Validate required arguments
    if (opts.in_path.empty()) {
        result.status = CliResult::Status::Usage;
        result.message = "Missing --in argument for encrypt";
        return result;
    }
    if (opts.pub_path.empty()) {
        result.status = CliResult::Status::Usage;
        result.message = "Missing --pub argument for encrypt";
        return result;
    }
    if (opts.out_path.empty()) {
        result.status = CliResult::Status::Usage;
        result.message = "Missing --out argument for encrypt";
        return result;
    }

    return result;
}

CliResult parse_decrypt(int argc, const char* const* argv, DecryptOptions& opts) {
    CliResult result;

    // decrypt --in <file> --priv <file> --out <file> [--label TEXT] [--encode raw|hex|base64]
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--in" && i + 1 < argc) {
            opts.in_path = argv[++i];
        } else if (arg == "--priv" && i + 1 < argc) {
            opts.priv_path = argv[++i];
        } else if (arg == "--out" && i + 1 < argc) {
            opts.out_path = argv[++i];
        } else if (arg == "--label" && i + 1 < argc) {
            opts.label = argv[++i];
        } else if (arg == "--encode" && i + 1 < argc) {
            opts.encode_format = parse_encode_format(argv[++i]);
        } else {
            result.status = CliResult::Status::Usage;
            result.message = "Unknown decrypt argument: " + arg;
            return result;
        }
    }

    // Validate required arguments
    if (opts.in_path.empty()) {
        result.status = CliResult::Status::Usage;
        result.message = "Missing --in argument for decrypt";
        return result;
    }
    if (opts.priv_path.empty()) {
        result.status = CliResult::Status::Usage;
        result.message = "Missing --priv argument for decrypt";
        return result;
    }
    if (opts.out_path.empty()) {
        result.status = CliResult::Status::Usage;
        result.message = "Missing --out argument for decrypt";
        return result;
    }

    return result;
}

void print_help() {
    std::cout << "rsatool - RSA-OAEP & Hybrid Encryption Tool (OpenSSL 4.x)\n\n";
    std::cout << "Usage:\n";
    std::cout << "  keygen --bits <n> --pub <path> --priv <path>\n";
    std::cout << "  encrypt --in <file> --pub <file> --out <file> [options]\n";
    std::cout << "  decrypt --in <file> --priv <file> --out <file> [options]\n\n";
    std::cout << "Keygen options:\n";
    std::cout << "  --bits <n>        Key size in bits (>= 3072, default: 3072 for test, 4096 recommended)\n";
    std::cout << "  --pub <path>      Output public key file (PEM)\n";
    std::cout << "  --priv <path>     Output private key file (PKCS#8 PEM)\n\n";
    std::cout << "Encrypt options:\n";
    std::cout << "  --in <file>       Input plaintext file\n";
    std::cout << "  --pub <file>      Public key file\n";
    std::cout << "  --out <file>      Output ciphertext file\n";
    std::cout << "  --label TEXT      OAEP label (UTF-8, default: empty)\n";
    std::cout << "  --encode FORMAT   Output format: raw | hex | base64 (default: raw)\n";
    std::cout << "  --force-hybrid    Force hybrid mode (AES-256-GCM envelope)\n";
    std::cout << "  --impl LIB|MANUAL Use OAEP implementation: lib (EVP) or manual\n\n";
    std::cout << "Decrypt options:\n";
    std::cout << "  --in <file>       Input ciphertext file\n";
    std::cout << "  --priv <file>     Private key file (PKCS#8 PEM)\n";
    std::cout << "  --out <file>      Output plaintext file\n";
    std::cout << "  --label TEXT      OAEP label (must match encrypt label, default: empty)\n";
    std::cout << "  --encode FORMAT   Input format: raw | hex | base64 (default: raw)\n\n";
    std::cout << "Supported formats: raw, hex, base64\n";
}

EncodeFormat parse_encode_format(const std::string& str) {
    if (str == "raw" || str == "RAW") return EncodeFormat::Raw;
    if (str == "hex" || str == "HEX") return EncodeFormat::Hex;
    if (str == "base64" || str == "BASE64") return EncodeFormat::Base64;
    throw std::invalid_argument("Unknown encode format: " + str);
}

Mode parse_mode(const std::string& str) {
    if (str == "auto" || str == "Auto" || str == "AUTO") return Mode::Auto;
    if (str == "direct" || str == "Direct" || str == "DIRECT") return Mode::Direct;
    if (str == "hybrid" || str == "Hybrid" || str == "HYBRID") return Mode::Hybrid;
    throw std::invalid_argument("Unknown mode: " + str);
}

} // namespace rsalab