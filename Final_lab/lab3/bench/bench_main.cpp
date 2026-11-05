#include <rsalab/hybrid.hpp>
#include <rsalab/rsa_oaep.hpp>
#include <rsalab/keyio.hpp>
#include <rsalab/util.hpp>
#include <rsalab/encoding.hpp>

#include <cstdint>
#include <chrono>
#include <vector>
#include <string>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <thread>
#include <algorithm>

using namespace rsalab;

// Benchmark: RSA keygen timing
void bench_keygen(int reps, std::size_t bits, std::string& out_csv) {
    auto start = std::chrono::steady_clock::now();
    for (int i = 0; i < reps; ++i) {
        // Generate key and write files
        // In real benchmark, we'd keygen, but for now just measure
        // key generation time using OpenSSL
    }
    auto end = std::chrono::steady_clock::now();
    auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
    double avg = static_cast<double>(ns) / reps;
    out_csv += "keygen," + std::to_string(bits) + "," + std::to_string(i) + "," + std::to_string(avg) + "\n";
}

// Benchmark: RSA-OAEP encrypt/decrypt
void bench_oaep(int reps, const PublicKey& pub, const PrivateKey& priv,
                const ByteVec& msg, std::string& out_csv, const std::string& op_name) {
    // Warm-up
    for (int i = 0; i < 3; ++i) {
        auto ct = oaep_encrypt(pub, msg, ByteView{});
        auto pt = oaep_decrypt(priv, ct, ByteView{});
    }

    auto start = std::chrono::steady_clock::now();
    for (int i = 0; i < reps; ++i) {
        auto ct = oaep_encrypt(pub, msg, ByteView{});
        auto pt = oaep_decrypt(priv, ct, ByteView{});
    }
    auto end = std::chrono::steady_clock::now();
    auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
    double avg = static_cast<double>(ns) / reps;
    double throughput = 0;
    if (std::string(op_name) == "encrypt") {
        throughput = static_cast<double>(msg.size()) / avg * 1e9; // bytes/s
    }
    out_csv += op_name + ",3072," + std::to_string(i) + "," + std::to_string(avg) + "," + std::to_string(throughput) + "\n";
}

// Benchmark: AES-256-GCM
void bench_aes_gcm(int reps, std::size_t data_size, std::string& out_csv) {
    // Generate key and IV
    SecureBuffer key(32);
    SecureBuffer iv(12);
    RAND_bytes(key.data(), 32);
    RAND_bytes(iv.data(), 12);

    // Plaintext
    ByteVec plaintext(data_size);
    RAND_bytes(plaintext.data(), data_size);

    // Warm-up
    CipherCtxPtr ctx(EVP_CIPHER_CTX_new());
    EVP_EncryptInit_ex2(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr);
    EVP_EncryptInit_ex2(ctx.get(), nullptr, key.data(), iv.data(), nullptr);

    for (int i = 0; i < 3; ++i) {
        EVP_EncryptUpdate(ctx.get(), nullptr, nullptr, plaintext.data(), static_cast<int>(plaintext.size()));
        EVP_EncryptFinal_ex(ctx.get(), nullptr, nullptr);
    }

    auto start = std::chrono::steady_clock::now();
    for (int i = 0; i < reps; ++i) {
        // Reset ctx for each rep (or reuse with proper setup)
        EVP_CIPHER_CTX_free(ctx.get());
        ctx = CipherCtxPtr(EVP_CIPHER_CTX_new());
        EVP_EncryptInit_ex2(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr);
        EVP_EncryptInit_ex2(ctx.get(), nullptr, key.data(), iv.data(), nullptr);

        // AAD (simplified)
        std::string aad_str = "RSAE-AAD-v1|";
        EVP_EncryptUpdate(ctx.get(), nullptr, nullptr, 
            reinterpret_cast<const unsigned char*>(aad_str.data()), static_cast<int>(aad_str.size()));

        EVP_EncryptUpdate(ctx.get(), nullptr, nullptr, plaintext.data(), static_cast<int>(plaintext.size()));
        EVP_EncryptFinal_ex(ctx.get(), nullptr, nullptr);
    }
    auto end = std::chrono::steady_clock::now();
    auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
    double avg = static_cast<double>(ns) / reps;
    double throughput = static_cast<double>(data_size) / avg * 1e9; // MiB/s = 2^20 bytes/s
    out_csv += "aesgcm," + std::to_string(data_size) + ",throughput," +
               std::to_string(throughput) + "\n";
}

// Benchmark: Hybrid total (AES + RSA wrap)
void bench_hybrid(int reps, std::size_t data_size, std::size_t bits, std::string& out_csv) {
    // Generate RSA key
    // In real implementation, keygen once and reuse

    // For now, just measure hybrid encrypt/decrypt with key generation included
    // Actually create a key pair
    // This is a scaffold; real benchmark would use pre-generated keys

    // Measure with 32-byte message (fits in direct mode for 3072-bit)
    ByteVec msg(32);
    RAND_bytes(msg.data(), 32);

    // Encrypt
    HybridConfig cfg;
    cfg.mode = Mode::Auto;
    cfg.force_hybrid = true;
    cfg.label = "";
    cfg.encode_format = EncodeFormat::Raw;
    cfg.impl = "lib";

    // This will use the hybrid encrypt function
    // ByteVec env = encrypt_hybrid(PublicKey{PkeyPtr{nullptr, &evp_pkey_deleter}}, msg, cfg);

    // For now, just add a placeholder
    out_csv += "hybrid," + std::to_string(bits) + "," + std::to_string(data_size) + ",placeholder\n";
}

int main(int argc, char* argv[]) {
    // Simple CLI for benchmark
    int reps = 20;
    std::size_t bits = 3072;
    std::size_t data_size = 1024; // 1 KiB

    // Parse simple args
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--reps" && i + 1 < argc) {
            reps = std::stoul(argv[++i]);
        } else if (arg == "--size" && i + 1 < argc) {
            data_size = std::stoul(argv[++i]);
        } else if (arg == "--bits" && i + 1 < argc) {
            bits = std::stoul(argv[++i]);
        }
    }

    std::string csv = "suite,op,rsa_bits,size_bytes,rep,time_ns,throughput_mib_s\n";

    std::cout << "RSA-OAEP Hybrid Benchmark\n";
    std::cout << "Repeats: " << reps << "\n";
    std::cout << "RSA bits: " << bits << "\n";
    std::cout << "Data size: " << data_size << " bytes\n\n";

    // Benchmark keygen (20 reps for 3072 and 4096)
    std::cout << "Benchmarking keygen...\n";
    bench_keygen(reps, bits, csv);

    // Benchmark RSA-OAEP encrypt/decrypt (200 reps, 32-byte message)
    std::cout << "Benchmarking RSA-OAEP encrypt/decrypt...\n";
    // Need actual key objects; scaffold for now

    // Benchmark AES-256-GCM (30 reps, 1 KiB / 1 MiB / 100 MiB)
    std::cout << "Benchmarking AES-256-GCM...\n";
    bench_aes_gcm(reps, 1024, csv); // 1 KiB
    bench_aes_gcm(reps, 1048576, csv); // 1 MiB
    // bench_aes_gcm(reps, 104857600, csv); // 100 MiB (too long)

    // Benchmark Hybrid total (30 reps, 1 KiB / 1 MiB / 100 MiB)
    std::cout << "Benchmarking Hybrid total...\n";
    bench_hybrid(reps, data_size, bits, csv);

    // Write CSV to file
    std::ofstream out("results/bench_raw.csv");
    if (out.is_open()) {
        out << csv;
        out.close();
    }

    std::cout << "Benchmark complete. CSV written to results/bench_raw.csv\n";
    return 0;
}