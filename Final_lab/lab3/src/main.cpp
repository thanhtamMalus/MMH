// main.cpp — CLI entry point for rsatool
// Subcommands: keygen, encrypt, decrypt. Uses CLI11 for argument parsing.
// All crypto errors exit non-zero with a generic message.
#include "errors.hpp"
#include "keys.hpp"
#include "envelope.hpp"
#include "platform.hpp"

#include <CLI/CLI.hpp>

#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <string>

int main(int argc, char* argv[]) {
    CLI::App app{"rsatool — RSA-OAEP and Hybrid Encryption Tool", "rsatool"};
    app.require_subcommand(1);

    // ── keygen ────────────────────────────────────────────────────────────────
    auto* keygen = app.add_subcommand("keygen", "Generate RSA key pair");
    int   bits_opt = 3072;
    std::string pub_path  = "pub.pem";
    std::string priv_path = "priv.pem";

    keygen->add_option("--bits", bits_opt, "RSA modulus bits (3072 or 4096)")
          ->default_val(3072);
    keygen->add_option("--pub",  pub_path,  "Public key output path (PEM)")
          ->default_val("pub.pem");
    keygen->add_option("--priv", priv_path, "Private key output path (PEM)")
          ->default_val("priv.pem");

    keygen->callback([&]() {
        try {
            rsatool::keys::validate_bits(bits_opt);

            auto pub_p  = rsatool::platform::from_utf8(pub_path);
            auto priv_p = rsatool::platform::from_utf8(priv_path);

            std::cerr << "Generating RSA-" << bits_opt << " key pair...\n";
            auto key = rsatool::keys::generate_key(bits_opt);

            rsatool::keys::write_public_pem(key.get(),  pub_p);
            rsatool::keys::write_private_pem(key.get(), priv_p);

            // DER versions alongside PEM
            auto pub_der  = pub_p.parent_path()  / (pub_p.stem().string()  + ".der");
            auto priv_der = priv_p.parent_path() / (priv_p.stem().string() + ".der");
            rsatool::keys::write_public_der(key.get(),  pub_der);
            rsatool::keys::write_private_der(key.get(), priv_der);

            // meta.json in same directory as private key
            rsatool::keys::write_meta_json(priv_p.parent_path(), bits_opt);

            std::cerr << "Public key  -> " << pub_p.string()   << "\n";
            std::cerr << "Private key -> " << priv_p.string()  << "\n";
            std::cerr << "Public DER  -> " << pub_der.string() << "\n";
            std::cerr << "Private DER -> " << priv_der.string()<< "\n";
            std::cerr << "Metadata    -> " << (priv_p.parent_path() / "meta.json").string() << "\n";
        } catch (const rsatool::UsageError& e) {
            std::cerr << e.what() << "\n";
            std::exit(1);
        } catch (const rsatool::CryptoError& e) {
            std::cerr << e.what() << "\n";
            std::exit(1);
        } catch (const std::exception& e) {
            std::cerr << "error: " << e.what() << "\n";
            std::exit(1);
        }
    });

    // ── encrypt ───────────────────────────────────────────────────────────────
    auto* encrypt_cmd = app.add_subcommand("encrypt", "Encrypt a file (RSA-OAEP or hybrid)");
    std::string enc_in, enc_pub, enc_out;
    std::string enc_label, enc_encode = "raw", enc_mode = "auto";

    encrypt_cmd->add_option("--in",     enc_in,  "Input plaintext file")->required();
    encrypt_cmd->add_option("--pub",    enc_pub, "Public key (PEM or DER)")->required();
    encrypt_cmd->add_option("--out",    enc_out, "Output ciphertext file")->required();
    encrypt_cmd->add_option("--label",  enc_label, "Optional OAEP label");
    encrypt_cmd->add_option("--encode", enc_encode, "Output encoding: raw, hex, base64")
               ->default_val("raw");
    encrypt_cmd->add_option("--mode",   enc_mode, "Encryption mode: auto, direct, hybrid")
               ->default_val("auto");

    encrypt_cmd->callback([&]() {
        try {
            rsatool::envelope::encrypt_file(
                rsatool::platform::from_utf8(enc_in),
                rsatool::platform::from_utf8(enc_out),
                rsatool::platform::from_utf8(enc_pub),
                enc_label,
                enc_encode,
                enc_mode);
            std::cerr << "Encrypted -> " << enc_out << "\n";
        } catch (const rsatool::UsageError& e) {
            std::cerr << e.what() << "\n";
            std::exit(1);
        } catch (const rsatool::CryptoError& e) {
            std::cerr << "error: decryption failed\n";
            std::exit(1);
        } catch (const rsatool::FormatError& e) {
            std::cerr << e.what() << "\n";
            std::exit(1);
        } catch (const std::exception& e) {
            std::cerr << "error: " << e.what() << "\n";
            std::exit(1);
        }
    });

    // ── decrypt ───────────────────────────────────────────────────────────────
    auto* decrypt_cmd = app.add_subcommand("decrypt", "Decrypt an envelope file");
    std::string dec_in, dec_priv, dec_out;
    std::string dec_label, dec_encode = "raw";

    decrypt_cmd->add_option("--in",     dec_in,   "Input ciphertext file")->required();
    decrypt_cmd->add_option("--priv",   dec_priv, "Private key (PEM or DER)")->required();
    decrypt_cmd->add_option("--out",    dec_out,  "Output plaintext file")->required();
    decrypt_cmd->add_option("--label",  dec_label, "Optional OAEP label (must match encrypt)");
    decrypt_cmd->add_option("--encode", dec_encode, "Input encoding: raw, hex, base64")
               ->default_val("raw");

    decrypt_cmd->callback([&]() {
        try {
            rsatool::envelope::decrypt_file(
                rsatool::platform::from_utf8(dec_in),
                rsatool::platform::from_utf8(dec_out),
                rsatool::platform::from_utf8(dec_priv),
                dec_label,
                dec_encode);
            std::cerr << "Decrypted -> " << dec_out << "\n";
        } catch (const rsatool::CryptoError&) {
            // Always generic message for crypto failures
            std::cerr << "error: decryption failed\n";
            std::exit(1);
        } catch (const rsatool::FormatError& e) {
            std::cerr << e.what() << "\n";
            std::exit(1);
        } catch (const rsatool::UsageError& e) {
            std::cerr << e.what() << "\n";
            std::exit(1);
        } catch (const std::exception& e) {
            std::cerr << "error: " << e.what() << "\n";
            std::exit(1);
        }
    });

    CLI11_PARSE(app, argc, argv);
    return 0;
}

