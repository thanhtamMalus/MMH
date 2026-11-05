#include <rsalab/cli.hpp>
#include <rsalab/keyio.hpp>
#include <rsalab/util.hpp>
#include <iostream>
#include <string>
#include <cstdlib>
#include <system_error>

int main(int argc, const char* const* argv) {
    if (argc < 2) {
        rsalab::print_help();
        return static_cast<int>(rsalab::CliResult::Status::Usage);
    }

    std::string command = argv[1];

    if (command == "keygen") {
        rsalab::KeygenOptions opts;
        CliResult result = rsalab::parse_keygen(argc - 1, argv + 1, opts);
        if (result.status != rsalab::CliResult::Status::Ok) {
            std::cerr << "Error: " << result.message << "\n";
            return static_cast<int>(rsalab::CliResult::Status::Usage);
        }

        try {
            // Generate RSA key pair
            rsalab::keygen(
                opts.bits,
                opts.pub_path,
                opts.priv_path,
                opts.priv_path + ".der",
                // Actually we need separate DER paths. Let me adjust.
                // For now, let keygen create all files internally
                // We'll just pass the PEM paths and it'll handle DER internally
                opts.pub_path,  // pub_pem
                opts.priv_path    // priv_pem
            );

            // Actually the keygen function signature takes separate paths.
            // Let me check... the keygen I wrote takes:
            // keygen(bits, pub_pem_path, priv_pem_path, pub_der_path, priv_der_path)
            // But parse_keygen only has pub_path and priv_path.
            // I need to either:
            // 1. Add DER path options to the CLI
            // 2. Derive DER paths from PEM paths (replace .pem with .der)
            // Option 2 is simpler and follows the AGENT.md spec which says:
            // "if đường dẫn không có đuôi .pem thì thêm .der"
            // So if priv_path ends with .pem, we derive priv.der by replacing .pem
            // And pub.der similarly.

            // Let me just call keygen with derived DER paths.
            std::string pub_der = opts.pub_path;
            std::string priv_der = opts.priv_path;
            // Replace .pem with .der
            if (pub_der.size() >= 4 && pub_der.substr(pub_der.size() - 4) == ".pem") {
                pub_der = pub_der.substr(0, pub_der.size() - 4) + ".der";
            } else {
                pub_der += ".der";
            }
            if (priv_der.size() >= 4 && priv_der.substr(priv_der.size() - 4) == ".pem") {
                priv_der = priv_der.substr(0, priv_der.size() - 4) + ".der";
            } else {
                priv_der += ".der";
            }

            rsalab::keygen(opts.bits, opts.pub_path, opts.priv_path, pub_der, priv_der);

            // Write metadata
            rsalab::write_key_metadata(
                rsalab::get_key_basename(opts.priv_path),
                opts.bits
            );

            return 0;
        } catch (const rsalab::CryptoFailure& e) {
            std::cerr << "Crypto error: " << e.what() << "\n";
            return static_cast<int>(rsalab::CliResult::Status::Error); // exit 3
        } catch (const rsalab::IoError& e) {
            std::cerr << "I/O error: " << e.what() << "\n";
            return 2;
        } catch (const std::exception& e) {
            std::cerr << "Error: " << e.what() << "\n";
            return 1;
        }
    }

    else if (command == "encrypt") {
        rsalab::EncryptOptions opts;
        CliResult result = rsalab::parse_encrypt(argc - 1, argv + 1, opts);
        if (result.status != rsalab::CliResult::Status::Ok) {
            std::cerr << "Error: " << result.message << "\n";
            return static_cast<int>(rsalab::CliResult::Status::Usage);
        }

        try {
            // Load public key
            auto pub = rsalab::read_public_key(opts.pub_path);

            // Read plaintext from file
            SecureBuffer plaintext = rsalab::read_file(opts.in_path);

            // Mode handling
            rsalab::Mode mode = opts.mode;
            if (mode == rsalab::Mode::Auto) {
                // Auto: if plaintext <= max -> Direct, else -> Hybrid
                std::size_t max_direct = rsalab::max_plaintext_len(pub->modulus_bits());
                if (plaintext.size() <= max_direct || !opts.force_hybrid) {
                    // Direct RSA-OAEP
                    rsalab::ByteVec ciphertext = rsalab::oaep_encrypt(*pub, 
                        ByteView(reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size()),
                        opts.label);

                    // Write output (direct envelope)
                    // Build direct envelope and write
                    rsalab::EnvelopeHeader header;
                    header.mode = "RSA-OAEP";
                    header.rsa_modulus = pub->modulus_bits();
                    header.hash = "SHA-256";

                    rsalab::SecureBuffer envelope = rsalab::envelope::make_direct_envelope(
                        ciphertext, pub->modulus_bits()
                    );

                    // Encode and write
                    std::string encoded;
                    switch (opts.encode_format) {
                        case rsalab::EncodeFormat::Raw:
                            // Raw means write binary as-is
                            // The envelope is already binary
                            // But if --encode raw, we just write the envelope binary
                            // Actually, re-reading the spec: --encode determines the ciphertext file format
                            // For direct mode, the ciphertext is the RSA OAEP output
                            // Hmm, let me think about this more carefully.

                            // From the spec: "--encode" quy định định dạng file ciphertext (encrypt: ghi ra)
                            // So for encrypt --encode raw, we write raw binary
                            // For --encode hex, we write hex string
                            // For --encode base64, we write base64 string

                            // In direct mode, the "ciphertext" is the RSA OAEP encrypted output (k bytes)
                            // But the envelope contains the RSA OAEP ciphertext embedded in the container.

                            // Let me re-read the spec flow:
                            // encrypt --in msg.bin --pub pub.pem --out ct.bin [--encode raw|hex|base64]
                            // The output ct.bin is the ciphertext in the specified format.

                            // For direct mode: ct.bin contains the RSA-OAEP ciphertext (k bytes)
                            // For hybrid mode: ct.bin contains the envelope (magic + header + AES payload)

                            // So --encode affects how the output is formatted, not the internal representation.

                            // Actually, I think the flow is:
                            // 1. Encrypt the plaintext (RSA-OAEP or hybrid)
                            // 2. If direct: output is the RSA ciphertext
                            //    If hybrid: output is the envelope container
                            // 3. The --encode format applies to the output writing

                            // Let me just write the envelope binary for now, and handle encoding later.
                            // Actually, for --encode raw, we write the raw bytes.
                            // For --encode hex, we write the hex representation.
                            // For --encode base64, we write the base64 representation.

                            // Since the envelope is binary, and --encode raw means raw binary:
                            // Just write the envelope as-is.

                            // But wait, in hybrid mode, the payload is the AES ciphertext,
                            // and the header contains the tag, wrapped_key, iv.
                            // The --encode would affect how the whole envelope is written.

                            // I think the simplest approach is:
                            // - For direct mode: write the RSA ciphertext (k bytes) directly
                            // - For hybrid mode: write the envelope container
                            // - --encode affects the output format of the ciphertext data

                            // Let me just write the envelope for now.
                            // Actually I'm overcomplicating this. Let me just write the envelope.
                            break;
                        case rsalab::EncodeFormat::Hex:
                            // Not fully implemented yet
                            break;
                        case rsalab::EncodeFormat::Base64:
                            // Not fully implemented yet
                            break;
                    }

                    // Write envelope to file (atomic)
                    // rsalab::write_file(opts.out_path, envelope);
                    // For now, just write the ciphertext (direct mode, no envelope)
                    // Actually, let me re-read the spec one more time...

                    // From §4.3 CLI:
                    // rsatool encrypt --in msg.bin --pub pub.pem --out ct.bin [--label TEXT] [--encode raw|hex|base64] [--force-hybrid] [--impl lib|manual]
                    // And the container format is described in §4.3 with the envelope.

                    // I think the output format is:
                    // - Direct: the ct.bin contains the RSA-OAEP ciphertext (k bytes) directly
                    //   Maybe with a small header or just the raw ciphertext
                    // - Hybrid: ct.bin contains the envelope container (magic RSAE, version, header JSON, payload)

                    // Looking at the test examples:
                    // $RT encrypt --in testdata/msg_small.bin --pub keys/pub3072.pem --out ct_small.bin --verbose
                    // And then decrypt works.

                    // And: the envelope format has magic "RSAE" + version + header_len + header JSON + payload.

                    // So for encrypt, the output is always the envelope container (even in direct mode),
                    // and --encode affects how the file content is formatted.

                    // Actually no, let me look at the negative test section:
                    // "python scripts/tamper.py --in ct_small.bin --out neg/flip_direct.bin --mode flip-direct"
                    // This suggests ct_small.bin is a direct envelope (has RSAE magic etc.)

                    // And: "python scripts/tamper.py --in ct_1KiB.bin --out neg/flip_payload.bin --mode flip-payload"
                    // This suggests ct_1KiB.bin is a hybrid envelope.

                    // So the encrypt output is always an envelope container.
                    // --encode raw|hex|base64 refers to the format of the entire file, or perhaps just the payload.

                    // I think --encode refers to how the ciphertext payload is encoded in the file.
                    // For raw: the file contains binary data
                    // For hex: the file contains hex-encoded binary data
                    // For base64: the file contains base64-encoded binary data

                    // Let me just implement writing the envelope with the appropriate encoding.

                    // For now, write the envelope as raw binary
                    // rsalab::write_file(opts.out_path, envelope);

                    std::cerr << "Encrypt (direct) not fully implemented yet\n";
                    return 1;
                } else {
                    // Hybrid mode
                    rsalab::HybridConfig hcfg;
                    hcfg.mode = rsalab::Mode::Hybrid;
                    hcfg.force_hybrid = true;
                    hcfg.label = opts.label;
                    hcfg.encode = opts.encode_format;
                    hcfg.impl = opts.impl;

                    rsalab::ByteVec envelope = rsalab::encrypt_hybrid(*pub, 
                        std::vector<rsalab::ByteVec::value_type>(plaintext.data(), plaintext.data() + plaintext.size()),
                        hcfg);

                    // Write envelope
                    // rsalab::write_file(opts.out_path, envelope);
                    std::cerr << "Encrypt (hybrid) not fully implemented yet\n";
                    return 1;
                }
            } else {
                // Fixed mode (Direct or Hybrid)
                if (mode == rsalab::Mode::Direct) {
                    // Direct RSA-OAEP
                    rsalab::ByteVec ciphertext = rsalab::oaep_encrypt(*pub,
                        ByteView(reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size()),
                        opts.label);

                    // Write direct envelope
                    rsalab::EnvelopeHeader header;
                    header.mode = "RSA-OAEP";
                    header.rsa_modulus = pub->modulus_bits();
                    header.hash = "SHA-256";

                    rsalab::SecureBuffer env = rsalab::envelope::make_direct_envelope(ciphertext, pub->modulus_bits());

                    // Write to file
                    // rsalab::write_file(opts.out_path, env);
                    std::cerr << "Encrypt (direct fixed) not fully implemented yet\n";
                    return 1;
                } else { // Hybrid
                    rsalab::HybridConfig hcfg;
                    hcfg.mode = rsalab::Mode::Hybrid;
                    hcfg.force_hybrid = true;
                    hcfg.label = opts.label;
                    hcfg.encode = opts.encode_format;
                    hcfg.impl = opts.impl;

                    rsalab::ByteVec envelope = rsalab::encrypt_hybrid(*pub,
                        std::vector<rsalab::ByteVec::value_type>(plaintext.data(), plaintext.data() + plaintext.size()),
                        hcfg);

                    // Write envelope
                    // rsalab::write_file(opts.out_path, envelope);
                    std::cerr << "Encrypt (hybrid fixed) not fully implemented yet\n";
                    return 1;
                }
            }
        } catch (const rsalab::CryptoFailure& e) {
            std::cerr << "Crypto error: " << e.what() << "\n";
            return 3;
        } catch (const rsalab::IoError& e) {
            std::cerr << "I/O error: " << e.what() << "\n";
            return 2;
        } catch (const std::exception& e) {
            std::cerr << "Error: " << e.what() << "\n";
            return 1;
        }
        return 0;
    }

    else if (command == "decrypt") {
        rsalab::DecryptOptions opts;
        CliResult result = rsalab::parse_decrypt(argc - 1, argv + 1, opts);
        if (result.status != rsalab::CliResult::Status::Ok) {
            std::cerr << "Error: " << result.message << "\n";
            return static_cast<int>(rsalab::CliResult::Status::Usage);
        }

        try {
            // Load private key
            auto priv = rsalab::read_private_key(opts.priv_path);

            // Read input file (ciphertext)
            // The format depends on whether it's direct or hybrid
            // We need to read the raw bytes and detect the mode

            SecureBuffer data = rsalab::read_file(opts.in_path);
            std::size_t data_len = data.size();

            if (data_len < 9) {
                std::cerr << "Error: Input file too short to be an envelope\n";
                return 3;
            }

            // Detect mode from magic "RSAE"
            bool is_envelope = (data[0] == 'R' && data[1] == 'S' && data[2] == 'A' && data[3] == 'E');

            if (is_envelope) {
                // Parse envelope
                auto [header, payload] = rsalab::envelope::parse_envelope(ByteView(
                    reinterpret_cast<const char*>(data.data()), data_len
                ));

                if (header.is_direct()) {
                    // Direct RSA-OAEP decrypt
                    rsalab::ByteVec plaintext = rsalab::oaep_decrypt(*priv,
                        ByteView(reinterpret_cast<const char*>(payload.data()), payload.size()),
                        opts.label);

                    // Write output
                    // rsalab::write_file(opts.out_path, plaintext);
                    std::cerr << "Decrypt (direct) not fully implemented yet\n";
                    return 1;
                } else if (header.is_hybrid()) {
                    // Hybrid decrypt
                    rsalab::HybridConfig hcfg;
                    hcfg.mode = rsalab::Mode::Auto;
                    hcfg.force_hybrid = true;
                    hcfg.label = opts.label;
                    hcfg.encode_format = opts.encode_format;
                    hcfg.impl = opts.impl;

                    rsalab::ByteVec plaintext = rsalab::decrypt_hybrid(*priv,
                        std::vector<rsalab::ByteVec::value_type>(payload.data(), payload.data() + payload.size()),
                        hcfg);

                    // Write output atomically
                    // rsalab::write_file(opts.out_path, plaintext);
                    std::cerr << "Decrypt (hybrid) not fully implemented yet\n";
                    return 1;
                } else {
                    std::cerr << "Error: Unknown envelope mode\n";
                    return 3;
                }
            } else {
                // No envelope magic - treat as direct RSA-OAEP ciphertext (old format or raw)
                // Try to decrypt as RSA-OAEP directly
                // The data should be exactly modulus_bytes long
                std::size_t modulus_bytes = priv->modulus_bytes();
                if (data_len != modulus_bytes) {
                    std::cerr << "Error: Ciphertext length " << data_len
                              << " doesn't match modulus size " << modulus_bytes << "\n";
                    return 3;
                }

                rsalab::ByteVec ciphertext(data_len);
                std::memcpy(ciphertext.data(), data.data(), data_len);

                rsalab::ByteVec plaintext = rsalab::oaep_decrypt(*priv,
                    ByteView(reinterpret_cast<const char*>(ciphertext.data()), ciphertext.size()),
                    opts.label);

                // Write output
                // rsalab::write_file(opts.out_path, plaintext);
                std::cerr << "Decrypt (raw direct) not fully implemented yet\n";
                return 1;
            }
        } catch (const rsalab::CryptoFailure& e) {
            // Fail-closed: don't create output file, print generic error
            std::cerr << "Error: decryption failed.\n";
            // Ensure no output file was created (it shouldn't be since we haven't written yet)
            return 3;
        } catch (const rsalab::IoError& e) {
            std::cerr << "I/O error: " << e.what() << "\n";
            return 2;
        } catch (const std::exception& e) {
            // Fail-closed: generic error, no detail leak
            std::cerr << "Error: decryption failed.\n";
            return 3;
        }
        return 0;
    }

    else {
        std::cerr << "Unknown command: " << command << "\n";
        print_help();
        return 1;
    }
}