#include "test_harness.hpp"
#include "aes/cli.hpp"
#include "aes/ctr.hpp"
#include "aes/util.hpp"
#include <filesystem>
#include <vector>
#include <cstring>

TEST_CASE("Portability: Raw binary bytes 0x0A, 0x0D, 0x1A, 0x00 preserved on Windows/Linux") {
    std::filesystem::path dir = "./test_port_tmp";
    std::filesystem::create_directories(dir);

    std::string key_file = (dir / "port_key.bin").string();
    std::string iv_file  = (dir / "port_iv.bin").string();
    std::string in_file  = (dir / "port_in.bin").string();
    std::string ct_file  = (dir / "port_ct.bin").string();
    std::string dec_file = (dir / "port_dec.bin").string();

    uint8_t key[16] = {0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00};
    uint8_t iv[16]  = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
    aes::util::write_binary_file(key_file, key, 16);
    aes::util::write_binary_file(iv_file, iv, 16);

    // Problematic bytes: \n (0x0A), \r (0x0D), EOF (0x1A in DOS), \0 (0x00)
    std::vector<uint8_t> sensitive_bytes = {
        0x0A, 0x0D, 0x0A, 0x0D, 0x1A, 0x00, 0xFF, 0x1A,
        0x0D, 0x0A, 0x00, 0x00, 0x1A, 0x1A, 0x0D, 0x0A,
        0x42, 0x0A, 0x0D, 0x1A
    };
    aes::util::write_binary_file(in_file, sensitive_bytes.data(), sensitive_bytes.size());

    // Encrypt via CLI
    int rc_enc = aes::cli::run({"encrypt", "--mode", "ctr", "--key", key_file, "--iv", iv_file, "--in", in_file, "--out", ct_file});
    REQUIRE(rc_enc == 0);

    // Decrypt via CLI
    int rc_dec = aes::cli::run({"decrypt", "--mode", "ctr", "--key", key_file, "--iv", iv_file, "--in", ct_file, "--out", dec_file});
    REQUIRE(rc_dec == 0);

    // Read back and compare
    std::vector<uint8_t> read_back;
    REQUIRE(aes::util::read_binary_file(dec_file, read_back));
    REQUIRE(read_back.size() == sensitive_bytes.size());
    REQUIRE(std::memcmp(read_back.data(), sensitive_bytes.data(), sensitive_bytes.size()) == 0);

    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
}

TEST_CASE("Portability: Directory and file paths containing spaces") {
    std::filesystem::path dir = "./test dir with spaces";
    std::filesystem::create_directories(dir);

    std::string key_file = (dir / "my secret key.bin").string();
    std::string iv_file  = (dir / "my initial vector.bin").string();
    std::string in_file  = (dir / "my plain text.bin").string();
    std::string ct_file  = (dir / "my cipher text.bin").string();
    std::string dec_file = (dir / "my decrypted text.bin").string();

    uint8_t key[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    uint8_t iv[16]  = {9, 8, 7, 6, 5, 4, 3, 2, 1, 0,  1,  2,  3,  4,  5,  6};
    aes::util::write_binary_file(key_file, key, 16);
    aes::util::write_binary_file(iv_file, iv, 16);

    std::string msg = "Message inside folder with spaces!";
    aes::util::write_binary_file(in_file, reinterpret_cast<const uint8_t*>(msg.data()), msg.size());

    int rc_enc = aes::cli::run({"encrypt", "--mode", "ctr", "--key", key_file, "--iv", iv_file, "--in", in_file, "--out", ct_file});
    REQUIRE(rc_enc == 0);

    int rc_dec = aes::cli::run({"decrypt", "--mode", "ctr", "--key", key_file, "--iv", iv_file, "--in", ct_file, "--out", dec_file});
    REQUIRE(rc_dec == 0);

    std::vector<uint8_t> recovered;
    REQUIRE(aes::util::read_binary_file(dec_file, recovered));
    REQUIRE(recovered.size() == msg.size());
    REQUIRE(std::memcmp(recovered.data(), msg.data(), msg.size()) == 0);

    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
}

TEST_CASE("Portability: Atomic replacement of existing destination file") {
    std::filesystem::path dir = "./test_port_replace";
    std::filesystem::create_directories(dir);

    std::string key_file = (dir / "k.bin").string();
    std::string iv_file  = (dir / "iv.bin").string();
    std::string in_file  = (dir / "in.bin").string();
    std::string out_file = (dir / "out.bin").string();

    uint8_t key[16] = {0};
    uint8_t iv[16]  = {0};
    aes::util::write_binary_file(key_file, key, 16);
    aes::util::write_binary_file(iv_file, iv, 16);

    // Pre-create destination file with old contents
    std::string old_content = "Old existing destination content that must be overwritten";
    aes::util::write_binary_file(out_file, reinterpret_cast<const uint8_t*>(old_content.data()), old_content.size());

    std::string new_content = "New plain";
    aes::util::write_binary_file(in_file, reinterpret_cast<const uint8_t*>(new_content.data()), new_content.size());

    // Encrypt directly to out_file (testing atomic replacement)
    int rc = aes::cli::run({"encrypt", "--mode", "ctr", "--key", key_file, "--iv", iv_file, "--in", in_file, "--out", out_file});
    REQUIRE(rc == 0);

    // Verify out_file size matches new encrypted content length, not old length
    uint64_t out_sz = 0;
    REQUIRE(aes::util::get_file_size(out_file, out_sz));
    REQUIRE(out_sz == new_content.size());

    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
}
