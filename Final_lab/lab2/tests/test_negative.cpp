#include "test_harness.hpp"
#include "aes/cli.hpp"
#include "aes/ctr.hpp"
#include "aes/util.hpp"
#include <filesystem>
#include <vector>
#include <cstring>

TEST_CASE("Negative: Wrong Key length fails closed") {
    std::filesystem::path dir = "./test_neg_tmp";
    std::filesystem::create_directories(dir);

    std::string key_file = (dir / "short_key.bin").string();
    std::string iv_file  = (dir / "good_iv.bin").string();
    std::string in_file  = (dir / "in.bin").string();
    std::string out_file = (dir / "out.bin").string();

    uint8_t short_key[15] = {0};
    uint8_t good_iv[16]   = {0};
    uint8_t msg[32]       = "Secret message to be tested...";

    aes::util::write_binary_file(key_file, short_key, 15);
    aes::util::write_binary_file(iv_file, good_iv, 16);
    aes::util::write_binary_file(in_file, msg, 32);

    int rc = aes::cli::run({"encrypt", "--mode", "ctr", "--key", key_file, "--iv", iv_file, "--in", in_file, "--out", out_file});
    REQUIRE(rc == 2); // Key/IV error
    REQUIRE(!aes::util::file_exists(out_file));
    REQUIRE(!aes::util::file_exists(out_file + ".tmp"));

    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
}

TEST_CASE("Negative: Wrong IV length fails closed") {
    std::filesystem::path dir = "./test_neg_tmp2";
    std::filesystem::create_directories(dir);

    std::string key_file = (dir / "good_key.bin").string();
    std::string iv_file  = (dir / "long_iv.bin").string();
    std::string in_file  = (dir / "in.bin").string();
    std::string out_file = (dir / "out.bin").string();

    uint8_t good_key[16] = {0};
    uint8_t long_iv[17]  = {0};
    uint8_t msg[16]      = "16-byte message";

    aes::util::write_binary_file(key_file, good_key, 16);
    aes::util::write_binary_file(iv_file, long_iv, 17);
    aes::util::write_binary_file(in_file, msg, 16);

    int rc = aes::cli::run({"encrypt", "--mode", "ctr", "--key", key_file, "--iv", iv_file, "--in", in_file, "--out", out_file});
    REQUIRE(rc == 2); // Key/IV error
    REQUIRE(!aes::util::file_exists(out_file));
    REQUIRE(!aes::util::file_exists(out_file + ".tmp"));

    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
}

TEST_CASE("Negative: Non-existent input file fails closed") {
    std::filesystem::path dir = "./test_neg_tmp3";
    std::filesystem::create_directories(dir);

    std::string key_file = (dir / "key.bin").string();
    std::string iv_file  = (dir / "iv.bin").string();
    std::string in_file  = (dir / "non_existent_file.bin").string();
    std::string out_file = (dir / "out.bin").string();

    uint8_t dummy[16] = {0};
    aes::util::write_binary_file(key_file, dummy, 16);
    aes::util::write_binary_file(iv_file, dummy, 16);

    int rc = aes::cli::run({"encrypt", "--mode", "ctr", "--key", key_file, "--iv", iv_file, "--in", in_file, "--out", out_file});
    REQUIRE(rc == 3); // IOError
    REQUIRE(!aes::util::file_exists(out_file));

    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
}

TEST_CASE("Negative: Decrypt with Wrong Key / IV yields garbage") {
    uint8_t key1[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    uint8_t key2[16] = {9, 9, 9, 9, 9, 9, 9, 9, 9, 9,  9,  9,  9,  9,  9,  9};
    uint8_t iv[16]   = {0};

    uint8_t pt[16] = "Hello world 123";
    uint8_t ct[16] = {0};
    uint8_t decrypted[16] = {0};

    // Encrypt with key1
    REQUIRE(aes::ctr_crypt_buffer(pt, ct, 16, key1, iv) == aes::CtrStatus::Success);

    // Decrypt with key2 (Wrong key)
    REQUIRE(aes::ctr_crypt_buffer(ct, decrypted, 16, key2, iv) == aes::CtrStatus::Success);

    // Must not match original plaintext
    REQUIRE(std::memcmp(pt, decrypted, 16) != 0);
}

TEST_CASE("Malleability: Flipping 1 bit in ciphertext flips exactly 1 bit in plaintext") {
    uint8_t key[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                       0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
    uint8_t iv[16]  = {0};

    std::vector<uint8_t> pt = {'T', 'e', 's', 't', ' ', 'M', 'a', 'l', 'l', 'e', 'a', 'b', 'i', 'l', 'i', 't', 'y'};
    std::vector<uint8_t> ct(pt.size());
    std::vector<uint8_t> tampered_ct(pt.size());
    std::vector<uint8_t> decrypted(pt.size());

    REQUIRE(aes::ctr_crypt_buffer(pt.data(), ct.data(), pt.size(), key, iv) == aes::CtrStatus::Success);

    tampered_ct = ct;
    // Flip bit 3 of byte 5
    tampered_ct[5] ^= (1 << 3);

    REQUIRE(aes::ctr_crypt_buffer(tampered_ct.data(), decrypted.data(), tampered_ct.size(), key, iv) == aes::CtrStatus::Success);

    // Verify all other bytes are identical, and byte 5 has exactly that bit flipped
    for (size_t i = 0; i < pt.size(); ++i) {
        if (i == 5) {
            REQUIRE(decrypted[i] == (pt[i] ^ (1 << 3)));
        } else {
            REQUIRE(decrypted[i] == pt[i]);
        }
    }
}
