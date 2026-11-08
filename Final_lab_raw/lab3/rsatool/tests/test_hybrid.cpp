// test_hybrid.cpp — Positive tests for hybrid envelope round trips
#include <catch2/catch_test_macros.hpp>
#include <rsatool/keys.hpp>
#include <rsatool/hybrid.hpp>
#include <rsatool/oaep.hpp>
#include <rsatool/envelope.hpp>
#include <rsatool/errors.hpp>

#include <openssl/rand.h>
#include <filesystem>
#include <fstream>
#include <vector>

#include <functional>
#include <algorithm>
#include <stdexcept>

using namespace rsatool;

static std::vector<uint8_t> rand_vec(std::size_t n) {
    std::vector<uint8_t> v(n);
    if (RAND_bytes(v.data(), static_cast<int>(n)) != 1)
        throw std::runtime_error("RAND_bytes failed");
    return v;
}

TEST_CASE("Hybrid AES-GCM round trip — 1 KiB", "[hybrid][aes]") {
    auto pt = rand_vec(1024);
    std::vector<uint8_t> aad = {0x01, 0x02, 0x03};  // some AAD

    auto res = hybrid::encrypt_mem(pt.data(), pt.size(), aad);
    REQUIRE(res.iv.size()  == hybrid::AES_IV_BYTES);
    REQUIRE(res.tag.size() == hybrid::AES_TAG_BYTES);
    REQUIRE(res.key.size() == hybrid::AES_KEY_BYTES);

    auto dec = hybrid::decrypt_mem(
        res.ciphertext.data(), res.ciphertext.size(),
        res.key.data(), res.iv.data(), res.tag.data(), aad);

    REQUIRE(dec.size() == pt.size());
    REQUIRE(std::equal(dec.begin(), dec.end(), pt.begin()));
}

TEST_CASE("Hybrid AES-GCM round trip — 1 MiB", "[hybrid][aes]") {
    auto pt = rand_vec(1024 * 1024);
    std::vector<uint8_t> aad(32, 0xAA);

    auto res = hybrid::encrypt_mem(pt.data(), pt.size(), aad);
    auto dec = hybrid::decrypt_mem(
        res.ciphertext.data(), res.ciphertext.size(),
        res.key.data(), res.iv.data(), res.tag.data(), aad);

    REQUIRE(dec.size() == pt.size());
    REQUIRE(std::equal(dec.begin(), dec.end(), pt.begin()));
}

TEST_CASE("Full hybrid envelope round trip — mLen+1 triggers hybrid auto", "[hybrid][envelope]") {
    namespace fs = std::filesystem;
    auto tmpdir = fs::temp_directory_path() / "rsatool_test_hybrid";
    fs::create_directories(tmpdir);

    auto pub_pem  = tmpdir / "pub.pem";
    auto priv_pem = tmpdir / "priv.pem";
    auto in_file  = tmpdir / "in.bin";
    auto ct_file  = tmpdir / "ct.bin";
    auto out_file = tmpdir / "out.bin";

    // Generate key
    auto key = keys::generate_key(3072);
    keys::write_public_pem(key.get(),  pub_pem);
    keys::write_private_pem(key.get(), priv_pem);

    // Plaintext: mLen + 1 (forces hybrid in auto mode)
    std::size_t mLen = oaep::max_plaintext_len(3072);
    auto pt = rand_vec(mLen + 1);
    {
        std::ofstream ofs(in_file, std::ios::binary);
        ofs.write(reinterpret_cast<const char*>(pt.data()),
                   static_cast<std::streamsize>(pt.size()));
    }

    // Encrypt (auto mode -> hybrid)
    envelope::encrypt_file(in_file, ct_file, pub_pem, "", "raw", "auto");
    REQUIRE(fs::exists(ct_file));

    // Decrypt
    envelope::decrypt_file(ct_file, out_file, priv_pem, "", "raw");
    REQUIRE(fs::exists(out_file));

    // Compare
    std::ifstream ofs(out_file, std::ios::binary);
    std::vector<uint8_t> dec_data(
        (std::istreambuf_iterator<char>(ofs)),
        std::istreambuf_iterator<char>());

    REQUIRE(dec_data.size() == pt.size());
    REQUIRE(std::equal(dec_data.begin(), dec_data.end(), pt.begin()));

    fs::remove_all(tmpdir);
}

TEST_CASE("Full hybrid envelope round trip — 1 KiB forced hybrid", "[hybrid][envelope]") {
    namespace fs = std::filesystem;
    auto tmpdir = fs::temp_directory_path() / "rsatool_test_hybrid2";
    fs::create_directories(tmpdir);

    auto pub_pem  = tmpdir / "pub.pem";
    auto priv_pem = tmpdir / "priv.pem";
    auto in_file  = tmpdir / "in.bin";
    auto ct_file  = tmpdir / "ct.bin";
    auto out_file = tmpdir / "out.bin";

    auto key = keys::generate_key(3072);
    keys::write_public_pem(key.get(),  pub_pem);
    keys::write_private_pem(key.get(), priv_pem);

    auto pt = rand_vec(1024);
    {
        std::ofstream ofs(in_file, std::ios::binary);
        ofs.write(reinterpret_cast<const char*>(pt.data()),
                   static_cast<std::streamsize>(pt.size()));
    }

    envelope::encrypt_file(in_file, ct_file, pub_pem, "", "raw", "hybrid");
    envelope::decrypt_file(ct_file, out_file, priv_pem, "", "raw");

    std::ifstream ifs(out_file, std::ios::binary);
    std::vector<uint8_t> dec_data(
        (std::istreambuf_iterator<char>(ifs)),
        std::istreambuf_iterator<char>());

    REQUIRE(dec_data.size() == pt.size());
    REQUIRE(std::equal(dec_data.begin(), dec_data.end(), pt.begin()));

    fs::remove_all(tmpdir);
}

TEST_CASE("Direct OAEP envelope round trip — small message", "[direct][envelope]") {
    namespace fs = std::filesystem;
    auto tmpdir = fs::temp_directory_path() / "rsatool_test_direct";
    fs::create_directories(tmpdir);

    auto pub_pem  = tmpdir / "pub.pem";
    auto priv_pem = tmpdir / "priv.pem";
    auto in_file  = tmpdir / "in.bin";
    auto ct_file  = tmpdir / "ct.bin";
    auto out_file = tmpdir / "out.bin";

    auto key = keys::generate_key(3072);
    keys::write_public_pem(key.get(),  pub_pem);
    keys::write_private_pem(key.get(), priv_pem);

    auto pt = rand_vec(100);
    {
        std::ofstream ofs(in_file, std::ios::binary);
        ofs.write(reinterpret_cast<const char*>(pt.data()),
                   static_cast<std::streamsize>(pt.size()));
    }

    envelope::encrypt_file(in_file, ct_file, pub_pem, "", "raw", "direct");
    envelope::decrypt_file(ct_file, out_file, priv_pem, "", "raw");

    std::ifstream ifs(out_file, std::ios::binary);
    std::vector<uint8_t> dec_data(
        (std::istreambuf_iterator<char>(ifs)),
        std::istreambuf_iterator<char>());

    REQUIRE(dec_data.size() == pt.size());
    REQUIRE(std::equal(dec_data.begin(), dec_data.end(), pt.begin()));

    fs::remove_all(tmpdir);
}

