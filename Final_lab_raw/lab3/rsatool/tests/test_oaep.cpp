// test_oaep.cpp - Positive tests for RSA-OAEP round trips
#include <catch2/catch_test_macros.hpp>
#include <rsatool/keys.hpp>
#include <rsatool/oaep.hpp>
#include <rsatool/secure.hpp>
#include <rsatool/errors.hpp>

#include <openssl/rand.h>
#include <vector>
#include <string>

#include <fstream>
#include <filesystem>
#include <functional>
#include <algorithm>
#include <stdexcept>
#include <iterator>

using namespace rsatool;

// Helper: generate random bytes
static std::vector<uint8_t> rand_vec(std::size_t n) {
    std::vector<uint8_t> v(n);
    if (RAND_bytes(v.data(), static_cast<int>(n)) != 1)
        throw std::runtime_error("RAND_bytes failed");
    return v;
}

// Helper: generate key (slow, cache between tests)
static UniqueEVPPKEY make_key_3072() {
    return keys::generate_key(3072);
}
static UniqueEVPPKEY make_key_4096() {
    return keys::generate_key(4096);
}

TEST_CASE("RSA-3072 OAEP round trip - 0 bytes, no label", "[oaep][3072]") {
    auto key = make_key_3072();
    std::vector<uint8_t> pt;  // empty

    auto ct = oaep::encrypt(key.get(), pt.data(), pt.size());
    auto dec = oaep::decrypt(key.get(), ct.data(), ct.size());

    REQUIRE(dec.size() == 0);
}

TEST_CASE("RSA-3072 OAEP round trip - 1 byte, no label", "[oaep][3072]") {
    auto key = make_key_3072();
    std::vector<uint8_t> pt = {0xAB};

    auto ct = oaep::encrypt(key.get(), pt.data(), pt.size());
    auto dec = oaep::decrypt(key.get(), ct.data(), ct.size());

    REQUIRE(dec.size() == 1);
    REQUIRE(dec[0] == 0xAB);
}

TEST_CASE("RSA-3072 OAEP round trip - exactly mLen bytes, no label", "[oaep][3072]") {
    auto key = make_key_3072();
    std::size_t mLen = oaep::max_plaintext_len(3072);
    auto pt = rand_vec(mLen);

    auto ct = oaep::encrypt(key.get(), pt.data(), pt.size());
    auto dec = oaep::decrypt(key.get(), ct.data(), ct.size());

    REQUIRE(dec.size() == mLen);
    REQUIRE(std::equal(dec.begin(), dec.end(), pt.begin()));
}

TEST_CASE("RSA-3072 OAEP round trip - with label", "[oaep][3072][label]") {
    auto key = make_key_3072();
    std::vector<uint8_t> pt = rand_vec(64);
    std::string label = "test-label-2025";

    auto ct = oaep::encrypt(key.get(), pt.data(), pt.size(), label);
    auto dec = oaep::decrypt(key.get(), ct.data(), ct.size(), label);

    REQUIRE(std::equal(dec.begin(), dec.end(), pt.begin()));
}

TEST_CASE("RSA-3072 OAEP round trip - empty label explicit", "[oaep][3072][label]") {
    auto key = make_key_3072();
    auto pt = rand_vec(100);

    auto ct = oaep::encrypt(key.get(), pt.data(), pt.size(), "");
    auto dec = oaep::decrypt(key.get(), ct.data(), ct.size(), "");

    REQUIRE(std::equal(dec.begin(), dec.end(), pt.begin()));
}

TEST_CASE("RSA-4096 OAEP round trip - 0 bytes, no label", "[oaep][4096]") {
    auto key = make_key_4096();
    std::vector<uint8_t> pt;

    auto ct = oaep::encrypt(key.get(), pt.data(), 0);
    auto dec = oaep::decrypt(key.get(), ct.data(), ct.size());

    REQUIRE(dec.size() == 0);
}

TEST_CASE("RSA-4096 OAEP round trip - 1 byte, no label", "[oaep][4096]") {
    auto key = make_key_4096();
    std::vector<uint8_t> pt = {0xCD};

    auto ct = oaep::encrypt(key.get(), pt.data(), pt.size());
    auto dec = oaep::decrypt(key.get(), ct.data(), ct.size());

    REQUIRE(dec.size() == 1);
    REQUIRE(dec[0] == 0xCD);
}

TEST_CASE("RSA-4096 OAEP round trip - exactly mLen bytes, no label", "[oaep][4096]") {
    auto key = make_key_4096();
    std::size_t mLen = oaep::max_plaintext_len(4096);
    auto pt = rand_vec(mLen);

    auto ct = oaep::encrypt(key.get(), pt.data(), pt.size());
    auto dec = oaep::decrypt(key.get(), ct.data(), ct.size());

    REQUIRE(std::equal(dec.begin(), dec.end(), pt.begin()));
}

TEST_CASE("RSA-4096 OAEP round trip - with label", "[oaep][4096][label]") {
    auto key = make_key_4096();
    auto pt = rand_vec(100);
    std::string label = "lab3-oaep-test";

    auto ct = oaep::encrypt(key.get(), pt.data(), pt.size(), label);
    auto dec = oaep::decrypt(key.get(), ct.data(), ct.size(), label);

    REQUIRE(std::equal(dec.begin(), dec.end(), pt.begin()));
}

TEST_CASE("Key generation produces valid PEM, DER, and metadata", "[keygen]") {
    namespace fs = std::filesystem;

    auto tmpdir = fs::temp_directory_path() / "rsatool_test_keygen";
    fs::create_directories(tmpdir);

    auto pub_pem  = tmpdir / "pub.pem";
    auto priv_pem = tmpdir / "priv.pem";
    auto pub_der  = tmpdir / "pub.der";
    auto priv_der = tmpdir / "priv.der";
    auto meta     = tmpdir / "meta.json";

    auto key = keys::generate_key(3072);
    keys::write_public_pem(key.get(),  pub_pem);
    keys::write_private_pem(key.get(), priv_pem);
    keys::write_public_der(key.get(),  pub_der);
    keys::write_private_der(key.get(), priv_der);
    keys::write_meta_json(tmpdir, 3072);

    REQUIRE(fs::exists(pub_pem));
    REQUIRE(fs::exists(priv_pem));
    REQUIRE(fs::exists(pub_der));
    REQUIRE(fs::exists(priv_der));
    REQUIRE(fs::exists(meta));

    // Reload and check
    auto pub2  = keys::load_key(pub_pem,  false);
    auto priv2 = keys::load_key(priv_pem, true);
    REQUIRE(keys::key_bits(pub2.get())  == 3072);
    REQUIRE(keys::key_bits(priv2.get()) == 3072);

    // Load DER
    auto pub3  = keys::load_key(pub_der,  false);
    auto priv3 = keys::load_key(priv_der, true);
    REQUIRE(keys::key_bits(pub3.get())  == 3072);
    REQUIRE(keys::key_bits(priv3.get()) == 3072);

    // Check meta.json contains expected fields
    {
        std::ifstream mf(meta, std::ios::binary);
        REQUIRE(mf.is_open());
        std::string contents((std::istreambuf_iterator<char>(mf)),
                              std::istreambuf_iterator<char>());
        REQUIRE(contents.find("\"modulus_bits\": 3072") != std::string::npos);
        REQUIRE(contents.find("\"hash\": \"SHA-256\"") != std::string::npos);
        REQUIRE(contents.find("\"creation_time\"") != std::string::npos);
    }   // mf đóng ở đây, trước khi xóa thư mục

    // Cleanup
    std::error_code ec;
    fs::remove_all(tmpdir, ec);
}

