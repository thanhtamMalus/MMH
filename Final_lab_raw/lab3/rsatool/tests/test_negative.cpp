// test_negative.cpp — Negative tests: all must fail closed with no output file
#include <catch2/catch_test_macros.hpp>
#include <rsatool/keys.hpp>
#include <rsatool/oaep.hpp>
#include <rsatool/hybrid.hpp>
#include <rsatool/envelope.hpp>
#include <rsatool/codec.hpp>
#include <rsatool/errors.hpp>
#include <rsatool/secure.hpp>

#include <openssl/rand.h>
#include <filesystem>
#include <fstream>
#include <vector>
#include <cstring>

#include <functional>
#include <algorithm>
#include <stdexcept>
#include <functional>
#include <nlohmann/json.hpp>

using namespace rsatool;
namespace fs = std::filesystem;

static std::vector<uint8_t> rand_vec(std::size_t n) {
    std::vector<uint8_t> v(n);
    RAND_bytes(v.data(), static_cast<int>(n));
    return v;
}

// Helper: write file from vector
static void write_file_vec(const fs::path& p, const std::vector<uint8_t>& data) {
    std::ofstream ofs(p, std::ios::binary);
    ofs.write(reinterpret_cast<const char*>(data.data()),
               static_cast<std::streamsize>(data.size()));
}

struct EncryptedEnv {
    fs::path tmpdir;
    fs::path pub_pem, priv_pem;
    fs::path in_file, ct_file;
    std::vector<uint8_t> plaintext;
};

static EncryptedEnv make_hybrid_env(const std::string& tag_name) {
    EncryptedEnv e;
    e.tmpdir = fs::temp_directory_path() / ("rsatool_neg_" + tag_name);
    fs::create_directories(e.tmpdir);

    e.pub_pem  = e.tmpdir / "pub.pem";
    e.priv_pem = e.tmpdir / "priv.pem";
    e.in_file  = e.tmpdir / "in.bin";
    e.ct_file  = e.tmpdir / "ct.bin";

    auto key = keys::generate_key(3072);
    keys::write_public_pem(key.get(),  e.pub_pem);
    keys::write_private_pem(key.get(), e.priv_pem);

    e.plaintext = rand_vec(1024);
    write_file_vec(e.in_file, e.plaintext);
    envelope::encrypt_file(e.in_file, e.ct_file, e.pub_pem, "", "raw", "hybrid");
    return e;
}

// ── 1. Flip one bit in RSA ciphertext (wrapped_key) ──────────────────────────
TEST_CASE("Negative: flipped bit in RSA ciphertext -> decryption failed", "[negative][oaep]") {
    auto key = keys::generate_key(3072);
    auto pt = rand_vec(100);
    auto ct = oaep::encrypt(key.get(), pt.data(), pt.size());

    ct[ct.size() / 2] ^= 0x01;  // flip one bit

    REQUIRE_THROWS_AS(
        oaep::decrypt(key.get(), ct.data(), ct.size()),
        CryptoError);
}

// ── 2. Flip one bit in AES-GCM ciphertext -> tag failure ─────────────────────
TEST_CASE("Negative: flipped bit in AES ciphertext -> tag failure", "[negative][aes]") {
    auto pt = rand_vec(512);
    std::vector<uint8_t> aad = {0xDE, 0xAD};

    auto res = hybrid::encrypt_mem(pt.data(), pt.size(), aad);
    res.ciphertext[res.ciphertext.size() / 2] ^= 0x01;

    REQUIRE_THROWS_AS(
        hybrid::decrypt_mem(
            res.ciphertext.data(), res.ciphertext.size(),
            res.key.data(), res.iv.data(), res.tag.data(), aad),
        CryptoError);
}

// ── 3. Wrong private key ──────────────────────────────────────────────────────
TEST_CASE("Negative: wrong private key -> decryption failed", "[negative][key]") {
    auto key1 = keys::generate_key(3072);
    auto key2 = keys::generate_key(3072);  // different key

    auto pt = rand_vec(100);
    auto ct = oaep::encrypt(key1.get(), pt.data(), pt.size());

    REQUIRE_THROWS_AS(
        oaep::decrypt(key2.get(), ct.data(), ct.size()),
        CryptoError);
}

// ── 4. Wrong OAEP label ───────────────────────────────────────────────────────
TEST_CASE("Negative: wrong OAEP label -> decryption failed", "[negative][label]") {
    auto key = keys::generate_key(3072);
    auto pt = rand_vec(100);

    auto ct = oaep::encrypt(key.get(), pt.data(), pt.size(), "correct-label");

    REQUIRE_THROWS_AS(
        oaep::decrypt(key.get(), ct.data(), ct.size(), "wrong-label"),
        CryptoError);
}

TEST_CASE("Negative: label present in encrypt, absent in decrypt -> failed", "[negative][label]") {
    auto key = keys::generate_key(3072);
    auto pt = rand_vec(100);

    auto ct = oaep::encrypt(key.get(), pt.data(), pt.size(), "my-label");

    REQUIRE_THROWS_AS(
        oaep::decrypt(key.get(), ct.data(), ct.size(), ""),
        CryptoError);
}

TEST_CASE("Negative: no label in encrypt, label in decrypt -> failed", "[negative][label]") {
    auto key = keys::generate_key(3072);
    auto pt = rand_vec(100);

    auto ct = oaep::encrypt(key.get(), pt.data(), pt.size(), "");

    REQUIRE_THROWS_AS(
        oaep::decrypt(key.get(), ct.data(), ct.size(), "extra-label"),
        CryptoError);
}

// ── 5. Tampered header fields ─────────────────────────────────────────────────
static std::vector<uint8_t> read_file_vec(const fs::path& p) {
    std::ifstream ifs(p, std::ios::binary);
    return std::vector<uint8_t>(
        (std::istreambuf_iterator<char>(ifs)),
        std::istreambuf_iterator<char>());
}

static void corrupt_header(const fs::path& ct_file, const fs::path& priv_pem,
                             const std::string& test_name,
                             std::function<void(nlohmann::json&)> mutate) {
    auto raw = read_file_vec(ct_file);
    REQUIRE(raw.size() >= 4);

    uint32_t hlen = (uint32_t(raw[0]) << 24) | (uint32_t(raw[1]) << 16) |
                    (uint32_t(raw[2]) << 8)  | uint32_t(raw[3]);
    REQUIRE(raw.size() >= 4 + hlen);

    std::string header_str(reinterpret_cast<const char*>(raw.data() + 4), hlen);
    auto hdr = nlohmann::json::parse(header_str);
    mutate(hdr);
    std::string new_hdr = hdr.dump();

    std::vector<uint8_t> tampered;
    tampered.resize(4 + new_hdr.size() + (raw.size() - 4 - hlen));
    uint32_t nhlen = static_cast<uint32_t>(new_hdr.size());
    tampered[0] = uint8_t(nhlen >> 24);
    tampered[1] = uint8_t(nhlen >> 16);
    tampered[2] = uint8_t(nhlen >> 8);
    tampered[3] = uint8_t(nhlen);
    std::memcpy(tampered.data() + 4, new_hdr.data(), new_hdr.size());
    std::memcpy(tampered.data() + 4 + new_hdr.size(),
                 raw.data() + 4 + hlen, raw.size() - 4 - hlen);

    auto tmpdir = fs::temp_directory_path() / ("rsatool_hdr_" + test_name);
    fs::create_directories(tmpdir);
    auto tampered_ct  = tmpdir / "ct_tampered.bin";
    auto tampered_out = tmpdir / "out.bin";

    write_file_vec(tampered_ct, tampered);

    // Should throw
    bool threw = false;
    try {
        envelope::decrypt_file(tampered_ct, tampered_out, priv_pem, "", "raw");
    } catch (const CryptoError&) { threw = true;
    } catch (const FormatError&) { threw = true; }

    REQUIRE(threw);
    // Output file must not exist
    REQUIRE_FALSE(fs::exists(tampered_out));

    fs::remove_all(tmpdir);
}

TEST_CASE("Negative: tampered header rsa_modulus", "[negative][header]") {
    auto e = make_hybrid_env("mod");
    corrupt_header(e.ct_file, e.priv_pem, "mod",
        [](nlohmann::json& h) { h["rsa_modulus"] = 2048; });
    fs::remove_all(e.tmpdir);
}

TEST_CASE("Negative: tampered header mode", "[negative][header]") {
    auto e = make_hybrid_env("mode");
    corrupt_header(e.ct_file, e.priv_pem, "mode_tamp",
        [](nlohmann::json& h) { h["mode"] = "RSA-OAEP"; });
    fs::remove_all(e.tmpdir);
}

TEST_CASE("Negative: tampered header iv", "[negative][header]") {
    auto e = make_hybrid_env("iv");
    corrupt_header(e.ct_file, e.priv_pem, "iv_tamp",
        [](nlohmann::json& h) { h["iv"] = "AAAAAAAAAAAAAAAAAA=="; });
    fs::remove_all(e.tmpdir);
}

TEST_CASE("Negative: tampered header tag", "[negative][header]") {
    auto e = make_hybrid_env("tag");
    corrupt_header(e.ct_file, e.priv_pem, "tag_tamp",
        [](nlohmann::json& h) { h["tag"] = "AAAAAAAAAAAAAAAAAAAAAA=="; });
    fs::remove_all(e.tmpdir);
}

// ── 6. Truncated / empty / absurd header_len files ───────────────────────────
TEST_CASE("Negative: empty file -> malformed envelope", "[negative][format]") {
    auto tmpdir = fs::temp_directory_path() / "rsatool_neg_empty";
    fs::create_directories(tmpdir);
    auto key = keys::generate_key(3072);
    auto priv_pem = tmpdir / "priv.pem";
    keys::write_private_pem(key.get(), priv_pem);

    auto empty_file = tmpdir / "empty.bin";
    { std::ofstream ofs(empty_file, std::ios::binary); }  // create empty

    auto out = tmpdir / "out.bin";
    REQUIRE_THROWS_AS(
        envelope::decrypt_file(empty_file, out, priv_pem, "", "raw"),
        FormatError);
    REQUIRE_FALSE(fs::exists(out));
    fs::remove_all(tmpdir);
}

TEST_CASE("Negative: truncated file -> malformed envelope", "[negative][format]") {
    auto e = make_hybrid_env("trunc");
    auto raw = read_file_vec(e.ct_file);
    // Truncate to first 10 bytes
    raw.resize(10);
    write_file_vec(e.ct_file, raw);

    auto out = e.tmpdir / "out.bin";
    REQUIRE_THROWS_AS(
        envelope::decrypt_file(e.ct_file, out, e.priv_pem, "", "raw"),
        FormatError);
    REQUIRE_FALSE(fs::exists(out));
    fs::remove_all(e.tmpdir);
}

TEST_CASE("Negative: absurd header_len -> malformed envelope", "[negative][format]") {
    auto tmpdir = fs::temp_directory_path() / "rsatool_neg_hlen";
    fs::create_directories(tmpdir);
    auto key = keys::generate_key(3072);
    auto priv_pem = tmpdir / "priv.pem";
    keys::write_private_pem(key.get(), priv_pem);

    // header_len = 0xFFFFFFFF (way larger than MAX_HEADER_LEN)
    std::vector<uint8_t> bad = {0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x01};
    auto bad_file = tmpdir / "bad.bin";
    write_file_vec(bad_file, bad);

    auto out = tmpdir / "out.bin";
    REQUIRE_THROWS_AS(
        envelope::decrypt_file(bad_file, out, priv_pem, "", "raw"),
        FormatError);
    REQUIRE_FALSE(fs::exists(out));
    fs::remove_all(tmpdir);
}

// ── 7. Invalid encoding ───────────────────────────────────────────────────────
TEST_CASE("Negative: invalid base64 input", "[negative][codec]") {
    REQUIRE_THROWS_AS(
        codec::decode("!!!invalid!!!", codec::Encoding::Base64),
        FormatError);
}

TEST_CASE("Negative: odd-length hex input", "[negative][codec]") {
    REQUIRE_THROWS_AS(
        codec::decode("abc", codec::Encoding::Hex),
        FormatError);
}

// ── 8. Unsupported key size ───────────────────────────────────────────────────
TEST_CASE("Negative: unsupported key size 2048 -> rejected", "[negative][keysize]") {
    REQUIRE_THROWS_AS(keys::validate_bits(2048), UsageError);
}

TEST_CASE("Negative: unsupported key size 1024 -> rejected", "[negative][keysize]") {
    REQUIRE_THROWS_AS(keys::validate_bits(1024), UsageError);
}

// ── 9. Plaintext too long in direct mode ─────────────────────────────────────
TEST_CASE("Negative: plaintext too long for direct OAEP", "[negative][oaep][overflow]") {
    auto key = keys::generate_key(3072);
    std::size_t mLen = oaep::max_plaintext_len(3072);
    auto too_long = rand_vec(mLen + 1);

    REQUIRE_THROWS_AS(
        oaep::encrypt(key.get(), too_long.data(), too_long.size()),
        UsageError);
}

