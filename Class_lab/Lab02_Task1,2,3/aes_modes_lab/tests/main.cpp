#include "aes.hpp"
#include "sp800_38a.hpp"
#include "sp800_38c.hpp"
#include "sp800_38d.hpp"

#include <cstdlib>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>

namespace {

using lab::Bytes;

Bytes from_hex(const std::string& text) {
    if (text.size() % 2 != 0) {
        throw std::invalid_argument("hex string must have an even number of characters: " + text);
    }
    Bytes result;
    result.reserve(text.size() / 2);
    for (std::size_t i = 0; i < text.size(); i += 2) {
        result.push_back(static_cast<std::uint8_t>(std::stoul(text.substr(i, 2), nullptr, 16)));
    }
    return result;
}

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

void require_throws(const std::function<void()>& operation, const std::string& message) {
    bool threw = false;
    try {
        operation();
    } catch (const std::exception&) {
        threw = true;
    }
    require(threw, message);
}

void test_aes_block_vectors() {
    const lab::AES aes128(from_hex("000102030405060708090a0b0c0d0e0f"));
    const Bytes plain = from_hex("00112233445566778899aabbccddeeff");
    const Bytes expected = from_hex("69c4e0d86a7b0430d8cdb78070b4c55a");
    const lab::Block encrypted = aes128.encrypt(lab::block(plain, 0));
    require(Bytes(encrypted.begin(), encrypted.end()) == expected, "AES-128 encryption vector failed");
    const lab::AES aes192(from_hex("000102030405060708090a0b0c0d0e0f1011121314151617"));
    const lab::Block encrypted192 = aes192.encrypt(lab::block(plain, 0));
    require(encrypted192 == lab::block(from_hex("dda97ca4864cdfe06eaf70a0ec0d7191"), 0),
            "AES-192 encryption vector failed");
    require(aes192.decrypt(encrypted192) == lab::block(plain, 0), "AES-192 decryption failed");
    const lab::AES aes256(from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"));
    const lab::Block encrypted256 = aes256.encrypt(lab::block(plain, 0));
    require(encrypted256 == lab::block(from_hex("8ea2b7ca516745bfeafc49904b496089"), 0),
            "AES-256 encryption vector failed");
    require(aes256.decrypt(encrypted256) == lab::block(plain, 0), "AES-256 decryption failed");
    require(aes128.decrypt(encrypted) == lab::block(plain, 0), "AES block decryption failed");
    require_throws([] { lab::AES invalid(Bytes(15, 0)); }, "Invalid AES key length was accepted");
}

void test_sp800_38a() {
    const lab::AES aes(from_hex("2b7e151628aed2a6abf7158809cf4f3c"));
    const Bytes iv = from_hex("000102030405060708090a0b0c0d0e0f");
    const Bytes ctr_initial = from_hex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    const Bytes plain = from_hex(
        "6bc1bee22e409f96e93d7e117393172a"
        "ae2d8a571e03ac9c9eb76fac45af8e51"
        "30c81c46a35ce411e5fbc1191a0a52ef"
        "f69f2445df4f9b17ad2b417be66c3710");
    const Bytes ecb = from_hex(
        "3ad77bb40d7a3660a89ecaf32466ef97"
        "f5d3d58503b9699de785895a96fdbaaf"
        "43b1cd7f598ece23881b00e3ed030688"
        "7b0c785e27e8ad3f8223207104725dd4");
    const Bytes cbc = from_hex(
        "7649abac8119b246cee98e9b12e9197d"
        "5086cb9b507219ee95db113a917678b2"
        "73bed6b8e3c1743b7116e69e22229516"
        "3ff1caa1681fac09120eca307586e1a7");
    const Bytes cfb = from_hex(
        "3b3fd92eb72dad20333449f8e83cfb4a"
        "c8a64537a0b3a93fcde3cdad9f1ce58b"
        "26751f67a3cbb140b1808cf187a4f4df"
        "c04b05357c5d1c0eeac4c66f9ff7f2e6");
    const Bytes ofb = from_hex(
        "3b3fd92eb72dad20333449f8e83cfb4a"
        "7789508d16918f03f53c52dac54ed825"
        "9740051e9c5fecf64344f7a82260edcc"
        "304c6528f659c77866a510d9c1d6ae5e");
    const Bytes ctr = from_hex(
        "874d6191b620e3261bef6864990db6ce"
        "9806f66b7970fdff8617187bb9fffdff"
        "5ae4df3edbd5d35e5b4f09020db03eab"
        "1e031dda2fbe03d1792170a0f3009cee");

    const Bytes ecb_encrypted = lab::ecb_encrypt(aes, plain);
    require(Bytes(ecb_encrypted.begin(), ecb_encrypted.begin() + 64) == ecb, "ECB NIST vector failed");
    require(lab::ecb_decrypt(aes, ecb_encrypted) == plain, "ECB round-trip failed");
    const Bytes cbc_encrypted = lab::cbc_encrypt(aes, plain, iv);
    require(Bytes(cbc_encrypted.begin(), cbc_encrypted.begin() + 64) == cbc, "CBC NIST vector failed");
    require(lab::cbc_decrypt(aes, cbc_encrypted, iv) == plain, "CBC round-trip failed");
    require(lab::cfb_encrypt(aes, plain, iv) == cfb, "CFB-128 NIST vector failed");
    require(lab::cfb_decrypt(aes, cfb, iv) == plain, "CFB-128 round-trip failed");
    require(lab::ofb_crypt(aes, plain, iv) == ofb, "OFB NIST vector failed");
    require(lab::ofb_crypt(aes, ofb, iv) == plain, "OFB round-trip failed");
    require(lab::ctr_crypt(aes, plain, ctr_initial) == ctr, "CTR NIST vector failed");
    require(lab::ctr_crypt(aes, ctr, ctr_initial) == plain, "CTR round-trip failed");

    const Bytes short_plain = from_hex("0102030405060708090a0b0c0d0e0f1011");
    const Bytes cfb8 = lab::cfb_encrypt(aes, short_plain, iv, 8);
    require(lab::cfb_decrypt(aes, cfb8, iv, 8) == short_plain, "CFB-8 round-trip failed");
    require_throws([&] { lab::cfb_encrypt(aes, short_plain, iv, 7); }, "Invalid CFB segment size was accepted");
    require_throws([&] { lab::ctr_crypt(aes, Bytes(17, 0), Bytes(16, 0xff)); },
                   "CTR counter overflow was not detected");
    require_throws([&] { lab::cbc_decrypt(aes, Bytes(15, 0), iv); }, "Unaligned CBC input was accepted");
}

void test_ccm() {
    const lab::AES aes(from_hex("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"));
    const Bytes nonce = from_hex("00000003020100a0a1a2a3a4a5");
    const Bytes aad = from_hex("0001020304050607");
    const Bytes plaintext = from_hex("08090a0b0c0d0e0f");
    const auto result = lab::ccm_encrypt(aes, plaintext, nonce, aad, 8);
    require(result.first == from_hex("588c979a61c663d2"), "CCM RFC 3610 ciphertext vector failed");
    require(result.second == from_hex("ea378169c1bc6209"), "CCM known-answer tag vector failed");
    require(lab::ccm_decrypt(aes, result.first, nonce, aad, result.second, 8) == plaintext,
            "CCM round-trip failed");

    Bytes bad_tag = result.second;
    bad_tag[0] ^= 1;
    require_throws([&] { lab::ccm_decrypt(aes, result.first, nonce, aad, bad_tag, 8); },
                   "CCM accepted a damaged tag");
    Bytes bad_ciphertext = result.first;
    bad_ciphertext[0] ^= 1;
    require_throws([&] { lab::ccm_decrypt(aes, bad_ciphertext, nonce, aad, result.second, 8); },
                   "CCM accepted damaged ciphertext");
    require_throws([&] { lab::ccm_encrypt(aes, plaintext, Bytes(6, 0), aad, 8); },
                   "CCM accepted an invalid nonce size");
}

void test_gcm() {
    const lab::AES aes(Bytes(16, 0));
    const Bytes nonce(12, 0);
    const auto empty = lab::gcm_encrypt(aes, {}, nonce, {}, 16);
    require(empty.first.empty(), "GCM empty plaintext produced ciphertext");
    require(empty.second == from_hex("58e2fccefa7e3061367f1d57a4e7455a"),
            "GCM empty-message NIST vector failed");

    const Bytes plaintext(16, 0);
    const auto result = lab::gcm_encrypt(aes, plaintext, nonce, {}, 16);
    require(result.first == from_hex("0388dace60b6a392f328c2b971b2fe78"),
            "GCM NIST ciphertext vector failed");
    require(result.second == from_hex("ab6e47d42cec13bdf53a67b21257bddf"),
            "GCM NIST tag vector failed");
    require(lab::gcm_decrypt(aes, result.first, nonce, {}, result.second, 16) == plaintext,
            "GCM round-trip failed");

    const Bytes aad = from_hex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
    const Bytes nonstandard_iv = from_hex("cafebabefacedbad");
    const auto authenticated = lab::gcm_encrypt(aes, plaintext, nonstandard_iv, aad, 12);
    require(authenticated.first == from_hex("5680d907f534f148fe1e9e3b27009353"),
            "GCM non-96-bit IV ciphertext vector failed");
    require(authenticated.second == from_hex("94b53f3c11cd058ab1824255"),
            "GCM non-96-bit IV authentication vector failed");
    require(lab::gcm_decrypt(aes, authenticated.first, nonstandard_iv, aad,
                            authenticated.second, 12) == plaintext,
            "GCM non-96-bit IV/AAD round-trip failed");
    Bytes bad_tag = result.second;
    bad_tag.back() ^= 0x80;
    require_throws([&] { lab::gcm_decrypt(aes, result.first, nonce, {}, bad_tag, 16); },
                   "GCM accepted a damaged tag");
    Bytes bad_ciphertext = result.first;
    bad_ciphertext[0] ^= 1;
    require_throws([&] { lab::gcm_decrypt(aes, bad_ciphertext, nonce, {}, result.second, 16); },
                   "GCM accepted damaged ciphertext");
    require_throws([&] { lab::gcm_decrypt(aes, result.first, nonce, Bytes{1}, result.second, 16); },
                   "GCM accepted damaged AAD");
}

} // namespace

int main() {
    try {
        test_aes_block_vectors();
        test_sp800_38a();
        test_ccm();
        test_gcm();
        std::cout << "All AES mode tests passed.\n";
        return EXIT_SUCCESS;
    } catch (const std::exception& error) {
        std::cerr << "Test failure: " << error.what() << '\n';
        return EXIT_FAILURE;
    }
}
