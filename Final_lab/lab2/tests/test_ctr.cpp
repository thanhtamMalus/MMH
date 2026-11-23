#include "test_harness.hpp"
#include "aes/ctr.hpp"
#include "aes/util.hpp"
#include <vector>
#include <cstring>

TEST_CASE("CTR: NIST SP 800-38A F.5.1 KAT") {
    std::string key_hex = "2b7e151628aed2a6abf7158809cf4f3c";
    std::string iv_hex  = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
    std::string pt_hex  = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710";
    std::string ct_hex  = "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee";

    std::vector<uint8_t> key, iv, pt, ct;
    REQUIRE(aes::util::from_hex(key_hex, key));
    REQUIRE(aes::util::from_hex(iv_hex, iv));
    REQUIRE(aes::util::from_hex(pt_hex, pt));
    REQUIRE(aes::util::from_hex(ct_hex, ct));

    std::vector<uint8_t> actual_ct(pt.size());
    aes::CtrStatus st1 = aes::ctr_crypt_buffer(
        pt.data(), actual_ct.data(), pt.size(),
        key.data(), iv.data(), aes::SBoxMode::Table, 128
    );
    REQUIRE(st1 == aes::CtrStatus::Success);
    REQUIRE(std::memcmp(actual_ct.data(), ct.data(), ct.size()) == 0);

    // Decrypt (identical operation)
    std::vector<uint8_t> actual_pt(ct.size());
    aes::CtrStatus st2 = aes::ctr_crypt_buffer(
        ct.data(), actual_pt.data(), ct.size(),
        key.data(), iv.data(), aes::SBoxMode::Table, 128
    );
    REQUIRE(st2 == aes::CtrStatus::Success);
    REQUIRE(std::memcmp(actual_pt.data(), pt.data(), pt.size()) == 0);
}

TEST_CASE("CTR: Arbitrary lengths (0, 1, 15, 16, 17, 31, 32, 33 bytes)") {
    uint8_t key[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    uint8_t iv[16]  = {16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1};

    std::vector<size_t> test_lengths = {0, 1, 15, 16, 17, 31, 32, 33, 1024, 65535};

    for (size_t len : test_lengths) {
        std::vector<uint8_t> pt(len);
        for (size_t i = 0; i < len; ++i) {
            pt[i] = static_cast<uint8_t>((i * 7 + 13) & 0xFF);
        }

        std::vector<uint8_t> ct(len);
        std::vector<uint8_t> decrypted(len);

        aes::CtrStatus st_enc = aes::ctr_crypt_buffer(pt.data(), ct.data(), len, key, iv);
        REQUIRE(st_enc == aes::CtrStatus::Success);

        aes::CtrStatus st_dec = aes::ctr_crypt_buffer(ct.data(), decrypted.data(), len, key, iv);
        REQUIRE(st_dec == aes::CtrStatus::Success);

        if (len > 0) {
            REQUIRE(std::memcmp(pt.data(), decrypted.data(), len) == 0);
        }
    }
}

TEST_CASE("CTR: Counter Carry across byte boundaries") {
    uint8_t counter[16];
    std::memset(counter, 0, 16);
    counter[15] = 0xFE;

    // FE -> FF (no carry to byte 14)
    REQUIRE(aes::increment_counter_128(counter));
    REQUIRE(counter[15] == 0xFF);
    REQUIRE(counter[14] == 0x00);

    // FF -> 00 (carry to byte 14)
    REQUIRE(aes::increment_counter_128(counter));
    REQUIRE(counter[15] == 0x00);
    REQUIRE(counter[14] == 0x01);

    // Multi-byte carry: 00...00FFFF -> 00...010000
    counter[14] = 0xFF;
    counter[15] = 0xFF;
    counter[13] = 0x00;
    REQUIRE(aes::increment_counter_128(counter));
    REQUIRE(counter[15] == 0x00);
    REQUIRE(counter[14] == 0x00);
    REQUIRE(counter[13] == 0x01);
}

TEST_CASE("CTR: 128-bit Counter Overflow (Fail-Closed)") {
    uint8_t key[16] = {0};
    uint8_t max_iv[16];
    std::memset(max_iv, 0xFF, 16);

    // Case 1: Data length <= 16 bytes. Uses exactly 1 block, no subsequent block needed.
    // Should succeed without incrementing past 0xFF..FF.
    uint8_t buf16[16] = {0};
    uint8_t out16[16] = {0};
    aes::CtrStatus st_ok = aes::ctr_crypt_buffer(buf16, out16, 16, key, max_iv);
    REQUIRE(st_ok == aes::CtrStatus::Success);

    // Case 2: Data length > 16 bytes (17 bytes). Needs 2 blocks.
    // Incrementing max_iv overflows 128-bit integer. Must return CounterOverflow!
    uint8_t buf17[17] = {0};
    uint8_t out17[17] = {0};
    aes::CtrStatus st_overflow = aes::ctr_crypt_buffer(buf17, out17, 17, key, max_iv);
    REQUIRE(st_overflow == aes::CtrStatus::CounterOverflow);
}
