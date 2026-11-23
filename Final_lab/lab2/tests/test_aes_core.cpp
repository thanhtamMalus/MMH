#include "test_harness.hpp"
#include "aes/aes128.hpp"
#include "aes/util.hpp"
#include <cstring>

TEST_CASE("SBox: Table vs Computed matches on all 256 values") {
    for (int i = 0; i < 256; ++i) {
        uint8_t byte = static_cast<uint8_t>(i);
        uint8_t tbl = aes::sbox_table_get(byte);
        uint8_t cmp = aes::sbox_computed_get(byte);
        REQUIRE(tbl == cmp);

        uint8_t inv_tbl = aes::inv_sbox_table_get(byte);
        uint8_t inv_cmp = aes::inv_sbox_computed_get(byte);
        REQUIRE(inv_tbl == inv_cmp);

        // Round-trip check: S-box followed by InvS-box
        REQUIRE(aes::inv_sbox_lookup(aes::sbox_lookup(byte)) == byte);
    }
}

TEST_CASE("AES-128: KeyExpansion matches FIPS-197 Appendix A.1") {
    // Cipher Key: 2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c
    std::string key_hex = "2b7e151628aed2a6abf7158809cf4f3c";
    std::vector<uint8_t> key;
    REQUIRE(aes::util::from_hex(key_hex, key));

    uint8_t round_keys[176];
    aes::key_expansion_128(key.data(), round_keys, aes::SBoxMode::Table);

    // Expected round keys from FIPS-197 App A.1
    std::string expected_rk[11] = {
        "2b7e151628aed2a6abf7158809cf4f3c", // Round 0
        "a0fafe1788542cb123a339392a6c7605", // Round 1
        "f2c295f27a96b9435935807a7359f67f", // Round 2
        "3d80477d4716fe3e1e237e446d7a883b", // Round 3
        "ef44a541a8525b7fb671253bdb0bad00", // Round 4
        "d4d1c6f87c839d87caf2b8bc11f915bc", // Round 5
        "6d88a37a110b3efddbf98641ca0093fd", // Round 6
        "4e54f70e5f5fc9f384a64fb24ea6dc4f", // Round 7
        "ead27321b58dbad2312bf5607f8d292f", // Round 8
        "ac7766f319fadc2128d12941575c006e", // Round 9
        "d014f9a8c9ee2589e13f0cc8b6630ca6"  // Round 10
    };

    for (size_t r = 0; r <= 10; ++r) {
        std::string actual_rk = aes::util::to_hex(round_keys + r * 16, 16);
        REQUIRE(actual_rk == expected_rk[r]);
    }
}

TEST_CASE("AES-128: Individual Round Transformations (FIPS-197 Appendix B)") {
    std::string key_hex = "2b7e151628aed2a6abf7158809cf4f3c";
    std::string pt_hex  = "3243f6a8885a308d313198a2e0370734";
    std::vector<uint8_t> key, pt;
    REQUIRE(aes::util::from_hex(key_hex, key));
    REQUIRE(aes::util::from_hex(pt_hex, pt));

    uint8_t state[16];
    std::memcpy(state, pt.data(), 16);

    uint8_t round_keys[176];
    aes::key_expansion_128(key.data(), round_keys);

    // Round 0: AddRoundKey
    aes::add_round_key(state, round_keys);
    REQUIRE(aes::util::to_hex(state, 16) == "193de3bea0f4e22b9ac68d2ae9f84808");

    // Round 1: SubBytes
    aes::sub_bytes(state, aes::SBoxMode::Table);
    REQUIRE(aes::util::to_hex(state, 16) == "d42711aee0bf98f1b8b45de51e415230");

    // Round 1: ShiftRows
    aes::shift_rows(state);
    REQUIRE(aes::util::to_hex(state, 16) == "d4bf5d30e0b452aeb84111f11e2798e5");

    // Round 1: MixColumns
    aes::mix_columns(state);
    REQUIRE(aes::util::to_hex(state, 16) == "046681e5e0cb199a48f8d37a2806264c");

    // Round 1: AddRoundKey
    aes::add_round_key(state, round_keys + 16);
    REQUIRE(aes::util::to_hex(state, 16) == "a49c7ff2689f352b6b5bea43026a5049");
}

TEST_CASE("AES-128: Block KAT FIPS-197 Appendix B & C.1 (Encrypt & Decrypt)") {
    // Vector 1: FIPS-197 Appendix B
    {
        std::vector<uint8_t> key, pt, ct;
        REQUIRE(aes::util::from_hex("2b7e151628aed2a6abf7158809cf4f3c", key));
        REQUIRE(aes::util::from_hex("3243f6a8885a308d313198a2e0370734", pt));
        REQUIRE(aes::util::from_hex("3925841d02dc09fbdc118597196a0b32", ct));

        uint8_t rk[176];
        aes::key_expansion_128(key.data(), rk);

        uint8_t actual_ct[16];
        aes::encrypt_block_128(pt.data(), actual_ct, rk, aes::SBoxMode::Table);
        REQUIRE(std::memcmp(actual_ct, ct.data(), 16) == 0);

        uint8_t actual_pt[16];
        aes::decrypt_block_128(actual_ct, actual_pt, rk, aes::SBoxMode::Table);
        REQUIRE(std::memcmp(actual_pt, pt.data(), 16) == 0);

        // Also verify with computed S-box
        uint8_t actual_ct_comp[16];
        aes::encrypt_block_128(pt.data(), actual_ct_comp, rk, aes::SBoxMode::Computed);
        REQUIRE(std::memcmp(actual_ct_comp, ct.data(), 16) == 0);
    }

    // Vector 2: FIPS-197 Appendix C.1
    {
        std::vector<uint8_t> key, pt, ct;
        REQUIRE(aes::util::from_hex("000102030405060708090a0b0c0d0e0f", key));
        REQUIRE(aes::util::from_hex("00112233445566778899aabbccddeeff", pt));
        REQUIRE(aes::util::from_hex("69c4e0d86a7b0430d8cdb78070b4c55a", ct));

        uint8_t rk[176];
        aes::key_expansion_128(key.data(), rk);

        uint8_t actual_ct[16];
        aes::encrypt_block_128(pt.data(), actual_ct, rk, aes::SBoxMode::Table);
        REQUIRE(std::memcmp(actual_ct, ct.data(), 16) == 0);

        uint8_t actual_pt[16];
        aes::decrypt_block_128(actual_ct, actual_pt, rk, aes::SBoxMode::Table);
        REQUIRE(std::memcmp(actual_pt, pt.data(), 16) == 0);
    }
}
