#include "test_main_or_catch.hpp"
#include <rsalab/oaep_manual.hpp>
#include <rsalab/rsa_oaep.hpp>
#include <rsalab/keyio.hpp>
#include <rsalab/util.hpp>
#include <cstdint>
#include <string>
#include <vector>
#include <iostream>

using namespace rsalab;

// Bonus A: Cross-check manual OAEP ↔ library OAEP

TEST(OaepManualTest, ManualEncryptLibraryDecrypt) {
    // manual_encrypt ↔ library_decrypt round-trip
    SUCCEED() << "Manual encrypt + library decrypt cross-check scaffold";
}

TEST(OaepManualTest, LibraryEncryptManualDecrypt) {
    // library_encrypt ↔ manual_decrypt round-trip
    SUCCEED() << "Library encrypt + manual decrypt cross-check scaffold";
}

TEST(OaepManualTest, ErrorSaiLabel) {
    // Test lỗi sai label cả hai hướng
    SUCCEED() << "Wrong label test scaffold";
}

TEST(OaepManualTest, LBitInCiphertext) {
    // Test lật bit trong ciphertext -> cùng lỗi generic với library
    SUCCEED() << "Flip bit in ciphertext test scaffold";
}