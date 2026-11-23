#include "aes/aes128.hpp"

namespace aes {

// GF(2^8) multiplication modulo irreducible polynomial m(x) = x^8 + x^4 + x^3 + x + 1 (0x11B)
// FIPS-197 Section 4.2.1
uint8_t xtime(uint8_t b) {
    uint8_t mask = static_cast<uint8_t>(-static_cast<int8_t>(b >> 7));
    return static_cast<uint8_t>((b << 1) ^ (mask & 0x1B));
}

uint8_t gf_mult(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; ++i) {
        if (b & 1) {
            p ^= a;
        }
        a = xtime(a);
        b >>= 1;
    }
    return p;
}

// Compute multiplicative inverse in GF(2^8) via exponentiation: a^(254) = a^(-1) for a != 0, 0 for a == 0
static uint8_t gf_inv(uint8_t a) {
    // 254 = 11111110_2
    uint8_t a2   = gf_mult(a, a);       // a^2
    uint8_t a3   = gf_mult(a2, a);      // a^3
    uint8_t a6   = gf_mult(a3, a3);     // a^6
    uint8_t a7   = gf_mult(a6, a);      // a^7
    uint8_t a14  = gf_mult(a7, a7);     // a^14
    uint8_t a15  = gf_mult(a14, a);     // a^15
    uint8_t a30  = gf_mult(a15, a15);   // a^30
    uint8_t a31  = gf_mult(a30, a);     // a^31
    uint8_t a62  = gf_mult(a31, a31);   // a^62
    uint8_t a63  = gf_mult(a62, a);     // a^63
    uint8_t a126 = gf_mult(a63, a63);   // a^126
    uint8_t a127 = gf_mult(a126, a);    // a^127
    uint8_t a254 = gf_mult(a127, a127); // a^254
    return a254;
}

static inline uint8_t rotl8(uint8_t val, int shift) {
    return static_cast<uint8_t>((val << shift) | (val >> (8 - shift)));
}

// FIPS-197 Section 5.1.1: S-box Affine Transformation
// b' = b ^ rotl(b, 1) ^ rotl(b, 2) ^ rotl(b, 3) ^ rotl(b, 4) ^ 0x63
uint8_t sbox_computed_get(uint8_t byte) {
    uint8_t inv = gf_inv(byte);
    uint8_t transformed = inv ^
                          rotl8(inv, 1) ^
                          rotl8(inv, 2) ^
                          rotl8(inv, 3) ^
                          rotl8(inv, 4) ^
                          0x63;
    return transformed;
}

// FIPS-197 Section 5.3.2: Inverse S-box
// Inverse Affine: b = rotl(y, 1) ^ rotl(y, 3) ^ rotl(y, 6) ^ 0x05
// Followed by multiplicative inverse in GF(2^8)
uint8_t inv_sbox_computed_get(uint8_t byte) {
    uint8_t affine_inv = rotl8(byte, 1) ^
                         rotl8(byte, 3) ^
                         rotl8(byte, 6) ^
                         0x05;
    return gf_inv(affine_inv);
}

uint8_t sbox_lookup(uint8_t byte, SBoxMode mode) {
    if (mode == SBoxMode::Computed) {
        return sbox_computed_get(byte);
    }
    return sbox_table_get(byte);
}

uint8_t inv_sbox_lookup(uint8_t byte, SBoxMode mode) {
    if (mode == SBoxMode::Computed) {
        return inv_sbox_computed_get(byte);
    }
    return inv_sbox_table_get(byte);
}

} // namespace aes
