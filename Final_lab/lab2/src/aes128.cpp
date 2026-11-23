#include "aes/aes128.hpp"
#include "aes/platform.hpp"
#include <algorithm>

namespace aes {

// FIPS-197 Section 5.2: Round Constant Word Array
static const uint8_t RCON[11] = {
    0x00, // Unused (index 0)
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

// FIPS-197 Section 5.1.4: AddRoundKey
// State is XORed with the corresponding Round Key block
void add_round_key(uint8_t state[16], const uint8_t round_key[16]) {
    for (size_t i = 0; i < 16; ++i) {
        state[i] ^= round_key[i];
    }
}

// FIPS-197 Section 5.1.1: SubBytes
// Non-linear byte substitution using S-box
void sub_bytes(uint8_t state[16], SBoxMode mode) {
    for (size_t i = 0; i < 16; ++i) {
        state[i] = sbox_lookup(state[i], mode);
    }
}

// FIPS-197 Section 5.3.2: InvSubBytes
void inv_sub_bytes(uint8_t state[16], SBoxMode mode) {
    for (size_t i = 0; i < 16; ++i) {
        state[i] = inv_sbox_lookup(state[i], mode);
    }
}

// FIPS-197 Section 5.1.2: ShiftRows
// Row r is cyclically shifted to the left by r bytes
// Column-major representation: state[r + 4*c]
void shift_rows(uint8_t state[16]) {
    // Row 0: no shift

    // Row 1: shift left by 1 byte
    uint8_t temp1 = state[1];
    state[1]  = state[5];
    state[5]  = state[9];
    state[9]  = state[13];
    state[13] = temp1;

    // Row 2: shift left by 2 bytes
    uint8_t temp2_0 = state[2];
    uint8_t temp2_1 = state[6];
    state[2]  = state[10];
    state[6]  = state[14];
    state[10] = temp2_0;
    state[14] = temp2_1;

    // Row 3: shift left by 3 bytes (shift right by 1 byte)
    uint8_t temp3 = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7]  = state[3];
    state[3]  = temp3;
}

// FIPS-197 Section 5.3.1: InvShiftRows
void inv_shift_rows(uint8_t state[16]) {
    // Row 0: no shift

    // Row 1: shift right by 1 byte
    uint8_t temp1 = state[13];
    state[13] = state[9];
    state[9]  = state[5];
    state[5]  = state[1];
    state[1]  = temp1;

    // Row 2: shift right by 2 bytes
    uint8_t temp2_0 = state[10];
    uint8_t temp2_1 = state[14];
    state[10] = state[2];
    state[14] = state[6];
    state[2]  = temp2_0;
    state[6]  = temp2_1;

    // Row 3: shift right by 3 bytes (shift left by 1 byte)
    uint8_t temp3 = state[3];
    state[3]  = state[7];
    state[7]  = state[11];
    state[11] = state[15];
    state[15] = temp3;
}

// FIPS-197 Section 5.1.3: MixColumns
// Each column is transformed as a 4-term polynomial in GF(2^8) modulo x^4 + 1
void mix_columns(uint8_t state[16]) {
    for (size_t c = 0; c < 4; ++c) {
        size_t idx = c * 4;
        uint8_t s0 = state[idx + 0];
        uint8_t s1 = state[idx + 1];
        uint8_t s2 = state[idx + 2];
        uint8_t s3 = state[idx + 3];

        uint8_t u = s0 ^ s1 ^ s2 ^ s3;
        state[idx + 0] = s0 ^ xtime(static_cast<uint8_t>(s0 ^ s1)) ^ u;
        state[idx + 1] = s1 ^ xtime(static_cast<uint8_t>(s1 ^ s2)) ^ u;
        state[idx + 2] = s2 ^ xtime(static_cast<uint8_t>(s2 ^ s3)) ^ u;
        state[idx + 3] = s3 ^ xtime(static_cast<uint8_t>(s3 ^ s0)) ^ u;
    }
}

// FIPS-197 Section 5.3.3: InvMixColumns
void inv_mix_columns(uint8_t state[16]) {
    for (size_t c = 0; c < 4; ++c) {
        size_t idx = c * 4;
        uint8_t s0 = state[idx + 0];
        uint8_t s1 = state[idx + 1];
        uint8_t s2 = state[idx + 2];
        uint8_t s3 = state[idx + 3];

        state[idx + 0] = gf_mult(s0, 0x0e) ^ gf_mult(s1, 0x0b) ^ gf_mult(s2, 0x0d) ^ gf_mult(s3, 0x09);
        state[idx + 1] = gf_mult(s0, 0x09) ^ gf_mult(s1, 0x0e) ^ gf_mult(s2, 0x0b) ^ gf_mult(s3, 0x0d);
        state[idx + 2] = gf_mult(s0, 0x0d) ^ gf_mult(s1, 0x09) ^ gf_mult(s2, 0x0e) ^ gf_mult(s3, 0x0b);
        state[idx + 3] = gf_mult(s0, 0x0b) ^ gf_mult(s1, 0x0d) ^ gf_mult(s2, 0x09) ^ gf_mult(s3, 0x0e);
    }
}

// FIPS-197 Section 5.2: KeyExpansion for AES-128 (Nk = 4, Nr = 10, Nb = 4)
void key_expansion_128(const uint8_t key[16], uint8_t round_keys[176], SBoxMode mode) {
    // Copy the original 128-bit cipher key into the first round key
    for (size_t i = 0; i < 16; ++i) {
        round_keys[i] = key[i];
    }

    uint8_t temp[4];
    for (size_t col = 4; col < 44; ++col) {
        // temp = w[col - 1]
        temp[0] = round_keys[(col - 1) * 4 + 0];
        temp[1] = round_keys[(col - 1) * 4 + 1];
        temp[2] = round_keys[(col - 1) * 4 + 2];
        temp[3] = round_keys[(col - 1) * 4 + 3];

        if (col % 4 == 0) {
            // RotWord: cyclic shift of 4-byte word [a0, a1, a2, a3] -> [a1, a2, a3, a0]
            uint8_t t = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = t;

            // SubWord: apply S-box to each of the 4 bytes
            temp[0] = sbox_lookup(temp[0], mode);
            temp[1] = sbox_lookup(temp[1], mode);
            temp[2] = sbox_lookup(temp[2], mode);
            temp[3] = sbox_lookup(temp[3], mode);

            // XOR with Rcon[col / 4]
            temp[0] ^= RCON[col / 4];
        }

        // w[col] = w[col - 4] ^ temp
        round_keys[col * 4 + 0] = round_keys[(col - 4) * 4 + 0] ^ temp[0];
        round_keys[col * 4 + 1] = round_keys[(col - 4) * 4 + 1] ^ temp[1];
        round_keys[col * 4 + 2] = round_keys[(col - 4) * 4 + 2] ^ temp[2];
        round_keys[col * 4 + 3] = round_keys[(col - 4) * 4 + 3] ^ temp[3];
    }

    // Clean up temporary variables
    platform::secure_zero(temp, sizeof(temp));
}

// FIPS-197 Section 5.1: Cipher (Encrypt Block)
void encrypt_block_128(const uint8_t in[16], uint8_t out[16], const uint8_t round_keys[176], SBoxMode mode) {
    uint8_t state[16];
    for (size_t i = 0; i < 16; ++i) {
        state[i] = in[i];
    }

    // Initial round: AddRoundKey
    add_round_key(state, round_keys);

    // Rounds 1 through Nr - 1 (1 to 9)
    for (size_t r = 1; r < ROUNDS_128; ++r) {
        sub_bytes(state, mode);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, round_keys + r * 16);
    }

    // Final round (Round 10): SubBytes, ShiftRows, AddRoundKey (No MixColumns)
    sub_bytes(state, mode);
    shift_rows(state);
    add_round_key(state, round_keys + ROUNDS_128 * 16);

    for (size_t i = 0; i < 16; ++i) {
        out[i] = state[i];
    }

    platform::secure_zero(state, sizeof(state));
}

// FIPS-197 Section 5.3: InvCipher (Decrypt Block)
void decrypt_block_128(const uint8_t in[16], uint8_t out[16], const uint8_t round_keys[176], SBoxMode mode) {
    uint8_t state[16];
    for (size_t i = 0; i < 16; ++i) {
        state[i] = in[i];
    }

    // Initial round: AddRoundKey with final round key
    add_round_key(state, round_keys + ROUNDS_128 * 16);

    // Rounds Nr - 1 down to 1 (9 down to 1)
    for (size_t r = ROUNDS_128 - 1; r >= 1; --r) {
        inv_shift_rows(state);
        inv_sub_bytes(state, mode);
        add_round_key(state, round_keys + r * 16);
        inv_mix_columns(state);
    }

    // Final round: InvShiftRows, InvSubBytes, AddRoundKey
    inv_shift_rows(state);
    inv_sub_bytes(state, mode);
    add_round_key(state, round_keys);

    for (size_t i = 0; i < 16; ++i) {
        out[i] = state[i];
    }

    platform::secure_zero(state, sizeof(state));
}

} // namespace aes
