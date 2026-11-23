#include "bonus/aes_ext.hpp"
#include "aes/platform.hpp"

namespace aes {

static const uint8_t RCON_EXT[16] = {
    0x00, // index 0
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
    0x6c, 0xd8, 0xab, 0x4d, 0x9a
};

void key_expansion_192(const uint8_t key[24], uint8_t round_keys[208], SBoxMode mode) {
    const size_t Nk = 6;
    const size_t Nr = 12;
    const size_t total_words = 4 * (Nr + 1); // 52 words = 208 bytes

    for (size_t i = 0; i < 24; ++i) {
        round_keys[i] = key[i];
    }

    uint8_t temp[4];
    for (size_t col = Nk; col < total_words; ++col) {
        temp[0] = round_keys[(col - 1) * 4 + 0];
        temp[1] = round_keys[(col - 1) * 4 + 1];
        temp[2] = round_keys[(col - 1) * 4 + 2];
        temp[3] = round_keys[(col - 1) * 4 + 3];

        if (col % Nk == 0) {
            uint8_t t = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = t;

            temp[0] = sbox_lookup(temp[0], mode);
            temp[1] = sbox_lookup(temp[1], mode);
            temp[2] = sbox_lookup(temp[2], mode);
            temp[3] = sbox_lookup(temp[3], mode);

            temp[0] ^= RCON_EXT[col / Nk];
        }

        round_keys[col * 4 + 0] = round_keys[(col - Nk) * 4 + 0] ^ temp[0];
        round_keys[col * 4 + 1] = round_keys[(col - Nk) * 4 + 1] ^ temp[1];
        round_keys[col * 4 + 2] = round_keys[(col - Nk) * 4 + 2] ^ temp[2];
        round_keys[col * 4 + 3] = round_keys[(col - Nk) * 4 + 3] ^ temp[3];
    }
    platform::secure_zero(temp, sizeof(temp));
}

void encrypt_block_192(const uint8_t in[16], uint8_t out[16], const uint8_t round_keys[208], SBoxMode mode) {
    uint8_t state[16];
    for (size_t i = 0; i < 16; ++i) state[i] = in[i];

    add_round_key(state, round_keys);

    for (size_t r = 1; r < ROUNDS_192; ++r) {
        sub_bytes(state, mode);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, round_keys + r * 16);
    }

    sub_bytes(state, mode);
    shift_rows(state);
    add_round_key(state, round_keys + ROUNDS_192 * 16);

    for (size_t i = 0; i < 16; ++i) out[i] = state[i];
    platform::secure_zero(state, sizeof(state));
}

void key_expansion_256(const uint8_t key[32], uint8_t round_keys[240], SBoxMode mode) {
    const size_t Nk = 8;
    const size_t Nr = 14;
    const size_t total_words = 4 * (Nr + 1); // 60 words = 240 bytes

    for (size_t i = 0; i < 32; ++i) {
        round_keys[i] = key[i];
    }

    uint8_t temp[4];
    for (size_t col = Nk; col < total_words; ++col) {
        temp[0] = round_keys[(col - 1) * 4 + 0];
        temp[1] = round_keys[(col - 1) * 4 + 1];
        temp[2] = round_keys[(col - 1) * 4 + 2];
        temp[3] = round_keys[(col - 1) * 4 + 3];

        if (col % Nk == 0) {
            uint8_t t = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = t;

            temp[0] = sbox_lookup(temp[0], mode);
            temp[1] = sbox_lookup(temp[1], mode);
            temp[2] = sbox_lookup(temp[2], mode);
            temp[3] = sbox_lookup(temp[3], mode);

            temp[0] ^= RCON_EXT[col / Nk];
        } else if (col % Nk == 4) {
            // FIPS-197 Section 5.2: for Nk=8, if (i % Nk == 4), SubWord without RotWord or Rcon
            temp[0] = sbox_lookup(temp[0], mode);
            temp[1] = sbox_lookup(temp[1], mode);
            temp[2] = sbox_lookup(temp[2], mode);
            temp[3] = sbox_lookup(temp[3], mode);
        }

        round_keys[col * 4 + 0] = round_keys[(col - Nk) * 4 + 0] ^ temp[0];
        round_keys[col * 4 + 1] = round_keys[(col - Nk) * 4 + 1] ^ temp[1];
        round_keys[col * 4 + 2] = round_keys[(col - Nk) * 4 + 2] ^ temp[2];
        round_keys[col * 4 + 3] = round_keys[(col - Nk) * 4 + 3] ^ temp[3];
    }
    platform::secure_zero(temp, sizeof(temp));
}

void encrypt_block_256(const uint8_t in[16], uint8_t out[16], const uint8_t round_keys[240], SBoxMode mode) {
    uint8_t state[16];
    for (size_t i = 0; i < 16; ++i) state[i] = in[i];

    add_round_key(state, round_keys);

    for (size_t r = 1; r < ROUNDS_256; ++r) {
        sub_bytes(state, mode);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, round_keys + r * 16);
    }

    sub_bytes(state, mode);
    shift_rows(state);
    add_round_key(state, round_keys + ROUNDS_256 * 16);

    for (size_t i = 0; i < 16; ++i) out[i] = state[i];
    platform::secure_zero(state, sizeof(state));
}

} // namespace aes
