#ifndef AES_AES128_HPP
#define AES_AES128_HPP

#include <cstddef>
#include <cstdint>

namespace aes {

enum class SBoxMode {
    Table,
    Computed
};

constexpr size_t BLOCK_SIZE = 16;
constexpr size_t KEY_SIZE_128 = 16;
constexpr size_t ROUNDS_128 = 10;
constexpr size_t ROUND_KEYS_SIZE_128 = 16 * (ROUNDS_128 + 1); // 176 bytes

// S-box functions
uint8_t sbox_lookup(uint8_t byte, SBoxMode mode = SBoxMode::Table);
uint8_t inv_sbox_lookup(uint8_t byte, SBoxMode mode = SBoxMode::Table);

uint8_t sbox_table_get(uint8_t byte);
uint8_t sbox_computed_get(uint8_t byte);
uint8_t inv_sbox_table_get(uint8_t byte);
uint8_t inv_sbox_computed_get(uint8_t byte);

// Finite Field Multiplication over GF(2^8) (FIPS-197 Section 4.2.1)
uint8_t xtime(uint8_t b);
uint8_t gf_mult(uint8_t a, uint8_t b);

// Core Transformations (FIPS-197 Section 5.1 & 5.3)
void sub_bytes(uint8_t state[16], SBoxMode mode = SBoxMode::Table);
void inv_sub_bytes(uint8_t state[16], SBoxMode mode = SBoxMode::Table);

void shift_rows(uint8_t state[16]);
void inv_shift_rows(uint8_t state[16]);

void mix_columns(uint8_t state[16]);
void inv_mix_columns(uint8_t state[16]);

void add_round_key(uint8_t state[16], const uint8_t round_key[16]);

// Key Expansion (FIPS-197 Section 5.2)
void key_expansion_128(const uint8_t key[16], uint8_t round_keys[176], SBoxMode mode = SBoxMode::Table);

// Block Cipher (FIPS-197 Section 5.1)
void encrypt_block_128(const uint8_t in[16], uint8_t out[16], const uint8_t round_keys[176], SBoxMode mode = SBoxMode::Table);
void decrypt_block_128(const uint8_t in[16], uint8_t out[16], const uint8_t round_keys[176], SBoxMode mode = SBoxMode::Table);

} // namespace aes

#endif // AES_AES128_HPP
