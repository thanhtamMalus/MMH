#ifndef AES_EXT_HPP
#define AES_EXT_HPP

#include <cstddef>
#include <cstdint>
#include "aes/aes128.hpp"

namespace aes {

constexpr size_t KEY_SIZE_192 = 24;
constexpr size_t ROUNDS_192 = 12;
constexpr size_t ROUND_KEYS_SIZE_192 = 16 * (ROUNDS_192 + 1); // 208 bytes

constexpr size_t KEY_SIZE_256 = 32;
constexpr size_t ROUNDS_256 = 14;
constexpr size_t ROUND_KEYS_SIZE_256 = 16 * (ROUNDS_256 + 1); // 240 bytes

void key_expansion_192(const uint8_t key[24], uint8_t round_keys[208], SBoxMode mode = SBoxMode::Table);
void encrypt_block_192(const uint8_t in[16], uint8_t out[16], const uint8_t round_keys[208], SBoxMode mode = SBoxMode::Table);

void key_expansion_256(const uint8_t key[32], uint8_t round_keys[240], SBoxMode mode = SBoxMode::Table);
void encrypt_block_256(const uint8_t in[16], uint8_t out[16], const uint8_t round_keys[240], SBoxMode mode = SBoxMode::Table);

} // namespace aes

#endif // AES_EXT_HPP
