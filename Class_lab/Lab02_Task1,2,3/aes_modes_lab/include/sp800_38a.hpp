#pragma once

#include "aes.hpp"

#include <cstddef>

namespace lab {

Bytes ecb_encrypt(const AES& aes, const Bytes& plaintext);
Bytes ecb_decrypt(const AES& aes, const Bytes& ciphertext);

Bytes cbc_encrypt(const AES& aes, const Bytes& plaintext, const Bytes& iv);
Bytes cbc_decrypt(const AES& aes, const Bytes& ciphertext, const Bytes& iv);

Bytes cfb_encrypt(const AES& aes, const Bytes& input, const Bytes& iv,
                  std::size_t segment_bits = 128);
Bytes cfb_decrypt(const AES& aes, const Bytes& input, const Bytes& iv,
                  std::size_t segment_bits = 128);

Bytes ofb_crypt(const AES& aes, const Bytes& input, const Bytes& iv);
Bytes ctr_crypt(const AES& aes, const Bytes& input, const Bytes& initial_counter);

} // namespace lab
