#pragma once

#include "aes.hpp"

#include <cstddef>
#include <utility>

namespace lab {

using AeadResult = std::pair<Bytes, Bytes>;

AeadResult ccm_encrypt(const AES& aes, const Bytes& plaintext, const Bytes& iv,
                       const Bytes& aad, std::size_t tag_len);
Bytes ccm_decrypt(const AES& aes, const Bytes& ciphertext, const Bytes& iv,
                  const Bytes& aad, const Bytes& tag, std::size_t tag_len);

} // namespace lab
