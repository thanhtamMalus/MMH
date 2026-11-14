#pragma once

#include "aes.hpp"
#include "sp800_38c.hpp"

#include <cstddef>

namespace lab {

AeadResult gcm_encrypt(const AES& aes, const Bytes& plaintext, const Bytes& iv,
                       const Bytes& aad, std::size_t tag_len);
Bytes gcm_decrypt(const AES& aes, const Bytes& ciphertext, const Bytes& iv,
                  const Bytes& aad, const Bytes& tag, std::size_t tag_len);

} // namespace lab
