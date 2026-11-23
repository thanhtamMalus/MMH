#ifndef AES_CTR_HPP
#define AES_CTR_HPP

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include "aes/aes128.hpp"

namespace aes {

enum class CtrStatus {
    Success = 0,
    ParamError = 1,
    KeyIvError = 2,
    IOError = 3,
    CounterOverflow = 4,
    KatFailure = 5
};

const char* ctr_status_to_string(CtrStatus status);

/**
 * @brief Increments a 128-bit big-endian counter block.
 * Starts from byte 15, carrying towards byte 0.
 * @return true if increment succeeded without 128-bit overflow.
 * @return false if carry propagated beyond byte 0 (overflow).
 */
bool increment_counter_128(uint8_t counter[16]);

/**
 * @brief In-memory CTR mode encryption/decryption.
 * Encrypt and decrypt are identical.
 */
CtrStatus ctr_crypt_buffer(
    const uint8_t* in,
    uint8_t* out,
    size_t length,
    const uint8_t key[16],
    const uint8_t iv[16],
    SBoxMode sbox_mode = SBoxMode::Table,
    size_t key_bits = 128
);

/**
 * @brief Streaming CTR mode encryption/decryption between files.
 * Streams in 1 MiB chunks for constant memory overhead.
 * Atomically replaces out_file on success.
 * Removes temporary file on any error (Fail-Closed).
 */
CtrStatus ctr_crypt_file(
    const std::string& in_file,
    const std::string& out_file,
    const std::string& key_file,
    const std::string& iv_file,
    SBoxMode sbox_mode = SBoxMode::Table,
    size_t key_bits = 128,
    size_t chunk_size = 1024 * 1024 // 1 MiB
);

} // namespace aes

#endif // AES_CTR_HPP
