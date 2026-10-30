#include "aes/ctr.hpp"
#include "aes/util.hpp"
#include "aes/platform.hpp"
#include "bonus/aes_ext.hpp"
#include <fstream>
#include <filesystem>
#include <algorithm>
#include <cstring>

namespace aes {

const char* ctr_status_to_string(CtrStatus status) {
    switch (status) {
        case CtrStatus::Success: return "Success";
        case CtrStatus::ParamError: return "Parameter Error";
        case CtrStatus::KeyIvError: return "Key/IV Error";
        case CtrStatus::IOError: return "I/O Error";
        case CtrStatus::CounterOverflow: return "Counter 128-bit Overflow Error";
        case CtrStatus::KatFailure: return "KAT Failure";
        default: return "Unknown Error";
    }
}

bool increment_counter_128(uint8_t counter[16]) {
    for (int i = 15; i >= 0; --i) {
        counter[i]++;
        if (counter[i] != 0) {
            return true;
        }
    }
    // All 16 bytes overflowed from 0xFF to 0x00: carry propagated out of bit 128!
    return false;
}

static inline void encrypt_block_dispatch(
    const uint8_t in[16],
    uint8_t out[16],
    const uint8_t* round_keys,
    SBoxMode mode,
    size_t key_bits
) {
    if (key_bits == 128) {
        encrypt_block_128(in, out, round_keys, mode);
    } else if (key_bits == 192) {
        encrypt_block_192(in, out, round_keys, mode);
    } else if (key_bits == 256) {
        encrypt_block_256(in, out, round_keys, mode);
    } else {
        encrypt_block_128(in, out, round_keys, mode);
    }
}

CtrStatus ctr_crypt_buffer(
    const uint8_t* in,
    uint8_t* out,
    size_t length,
    const uint8_t key[16],
    const uint8_t iv[16],
    SBoxMode sbox_mode,
    size_t key_bits
) {
    if (length == 0) {
        return CtrStatus::Success;
    }
    if (!in || !out || !key || !iv) {
        return CtrStatus::ParamError;
    }

    // Allocate round keys securely
    size_t round_keys_size = (key_bits == 256) ? ROUND_KEYS_SIZE_256 :
                             (key_bits == 192) ? ROUND_KEYS_SIZE_192 :
                             ROUND_KEYS_SIZE_128;

    util::SecureByteVector round_keys(round_keys_size);
    if (key_bits == 128) {
        key_expansion_128(key, round_keys.data(), sbox_mode);
    } else if (key_bits == 192) {
        key_expansion_192(key, round_keys.data(), sbox_mode);
    } else if (key_bits == 256) {
        key_expansion_256(key, round_keys.data(), sbox_mode);
    } else {
        return CtrStatus::KeyIvError;
    }

    uint8_t counter[16];
    std::memcpy(counter, iv, 16);

    uint8_t keystream[16];
    size_t offset = 0;

    while (offset < length) {
        // S_i = AES_K(Counter_i)
        encrypt_block_dispatch(counter, keystream, round_keys.data(), sbox_mode, key_bits);

        size_t block_bytes = std::min(static_cast<size_t>(16), length - offset);
        for (size_t b = 0; b < block_bytes; ++b) {
            out[offset + b] = in[offset + b] ^ keystream[b];
        }
        offset += block_bytes;

        // If there are more bytes to process, increment counter
        if (offset < length) {
            if (!increment_counter_128(counter)) {
                // Fail-closed on counter overflow
                platform::secure_zero(counter, sizeof(counter));
                platform::secure_zero(keystream, sizeof(keystream));
                return CtrStatus::CounterOverflow;
            }
        }
    }

    platform::secure_zero(counter, sizeof(counter));
    platform::secure_zero(keystream, sizeof(keystream));
    return CtrStatus::Success;
}

CtrStatus ctr_crypt_file(
    const std::string& in_file,
    const std::string& out_file,
    const std::string& key_file,
    const std::string& iv_file,
    SBoxMode sbox_mode,
    size_t key_bits,
    size_t chunk_size
) {
    // Validate key and IV file sizes
    size_t expected_key_len = key_bits / 8;
    std::vector<uint8_t> key_raw;
    if (!util::read_binary_file(key_file, key_raw) || key_raw.size() != expected_key_len) {
        platform::secure_zero(key_raw.data(), key_raw.size());
        return CtrStatus::KeyIvError;
    }

    std::vector<uint8_t> iv_raw;
    if (!util::read_binary_file(iv_file, iv_raw) || iv_raw.size() != 16) {
        platform::secure_zero(key_raw.data(), key_raw.size());
        platform::secure_zero(iv_raw.data(), iv_raw.size());
        return CtrStatus::KeyIvError;
    }

    std::ifstream in_stream(in_file, std::ios::binary);
    if (!in_stream.is_open()) {
        platform::secure_zero(key_raw.data(), key_raw.size());
        platform::secure_zero(iv_raw.data(), iv_raw.size());
        return CtrStatus::IOError;
    }

    // Temporary output file to guarantee fail-closed atomicity
    std::string temp_file = out_file + ".tmp";
    std::ofstream out_stream(temp_file, std::ios::binary | std::ios::trunc);
    if (!out_stream.is_open()) {
        in_stream.close();
        platform::secure_zero(key_raw.data(), key_raw.size());
        platform::secure_zero(iv_raw.data(), iv_raw.size());
        return CtrStatus::IOError;
    }

    // Expand keys
    size_t round_keys_size = (key_bits == 256) ? ROUND_KEYS_SIZE_256 :
                             (key_bits == 192) ? ROUND_KEYS_SIZE_192 :
                             ROUND_KEYS_SIZE_128;

    util::SecureByteVector round_keys(round_keys_size);
    if (key_bits == 128) {
        key_expansion_128(key_raw.data(), round_keys.data(), sbox_mode);
    } else if (key_bits == 192) {
        key_expansion_192(key_raw.data(), round_keys.data(), sbox_mode);
    } else if (key_bits == 256) {
        key_expansion_256(key_raw.data(), round_keys.data(), sbox_mode);
    }

    // Securely wipe raw key
    platform::secure_zero(key_raw.data(), key_raw.size());

    uint8_t counter[16];
    std::memcpy(counter, iv_raw.data(), 16);
    platform::secure_zero(iv_raw.data(), iv_raw.size());

    // Allocate streaming chunk buffers
    if (chunk_size == 0) chunk_size = 1024 * 1024;
    std::vector<uint8_t> in_chunk(chunk_size);
    std::vector<uint8_t> out_chunk(chunk_size);
    uint8_t keystream[16];

    CtrStatus status = CtrStatus::Success;

    while (in_stream.good()) {
        in_stream.read(reinterpret_cast<char*>(in_chunk.data()), static_cast<std::streamsize>(chunk_size));
        std::streamsize bytes_read = in_stream.gcount();
        if (bytes_read <= 0) break;

        size_t offset = 0;
        size_t total_in_chunk = static_cast<size_t>(bytes_read);

        while (offset < total_in_chunk) {
            encrypt_block_dispatch(counter, keystream, round_keys.data(), sbox_mode, key_bits);

            size_t block_bytes = std::min(static_cast<size_t>(16), total_in_chunk - offset);
            for (size_t b = 0; b < block_bytes; ++b) {
                out_chunk[offset + b] = in_chunk[offset + b] ^ keystream[b];
            }
            offset += block_bytes;

            // Check if more bytes remain in this chunk or in the file
            bool more_data = (offset < total_in_chunk) || (in_stream.peek() != EOF);
            if (more_data) {
                if (!increment_counter_128(counter)) {
                    status = CtrStatus::CounterOverflow;
                    break;
                }
            }
        }

        if (status != CtrStatus::Success) {
            break;
        }

        out_stream.write(reinterpret_cast<const char*>(out_chunk.data()), bytes_read);
        if (!out_stream) {
            status = CtrStatus::IOError;
            break;
        }
    }

    if (in_stream.bad()) {
        status = CtrStatus::IOError;
    }

    in_stream.close();
    out_stream.flush();
    out_stream.close();

    // Clean sensitive memory
    platform::secure_zero(counter, sizeof(counter));
    platform::secure_zero(keystream, sizeof(keystream));
    platform::secure_zero(in_chunk.data(), in_chunk.size());
    platform::secure_zero(out_chunk.data(), out_chunk.size());

    if (status != CtrStatus::Success) {
        // Fail-Closed: cleanly delete temporary file so no partial file remains
        std::error_code ec;
        std::filesystem::remove(temp_file, ec);
        return status;
    }

    // Atomically replace destination
    if (!platform::atomic_replace_file(temp_file, out_file)) {
        std::error_code ec;
        std::filesystem::remove(temp_file, ec);
        return CtrStatus::IOError;
    }

    return CtrStatus::Success;
}

} // namespace aes
