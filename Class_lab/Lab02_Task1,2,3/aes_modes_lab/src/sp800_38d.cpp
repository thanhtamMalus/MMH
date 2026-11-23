#include "sp800_38d.hpp"

#include <algorithm>
#include <limits>
#include <stdexcept>

namespace lab {
namespace {

bool valid_tag_length(std::size_t length) {
    return length == 4 || length == 8 || (length >= 12 && length <= 16);
}

Block xor_blocks(const Block& lhs, const Block& rhs) {
    return xorblock(lhs, rhs);
}

Block multiply_gf128(const Block& x, const Block& y) {
    Block z{};
    Block v = y;
    for (std::size_t bit = 0; bit < 128; ++bit) {
        if ((x[bit / 8] & static_cast<std::uint8_t>(0x80U >> (bit % 8))) != 0) {
            z = xor_blocks(z, v);
        }
        const bool least_significant_bit = (v[15] & 1U) != 0U;
        for (std::size_t i = 16; i-- > 0;) {
            const std::uint8_t carry = i == 0 ? 0 : static_cast<std::uint8_t>((v[i - 1] & 1U) << 7U);
            v[i] = static_cast<std::uint8_t>((v[i] >> 1U) | carry);
        }
        if (least_significant_bit) {
            v[0] ^= 0xe1U;
        }
    }
    return z;
}

void ghash_blocks(Block& state, const Block& hash_key, const Bytes& input) {
    for (std::size_t offset = 0; offset < input.size();) {
        Block current{};
        const std::size_t count = std::min<std::size_t>(16, input.size() - offset);
        std::copy_n(input.begin() + static_cast<std::ptrdiff_t>(offset), count, current.begin());
        state = multiply_gf128(xor_blocks(state, current), hash_key);
        offset += count;
    }
}

void store_u64_be(Block& output, std::size_t offset, std::uint64_t value) {
    for (std::size_t i = 0; i < 8; ++i) {
        output[offset + 7 - i] = static_cast<std::uint8_t>(value & 0xffU);
        value >>= 8U;
    }
}

Block ghash(const Block& hash_key, const Bytes& aad, const Bytes& ciphertext) {
    if (aad.size() > std::numeric_limits<std::uint64_t>::max() / 8 ||
        ciphertext.size() > std::numeric_limits<std::uint64_t>::max() / 8) {
        throw std::length_error("GCM input length cannot be represented in its bit-length field");
    }
    Block state{};
    ghash_blocks(state, hash_key, aad);
    ghash_blocks(state, hash_key, ciphertext);
    Block lengths{};
    store_u64_be(lengths, 0, static_cast<std::uint64_t>(aad.size()) * 8U);
    store_u64_be(lengths, 8, static_cast<std::uint64_t>(ciphertext.size()) * 8U);
    state = multiply_gf128(xor_blocks(state, lengths), hash_key);
    return state;
}

Block make_j0(const Block& hash_key, const Bytes& iv) {
    if (iv.empty()) {
        throw std::invalid_argument("GCM IV must not be empty");
    }
    if (iv.size() == 12) {
        Block result{};
        std::copy(iv.begin(), iv.end(), result.begin());
        result[15] = 1;
        return result;
    }
    if (iv.size() > std::numeric_limits<std::uint64_t>::max() / 8) {
        throw std::length_error("GCM IV length cannot be represented in its bit-length field");
    }
    Block state{};
    ghash_blocks(state, hash_key, iv);
    Block iv_length{};
    store_u64_be(iv_length, 8, static_cast<std::uint64_t>(iv.size()) * 8U);
    return multiply_gf128(xor_blocks(state, iv_length), hash_key);
}

void increment32(Block& counter) {
    for (std::size_t i = 16; i-- > 12;) {
        ++counter[i];
        if (counter[i] != 0) {
            break;
        }
    }
}

Bytes gctr(const AES& aes, Block counter, const Bytes& input) {
    const std::uint64_t maximum_blocks = (std::uint64_t{1} << 32U) - 2U;
    const std::uint64_t blocks = static_cast<std::uint64_t>(input.size() / 16) +
                                 (input.size() % 16 == 0 ? 0U : 1U);
    if (blocks > maximum_blocks) {
        throw std::length_error("GCM input exceeds the maximum number of counter blocks");
    }
    Bytes output;
    output.reserve(input.size());
    for (std::size_t offset = 0; offset < input.size();) {
        increment32(counter);
        const Block stream = aes.encrypt(counter);
        const std::size_t count = std::min<std::size_t>(16, input.size() - offset);
        for (std::size_t i = 0; i < count; ++i) {
            output.push_back(static_cast<std::uint8_t>(input[offset + i] ^ stream[i]));
        }
        offset += count;
    }
    return output;
}

bool tags_equal(const Bytes& expected, const Bytes& actual) {
    std::uint8_t difference = 0;
    for (std::size_t i = 0; i < expected.size(); ++i) {
        difference |= static_cast<std::uint8_t>(expected[i] ^ actual[i]);
    }
    return difference == 0;
}

AeadResult encrypt_impl(const AES& aes, const Bytes& plaintext, const Bytes& iv,
                        const Bytes& aad, std::size_t tag_len) {
    if (!valid_tag_length(tag_len)) {
        throw std::invalid_argument("GCM tag length must be 4, 8, or 12 to 16 bytes");
    }
    if (aad.size() > std::numeric_limits<std::uint64_t>::max() / 8) {
        throw std::length_error("GCM AAD length cannot be represented in its bit-length field");
    }
    const Block hash_key = aes.encrypt(Block{});
    const Block j0 = make_j0(hash_key, iv);
    const Bytes ciphertext = gctr(aes, j0, plaintext);
    const Block authentication = ghash(hash_key, aad, ciphertext);
    const Block encrypted_j0 = aes.encrypt(j0);
    Bytes tag(tag_len);
    for (std::size_t i = 0; i < tag_len; ++i) {
        tag[i] = static_cast<std::uint8_t>(authentication[i] ^ encrypted_j0[i]);
    }
    return {ciphertext, tag};
}

} // namespace

AeadResult gcm_encrypt(const AES& aes, const Bytes& plaintext, const Bytes& iv,
                       const Bytes& aad, std::size_t tag_len) {
    return encrypt_impl(aes, plaintext, iv, aad, tag_len);
}

Bytes gcm_decrypt(const AES& aes, const Bytes& ciphertext, const Bytes& iv,
                  const Bytes& aad, const Bytes& tag, std::size_t tag_len) {
    if (!valid_tag_length(tag_len)) {
        throw std::invalid_argument("GCM tag length must be 4, 8, or 12 to 16 bytes");
    }
    if (tag.size() != tag_len) {
        throw std::invalid_argument("GCM tag size does not match tag_len");
    }
    if (aad.size() > std::numeric_limits<std::uint64_t>::max() / 8) {
        throw std::length_error("GCM AAD length cannot be represented in its bit-length field");
    }
    const Block hash_key = aes.encrypt(Block{});
    const Block j0 = make_j0(hash_key, iv);
    const Block authentication = ghash(hash_key, aad, ciphertext);
    const Block encrypted_j0 = aes.encrypt(j0);
    Bytes expected(tag_len);
    for (std::size_t i = 0; i < tag_len; ++i) {
        expected[i] = static_cast<std::uint8_t>(authentication[i] ^ encrypted_j0[i]);
    }
    if (!tags_equal(expected, tag)) {
        throw std::runtime_error("GCM authentication tag verification failed");
    }
    return gctr(aes, j0, ciphertext);
}

} // namespace lab
