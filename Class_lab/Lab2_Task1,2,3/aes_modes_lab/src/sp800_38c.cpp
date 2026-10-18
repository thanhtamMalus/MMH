#include "sp800_38c.hpp"

#include <algorithm>
#include <limits>
#include <stdexcept>

namespace lab {
namespace {

bool valid_tag_length(std::size_t length) {
    return length >= 4 && length <= 16 && length % 2 == 0;
}

void encode_length(Bytes& output, std::size_t value, std::size_t width) {
    for (std::size_t i = width; i-- > 0;) {
        output[i] = static_cast<std::uint8_t>(value & 0xffU);
        value >>= 8U;
    }
    if (value != 0) {
        throw std::length_error("CCM message length does not fit in the nonce-selected length field");
    }
}

Block make_counter(const Bytes& nonce, std::size_t length_field_bytes, std::size_t value) {
    Block result{};
    result[0] = static_cast<std::uint8_t>(length_field_bytes - 1);
    std::copy(nonce.begin(), nonce.end(), result.begin() + 1);
    for (std::size_t i = 0; i < length_field_bytes; ++i) {
        result[15 - i] = static_cast<std::uint8_t>(value & 0xffU);
        value >>= 8U;
    }
    if (value != 0) {
        throw std::length_error("CCM counter does not fit in its length field");
    }
    return result;
}

Block cbc_mac(const AES& aes, const Bytes& plaintext, const Bytes& nonce,
              const Bytes& aad, std::size_t tag_length, std::size_t length_field_bytes) {
    Block first{};
    const bool has_aad = !aad.empty();
    first[0] = static_cast<std::uint8_t>((has_aad ? 0x40U : 0U) |
                   (((tag_length - 2) / 2) << 3U) | (length_field_bytes - 1));
    std::copy(nonce.begin(), nonce.end(), first.begin() + 1);
    Bytes length_bytes(length_field_bytes, 0);
    encode_length(length_bytes, plaintext.size(), length_field_bytes);
    std::copy(length_bytes.begin(), length_bytes.end(), first.end() - static_cast<std::ptrdiff_t>(length_field_bytes));

    Block state = aes.encrypt(first);
    if (has_aad) {
        Bytes formatted;
        if (aad.size() < 0xff00U) {
            formatted.push_back(static_cast<std::uint8_t>((aad.size() >> 8U) & 0xffU));
            formatted.push_back(static_cast<std::uint8_t>(aad.size() & 0xffU));
        } else if (aad.size() <= std::numeric_limits<std::uint32_t>::max()) {
            formatted.insert(formatted.end(), {0xff, 0xfe});
            for (int shift = 24; shift >= 0; shift -= 8) {
                formatted.push_back(static_cast<std::uint8_t>((aad.size() >> shift) & 0xffU));
            }
        } else {
            formatted.insert(formatted.end(), {0xff, 0xff});
            const std::uint64_t aad_length = static_cast<std::uint64_t>(aad.size());
            for (int shift = 56; shift >= 0; shift -= 8) {
                formatted.push_back(static_cast<std::uint8_t>((aad_length >> shift) & 0xffU));
            }
        }
        append(formatted, aad);
        formatted.resize(((formatted.size() + 15) / 16) * 16, 0);
        for (std::size_t offset = 0; offset < formatted.size(); offset += 16) {
            state = aes.encrypt(xorblock(state, block(formatted, offset)));
        }
    }

    for (std::size_t offset = 0; offset < plaintext.size(); offset += 16) {
        Block message_block{};
        const std::size_t count = std::min<std::size_t>(16, plaintext.size() - offset);
        std::copy_n(plaintext.begin() + static_cast<std::ptrdiff_t>(offset), count, message_block.begin());
        state = aes.encrypt(xorblock(state, message_block));
    }
    return state;
}

Bytes crypt_payload(const AES& aes, const Bytes& input, const Bytes& nonce,
                    std::size_t length_field_bytes) {
    Bytes output;
    output.reserve(input.size());
    std::size_t counter_value = 1;
    for (std::size_t offset = 0; offset < input.size();) {
        const Block stream = aes.encrypt(make_counter(nonce, length_field_bytes, counter_value));
        const std::size_t count = std::min<std::size_t>(16, input.size() - offset);
        for (std::size_t i = 0; i < count; ++i) {
            output.push_back(static_cast<std::uint8_t>(input[offset + i] ^ stream[i]));
        }
        offset += count;
        if (offset < input.size()) {
            if (counter_value == std::numeric_limits<std::size_t>::max()) {
                throw std::overflow_error("CCM counter overflow");
            }
            ++counter_value;
        }
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

} // namespace

AeadResult ccm_encrypt(const AES& aes, const Bytes& plaintext, const Bytes& iv,
                       const Bytes& aad, std::size_t tag_len) {
    if (iv.size() < 7 || iv.size() > 13) {
        throw std::invalid_argument("CCM nonce must contain from 7 to 13 bytes");
    }
    if (!valid_tag_length(tag_len)) {
        throw std::invalid_argument("CCM tag length must be an even number of bytes from 4 to 16");
    }
    const std::size_t length_field_bytes = 15 - iv.size();
    Bytes encoded_length(length_field_bytes, 0);
    encode_length(encoded_length, plaintext.size(), length_field_bytes);

    const Block mac = cbc_mac(aes, plaintext, iv, aad, tag_len, length_field_bytes);
    Block s0 = make_counter(iv, length_field_bytes, 0);
    s0 = aes.encrypt(s0);
    Bytes tag(tag_len);
    for (std::size_t i = 0; i < tag_len; ++i) {
        tag[i] = static_cast<std::uint8_t>(mac[i] ^ s0[i]);
    }
    return {crypt_payload(aes, plaintext, iv, length_field_bytes), tag};
}

Bytes ccm_decrypt(const AES& aes, const Bytes& ciphertext, const Bytes& iv,
                  const Bytes& aad, const Bytes& tag, std::size_t tag_len) {
    if (iv.size() < 7 || iv.size() > 13) {
        throw std::invalid_argument("CCM nonce must contain from 7 to 13 bytes");
    }
    if (!valid_tag_length(tag_len)) {
        throw std::invalid_argument("CCM tag length must be an even number of bytes from 4 to 16");
    }
    if (tag.size() != tag_len) {
        throw std::invalid_argument("CCM tag size does not match tag_len");
    }
    const std::size_t length_field_bytes = 15 - iv.size();
    Bytes encoded_length(length_field_bytes, 0);
    encode_length(encoded_length, ciphertext.size(), length_field_bytes);

    const Bytes plaintext = crypt_payload(aes, ciphertext, iv, length_field_bytes);
    const Block mac = cbc_mac(aes, plaintext, iv, aad, tag_len, length_field_bytes);
    Block s0 = aes.encrypt(make_counter(iv, length_field_bytes, 0));
    Bytes expected(tag_len);
    for (std::size_t i = 0; i < tag_len; ++i) {
        expected[i] = static_cast<std::uint8_t>(mac[i] ^ s0[i]);
    }
    if (!tags_equal(expected, tag)) {
        throw std::runtime_error("CCM authentication tag verification failed");
    }
    return plaintext;
}

} // namespace lab
