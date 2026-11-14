#include "sp800_38a.hpp"

#include <algorithm>
#include <limits>
#include <stdexcept>

namespace lab {
namespace {

void increment_counter(Block& counter) {
    for (std::size_t i = counter.size(); i-- > 0;) {
        ++counter[i];
        if (counter[i] != 0) {
            return;
        }
    }
    throw std::overflow_error("CTR counter overflow");
}

Bytes cfb_process(const AES& aes, const Bytes& input, const Bytes& iv,
                  std::size_t segment_bits, bool decrypting) {
    check_iv(iv);
    if (segment_bits < 8 || segment_bits > 128 || segment_bits % 8 != 0) {
        throw std::invalid_argument("CFB segment size must be a multiple of 8 from 8 to 128 bits");
    }
    const std::size_t segment_bytes = segment_bits / 8;
    Block feedback = block(iv, 0);
    Bytes output;
    output.reserve(input.size());

    for (std::size_t offset = 0; offset < input.size();) {
        const Block stream = aes.encrypt(feedback);
        const std::size_t count = std::min(segment_bytes, input.size() - offset);
        Bytes ciphertext_segment;
        ciphertext_segment.reserve(count);
        for (std::size_t i = 0; i < count; ++i) {
            const std::uint8_t value = static_cast<std::uint8_t>(input[offset + i] ^ stream[i]);
            output.push_back(value);
            ciphertext_segment.push_back(decrypting ? input[offset + i] : value);
        }
        std::move(feedback.begin() + static_cast<std::ptrdiff_t>(count), feedback.end(), feedback.begin());
        std::copy(ciphertext_segment.begin(), ciphertext_segment.end(),
                  feedback.end() - static_cast<std::ptrdiff_t>(count));
        offset += count;
    }
    return output;
}

} // namespace

Bytes ecb_encrypt(const AES& aes, const Bytes& plaintext) {
    const Bytes padded = pad(plaintext);
    Bytes ciphertext;
    ciphertext.reserve(padded.size());
    for (std::size_t offset = 0; offset < padded.size(); offset += 16) {
        append(ciphertext, aes.encrypt(block(padded, offset)));
    }
    return ciphertext;
}

Bytes ecb_decrypt(const AES& aes, const Bytes& ciphertext) {
    check_aligned(ciphertext);
    if (ciphertext.empty()) {
        throw std::invalid_argument("ECB ciphertext must contain at least one block");
    }
    Bytes plaintext;
    plaintext.reserve(ciphertext.size());
    for (std::size_t offset = 0; offset < ciphertext.size(); offset += 16) {
        append(plaintext, aes.decrypt(block(ciphertext, offset)));
    }
    return unpad(plaintext);
}

Bytes cbc_encrypt(const AES& aes, const Bytes& plaintext, const Bytes& iv) {
    check_iv(iv);
    const Bytes padded = pad(plaintext);
    Block previous = block(iv, 0);
    Bytes ciphertext;
    ciphertext.reserve(padded.size());
    for (std::size_t offset = 0; offset < padded.size(); offset += 16) {
        previous = aes.encrypt(xorblock(block(padded, offset), previous));
        append(ciphertext, previous);
    }
    return ciphertext;
}

Bytes cbc_decrypt(const AES& aes, const Bytes& ciphertext, const Bytes& iv) {
    check_iv(iv);
    check_aligned(ciphertext);
    if (ciphertext.empty()) {
        throw std::invalid_argument("CBC ciphertext must contain at least one block");
    }
    Block previous = block(iv, 0);
    Bytes plaintext;
    plaintext.reserve(ciphertext.size());
    for (std::size_t offset = 0; offset < ciphertext.size(); offset += 16) {
        const Block current = block(ciphertext, offset);
        append(plaintext, xorblock(aes.decrypt(current), previous));
        previous = current;
    }
    return unpad(plaintext);
}

Bytes cfb_encrypt(const AES& aes, const Bytes& input, const Bytes& iv, std::size_t segment_bits) {
    return cfb_process(aes, input, iv, segment_bits, false);
}

Bytes cfb_decrypt(const AES& aes, const Bytes& input, const Bytes& iv, std::size_t segment_bits) {
    return cfb_process(aes, input, iv, segment_bits, true);
}

Bytes ofb_crypt(const AES& aes, const Bytes& input, const Bytes& iv) {
    check_iv(iv);
    Block feedback = block(iv, 0);
    Bytes output;
    output.reserve(input.size());
    for (std::size_t offset = 0; offset < input.size();) {
        feedback = aes.encrypt(feedback);
        const std::size_t count = std::min<std::size_t>(16, input.size() - offset);
        for (std::size_t i = 0; i < count; ++i) {
            output.push_back(static_cast<std::uint8_t>(input[offset + i] ^ feedback[i]));
        }
        offset += count;
    }
    return output;
}

Bytes ctr_crypt(const AES& aes, const Bytes& input, const Bytes& initial_counter) {
    check_iv(initial_counter);
    Block counter = block(initial_counter, 0);
    Bytes output;
    output.reserve(input.size());
    for (std::size_t offset = 0; offset < input.size();) {
        const Block stream = aes.encrypt(counter);
        const std::size_t count = std::min<std::size_t>(16, input.size() - offset);
        for (std::size_t i = 0; i < count; ++i) {
            output.push_back(static_cast<std::uint8_t>(input[offset + i] ^ stream[i]));
        }
        offset += count;
        if (offset < input.size()) {
            increment_counter(counter);
        }
    }
    return output;
}

} // namespace lab
