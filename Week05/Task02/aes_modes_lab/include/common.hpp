#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <vector>

namespace lab {

using Bytes = std::vector<std::uint8_t>;
using Block = std::array<std::uint8_t, 16>;

Bytes pad(const Bytes& input);
Bytes unpad(const Bytes& input);
Block xorblock(const Block& lhs, const Block& rhs);
void check_iv(const Bytes& iv);
void check_aligned(const Bytes& input);
void append(Bytes& destination, const Bytes& source);
void append(Bytes& destination, const Block& source);
Block block(const Bytes& input, std::size_t offset);

} // namespace lab
