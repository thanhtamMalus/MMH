#pragma once

#include "common.hpp"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace lab {

class AES {
public:
    explicit AES(const Bytes& key);

    Block encrypt(const Block& input) const;
    Block decrypt(const Block& input) const;

private:
    std::vector<std::uint8_t> round_keys_;
    std::size_t rounds_;
};

} // namespace lab
