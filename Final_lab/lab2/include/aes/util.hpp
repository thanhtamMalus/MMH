#ifndef AES_UTIL_HPP
#define AES_UTIL_HPP

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include "aes/platform.hpp"

namespace aes {
namespace util {

/**
 * @brief RAII wrapper to zeroize memory on destruction.
 */
template <typename T>
class SecureBuffer {
public:
    SecureBuffer() = default;
    explicit SecureBuffer(size_t size) : data_(size, 0) {}
    SecureBuffer(const uint8_t* data, size_t size) : data_(data, data + size) {}
    ~SecureBuffer() {
        if (!data_.empty()) {
            aes::platform::secure_zero(data_.data(), data_.size() * sizeof(T));
        }
    }

    // Move semantics
    SecureBuffer(SecureBuffer&& other) noexcept : data_(std::move(other.data_)) {}
    SecureBuffer& operator=(SecureBuffer&& other) noexcept {
        if (this != &other) {
            if (!data_.empty()) {
                aes::platform::secure_zero(data_.data(), data_.size() * sizeof(T));
            }
            data_ = std::move(other.data_);
        }
        return *this;
    }

    // Disable copying to prevent accidental plaintext/key copies
    SecureBuffer(const SecureBuffer&) = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;

    void resize(size_t size) {
        data_.resize(size, 0);
    }

    T* data() { return data_.data(); }
    const T* data() const { return data_.data(); }
    size_t size() const { return data_.size(); }
    bool empty() const { return data_.empty(); }

    T& operator[](size_t idx) { return data_[idx]; }
    const T& operator[](size_t idx) const { return data_[idx]; }

private:
    std::vector<T> data_;
};

using SecureByteVector = SecureBuffer<uint8_t>;

/**
 * @brief Convert raw bytes to lowercase hexadecimal string.
 */
std::string to_hex(const uint8_t* data, size_t size);

/**
 * @brief Parse hexadecimal string into raw bytes.
 * Ignores nothing; returns false if invalid hex characters or odd length.
 */
bool from_hex(const std::string& hex, std::vector<uint8_t>& out);

/**
 * @brief Reads entire binary file into buffer.
 * Opens strictly in std::ios::binary.
 * Returns false on I/O error.
 */
bool read_binary_file(const std::string& filepath, std::vector<uint8_t>& out);

/**
 * @brief Writes buffer into binary file.
 * Opens strictly in std::ios::binary.
 * Returns false on I/O error.
 */
bool write_binary_file(const std::string& filepath, const uint8_t* data, size_t size);

/**
 * @brief Check if file exists.
 */
bool file_exists(const std::string& filepath);

/**
 * @brief Get file size in 64-bit integer.
 * Returns false if cannot determine.
 */
bool get_file_size(const std::string& filepath, uint64_t& out_size);

} // namespace util
} // namespace aes

#endif // AES_UTIL_HPP
