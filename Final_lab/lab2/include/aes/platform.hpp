#ifndef AES_PLATFORM_HPP
#define AES_PLATFORM_HPP

#include <cstddef>
#include <cstdint>
#include <string>

namespace aes {
namespace platform {

/**
 * @brief Fills the provided buffer with cryptographically secure random bytes from the OS CSPRNG.
 * Windows: BCryptGenRandom
 * POSIX/Linux: getrandom() / /dev/urandom
 * @return true on success, false on failure (fail-closed)
 */
bool secure_random(uint8_t* buffer, size_t size);

/**
 * @brief Securely zeroes out sensitive memory (keys, round keys, state).
 * Guaranteed not to be optimized out by compiler dead-store elimination.
 */
void secure_zero(void* ptr, size_t size);

/**
 * @brief Atomically replaces destination file with temporary file.
 * If destination file already exists, it is safely overwritten.
 * @return true on success, false on failure
 */
bool atomic_replace_file(const std::string& temp_path, const std::string& dest_path);

} // namespace platform
} // namespace aes

#endif // AES_PLATFORM_HPP
