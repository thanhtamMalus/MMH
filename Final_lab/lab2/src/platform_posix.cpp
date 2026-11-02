#if !defined(_WIN32)

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>
#if defined(__linux__)
#include <sys/syscall.h>
#endif
#include "aes/platform.hpp"

namespace aes {
namespace platform {

bool secure_random(uint8_t* buffer, size_t size) {
    if (!buffer && size > 0) return false;
    if (size == 0) return true;

    size_t total_read = 0;

#if defined(SYS_getrandom)
    while (total_read < size) {
        ssize_t res = syscall(SYS_getrandom, buffer + total_read, size - total_read, 0);
        if (res < 0) {
            if (errno == EINTR) continue;
            // Fallback to /dev/urandom on failure
            break;
        }
        total_read += static_cast<size_t>(res);
    }
    if (total_read == size) return true;
#endif

    // Fallback: /dev/urandom
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;

    while (total_read < size) {
        ssize_t res = read(fd, buffer + total_read, size - total_read);
        if (res < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return false;
        }
        if (res == 0) {
            close(fd);
            return false;
        }
        total_read += static_cast<size_t>(res);
    }

    close(fd);
    return true;
}

void secure_zero(void* ptr, size_t size) {
    if (!ptr || size == 0) return;

#if defined(__GLIBC__) && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 25))
    explicit_bzero(ptr, size);
#else
    // Volatile pointer write ensures compiler does not optimize it away
    volatile uint8_t* p = static_cast<volatile uint8_t*>(ptr);
    while (size--) {
        *p++ = 0;
    }
#endif
}

bool atomic_replace_file(const std::string& temp_path, const std::string& dest_path) {
    // POSIX rename is atomic and overwrites destination file if it exists
    int res = ::rename(temp_path.c_str(), dest_path.c_str());
    return res == 0;
}

} // namespace platform
} // namespace aes

#endif // !_WIN32
