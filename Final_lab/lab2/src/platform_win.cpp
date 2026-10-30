#if defined(_WIN32)

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <bcrypt.h>
#include <string>
#include <vector>
#include "aes/platform.hpp"

#if defined(_MSC_VER)
#pragma comment(lib, "bcrypt.lib")
#endif

namespace aes {
namespace platform {

namespace {

std::wstring utf8_to_wide(const std::string& utf8_str) {
    if (utf8_str.empty()) return std::wstring();
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, utf8_str.data(), (int)utf8_str.size(), NULL, 0);
    if (size_needed <= 0) return std::wstring();
    std::wstring result(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, utf8_str.data(), (int)utf8_str.size(), &result[0], size_needed);
    return result;
}

} // namespace

bool secure_random(uint8_t* buffer, size_t size) {
    if (!buffer && size > 0) return false;
    if (size == 0) return true;

    // Process in chunks of ULONG max if size > ULONG_MAX
    size_t offset = 0;
    while (offset < size) {
        ULONG chunk = static_cast<ULONG>((size - offset > 0xFFFFFFFFUL) ? 0xFFFFFFFFUL : (size - offset));
        NTSTATUS status = BCryptGenRandom(
            NULL,
            buffer + offset,
            chunk,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG
        );
        if (status < 0) { // !NT_SUCCESS(status)
            return false;
        }
        offset += chunk;
    }
    return true;
}

void secure_zero(void* ptr, size_t size) {
    if (ptr && size > 0) {
        SecureZeroMemory(ptr, size);
    }
}

bool atomic_replace_file(const std::string& temp_path, const std::string& dest_path) {
    std::wstring w_temp = utf8_to_wide(temp_path);
    std::wstring w_dest = utf8_to_wide(dest_path);

    if (w_temp.empty() || w_dest.empty()) {
        return false;
    }

    // MOVEFILE_REPLACE_EXISTING replaces destination atomically on NTFS
    // MOVEFILE_WRITE_THROUGH flushes changes to disk before returning
    BOOL res = MoveFileExW(
        w_temp.c_str(),
        w_dest.c_str(),
        MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH
    );

    return res != 0;
}

} // namespace platform
} // namespace aes

#endif // _WIN32
