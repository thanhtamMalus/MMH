#include <cstddef>
#include <cstdint>
#include <cstring>
#include "aes/aes128.hpp"

#if defined(AES_ENABLE_AESNI_IMPL)
#if defined(_MSC_VER)
#include <intrin.h>
#include <wmmintrin.h>
#elif defined(__GNUC__) || defined(__clang__)
#include <cpuid.h>
#include <wmmintrin.h>
#endif

namespace aes {
namespace bonus {

bool has_aesni_support() {
#if defined(_MSC_VER)
    int cpuInfo[4];
    __cpuid(cpuInfo, 1);
    return (cpuInfo[2] & (1 << 25)) != 0; // ECX bit 25 = AES-NI
#elif defined(__GNUC__) || defined(__clang__)
    unsigned int eax, ebx, ecx, edx;
    if (__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
        return (ecx & (1 << 25)) != 0;
    }
    return false;
#else
    return false;
#endif
}

} // namespace bonus
} // namespace aes
#endif
