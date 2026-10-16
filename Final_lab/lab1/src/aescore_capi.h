#ifndef AESCORE_CAPI_H
#define AESCORE_CAPI_H
/* C API of the aescore shared/static library (used by the Python GUI via ctypes).
 * Return codes: 0 ok, 1 usage/format error (see err), 2 authentication failed, 3 other error.
 * Output buffers are allocated by the library; release them with aescore_free(). */
#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32)
#  if defined(AESCORE_BUILDING)
#    define AESCORE_API __declspec(dllexport)
#  else
#    define AESCORE_API
#  endif
#else
#  define AESCORE_API __attribute__((visibility("default")))
#endif

#ifdef __cplusplus
extern "C" {
#endif

AESCORE_API const char* aescore_version(void);

/* iv may be NULL/0 => random IV generated and stored in the output container. */
AESCORE_API int aescore_encrypt(const char* mode, const uint8_t* key, size_t key_len,
                                const uint8_t* iv, size_t iv_len,
                                const uint8_t* aad, size_t aad_len,
                                const uint8_t* in, size_t in_len, int allow_ecb,
                                uint8_t** out, size_t* out_len, char* err, size_t err_len);

/* mode may be NULL (taken from the container). */
AESCORE_API int aescore_decrypt(const char* mode, const uint8_t* key, size_t key_len,
                                const uint8_t* aad, size_t aad_len,
                                const uint8_t* in, size_t in_len, int allow_ecb,
                                uint8_t** out, size_t* out_len, char* err, size_t err_len);

AESCORE_API int aescore_random(uint8_t* buf, size_t n);
AESCORE_API void aescore_free(uint8_t* p);

#ifdef __cplusplus
}
#endif
#endif
