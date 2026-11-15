#pragma once
// Single place that includes Crypto++ headers. Debian/Ubuntu install them as
// <cryptopp/...> (symlink) and/or <crypto++/...>; vcpkg and MSYS2 use <cryptopp/...>.
#if defined(__has_include)
#  if __has_include(<cryptopp/aes.h>)
#    define AESCORE_CPP_DIR_CRYPTOPP 1
#  endif
#else
#  define AESCORE_CPP_DIR_CRYPTOPP 1
#endif

#ifdef AESCORE_CPP_DIR_CRYPTOPP
#  include <cryptopp/aes.h>
#  include <cryptopp/modes.h>
#  include <cryptopp/ccm.h>
#  include <cryptopp/gcm.h>
#  include <cryptopp/xts.h>
#  include <cryptopp/filters.h>
#  include <cryptopp/osrng.h>
#  include <cryptopp/secblock.h>
#  include <cryptopp/sha.h>
#  include <cryptopp/cpu.h>
#  include <cryptopp/config.h>
#  include <cryptopp/cryptlib.h>
#else
#  include <crypto++/aes.h>
#  include <crypto++/modes.h>
#  include <crypto++/ccm.h>
#  include <crypto++/gcm.h>
#  include <crypto++/xts.h>
#  include <crypto++/filters.h>
#  include <crypto++/osrng.h>
#  include <crypto++/secblock.h>
#  include <crypto++/sha.h>
#  include <crypto++/cpu.h>
#  include <crypto++/config.h>
#  include <crypto++/cryptlib.h>
#endif
