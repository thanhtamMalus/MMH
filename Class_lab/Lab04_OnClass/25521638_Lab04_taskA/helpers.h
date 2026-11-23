// helpers.h - cac ham tro giup dung chung cho ca 3 task
#pragma once
#include <openssl/bn.h>
#include <openssl/err.h>
#include <cstdio>
#include <cstdlib>
#include <vector>

using Bytes = std::vector<unsigned char>;
static int g_failures = 0; // dem so check bi FAIL

// Loi OpenSSL: in loi ra roi dung chuong trinh (de code ngan gon)
[[noreturn]] static void die(const char* what) {
 std::fprintf(stderr, "FAILED: %s\n", what);
 ERR_print_errors_fp(stderr);
 std::exit(1);
}

// OK1: ham tra ve 1 khi thanh cong. OKPOS: ham tra ve > 0. NOTNULL: ham tra ve con tro
#define OK1(call) do { if ((call) != 1) die(#call); } while (0)
#define OKPOS(call) do { if ((call) <= 0) die(#call); } while (0)
#define NOTNULL(ptr) do { if ((ptr) == nullptr) die(#ptr " is NULL"); } while (0)

// In day byte dang hex (toi da maxShown byte dau)
[[maybe_unused]] static void printHex(const char* label, const unsigned char* p, size_t n, size_t maxShown = 24) {
 std::printf(" %-14s", label);
 for (size_t i = 0; i < n && i < maxShown; ++i) std::printf("%02x", p[i]);
 if (n > maxShown) std::printf("... (%zu bytes)", n);
 std::printf("\n");
}

// In so lon: chi hien so bit va vai ky tu hex dau
[[maybe_unused]] static void printBnBits(const char* label, const BIGNUM* x) {
 char* s = BN_bn2hex(x);
 NOTNULL(s);
 std::printf(" %-14s%d bits, 0x%.16s...\n", label, BN_num_bits(x), s);
 OPENSSL_free(s);
}

// In PASS/FAIL cho 1 phep kiem tra
[[maybe_unused]] static void check(const char* name, bool ok) {
 std::printf(" [%s] %s\n", ok ? "PASS" : "FAIL", name);
 if (!ok) ++g_failures;
}

// Doi chuoi hex thanh byte
[[maybe_unused]] static Bytes fromHex(const char* h) {
 Bytes b;
 for (size_t i = 0; h[i] && h[i + 1]; i += 2) {
  char two[3] = {h[i], h[i + 1], 0};
  b.push_back(static_cast<unsigned char>(std::strtoul(two, nullptr, 16)));
 }
 return b;
}
