// task_b_rsa_keys.cpp -- Lab 3, Task B (in class)
// Part 1: build RSA parameters from first principles with BIGNUM.
// Part 2: generate a real key with EVP_PKEY, save it as PEM and DER,
// load all four files back and check they are the same key.
// Part 3: look inside OpenSSL’s key: which private exponent does it use?
//
// Build: g++ -std=c++17 -Wall -Wextra task_b_rsa_keys.cpp -o task_b -lcrypto
// Run: ./task_b [edu-bits] (default 512; writes 4 key files here)
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/crypto.h>
#include <chrono>
#include <cstring>
#include <fstream>
#include <map>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>
#include <iostream>
#include <vector>
#include <iomanip>
#include <string>

#include "helper.h"
// ... helper block (die, OK1, OKPOS, NOTNULL, printHex, printBn,
// printBnBits, check): see "Getting started" ...
// ==========================================================================
// Part 1. Educational RSA parameters (NOT for real use)
// ==========================================================================
// Draws probable primes until gcd(e, prime - 1) = 1. Returns the number of draws.
static int drawPrime(BIGNUM* prime, BIGNUM* primeMinus1, const BIGNUM* e, int bits, BN_CTX* ctx) {
    BIGNUM* g = BN_new();
    NOTNULL(g);
    int draws = 0;
    do {
        ++draws;
        OK1(BN_generate_prime_ex2(prime, bits, /*safe=*/0, nullptr, nullptr,
        nullptr, ctx));
        NOTNULL(BN_copy(primeMinus1, prime));
        OK1(BN_sub_word(primeMinus1, 1));
        OK1(BN_gcd(g, e, primeMinus1, ctx));
    } while (!BN_is_one(g));
    BN_free(g);
    return draws;
}

static void part1EducationalRsa(int bits) {
    std::printf("== Part 1: educational RSA, %d-bit modulus (INSECURE) ==\n", bits);
    BN_CTX* ctx = BN_CTX_new();
    NOTNULL(ctx);
    BIGNUM *e = BN_new(), *p = BN_new(), *q = BN_new(), *pm1 = BN_new(),
    *qm1 = BN_new(), *g = BN_new(), *n = BN_new(), *phi = BN_new(),
    *lambda = BN_new();
    NOTNULL(e); NOTNULL(p); NOTNULL(q); NOTNULL(pm1); NOTNULL(qm1);
    NOTNULL(g); NOTNULL(n); NOTNULL(phi); NOTNULL(lambda);
    OK1(BN_set_word(e, 65537));

    // Step 1: primes p != q with gcd(e, p-1) = gcd(e, q-1) = 1.
    // If the gcd test fails we draw a new prime instead of changing e.
    int attempts = drawPrime(p, pm1, e, bits / 2, ctx);
    do {
        attempts += drawPrime(q, qm1, e, bits / 2, ctx);
    } while (BN_cmp(p, q) == 0);
    std::printf(" primes found after %d draw(s)\n", attempts);

    // Step 2: n = p*q, phi = (p-1)(q-1), lambda = lcm(p-1, q-1)
    OK1(BN_mul(n, p, q, ctx));
    OK1(BN_mul(phi, pm1, qm1, ctx));
    OK1(BN_gcd(g, pm1, qm1, ctx));
    OK1(BN_div(lambda, nullptr, phi, g, ctx)); // lambda = phi / gcd

    // Step 3: the two valid private exponents
    BIGNUM* dPhi = BN_mod_inverse(nullptr, e, phi, ctx);
    BIGNUM* dLam = BN_mod_inverse(nullptr, e, lambda, ctx);
    NOTNULL(dPhi); NOTNULL(dLam);

    // Step 4: CRT values dP = d mod (p-1), dQ = d mod (q-1), qInv = q^-1 mod p
    BIGNUM *dP = BN_new(), *dQ = BN_new();
    NOTNULL(dP); NOTNULL(dQ);
    OK1(BN_nnmod(dP, dLam, pm1, ctx));
    OK1(BN_nnmod(dQ, dLam, qm1, ctx));
    BIGNUM* qInv = BN_mod_inverse(nullptr, q, p, ctx);
    NOTNULL(qInv);
    printBnBits("n", n);
    printBn("e", e);
    printBnBits("d (mod phi)", dPhi);
    printBnBits("d (mod lambda)", dLam);
    printBn("gcd(p-1,q-1)", g);

    // Step 5: verify e*d = 1 (mod phi) and (mod lambda)
    BIGNUM* t = BN_new();
    NOTNULL(t);
    OK1(BN_mod_mul(t, e, dPhi, phi, ctx));
    check("e * d_phi = 1 (mod phi)", BN_is_one(t));
    OK1(BN_mod_mul(t, e, dLam, lambda, ctx));
    check("e * d_lambda = 1 (mod lambda)", BN_is_one(t));

    // d_phi and d_lambda agree modulo lambda; since phi = gcd(p-1,q-1) * lambda,
    // d_phi may equal d_lambda + k*lambda. Both exponents decrypt correctly.
    OK1(BN_nnmod(t, dPhi, lambda, ctx));
    check("d_phi mod lambda == d_lambda", BN_cmp(t, dLam) == 0);
    std::printf(" d_phi == d_lambda this time? %s\n",
    BN_cmp(dPhi, dLam) == 0 ? "yes" : "no (d_phi = d_lambda + k*lambda)");

    // Step 6: for random m, (m^e)^d = m with both exponents and with CRT
    bool allOk = true;
    BIGNUM *m = BN_new(), *c = BN_new(), *r = BN_new(), *m1 = BN_new(),
    *m2 = BN_new(), *h = BN_new();
    NOTNULL(m); NOTNULL(c); NOTNULL(r); NOTNULL(m1); NOTNULL(m2); NOTNULL(h);
    for (int i = 0; i < 20; ++i) {
        OK1(BN_rand_range(m, n)); // m uniform in [0, n)
        OK1(BN_mod_exp(c, m, e, n, ctx)); // c = m^e mod n
        OK1(BN_mod_exp(r, c, dPhi, n, ctx));
        allOk &= BN_cmp(r, m) == 0;
        OK1(BN_mod_exp(r, c, dLam, n, ctx));
        allOk &= BN_cmp(r, m) == 0;

        // CRT (Garner): m1 = c^dP mod p, m2 = c^dQ mod q,
        // h = qInv (m1 - m2) mod p, m = m2 + h q
        OK1(BN_mod_exp(m1, c, dP, p, ctx));
        OK1(BN_mod_exp(m2, c, dQ, q, ctx));
        OK1(BN_mod_sub(h, m1, m2, p, ctx));
        OK1(BN_mod_mul(h, qInv, h, p, ctx));
        OK1(BN_mul(r, h, q, ctx));
        OK1(BN_add(r, r, m2));
        allOk &= BN_cmp(r, m) == 0;
    }
    check("20 random messages decrypt with d_phi, d_lambda and CRT", allOk);
    std::printf("\n");
    for (BIGNUM* x : {e, p, q, pm1, qm1, g, n, phi, lambda, dPhi, dLam, dP, dQ,  qInv, t, m, c, r, m1, m2, h})
        BN_clear_free(x); // wipe private values
    BN_CTX_free(ctx);
}


// ==========================================================================
// Part 2. Production key generation and key files
// ==========================================================================

static EVP_PKEY* generateKey(int bits) {
    EVP_PKEY_CTX* kctx = EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr);
    NOTNULL(kctx);
    OKPOS(EVP_PKEY_keygen_init(kctx));
    OKPOS(EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, bits)); // e = 65537 default
    EVP_PKEY* key = nullptr;
    OKPOS(EVP_PKEY_generate(kctx, &key));
    EVP_PKEY_CTX_free(kctx);
    return key;
}

static void writeKeyFiles(EVP_PKEY* key) {
    // PEM private key: PKCS#8 "BEGIN PRIVATE KEY", no encryption (lab only)
    BIO* b = BIO_new_file("private.pem", "wb"); NOTNULL(b);
    OK1(PEM_write_bio_PrivateKey(b, key, nullptr, nullptr, 0, nullptr, nullptr));
    BIO_free(b);

    // PEM public key: SubjectPublicKeyInfo "BEGIN PUBLIC KEY"
    b = BIO_new_file("public.pem", "wb"); NOTNULL(b);
    OK1(PEM_write_bio_PUBKEY(b, key));
    BIO_free(b);

    // DER private key: PKCS#8 (NOT i2d_PrivateKey, which writes PKCS#1)
    b = BIO_new_file("private.der", "wb"); NOTNULL(b);
    OK1(i2d_PKCS8PrivateKey_bio(b, key, nullptr, nullptr, 0, nullptr, nullptr));
    BIO_free(b);

    // DER public key: SubjectPublicKeyInfo
    b = BIO_new_file("public.der", "wb"); NOTNULL(b);
    OK1(i2d_PUBKEY_bio(b, key));
    BIO_free(b);
    std::printf(" wrote private.pem, public.pem, private.der, public.der\n");
}

static EVP_PKEY* loadKey(const char* path, bool isPrivate, bool isPem) {
    BIO* b = BIO_new_file(path, "rb");
    NOTNULL(b);
    EVP_PKEY* k = nullptr;
    if (isPrivate)
    k = isPem ? PEM_read_bio_PrivateKey(b, nullptr, nullptr, nullptr)
    : d2i_PrivateKey_bio(b, nullptr);
    else
    k = isPem ? PEM_read_bio_PUBKEY(b, nullptr, nullptr, nullptr)
    : d2i_PUBKEY_bio(b, nullptr);
    BIO_free(b);
    NOTNULL(k);
    return k;
}

// Key ID = SHA-256 over the DER SubjectPublicKeyInfo (used again in Task E)
static Bytes keyId(EVP_PKEY* key) {
    unsigned char* der = nullptr;
    int len = i2d_PUBKEY(key, &der); // allocates der
    if (len <= 0) die("i2d_PUBKEY");
    Bytes id(32);
    unsigned int outLen = 0;
    OK1(EVP_Digest(der, static_cast<size_t>(len), id.data(), &outLen,
    EVP_sha256(), nullptr));
    OPENSSL_free(der);
    return id;
}

static EVP_PKEY* part2KeyFiles() {
    std::printf("== Part 2: EVP_PKEY key generation, PEM and DER ==\n");
    EVP_PKEY* key = generateKey(3072);
    std::printf(" generated RSA-%d\n", EVP_PKEY_get_bits(key));
    writeKeyFiles(key);
    EVP_PKEY* privPem = loadKey("private.pem", true, true);
    EVP_PKEY* privDer = loadKey("private.der", true, false);
    EVP_PKEY* pubPem = loadKey("public.pem", false, true);
    EVP_PKEY* pubDer = loadKey("public.der", false, false);

    // EVP_PKEY_eq compares the public components (n, e)
    check("private.pem matches public.pem", EVP_PKEY_eq(privPem, pubPem) == 1);
    check("private.der matches public.der", EVP_PKEY_eq(privDer, pubDer) == 1);
    check("private.pem matches public.der", EVP_PKEY_eq(privPem, pubDer) == 1);
    check("private.der matches public.pem", EVP_PKEY_eq(privDer, pubPem) == 1);
    EVP_PKEY* other = generateKey(2048);
    check("a different key does NOT match", EVP_PKEY_eq(other, pubPem) != 1);
    ERR_clear_error();
    Bytes id1 = keyId(pubPem), id2 = keyId(pubDer);
    printHex("key ID", id1.data(), id1.size(), 32);
    check("key ID is the same for PEM and DER", id1 == id2);
    std::printf("\n");
    for (EVP_PKEY* k : {privPem, privDer, pubPem, pubDer, other}) EVP_PKEY_free(k);
    return key;
}

// ==========================================================================
// Part 3. Inside OpenSSL’s key: d is computed modulo lambda(n)
// ==========================================================================
static BIGNUM* getParam(EVP_PKEY* key, const char* name) {
    BIGNUM* x = nullptr; // EVP allocates x
    OK1(EVP_PKEY_get_bn_param(key, name, &x));
    return x;
}
static void part3InsideTheKey(EVP_PKEY* key) {
    std::printf("== Part 3: parameters inside the OpenSSL key ==\n");
    BN_CTX* ctx = BN_CTX_new();
    NOTNULL(ctx);
    BIGNUM* n = getParam(key, OSSL_PKEY_PARAM_RSA_N);
    BIGNUM* e = getParam(key, OSSL_PKEY_PARAM_RSA_E);
    BIGNUM* d = getParam(key, OSSL_PKEY_PARAM_RSA_D);
    BIGNUM* p = getParam(key, OSSL_PKEY_PARAM_RSA_FACTOR1);
    BIGNUM* q = getParam(key, OSSL_PKEY_PARAM_RSA_FACTOR2);
    printBnBits("n", n);
    printBn("e", e);
    BIGNUM *pq = BN_new(), *pm1 = BN_dup(p), *qm1 = BN_dup(q), *phi = BN_new(),
    *g = BN_new(), *lambda = BN_new();
    NOTNULL(pq); NOTNULL(pm1); NOTNULL(qm1); NOTNULL(phi); NOTNULL(g); NOTNULL(lambda);
    OK1(BN_mul(pq, p, q, ctx));
    check("n == p * q", BN_cmp(pq, n) == 0);
    OK1(BN_sub_word(pm1, 1));
    OK1(BN_sub_word(qm1, 1));
    OK1(BN_mul(phi, pm1, qm1, ctx));
    OK1(BN_gcd(g, pm1, qm1, ctx));
    OK1(BN_div(lambda, nullptr, phi, g, ctx));
    BIGNUM* dLam = BN_mod_inverse(nullptr, e, lambda, ctx);
    BIGNUM* dPhi = BN_mod_inverse(nullptr, e, phi, ctx);
    NOTNULL(dLam); NOTNULL(dPhi);
    check("OpenSSL’s d == e^-1 mod lambda(n)", BN_cmp(d, dLam) == 0);
    std::printf(" e^-1 mod phi(n) equals d this time? %s\n",
    BN_cmp(d, dPhi) == 0 ? "yes (happens by chance)" : "no");
    std::printf("\n");
    for (BIGNUM* x : {n, e, d, p, q, pq, pm1, qm1, phi, g, lambda, dLam, dPhi})
    BN_clear_free(x);
    BN_CTX_free(ctx);
}
int main(int argc, char** argv) {
    int eduBits = (argc > 1) ? std::atoi(argv[1]) : 512;
    if (eduBits < 128 || eduBits > 1024 || eduBits % 2) die("edu-bits must be even, 128..1024");
    part1EducationalRsa(eduBits);
    EVP_PKEY* key = part2KeyFiles();
    part3InsideTheKey(key);
    EVP_PKEY_free(key);
    std::printf("%s\n", g_failures ? "SOME CHECKS FAILED" : "ALL CHECKS PASSED");
    return g_failures ? 1 : 0;
}


//============================
static BIGNUM* nb() { BIGNUM* x = BN_new(); NOTNULL(x); return x; }

// Bài 1: d_phi == d_lambda xảy ra bao nhiêu lần, liên hệ với gcd(p-1, q-1)
static void exB1_dphi_vs_dlambda() {
    BN_CTX* ctx = BN_CTX_new(); NOTNULL(ctx);
    BIGNUM *e = nb(), *p = nb(), *q = nb(), *pm1 = nb(), *qm1 = nb(),
           *g = nb(), *phi = nb(), *lam = nb();
    OK1(BN_set_word(e, 65537));
    std::map<unsigned long long, std::pair<int, int>> stat;   // gcd -> (số lần, số lần bằng nhau)
    const int TRIALS = 300;
    for (int i = 0; i < TRIALS; ++i) {
        drawPrime(p, pm1, e, 128, ctx);
        do { drawPrime(q, qm1, e, 128, ctx); } while (BN_cmp(p, q) == 0);
        OK1(BN_mul(phi, pm1, qm1, ctx));
        OK1(BN_gcd(g, pm1, qm1, ctx));
        OK1(BN_div(lam, nullptr, phi, g, ctx));
        BIGNUM* dPhi = BN_mod_inverse(nullptr, e, phi, ctx);
        BIGNUM* dLam = BN_mod_inverse(nullptr, e, lam, ctx);
        NOTNULL(dPhi); NOTNULL(dLam);
        auto& s = stat[(unsigned long long)BN_get_word(g)];
        ++s.first;
        if (BN_cmp(dPhi, dLam) == 0) ++s.second;
        BN_free(dPhi); BN_free(dLam);
    }
    int same = 0;
    for (auto& kv : stat) {
        same += kv.second.second;
        std::printf("  gcd(p-1,q-1) = %-4llu trials = %-4d d_phi==d_lambda: %-4d (%3.0f%%)  expected ~ 1/gcd = %3.0f%%\n", kv.first, kv.second.first, kv.second.second, 100.0 * kv.second.second / kv.second.first, 100.0 / kv.first);
    }
    std::printf("  overall: %d / %d trials equal\n", same, TRIALS);
    for (BIGNUM* x : {e, p, q, pm1, qm1, g, phi, lam}) BN_clear_free(x);
    BN_CTX_free(ctx);
}

// Bài 2: e = 3 cần bao nhiêu lần rút số nguyên tố?
static void exB2_small_e() {
    BN_CTX* ctx = BN_CTX_new(); NOTNULL(ctx);
    BIGNUM *e = nb(), *p = nb(), *pm1 = nb();
    const int N = 300;
    for (unsigned long ev : {3ul, 65537ul}) {
        OK1(BN_set_word(e, ev));
        long total = 0;
        for (int i = 0; i < N; ++i) total += drawPrime(p, pm1, e, 256, ctx);
        std::printf("  e = %-6lu -> %.2f draws per prime (over %d primes)\n", ev, (double)total / N, N);
    }
    std::printf("  e = 3 fails whenever p = 1 (mod 3), i.e. for about half of all primes.\n");
    for (BIGNUM* x : {e, p, pm1}) BN_clear_free(x);
    BN_CTX_free(ctx);
}

// Bài 3: 1000 lần giải mã, d trực tiếp vs CRT (khóa giáo dục 1024 bit)
static void exB3_crt_speed() {
    using clk = std::chrono::steady_clock;
    BN_CTX* ctx = BN_CTX_new(); NOTNULL(ctx);
    BIGNUM *e = nb(), *p = nb(), *q = nb(), *pm1 = nb(), *qm1 = nb(), *g = nb(), *n = nb(),
           *phi = nb(), *lam = nb(), *dP = nb(), *dQ = nb(), *c = nb(), *r = nb(),
           *m1 = nb(), *m2 = nb(), *h = nb();
    OK1(BN_set_word(e, 65537));
    drawPrime(p, pm1, e, 512, ctx);
    do { drawPrime(q, qm1, e, 512, ctx); } while (BN_cmp(p, q) == 0);
    OK1(BN_mul(n, p, q, ctx));
    OK1(BN_mul(phi, pm1, qm1, ctx));
    OK1(BN_gcd(g, pm1, qm1, ctx));
    OK1(BN_div(lam, nullptr, phi, g, ctx));
    BIGNUM* d = BN_mod_inverse(nullptr, e, lam, ctx); NOTNULL(d);
    OK1(BN_nnmod(dP, d, pm1, ctx));
    OK1(BN_nnmod(dQ, d, qm1, ctx));
    BIGNUM* qInv = BN_mod_inverse(nullptr, q, p, ctx); NOTNULL(qInv);
    OK1(BN_rand_range(c, n));

    const int N = 1000;
    auto t0 = clk::now();
    for (int i = 0; i < N; ++i) OK1(BN_mod_exp(r, c, d, n, ctx));
    auto t1 = clk::now();
    BIGNUM* ref = BN_dup(r); NOTNULL(ref);
    for (int i = 0; i < N; ++i) {
        OK1(BN_mod_exp(m1, c, dP, p, ctx));
        OK1(BN_mod_exp(m2, c, dQ, q, ctx));
        OK1(BN_mod_sub(h, m1, m2, p, ctx));
        OK1(BN_mod_mul(h, qInv, h, p, ctx));
        OK1(BN_mul(r, h, q, ctx));
        OK1(BN_add(r, r, m2));
    }
    auto t2 = clk::now();
    double tDirect = std::chrono::duration<double, std::milli>(t1 - t0).count();
    double tCrt = std::chrono::duration<double, std::milli>(t2 - t1).count();
    check("CRT result equals direct result", BN_cmp(r, ref) == 0);
    std::printf("  direct c^d mod n : %8.1f ms for %d decryptions\n", tDirect, N);
    std::printf("  CRT (Garner)     : %8.1f ms for %d decryptions\n", tCrt, N);
    std::printf("  speed-up = %.2fx (theory: about 4x)\n", tDirect / tCrt);
    for (BIGNUM* x : {e, p, q, pm1, qm1, g, n, phi, lam, dP, dQ, c, r, m1, m2, h, d, qInv, ref})
        BN_clear_free(x);
    BN_CTX_free(ctx);
}

// Bài 4: dòng Base64 đầu của private.pem == những byte đầu của private.der
static void exB4_pem_vs_der() {
    std::ifstream pf("private.pem");
    std::string line, first;
    std::getline(pf, line);                    // -----BEGIN PRIVATE KEY-----
    std::getline(pf, first);                   // dòng Base64 đầu tiên
    if (!first.empty() && first.back() == '\r') first.pop_back();
    unsigned char dec[128];
    int decLen = EVP_DecodeBlock(dec, (const unsigned char*)first.data(), (int)first.size());
    std::ifstream df("private.der", std::ios::binary);
    unsigned char der[128] = {0};
    df.read((char*)der, sizeof der);
    std::printf("  PEM line 1 : %.16s...  (%d bytes after Base64 decoding)\n", first.c_str(), decLen);
    printHex("decoded PEM", dec, 16, 16);
    printHex("DER file", der, 16, 16);
    std::printf("  'MII' = 001100 001000 001000 -> 0x30 0x82 = ASN.1 SEQUENCE with a 2-byte length\n");
    check("first Base64 line == first bytes of private.der",
          decLen > 0 && std::memcmp(dec, der, (size_t)decLen) == 0);
}

static void runExercisesB() {
    std::printf("\nTASK B\n");
    std::printf("1. d_phi vs d_lambda (256-bit toy keys)\n");  exB1_dphi_vs_dlambda();
    std::printf("2. Prime draws: e = 3 vs e = 65537\n");        exB2_small_e();
    std::printf("3. Direct decryption vs CRT (1024-bit toy key)\n"); exB3_crt_speed();
    std::printf("4. PEM Base64 vs DER bytes\n");                exB4_pem_vs_der();
}
[[maybe_unused]] static const int exB_registered = [] {
    OPENSSL_init_crypto(0, nullptr);
    std::atexit(runExercisesB);
    return 0;
}();