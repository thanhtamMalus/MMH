// task_e_kem.cpp -- Lab 3, Task E (in class)
// Part 1: RSASVE key encapsulation by hand (BIGNUM) and with OpenSSL's
// EVP_PKEY_encapsulate / EVP_PKEY_decapsulate; check they interoperate.
// Part 2: HKDF-SHA-256 by hand (HMAC Extract + Expand) vs EVP_KDF "HKDF",
// checked against RFC 5869 test case 1.
// Part 3: the lab profile LAB02-RSASVE-HKDF-SHA256-AES256GCM-v1 end to end,
// including what happens when the encapsulation is modified.
//
// Build: g++ -std=c++17 -Wall -Wextra task_e_kem.cpp -o task_e -lcrypto
// Run: ./task_e
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include "common.h"

// ===== Minimal helpers =====================================================
using Bytes = std::vector<unsigned char>;
static int g_failures = 0;

[[noreturn]] static void die(const char* what) {
    std::fprintf(stderr, "FAILED: %s\n", what);
    ERR_print_errors_fp(stderr); // OpenSSL's reason strings
    std::exit(1);
}

#define OK1(call) do { if ((call) != 1) die(#call); } while (0)
#define OKPOS(call) do { if ((call) <= 0) die(#call); } while (0)
#define NOTNULL(ptr) do { if ((ptr) == nullptr) die(#ptr " is NULL"); } while (0)

[[maybe_unused]] static void printHex(const char* label, const unsigned char* p, size_t n, size_t maxShown = 24) {
    std::printf(" %-16s", label);
    for (size_t i = 0; i < n && i < maxShown; ++i) std::printf("%02x", p[i]);
    if (n > maxShown) std::printf("... (%zu bytes)", n);
    std::printf("\n");
}

[[maybe_unused]] static void printBn(const char* label, const BIGNUM* x) {
    char* s = BN_bn2dec(x);
    NOTNULL(s);
    std::printf(" %-16s%s\n", label, s);
    OPENSSL_free(s);
}

[[maybe_unused]] static void printBnBits(const char* label, const BIGNUM* x) {
    char* s = BN_bn2hex(x);
    NOTNULL(s);
    std::printf(" %-16s%d bits, 0x%.24s...\n", label, BN_num_bits(x), s);
    OPENSSL_free(s);
}

[[maybe_unused]] static void check(const char* name, bool ok) {
    std::printf(" [%s] %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) ++g_failures;
}

// ==========================================================================
static Bytes i2osp(const BIGNUM* x, size_t len) {
    Bytes out(len);
    if (BN_bn2binpad(x, out.data(), (int)len) < 0) die("I2OSP: integer too large");
    return out;
}

static BIGNUM* getParam(EVP_PKEY* key, const char* name) {
    BIGNUM* x = nullptr;
    OK1(EVP_PKEY_get_bn_param(key, name, &x));
    return x;
}

// ==========================================================================
// Part 1. RSASVE (NIST SP 800-56B): secret value encapsulation
// Encaps(pk): z random, 1 < z < n-1; c = z^e mod n
// C_kem = I2OSP(c, k), Z = I2OSP(z, k)
// Decaps(sk, C): check |C| = k and 0 < c < n; z = c^d mod n; Z = I2OSP(z, k)
// ==========================================================================
struct Encapsulation { Bytes kemCt; Bytes Z; };

static Encapsulation myEncaps(EVP_PKEY* pub) {
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM *n = getParam(pub, OSSL_PKEY_PARAM_RSA_N), *e = getParam(pub, OSSL_PKEY_PARAM_RSA_E);
    BIGNUM *range = BN_dup(n), *z = BN_new(), *c = BN_new();
    NOTNULL(ctx); NOTNULL(range); NOTNULL(z); NOTNULL(c);
    const size_t k = (size_t)BN_num_bytes(n);
    OK1(BN_sub_word(range, 3)); // z in [2, n-2]:
    OK1(BN_rand_range(z, range)); // rand in [0, n-4]
    OK1(BN_add_word(z, 2)); // then + 2
    OK1(BN_mod_exp(c, z, e, n, ctx));
    Encapsulation r{i2osp(c, k), i2osp(z, k)};
    BN_free(n); BN_free(e); BN_free(range); BN_clear_free(z); BN_free(c);
    BN_CTX_free(ctx);
    return r;
}

static bool myDecaps(EVP_PKEY* priv, const Bytes& kemCt, Bytes& Z) {
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM *n = getParam(priv, OSSL_PKEY_PARAM_RSA_N), *d = getParam(priv, OSSL_PKEY_PARAM_RSA_D);
    NOTNULL(ctx);
    const size_t k = (size_t)BN_num_bytes(n);
    bool ok = false;
    if (kemCt.size() == k) {
        BIGNUM* c = BN_bin2bn(kemCt.data(), (int)k, nullptr);
        NOTNULL(c);
        if (!BN_is_zero(c) && BN_cmp(c, n) < 0) { // 0 < c < n
            BIGNUM* z = BN_new();
            NOTNULL(z);
            OK1(BN_mod_exp(z, c, d, n, ctx));
            Z = i2osp(z, k);
            BN_clear_free(z);
            ok = true;
        }
        BN_free(c);
    }
    BN_free(n); BN_clear_free(d); BN_CTX_free(ctx);
    return ok;
}

static Encapsulation evpEncaps(EVP_PKEY* pub) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_pkey(nullptr, pub, nullptr);
    NOTNULL(ctx);
    OKPOS(EVP_PKEY_encapsulate_init(ctx, nullptr));
    OKPOS(EVP_PKEY_CTX_set_kem_op(ctx, "RSASVE")); // choose the RSA KEM
    size_t ctLen = 0, zLen = 0;
    OKPOS(EVP_PKEY_encapsulate(ctx, nullptr, &ctLen, nullptr, &zLen)); // sizes
    Encapsulation r{Bytes(ctLen), Bytes(zLen)};
    OKPOS(EVP_PKEY_encapsulate(ctx, r.kemCt.data(), &ctLen, r.Z.data(), &zLen));
    r.kemCt.resize(ctLen);
    r.Z.resize(zLen);
    EVP_PKEY_CTX_free(ctx);
    return r;
}

static bool evpDecaps(EVP_PKEY* priv, const Bytes& kemCt, Bytes& Z) {
    // OpenSSL 3.0 accepts c = 0, so check the range first (as myDecaps does).
    BIGNUM* n = getParam(priv, OSSL_PKEY_PARAM_RSA_N);
    BIGNUM* c = BN_bin2bn(kemCt.data(), (int)kemCt.size(), nullptr);
    NOTNULL(c);
    bool inRange = kemCt.size() == (size_t)BN_num_bytes(n) && !BN_is_zero(c) && BN_cmp(c, n) < 0;
    BN_free(n); BN_free(c);
    if (!inRange) return false;

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_pkey(nullptr, priv, nullptr);
    NOTNULL(ctx);
    OKPOS(EVP_PKEY_decapsulate_init(ctx, nullptr));
    OKPOS(EVP_PKEY_CTX_set_kem_op(ctx, "RSASVE"));
    size_t zLen = 0;
    OKPOS(EVP_PKEY_decapsulate(ctx, nullptr, &zLen, kemCt.data(), kemCt.size()));
    Z.assign(zLen, 0);
    bool ok = EVP_PKEY_decapsulate(ctx, Z.data(), &zLen, kemCt.data(), kemCt.size()) > 0;
    if (ok) Z.resize(zLen); else ERR_clear_error();
    EVP_PKEY_CTX_free(ctx);
    return ok;
}

static void part1Kem(EVP_PKEY* key) {
    std::printf("== Part 1: RSASVE encapsulation ==\n");
    Encapsulation a = myEncaps(key);
    printHex("C_kem", a.kemCt.data(), a.kemCt.size());
    printHex("Z (secret)", a.Z.data(), a.Z.size(), 8); // shown here for teaching only
    Bytes z1, z2;
    check("ours -> ours", myDecaps(key, a.kemCt, z1) && z1 == a.Z);
    check("ours -> OpenSSL", evpDecaps(key, a.kemCt, z2) && z2 == a.Z);
    Encapsulation b = evpEncaps(key);
    check("OpenSSL -> ours", myDecaps(key, b.kemCt, z1) && z1 == b.Z);
    check("OpenSSL -> OpenSSL", evpDecaps(key, b.kemCt, z2) && z2 == b.Z);
    check("two encapsulations differ", a.kemCt != b.kemCt && a.Z != b.Z);
    check("|C_kem| = |Z| = k", b.kemCt.size() == (size_t)EVP_PKEY_get_size(key) && b.Z.size() == b.kemCt.size());

    Bytes bad = b.kemCt;
    bad[2] ^= 0x01; // still < n
    check("modified C_kem still decapsulates (to a DIFFERENT Z)", evpDecaps(key, bad, z2) && z2 != b.Z);
    check("C_kem = 0 is rejected", !evpDecaps(key, Bytes(b.kemCt.size(), 0x00), z2));
    check("C_kem >= n is rejected", !evpDecaps(key, Bytes(b.kemCt.size(), 0xff), z2));
    check("C_kem of wrong length is rejected", !evpDecaps(key, Bytes(10, 0x01), z2));
    std::printf("\n");
}

// ==========================================================================
// Part 2. HKDF-SHA-256 (RFC 5869)
// Extract: PRK = HMAC(salt, IKM) (salt empty -> 32 zero bytes)
// Expand: T(0) = empty; T(i) = HMAC(PRK, T(i-1) || info || i), i = 1, 2, ...
// OKM = first L bytes of T(1) || T(2) || ...
// ==========================================================================
static Bytes hmacSha256(const Bytes& key, const Bytes& data) {
    Bytes out(32);
    unsigned int len = 0;
    NOTNULL(HMAC(EVP_sha256(), key.data(), (int)key.size(), data.data(), data.size(), out.data(), &len));
    return out;
}

static Bytes myHkdf(const Bytes& ikm, const Bytes& salt, const Bytes& info, size_t L) {
    if (L > 255 * 32) die("HKDF output too long");
    Bytes prk = hmacSha256(salt.empty() ? Bytes(32, 0) : salt, ikm); // Extract
    Bytes okm, t;
    for (unsigned char i = 1; okm.size() < L; ++i) { // Expand
        Bytes block = t;
        block.insert(block.end(), info.begin(), info.end());
        block.push_back(i);
        t = hmacSha256(prk, block);
        okm.insert(okm.end(), t.begin(), t.end());
    }
    okm.resize(L);
    OPENSSL_cleanse(prk.data(), prk.size());
    return okm;
}

static Bytes evpHkdf(const Bytes& ikm, const Bytes& salt, const Bytes& info, size_t L) {
    EVP_KDF* kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
    NOTNULL(kdf);
    EVP_KDF_CTX* kctx = EVP_KDF_CTX_new(kdf);
    NOTNULL(kctx);
    char digest[] = "SHA256";
    OSSL_PARAM params[3], *p = params;
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, digest, 0);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void*)ikm.data(), ikm.size());
    if (!salt.empty())
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (void*)salt.data(), salt.size());
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, (void*)info.data(), info.size());
    *p = OSSL_PARAM_construct_end();
    Bytes okm(L);
    OK1(EVP_KDF_derive(kctx, okm.data(), L, params));
    EVP_KDF_CTX_free(kctx);
    EVP_KDF_free(kdf);
    return okm;
}

static void part2Hkdf() {
    std::printf("== Part 2: HKDF-SHA-256 ==\n");
    Bytes ikm(22, 0x0b), salt, info; // RFC 5869 test case 1
    for (int i = 0x00; i <= 0x0c; ++i) salt.push_back((unsigned char)i);
    for (int i = 0xf0; i <= 0xf9; ++i) info.push_back((unsigned char)i);
    const char* expect = "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56"
                         "ecc4c5bf34007208d5b887185865";
    Bytes a = myHkdf(ikm, salt, info, 42), b = evpHkdf(ikm, salt, info, 42);
    std::string hex;
    for (unsigned char v : a) { char t[4]; std::snprintf(t, 3, "%02x", v); hex += t; }
    printHex("OKM", a.data(), a.size(), 42);
    check("our HKDF == RFC 5869 test vector", hex == expect);
    check("our HKDF == EVP_KDF HKDF", a == b);
    check("empty salt also agrees", myHkdf(ikm, {}, info, 32) == evpHkdf(ikm, {}, info, 32));
    std::printf("\n");
}

// ==========================================================================
// Part 3. Lab profile: RSASVE + HKDF-SHA-256 + AES-256-GCM
// info = "LAB02-RSASVE-HKDF-SHA256-AES256GCM-v1" || 0x00 || keyID(32)
// || I2OSP(k, 2) || C_kem
// K_aes = HKDF(IKM = Z, salt = empty, info, L = 32)
// ==========================================================================
static Bytes keyId(EVP_PKEY* key) { // SHA-256(SPKI DER), Task B
    unsigned char* der = nullptr;
    int len = i2d_PUBKEY(key, &der);
    if (len <= 0) die("i2d_PUBKEY");
    Bytes id(32);
    unsigned int outLen = 0;
    OK1(EVP_Digest(der, (size_t)len, id.data(), &outLen, EVP_sha256(), nullptr));
    OPENSSL_free(der);
    return id;
}

static Bytes buildInfo(const Bytes& keyId32, const Bytes& kemCt) {
    const char label[] = "LAB02-RSASVE-HKDF-SHA256-AES256GCM-v1";
    Bytes info(label, label + std::strlen(label)); // 37 bytes, no NUL
    info.push_back(0x00);
    info.insert(info.end(), keyId32.begin(), keyId32.end());
    info.push_back((unsigned char)(kemCt.size() >> 8));
    info.push_back((unsigned char)(kemCt.size() & 0xff));
    info.insert(info.end(), kemCt.begin(), kemCt.end());
    return info;
}

// AES-256-GCM in one function (no AAD here, to keep the focus on the KEM;
// the project authenticates the package header as AAD exactly as in Task D).
static Bytes gcm(bool encrypt, const Bytes& key, const Bytes& nonce,
                const Bytes& in, Bytes& tag, bool& ok) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    NOTNULL(ctx);
    OK1(EVP_CipherInit_ex2(ctx, EVP_aes_256_gcm(), key.data(), nonce.data(),
                          encrypt ? 1 : 0, nullptr));
    Bytes out(in.size() + 16);
    int len = 0, total = 0;
    OK1(EVP_CipherUpdate(ctx, out.data(), &len, in.data(), (int)in.size()));
    total = len;
    if (!encrypt)
        OK1(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag.data()));
    ok = EVP_CipherFinal_ex(ctx, out.data() + total, &len) == 1;
    total += len;
    if (encrypt) {
        tag.assign(16, 0);
        OK1(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag.data()));
    }
    if (!ok) { ERR_clear_error(); out.clear(); } else out.resize(total);
    EVP_CIPHER_CTX_free(ctx);
    return out;
}

static void part3Profile(EVP_PKEY* key) {
    std::printf("== Part 3: KEM + HKDF + AES-256-GCM (lab profile) ==\n");
    const char* text = "Exam questions are in the blue folder.";
    Bytes M(text, text + std::strlen(text)), id = keyId(key);

    // Sender
    Encapsulation enc = evpEncaps(key);
    Bytes info = buildInfo(id, enc.kemCt);
    Bytes kSend = evpHkdf(enc.Z, {}, info, 32);
    Bytes nonce(12), tag;
    OK1(RAND_bytes(nonce.data(), 12));
    bool ok = false;
    Bytes C = gcm(true, kSend, nonce, M, tag, ok);
    std::printf(" info is %zu bytes (37 + 1 + 32 + 2 + %zu)\n", info.size(), enc.kemCt.size());

    // Receiver
    Bytes Z, M2;
    check("receiver decapsulates", evpDecaps(key, enc.kemCt, Z));
    Bytes kRecv = evpHkdf(Z, {}, buildInfo(id, enc.kemCt), 32);
    check("both sides derive the same AES key", kSend == kRecv); // local test only
    M2 = gcm(false, kRecv, nonce, C, tag, ok);
    check("message decrypts and authenticates", ok && M2 == M);

    // Modified encapsulation: decapsulation "succeeds", GCM catches it
    Bytes bad = enc.kemCt;
    bad[5] ^= 0x01;
    Bytes Zbad;
    bool dec = evpDecaps(key, bad, Zbad);
    Bytes kBad = evpHkdf(Zbad, {}, buildInfo(id, bad), 32);
    gcm(false, kBad, nonce, C, tag, ok);
    check("modified C_kem: decaps OK but GCM rejects", dec && !ok);

    // Context binding: a different key ID gives a different key
    Bytes id2 = id;
    id2 ^= 0x01;
    check("different key ID -> different AES key", evpHkdf(Z, {}, buildInfo(id2, enc.kemCt), 32) != kRecv);

    // Using Z directly as the key is forbidden; Z is k bytes anyway, not 32.
    std::printf(" |Z| = %zu bytes, |K_aes| = %zu bytes\n\n", Z.size(), kRecv.size());
    for (Bytes* s : {&enc.Z, &Z, &Zbad, &kSend, &kRecv, &kBad})
        OPENSSL_cleanse(s->data(), s->size());
}

int main() {
    EVP_PKEY* key = EVP_RSA_gen(3072);
    NOTNULL(key);
    part1Kem(key);
    part2Hkdf();
    part3Profile(key);
    EVP_PKEY_free(key);
    std::printf("%s\n", g_failures ? "SOME CHECKS FAILED" : "ALL CHECKS PASSED");
    return g_failures ? 1 : 0;
}