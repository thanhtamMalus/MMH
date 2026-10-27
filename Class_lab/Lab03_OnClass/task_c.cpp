//Lab03 task c on class
#include<openssl/bn.h>
#include<openssl/core_names.h>
#include<openssl/err.h>
#include<openssl/evp.h>
#include<openssl/rand.h>
#include<openssl/rsa.h>
#include<cstdio>
#include<cstdlib>
#include<algorithm>
#include<cstring>
#include<string>
#include<vector>
#include <iomanip>
#include "helper.h"

//OS2IP:big-endianbytes->nonnegativeinteger.Leading0x00bytesvanish.
static BIGNUM* os2ip(const Bytes& x){
    BIGNUM*r=BN_bin2bn(x.data(), static_cast<int>(x.size()),nullptr);
    NOTNULL(r);
    return r;
}
//I2OSP:integer->exactlylenbytes,left-paddedwith0x00.
//Returnsfalse("integertoolarge")ifx>=256^len.
static bool i2osp(const BIGNUM* x,size_t len,Bytes& out){
    out.assign(len,0);
    return BN_bn2binpad(x,out.data(),static_cast<int>(len))>=0;
}

static Bytes hexToBytes(const char* h){
    Bytes b;
    for(size_t i=0;h[i]&&h[i+1];i+=2){
            char two[3]={h[i],h[i+1],0};
            b.push_back(static_cast<unsigned char>(std::strtoul(two,nullptr,16)));
    }
    return b;
}

    static void part1Encoding(){
    std::printf("==Part1:OS2IPandI2OSP==\n");
    struct Case{
        const char* id;const char* hex;size_t width;const char* expect;
    };
    const Case cases[]={
        {"C-T1","000001",3,"000001"},{"C-T2","000001",1,"01"},
        {"C-T3","0100",2,"0100"}, {"C-T4","0100",1,nullptr/*toolarge*/},
        {"C-T5","00ff00",3,"00ff00"},{"C-T6","",2,"0000"},
    };
    for(const Case& c:cases){
        Bytes in=hexToBytes(c.hex),out;
        BIGNUM* x=os2ip(in);
        char* dec=BN_bn2dec(x);
        NOTNULL(dec);
        bool fits=i2osp(x,c.width,out);
        std::string got;

        for(unsigned char v:out){
            char t[3];std::snprintf(t,3,"%02x",v);
            got+=t;
        }

        std::printf(" X=%-8s OS2IP=%-6s I2OSP(.,%zu)=%s\n",c.hex[0]?c.hex:"(empty)", dec,c.width,fits?got.c_str():"error:integertoolarge");
        check(c.id,c.expect?(fits&&got==c.expect):!fits);
        OPENSSL_free(dec);
        BN_free(x);
    }
    std::printf("\n");
}

static void part2Textbook() {
    std::printf("== Part 2: textbook RSA (INSECURE) ==\n");
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM *n = BN_new(), *e = BN_new(), *d = BN_new(), *m = BN_new(),
           *c = BN_new(), *c2 = BN_new(), *r = BN_new(), *c6 = BN_new(),
           *c7 = BN_new(), *forged = BN_new();
    NOTNULL(ctx); NOTNULL(forged);
    OK1(BN_set_word(n, 3233)); OK1(BN_set_word(e, 17)); OK1(BN_set_word(d, 2753));

    OK1(BN_set_word(m, 65));
    OK1(BN_mod_exp(c, m, e, n, ctx));             // c = m^e mod n
    OK1(BN_mod_exp(r, c, d, n, ctx));             // m = c^d mod n
    printBn("Enc(65)", c);
    check("Enc(65) = 2790 and decrypts to 65", BN_is_word(c, 2790) && BN_is_word(r, 65));

    // Determinism: same message, same ciphertext -> an eavesdropper can
    // test guesses (e.g. "yes"/"no") by encrypting them with the public key.
    OK1(BN_mod_exp(c2, m, e, n, ctx));
    check("deterministic: Enc(65) == Enc(65)", BN_cmp(c, c2) == 0);

    // Malleability: Enc(6) * Enc(7) = Enc(42) without knowing d.
    BIGNUM *six = BN_new(), *seven = BN_new();
    NOTNULL(six); NOTNULL(seven);
    OK1(BN_set_word(six, 6)); OK1(BN_set_word(seven, 7));
    OK1(BN_mod_exp(c6, six, e, n, ctx));
    OK1(BN_mod_exp(c7, seven, e, n, ctx));
    OK1(BN_mod_mul(forged, c6, c7, n, ctx));     // attacker's step
    OK1(BN_mod_exp(r, forged, d, n, ctx));       // victim decrypts
    printBn("Enc(6)",c6);printBn("Enc(7)",c7);printBn("Enc6*Enc7",forged);
    check("malleable: Dec(Enc(6)*Enc(7)) = 42", BN_is_word(r, 42));

    std::printf("\n");
    for (BIGNUM* x : {n, e, d, m, c, c2, r, c6, c7, forged, six, seven}) BN_free(x);
    BN_CTX_free(ctx);
}
// ============================================================================
// Part 3. RSA-OAEP by hand
// ============================================================================
static const size_t hLen = 32;                     // SHA-256 output size

static Bytes sha256(const Bytes& data) {
    Bytes out(hLen);
    unsigned int len = 0;
    OK1(EVP_Digest(data.data(), data.size(), out.data(), &len, EVP_sha256(), nullptr));
    return out;
}

// MGF1 (RFC 8017 B.2.1): T = H(seed || C(0)) || H(seed || C(1)) || ...
// C(i) = I2OSP(i, 4); output the first maskLen bytes.
static Bytes mgf1(const Bytes& seed, size_t maskLen) {
    Bytes t;
    for (uint32_t counter = 0; t.size() < maskLen; ++counter) {
        Bytes block = seed;
        block.push_back(static_cast<unsigned char>(counter >> 24));
        block.push_back(static_cast<unsigned char>(counter >> 16));
        block.push_back(static_cast<unsigned char>(counter >> 8));
        block.push_back(static_cast<unsigned char>(counter));
        Bytes h = sha256(block);
        t.insert(t.end(), h.begin(), h.end());
    }
    t.resize(maskLen);
    return t;
}

static void xorInto(Bytes& a, const Bytes& b) {
    for (size_t i = 0; i < a.size(); ++i) a[i] ^= b[i];
}

// EME-OAEP encoding (RFC 8017 7.1.1 step 2). Label L = empty.
// DB         = lHash || PS (zeros) || 0x01 || M       (k - hLen - 1 bytes)
// maskedDB   = DB XOR MGF1(seed, k - hLen - 1)
// maskedSeed = seed XOR MGF1(maskedDB, hLen)
// EM         = 0x00 || maskedSeed || maskedDB          (k bytes)
static Bytes oaepEncode(const Bytes& M, size_t k) {
    if (M.size() > k - 2 * hLen - 2) die("message too long for OAEP");
    Bytes lHash = sha256(Bytes());                  // hash of the empty label
    Bytes db = lHash;
    db.insert(db.end(), k - M.size() - 2 * hLen - 2, 0x00); // PS
    db.push_back(0x01);
    db.insert(db.end(), M.begin(), M.end());

    Bytes seed(hLen);
    OK1(RAND_bytes(seed.data(), static_cast<int>(hLen))); // fresh randomness
    xorInto(db, mgf1(seed, k - hLen - 1));               // db is now maskedDB
    xorInto(seed, mgf1(db, hLen));                       // seed is now maskedSeed

    Bytes em(0x00);
    em.insert(em.end(), seed.begin(), seed.end());
    em.insert(em.end(), db.begin(), db.end());
    return em;
}

// EME-OAEP decoding (RFC 8017 7.1.2 step 3). Returns false on any error.
// A real implementation must not reveal WHICH check failed (Manger's attack).
static bool oaepDecode(const Bytes& em, size_t k, Bytes& M) {
    if (em.size() != k || k < 2 * hLen + 2) return false;

    Bytes maskedSeed(em.begin() + 1, em.begin() + 1 + hLen);
    Bytes maskedDB(em.begin() + 1 + hLen, em.end());

    Bytes seed = maskedSeed;
    xorInto(seed, mgf1(maskedDB, hLen));

    Bytes db = maskedDB;
    xorInto(db, mgf1(seed, k - hLen - 1));

    Bytes lHash = sha256(Bytes());
    bool good = (em[0] == 0x00) &&
                std::equal(lHash.begin(), lHash.end(), db.begin());

    size_t i = 1 + hLen;
    while (i < db.size() && db[i] == 0x00) ++i;    // skip PS
    good = good && i < db.size() && db[i] == 0x01;
    if (good) M.assign(db.begin() + i + 1, db.end());
    return good;
}

static void configureOaep(EVP_PKEY_CTX* ctx) {     // both sides must match
    OKPOS(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING));
    OKPOS(EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256())); // default is SHA-1!
    OKPOS(EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()));
}

static Bytes evpOaepEncrypt(EVP_PKEY* key, const Bytes& M) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_pkey(nullptr, key, nullptr);
    NOTNULL(ctx);
    OKPOS(EVP_PKEY_encrypt_init(ctx));
    configureOaep(ctx);                             // after init

    size_t outLen = 0;
    OKPOS(EVP_PKEY_encrypt(ctx, nullptr, &outLen, M.data(), M.size())); // size
    Bytes out(outLen);
    OKPOS(EVP_PKEY_encrypt(ctx, out.data(), &outLen, M.data(), M.size()));
    out.resize(outLen);
    EVP_PKEY_CTX_free(ctx);
    return out;
}

static bool evpOaepDecrypt(EVP_PKEY* key, const Bytes& C, Bytes& M) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_pkey(nullptr, key, nullptr);
    NOTNULL(ctx);
    OKPOS(EVP_PKEY_decrypt_init(ctx));
    configureOaep(ctx);

    size_t outLen = 0;
    OKPOS(EVP_PKEY_decrypt(ctx, nullptr, &outLen, C.data(), C.size()));
    M.assign(outLen, 0);
    bool ok = EVP_PKEY_decrypt(ctx, M.data(), &outLen, C.data(), C.size()) > 0;
    if (ok) M.resize(outLen); else ERR_clear_error();
    EVP_PKEY_CTX_free(ctx);
    return ok;
}

// Raw RSA on byte strings: I2OSP(OS2IP(x)^exp mod n, k)
static Bytes rsaRaw(const Bytes& x, const BIGNUM* exp, const BIGNUM* n, size_t k) {
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* xi = os2ip(x), *yi = BN_new();
    NOTNULL(ctx); NOTNULL(yi);
    if (BN_cmp(xi, n) >= 0) die("representative out of range");
    OK1(BN_mod_exp(yi, xi, exp, n, ctx));
    Bytes y;
    if (!i2osp(yi, k, y)) die("I2OSP");
    BN_free(xi); BN_clear_free(yi); BN_CTX_free(ctx);
    return y;
}

static void part3Oaep() {
    std::printf("== Part 3: RSA-OAEP (SHA-256) by hand vs OpenSSL ==\n");
    EVP_PKEY* key = EVP_RSA_gen(2048);              // short form of keygen
    NOTNULL(key);
    BIGNUM *n = nullptr, *e = nullptr, *d = nullptr;
    OK1(EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_N, &n));
    OK1(EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_E, &e));
    OK1(EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_D, &d));
    const size_t k = static_cast<size_t>(BN_num_bytes(n)); // 256
    const char* text = "attack at dawn";
    Bytes M(text, text + std::strlen(text));

    // (a) our encoding + raw RSA -> OpenSSL decrypts it
    Bytes em = oaepEncode(M, k);
    printHex("EM (ours)", em.data(), em.size());
    Bytes C1 = rsaRaw(em, e, n, k);
    Bytes back;
    check("OpenSSL decrypts our OAEP ciphertext",
          evpOaepDecrypt(key, C1, back) && back == M);

    // (b) OpenSSL encrypts -> raw RSA with d + our decoding
    Bytes C2 = evpOaepEncrypt(key, M);
    Bytes em2 = rsaRaw(C2, d, n, k);
    printHex("EM (OpenSSL)", em2.data(), em2.size());
    Bytes M2;
    check("our decoder recovers OpenSSL's message",
          oaepDecode(em2, k, M2) && M2 == M);

    // (c) properties
    Bytes C3 = evpOaepEncrypt(key, M);
    check("randomized: two encryptions differ", C2 != C3);
    std::printf("  max message for k=%zu: %zu bytes\n", k, k - 2 * hLen - 2);
    Bytes big(k - 2 * hLen - 2, 'A');
    check("190-byte message accepted",
          evpOaepDecrypt(key, evpOaepEncrypt(key, big), back)
          && back == big);

    Bytes tampered = C2;
    tampered[10] ^= 0x01;
    check("tampered ciphertext is rejected",
          !evpOaepDecrypt(key, tampered, back));

    // Textbook malleability no longer works: multiply by Enc(2)
    BIGNUM *two = BN_new(), *c2i = os2ip(C2), *t = BN_new();
    BN_CTX* ctx = BN_CTX_new();
    NOTNULL(two); NOTNULL(t); NOTNULL(ctx);
    OK1(BN_set_word(two, 2));
    OK1(BN_mod_exp(t, two, e, n, ctx));
    OK1(BN_mod_mul(t, t, c2i, n, ctx));
    Bytes mauled;
    if (!i2osp(t, k, mauled)) die("I2OSP");
    check("Enc(2)*C is rejected (padding check fails)",
          !evpOaepDecrypt(key, mauled, back));

    std::printf("\n");

    for (BIGNUM* x : {n, e, two, c2i, t}) BN_free(x);
    BN_clear_free(d);
    BN_CTX_free(ctx);
    EVP_PKEY_free(key);
}

int main() {
    part1Encoding();
    part2Textbook();
    part3Oaep();
    std::printf("%s\n", g_failures ? "SOME CHECKS FAILED" : "ALL CHECKS PASSED");
    return g_failures ? 1 : 0;
}

// ===================== BÀI TẬP TASK C (dán xuống CUỐI file) =====================
#include <openssl/crypto.h>

// Bài 1: OS2IP mất độ dài (số 0 đứng đầu)
static void exC1_lengthLost() {
    Bytes x1 = hexToBytes("000001"), x2 = hexToBytes("01");
    BIGNUM *a = os2ip(x1), *b = os2ip(x2);
    check("OS2IP(000001) == OS2IP(01): leading zeros are lost", BN_cmp(a, b) == 0);
    std::printf("  RSA always uses I2OSP(., k) with k = modulus length, so the length is never lost.\n");
    BN_free(a); BN_free(b);
}

// Bài 2: tấn công vét cạn vì RSA thuần là tất định
static void exC2_bruteforce() {
    BN_CTX* ctx = BN_CTX_new(); NOTNULL(ctx);
    BIGNUM *n = BN_new(), *e = BN_new(), *c = BN_new(), *m = BN_new(), *t = BN_new();
    NOTNULL(n); NOTNULL(e); NOTNULL(c); NOTNULL(m); NOTNULL(t);
    OK1(BN_set_word(n, 3233)); OK1(BN_set_word(e, 17)); OK1(BN_set_word(c, 2790));
    long found = -1;
    for (unsigned long g = 0; g <= 100; ++g) {            // chỉ dùng (n, e), không dùng d
        OK1(BN_set_word(m, g));
        OK1(BN_mod_exp(t, m, e, n, ctx));
        if (BN_cmp(t, c) == 0) { found = (long)g; break; }
    }
    std::printf("  eavesdropper recovers m = %ld from c = 2790 using only (n, e)\n", found);
    check("brute force finds m = 65", found == 65);
    for (BIGNUM* x : {n, e, c, m, t}) BN_free(x);
    BN_CTX_free(ctx);
}

// Bài 3: giải mã OAEP với hash khác phía mã hóa
static bool exC3_decryptWith(EVP_PKEY* key, const Bytes& C, const EVP_MD* oaepMd, const EVP_MD* mgfMd, std::string& err) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_pkey(nullptr, key, nullptr);
    NOTNULL(ctx);
    OKPOS(EVP_PKEY_decrypt_init(ctx));
    OKPOS(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING));
    OKPOS(EVP_PKEY_CTX_set_rsa_oaep_md(ctx, oaepMd));
    OKPOS(EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, mgfMd));
    size_t outLen = 0;
    OKPOS(EVP_PKEY_decrypt(ctx, nullptr, &outLen, C.data(), C.size()));
    Bytes M(outLen);
    bool ok = EVP_PKEY_decrypt(ctx, M.data(), &outLen, C.data(), C.size()) > 0;
    if (!ok) {
        char buf[256];
        ERR_error_string_n(ERR_get_error(), buf, sizeof buf);
        err = buf;
        ERR_clear_error();
    }
    EVP_PKEY_CTX_free(ctx);
    return ok;
}

static void exC3_sha1Mismatch() {
    EVP_PKEY* key = EVP_RSA_gen(2048); NOTNULL(key);
    Bytes M(14, 'x');
    Bytes C = evpOaepEncrypt(key, M);                   // mã hóa với SHA-256
    std::string err;
    check("decrypt with SHA-256/SHA-256 (matching) works",
          exC3_decryptWith(key, C, EVP_sha256(), EVP_sha256(), err));
    bool a = exC3_decryptWith(key, C, EVP_sha1(), EVP_sha256(), err);
    std::printf("  OAEP=SHA-1, MGF1=SHA-256 -> %s %s\n", a ? "ok" : "FAILED:", a ? "" : err.c_str());
    check("OAEP hash mismatch is rejected", !a);
    bool b = exC3_decryptWith(key, C, EVP_sha1(), EVP_sha1(), err);
    std::printf("  OAEP=SHA-1, MGF1=SHA-1   -> %s %s\n", b ? "ok" : "FAILED:", b ? "" : err.c_str());
    check("OAEP+MGF1 hash mismatch is rejected", !b);
    std::printf("  Reason: a different hash gives a different mask and a different lHash,\n"
                "  so the unmasked DB does not contain the expected lHash / 0x01 structure.\n");
    EVP_PKEY_free(key);
}

// Bài 4: in DB của OAEP để nhận ra lHash, PS, 0x01 và thông điệp
static void exC4_dumpDb() {
    EVP_PKEY* key = EVP_RSA_gen(2048); NOTNULL(key);
    BIGNUM *n = nullptr, *d = nullptr;
    OK1(EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_N, &n));
    OK1(EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_D, &d));
    const size_t k = (size_t)BN_num_bytes(n);
    const char* text = "attack at dawn";
    Bytes M(text, text + std::strlen(text));
    Bytes C = evpOaepEncrypt(key, M);                   // do OpenSSL tạo
    Bytes em = rsaRaw(C, d, n, k);                      // RSA thô -> EM
    Bytes maskedSeed(em.begin() + 1, em.begin() + 1 + hLen);
    Bytes maskedDB(em.begin() + 1 + hLen, em.end());
    Bytes seed = maskedSeed; xorInto(seed, mgf1(maskedDB, hLen));
    Bytes db = maskedDB;     xorInto(db, mgf1(seed, k - hLen - 1));
    Bytes lHash = sha256(Bytes{});
    size_t i = hLen;
    while (i < db.size() && db[i] == 0x00) ++i;
    std::printf("  EM[0]            = 0x%02x (must be 00)\n", em[0]);
    printHex("lHash (in DB)", db.data(), hLen, 32);
    printHex("SHA256(empty)", lHash.data(), hLen, 32);
    std::printf("  PS               = %zu zero bytes\n", i - hLen);
    std::printf("  separator        = 0x%02x\n", db[i]);
    std::printf("  message          = \"%.*s\" (%zu bytes)\n", (int)(db.size() - i - 1),
                (const char*)&db[i + 1], db.size() - i - 1);
    check("lHash in DB equals SHA-256 of the empty label",
          std::equal(lHash.begin(), lHash.end(), db.begin()));
    check("separator is 0x01 and message is recovered",
          db[i] == 0x01 && Bytes(db.begin() + i + 1, db.end()) == M);
    BN_free(n); BN_clear_free(d);
    EVP_PKEY_free(key);
}

// Bài 5: độ dài thông điệp tối đa của OAEP-SHA256
static void exC5_maxLen() {
    for (int bits : {2048, 3072, 4096}) {
        size_t k = (size_t)bits / 8;
        std::printf("  RSA-%d: k = %zu bytes -> max message = k - 2*32 - 2 = %zu bytes\n",
                    bits, k, k - 2 * hLen - 2);
    }
    check("a 32-byte AES key fits in every size", 32 <= 256 - 2 * hLen - 2);
}

static void runExercisesC() {
    std::printf("\nTask c\n");
    std::printf("1. OS2IP loses the length\n");                   exC1_lengthLost();
    std::printf("2. Brute force on textbook RSA\n");              exC2_bruteforce();
    std::printf("3. OAEP hash mismatch on decryption\n");         exC3_sha1Mismatch();
    std::printf("4. Inside OAEP's DB\n");                         exC4_dumpDb();
    std::printf("5. Maximum OAEP message length\n");              exC5_maxLen();
}
[[maybe_unused]] static const int exC_registered = [] {
    OPENSSL_init_crypto(0, nullptr);
    std::atexit(runExercisesC);
    return 0;
}();