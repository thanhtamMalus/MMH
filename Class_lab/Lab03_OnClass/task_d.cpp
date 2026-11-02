// task_d_hybrid.cpp -- Lab 3, Task D (in class)
// Hybrid encryption: a fresh AES-256 key encrypts the data with GCM; the AES
// key is wrapped with RSA-OAEP-SHA256 for the recipient. The package uses the
// version-1 format of the handout, and its header is authenticated as AAD.
// Then we tamper with each field and watch where decryption fails.

// Build: g++ -std=c++17 -Wall -Wextra task_d_hybrid.cpp -o task_d -lcrypto
// Run: ./task_d (new key, demo message)
// ./task_d public.pem private.pem <file> (keys from Task B)
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>
#include "common.h"

// ==========================================================================
// RSA-OAEP key wrapping (from Task C)
// ==========================================================================
static void configureOaep(EVP_PKEY_CTX* ctx) {
    OKPOS(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING));
    OKPOS(EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()));
    OKPOS(EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()));
}

static Bytes oaepWrap(EVP_PKEY* pub, const Bytes& key) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_pkey(nullptr, pub, nullptr);
    NOTNULL(ctx);
    OKPOS(EVP_PKEY_encrypt_init(ctx));
    configureOaep(ctx);
    size_t len = 0;
    OKPOS(EVP_PKEY_encrypt(ctx, nullptr, &len, key.data(), key.size()));
    Bytes w(len);
    OKPOS(EVP_PKEY_encrypt(ctx, w.data(), &len, key.data(), key.size()));
    w.resize(len);
    EVP_PKEY_CTX_free(ctx);
    return w;
}

static bool oaepUnwrap(EVP_PKEY* priv, const Bytes& w, Bytes& key) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_pkey(nullptr, priv, nullptr);
    NOTNULL(ctx);
    OKPOS(EVP_PKEY_decrypt_init(ctx));
    configureOaep(ctx);
    size_t len = 0;
    OKPOS(EVP_PKEY_decrypt(ctx, nullptr, &len, w.data(), w.size()));
    key.assign(len, 0);
    bool ok = EVP_PKEY_decrypt(ctx, key.data(), &len, w.data(), w.size()) > 0;
    if (ok) key.resize(len); else ERR_clear_error();
    EVP_PKEY_CTX_free(ctx);
    return ok;
}

// ==========================================================================
// AES-256-GCM (one-shot, in memory)
// init(key, nonce) -> AAD -> plaintext -> final -> tag
// ==========================================================================
static Bytes gcmEncrypt(const Bytes& key, const Bytes& nonce, const Bytes& aad, const Bytes& pt, Bytes& tag) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    NOTNULL(ctx);
    // 12-byte nonce is GCM’s default IV length: no extra parameter needed.
    OK1(EVP_EncryptInit_ex2(ctx, EVP_aes_256_gcm(), key.data(), nonce.data(), nullptr));
    int len = 0;
    OK1(EVP_EncryptUpdate(ctx, nullptr, &len, aad.data(), (int)aad.size())); // AAD
    Bytes ct(pt.size() + 16);
    OK1(EVP_EncryptUpdate(ctx, ct.data(), &len, pt.data(), (int)pt.size()));
    int total = len;
    OK1(EVP_EncryptFinal_ex(ctx, ct.data() + total, &len)); // GCM: len == 0
    total += len;
    ct.resize(total);
    tag.assign(16, 0);
    OK1(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag.data()));
    EVP_CIPHER_CTX_free(ctx);
    return ct;
}

// Returns false if the tag does not verify. The plaintext buffer must not be
// used (or written anywhere) in that case.
static bool gcmDecrypt(const Bytes& key, const Bytes& nonce, const Bytes& aad, const Bytes& ct, const Bytes& tag, Bytes& pt) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    NOTNULL(ctx);
    OK1(EVP_DecryptInit_ex2(ctx, EVP_aes_256_gcm(), key.data(), nonce.data(), nullptr));
    int len = 0;
    OK1(EVP_DecryptUpdate(ctx, nullptr, &len, aad.data(), (int)aad.size()));
    pt.assign(ct.size() + 16, 0);
    OK1(EVP_DecryptUpdate(ctx, pt.data(), &len, ct.data(), (int)ct.size()));
    int total = len;
    // The expected tag must be set BEFORE Final; Final’s result is the verdict.
    OK1(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, const_cast<unsigned char*>(tag.data())));
    bool ok = EVP_DecryptFinal_ex(ctx, pt.data() + total, &len) == 1;
    if (ok) {
        pt.resize(total + len);
    } else {
        OPENSSL_cleanse(pt.data(), pt.size()); // discard unverified data
        pt.clear();
        ERR_clear_error();
    }
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

// ==========================================================================
// Package format v1 (big-endian):
// "L2PK" | ver=1 | mode=1 | reserved=0000 | klen(2) | wrapped key (klen)
// | nonce (12) | ct_len (8) | ciphertext | tag (16)
// Header = everything before the ciphertext = AAD.
// ==========================================================================
static void putU16(Bytes& b, uint16_t v) { b.push_back(v >> 8); b.push_back(v & 0xff); }
static void putU64(Bytes& b, uint64_t v) { for (int s = 56; s >= 0; s -= 8) b.push_back((v >> s) & 0xff); }
static uint16_t getU16(const unsigned char* p) { return (uint16_t)(p << 8 | p); }
static uint64_t getU64(const unsigned char* p) { uint64_t v = 0; for (int i = 0; i < 8; ++i) v = v << 8 | p[i]; return v; }

static Bytes sealPackage(EVP_PKEY* recipientPub, const Bytes& plaintext) {
    // 1. fresh AES key K and nonce N from the CSPRNG
    Bytes K(32), N(12);
    OK1(RAND_bytes(K.data(), 32));
    OK1(RAND_bytes(N.data(), 12));
    // 2. wrap K for the recipient: W = RSA-OAEP(pk, K)
    Bytes W = oaepWrap(recipientPub, K);
    // 3. header (all fields before the ciphertext)
    Bytes header = {'L', '2', 'P', 'K', 0x01, 0x01, 0x00, 0x00};
    putU16(header, (uint16_t)W.size());
    header.insert(header.end(), W.begin(), W.end());
    header.insert(header.end(), N.begin(), N.end());
    putU64(header, plaintext.size()); // GCM: |C| == |P|
    // 4. C, T = AES-256-GCM(K, N, AAD = header, plaintext)
    Bytes tag;
    Bytes C = gcmEncrypt(K, N, header, plaintext, tag);
    OPENSSL_cleanse(K.data(), K.size()); // K is no longer needed
    // 5. package = header || C || T
    Bytes pkg = header;
    pkg.insert(pkg.end(), C.begin(), C.end());
    pkg.insert(pkg.end(), tag.begin(), tag.end());
    return pkg;
}

// ‘strict = false‘ skips the reserved-bytes check, to show that the AAD
// still catches a modified header.
static bool openPackage(EVP_PKEY* priv, const Bytes& pkg, Bytes& plaintext, std::string& why, bool strict = true) {
    // 1. parse and validate the header before any cryptography
    const size_t k = (size_t)EVP_PKEY_get_size(priv);
    if (pkg.size() < 10) { why = "too short"; return false; }
    if (std::memcmp(pkg.data(), "L2PK", 4) != 0) { why = "bad magic"; return false; }
    if (pkg != 0x01) { why = "unsupported version"; return false; }
    if (pkg != 0x01) { why = "unexpected mode"; return false; }
    if (strict && getU16(&pkg) != 0) { why = "reserved bytes not zero"; return false; }
    size_t klen = getU16(&pkg);
    if (klen != k) { why = "klen does not match key size"; return false; }
    size_t headerLen = 10 + klen + 12 + 8;
    if (pkg.size() < headerLen + 16) { why = "truncated"; return false; }
    uint64_t ctLen = getU64(&pkg[10 + klen + 12]);
    if (ctLen != pkg.size() - headerLen - 16) { why = "length mismatch"; return false; }

    Bytes header(pkg.begin(), pkg.begin() + headerLen);
    Bytes W(pkg.begin() + 10, pkg.begin() + 10 + klen);
    Bytes N(pkg.begin() + 10 + klen, pkg.begin() + 10 + klen + 12);
    Bytes C(pkg.begin() + headerLen, pkg.end() - 16);
    Bytes T(pkg.end() - 16, pkg.end());

    // 2. unwrap K, 3. authenticated decryption with AAD = header
    Bytes K;
    if (!oaepUnwrap(priv, W, K) || K.size() != 32) { why = "decryption failed"; return false; }
    bool ok = gcmDecrypt(K, N, header, C, T, plaintext);
    OPENSSL_cleanse(K.data(), K.size());
    if (!ok) { why = "decryption failed"; return false; }
    why = "ok";
    return true;
}

// ==========================================================================
static EVP_PKEY* loadPem(const char* path, bool isPrivate) {
    BIO* b = BIO_new_file(path, "rb");
    NOTNULL(b);
    EVP_PKEY* k = isPrivate ? PEM_read_bio_PrivateKey(b, nullptr, nullptr, nullptr) : PEM_read_bio_PUBKEY(b, nullptr, nullptr, nullptr);
    BIO_free(b);
    NOTNULL(k);
    return k;
}

static void tamperTest(EVP_PKEY* priv, const Bytes& pkg, size_t offset, const char* what, bool strict = true) {
    Bytes bad = pkg;
    bad[offset] ^= 0x01; // flip one bit
    Bytes out;
    std::string why;
    bool opened = openPackage(priv, bad, out, why, strict);
    std::printf(" flip %-36s -> %s\n", what, why.c_str());
    check(what, !opened && out.empty());
}

int main(int argc, char** argv) {
    EVP_PKEY *pub, *priv;
    Bytes message;
    if (argc == 4) {
        pub = loadPem(argv, false);
        priv = loadPem(argv, true);
        std::ifstream f(argv, std::ios::binary);
        if (!f) die("cannot open input file");
        message.assign(std::istreambuf_iterator<char>(f), {});
    } else {
        priv = EVP_RSA_gen(3072); // the key pair
        NOTNULL(priv);
        pub = priv; // same object has both halves
        const char* text = "Meet at the library at 10:00. Bring the USB key.";
        message.assign(text, text + std::strlen(text));
    }
    std::printf("== Task D: RSA-OAEP + AES-256-GCM, %zu-byte message ==\n", message.size());

    Bytes pkg = sealPackage(pub, message);
    const size_t k = (size_t)EVP_PKEY_get_size(priv), hdr = 30 + k;
    printHex("header", pkg.data(), hdr, 16);
    printHex("ciphertext", pkg.data() + hdr, pkg.size() - hdr - 16, 16);
    printHex("tag", pkg.data() + pkg.size() - 16, 16, 16);
    std::ofstream("demo.l2pk", std::ios::binary).write(reinterpret_cast<const char*>(pkg.data()), (std::streamsize)pkg.size());
    std::fprintf(stdout, " wrote demo.l2pk (%zu bytes = %zu header + %zu ct + 16 tag)\n", pkg.size(), hdr, pkg.size() - hdr - 16);

    Bytes out;
    std::string why;
    check("round trip recovers the message", openPackage(priv, pkg, out, why) && out == message);
    Bytes pkg2 = sealPackage(pub, message);
    check("sealing twice gives different packages", pkg != pkg2);

    std::fprintf(stdout, "\n-- tampering (each must fail, no plaintext) --\n");
    tamperTest(priv, pkg, hdr + 0, "first ciphertext byte");
    tamperTest(priv, pkg, pkg.size() - 1, "last tag byte");
    tamperTest(priv, pkg, 10 + k, "first nonce byte");
    tamperTest(priv, pkg, 10 + 5, "a byte of the wrapped key");
    tamperTest(priv, pkg, 4, "version byte");
    tamperTest(priv, pkg, 7, "reserved byte (strict parser)");
    tamperTest(priv, pkg, 7, "reserved byte (lax parser, AAD)", false);

    EVP_PKEY* other = EVP_RSA_gen(3072);
    NOTNULL(other);
    check("wrong private key cannot open", !openPackage(other, pkg, out, why));
    std::fprintf(stdout, " wrong key -> %s\n", why.c_str());

    EVP_PKEY_free(other);
    if (pub != priv) EVP_PKEY_free(pub);
    EVP_PKEY_free(priv);
    std::fprintf(stdout, "\n%s\n", g_failures ? "SOME CHECKS FAILED" : "ALL CHECKS PASSED");
    return g_failures ? 1 : 0;
}
