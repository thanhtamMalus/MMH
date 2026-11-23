// Task C - trao doi khoa: ECDH, X25519, ECIES
// Phan 1: ECDH tren P-256 tu viet, so voi EVP_PKEY_derive
// Phan 2: X25519 Montgomery ladder tu viet (RFC 7748), kiem tra bang test vector
// Phan 3: ECIES = ECDH tam thoi + HKDF-SHA256 + AES-256-GCM
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/obj_mac.h>
#include <openssl/param_build.h>
#include <openssl/rand.h>
#include <cstring>
#include <string>
#include "helpers.h"

// Tinh bi mat chung bang OpenSSL: Z = derive(khoa rieng cua toi, khoa cong khai cua doi phuong)
static bool evpDerive(EVP_PKEY* mine, EVP_PKEY* peer, Bytes& Z) {
  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_pkey(nullptr, mine, nullptr);
  NOTNULL(ctx);
  OKPOS(EVP_PKEY_derive_init(ctx));
  bool ok = EVP_PKEY_derive_set_peer_ex(ctx, peer, 1) > 0; // 1 = kiem tra khoa doi phuong
  size_t len = 0;
  ok = ok && EVP_PKEY_derive(ctx, nullptr, &len) > 0; // lay kich thuoc
  if (ok) {
    Z.assign(len, 0);
    ok = EVP_PKEY_derive(ctx, Z.data(), &len) > 0;
    Z.resize(len);
  }
  if (!ok) { ERR_clear_error(); Z.clear(); }
  EVP_PKEY_CTX_free(ctx);
  return ok;
}

// Lay khoa cong khai dang byte: diem 04||x||y (EC) hoac 32 byte (X25519)
static Bytes encodedPub(EVP_PKEY* k) {
  unsigned char* p = nullptr;
  size_t len = EVP_PKEY_get1_encoded_public_key(k, &p);
  if (len == 0) die("EVP_PKEY_get1_encoded_public_key");
  Bytes out(p, p + len);
  OPENSSL_free(p);
  return out;
}

// Dung khoa cong khai tu byte. curve = nullptr thi la X25519. Loi thi tra ve nullptr
static EVP_PKEY* pubFromBytes(const char* curve, const Bytes& enc) {
  if (!curve) {
    EVP_PKEY* k = EVP_PKEY_new_raw_public_key_ex(nullptr, "X25519", nullptr, enc.data(), enc.size());
    if (!k) ERR_clear_error();
    return k;
  }
  OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
  NOTNULL(bld);
  OK1(OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, curve, 0));
  OK1(OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, enc.data(), enc.size()));
  OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(bld);
  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
  NOTNULL(params); NOTNULL(ctx);
  OKPOS(EVP_PKEY_fromdata_init(ctx));
  EVP_PKEY* k = nullptr;
  if (EVP_PKEY_fromdata(ctx, &k, EVP_PKEY_PUBLIC_KEY, params) <= 0) { ERR_clear_error(); k = nullptr; }
  EVP_PKEY_CTX_free(ctx); OSSL_PARAM_free(params); OSSL_PARAM_BLD_free(bld);
  return k;
}

// ---------------------------------------------------------------
// Phan 1: ECDH tren P-256 tu viet: Z = x(d * Q_doiphuong)
// ---------------------------------------------------------------
static Bytes myEcdh(EVP_PKEY* mine, EVP_PKEY* peer) {
  BN_CTX* ctx = BN_CTX_new();
  EC_GROUP* g = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
  NOTNULL(ctx); NOTNULL(g);
  BIGNUM* d = nullptr;
  OK1(EVP_PKEY_get_bn_param(mine, OSSL_PKEY_PARAM_PRIV_KEY, &d)); // khoa rieng cua toi
  Bytes q = encodedPub(peer);
  EC_POINT *Q = EC_POINT_new(g), *S = EC_POINT_new(g);
  BIGNUM* x = BN_new();
  NOTNULL(Q); NOTNULL(S); NOTNULL(x);
  OK1(EC_POINT_oct2point(g, Q, q.data(), q.size(), ctx)); // giai ma va kiem tra diem
  OK1(EC_POINT_mul(g, S, nullptr, Q, d, ctx)); // S = d*Q
  if (EC_POINT_is_at_infinity(g, S)) die("diem chung la vo cuc");
  OK1(EC_POINT_get_affine_coordinates(g, S, x, nullptr, ctx));
  Bytes Z(32);
  if (BN_bn2binpad(x, Z.data(), 32) != 32) die("I2OSP"); // Z = x (32 byte, big-endian)
  EC_POINT_free(Q); EC_POINT_free(S); EC_GROUP_free(g);
  BN_clear_free(d); BN_clear_free(x); BN_CTX_free(ctx);
  return Z;
}

static void part1() {
  std::printf("== Phan 1: ECDH tren P-256 ==\n");
  EVP_PKEY *alice = EVP_EC_gen("P-256"), *bob = EVP_EC_gen("P-256");
  NOTNULL(alice); NOTNULL(bob);
  Bytes zA = myEcdh(alice, bob), zB = myEcdh(bob, alice), zE;
  check("tu viet: x(dA*QB) == x(dB*QA)", zA == zB);
  check("EVP_PKEY_derive cho cung ket qua", evpDerive(alice, bob, zE) && zE == zA);
  std::printf("\n");
  EVP_PKEY_free(alice); EVP_PKEY_free(bob);
}

// ---------------------------------------------------------------
// Phan 2: X25519 bang Montgomery ladder (RFC 7748, muc 5)
// Chi dung toa do u. p = 2^255 - 19, a24 = 121665
// So nguyen o dang little-endian (BN_lebin2bn), khac voi SEC 1 la big-endian
// ---------------------------------------------------------------
// Hoan doi co dieu kien. Day KHONG phai constant-time, chi de de doc
static void cswap(int swap, BIGNUM* a, BIGNUM* b) { if (swap) BN_swap(a, b); }

static Bytes myX25519(const Bytes& kIn, const Bytes& uIn) {
  BN_CTX* ctx = BN_CTX_new();
  NOTNULL(ctx);
  Bytes kb = kIn, ub = uIn;
  kb[0] &= 248; kb[31] &= 127; kb[31] |= 64; // clamp khoa: xoa bit 0,1,2 va 255, dat bit 254
  ub[31] &= 127; // bo bit cao nhat cua u

  BIGNUM *p = BN_new(), *k = BN_lebin2bn(kb.data(), 32, nullptr);
  BIGNUM *x1 = BN_lebin2bn(ub.data(), 32, nullptr);
  BIGNUM *x2 = BN_new(), *z2 = BN_new(), *x3 = BN_new(), *z3 = BN_new(), *a24 = BN_new();
  BIGNUM *A = BN_new(), *AA = BN_new(), *B = BN_new(), *BB = BN_new(), *E = BN_new();
  BIGNUM *C = BN_new(), *D = BN_new(), *DA = BN_new(), *CB = BN_new(), *t = BN_new();
  for (BIGNUM* v : {p, k, x1, x2, z2, x3, z3, a24, A, AA, B, BB, E, C, D, DA, CB, t}) NOTNULL(v);

  OK1(BN_set_word(p, 1)); OK1(BN_lshift(p, p, 255)); OK1(BN_sub_word(p, 19)); // p = 2^255 - 19
  OK1(BN_nnmod(x1, x1, p, ctx));
  OK1(BN_set_word(a24, 121665));
  OK1(BN_one(x2)); BN_zero(z2); // (x2:z2) = diem vo cuc
  NOTNULL(BN_copy(x3, x1)); OK1(BN_one(z3)); // (x3:z3) = diem u

  int swap = 0;
  for (int i = 254; i >= 0; --i) {
    int bit = BN_is_bit_set(k, i);
    swap ^= bit;
    cswap(swap, x2, x3); cswap(swap, z2, z3);
    swap = bit;

    OK1(BN_mod_add(A, x2, z2, p, ctx)); OK1(BN_mod_sqr(AA, A, p, ctx)); // A = x2+z2, AA = A^2
    OK1(BN_mod_sub(B, x2, z2, p, ctx)); OK1(BN_mod_sqr(BB, B, p, ctx)); // B = x2-z2, BB = B^2
    OK1(BN_mod_sub(E, AA, BB, p, ctx)); // E = AA - BB
    OK1(BN_mod_add(C, x3, z3, p, ctx)); OK1(BN_mod_sub(D, x3, z3, p, ctx));
    OK1(BN_mod_mul(DA, D, A, p, ctx)); OK1(BN_mod_mul(CB, C, B, p, ctx));

    OK1(BN_mod_add(t, DA, CB, p, ctx)); OK1(BN_mod_sqr(x3, t, p, ctx)); // x3 = (DA+CB)^2
    OK1(BN_mod_sub(t, DA, CB, p, ctx)); OK1(BN_mod_sqr(t, t, p, ctx));
    OK1(BN_mod_mul(z3, x1, t, p, ctx)); // z3 = x1 * (DA-CB)^2
    OK1(BN_mod_mul(x2, AA, BB, p, ctx)); // x2 = AA*BB
    OK1(BN_mod_mul(t, a24, E, p, ctx)); OK1(BN_mod_add(t, AA, t, p, ctx));
    OK1(BN_mod_mul(z2, E, t, p, ctx)); // z2 = E*(AA + a24*E)
  }
  cswap(swap, x2, x3); cswap(swap, z2, z3);

  // Ket qua = x2 / z2 = x2 * z2^(p-2) mod p
  NOTNULL(BN_copy(t, p)); OK1(BN_sub_word(t, 2));
  OK1(BN_mod_exp(z2, z2, t, p, ctx));
  OK1(BN_mod_mul(x2, x2, z2, p, ctx));
  Bytes out(32);
  if (BN_bn2lebinpad(x2, out.data(), 32) != 32) die("BN_bn2lebinpad");

  for (BIGNUM* v : {p, x1, x3, z3, a24, A, AA, B, BB, E, C, D, DA, CB, t}) BN_free(v);
  BN_clear_free(k); BN_clear_free(x2); BN_clear_free(z2);
  BN_CTX_free(ctx);
  return out;
}

static void part2() {
  std::printf("== Phan 2: X25519 (RFC 7748) ==\n");
  // Test vector RFC 7748 muc 6.1
  Bytes aPriv = fromHex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
  Bytes bPriv = fromHex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
  Bytes aPubE = fromHex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
  Bytes bPubE = fromHex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
  Bytes zE = fromHex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
  Bytes base(32, 0);
  base[0] = 9; // diem co so u = 9

  Bytes aPub = myX25519(aPriv, base), bPub = myX25519(bPriv, base);
  check("tu viet: khoa cong khai Alice khop RFC", aPub == aPubE);
  check("tu viet: khoa cong khai Bob khop RFC", bPub == bPubE);
  Bytes z1 = myX25519(aPriv, bPub), z2 = myX25519(bPriv, aPub);
  check("tu viet: hai ben ra bi mat chung cua RFC", z1 == zE && z2 == zE);

  EVP_PKEY* A = EVP_PKEY_new_raw_private_key_ex(nullptr, "X25519", nullptr, aPriv.data(), 32);
  EVP_PKEY* Bp = pubFromBytes(nullptr, bPubE);
  NOTNULL(A); NOTNULL(Bp);
  Bytes z3;
  check("EVP_PKEY_derive cho cung bi mat", evpDerive(A, Bp, z3) && z3 == zE);

  // Diem bac thap u = 0: ket qua luon toan 0, OpenSSL tu choi
  Bytes zero(32, 0);
  check("tu viet: X25519(k, 0) = toan 0", myX25519(aPriv, zero) == zero);
  EVP_PKEY* bad = pubFromBytes(nullptr, zero);
  NOTNULL(bad);
  check("OpenSSL tu choi diem bac thap", !evpDerive(A, bad, z3));
  std::printf("\n");
  EVP_PKEY_free(A); EVP_PKEY_free(Bp); EVP_PKEY_free(bad);
}

// ---------------------------------------------------------------
// Phan 3: ECIES = ECDH tam thoi + HKDF-SHA256 + AES-256-GCM
// Goi tin: len(E) (2 byte) | E | nonce (12 byte) | ban ma | tag (16 byte)
// Phan dau (len(E) | E | nonce) duoc dung lam AAD cho GCM
// ---------------------------------------------------------------
// HKDF-SHA256: bien bi mat ECDH thanh khoa AES 32 byte
static Bytes hkdf(const Bytes& ikm, const Bytes& info) {
  EVP_KDF* kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
  NOTNULL(kdf);
  EVP_KDF_CTX* kctx = EVP_KDF_CTX_new(kdf);
  NOTNULL(kctx);
  char digest[] = "SHA256";
  OSSL_PARAM params[] = {
    OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, digest, 0),
    OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void*)ikm.data(), ikm.size()),
    OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, (void*)info.data(), info.size()),
    OSSL_PARAM_construct_end()};
  Bytes out(32);
  OK1(EVP_KDF_derive(kctx, out.data(), out.size(), params));
  EVP_KDF_CTX_free(kctx); EVP_KDF_free(kdf);
  return out;
}

// info = nhan || E || Q_nguoinhan (gan khoa voi ca hai khoa cong khai)
static Bytes kdfInfo(const Bytes& E, const Bytes& QR) {
  const char label[] = "LAB-ECIES-HKDF-SHA256-AES256GCM";
  Bytes info(label, label + std::strlen(label));
  info.insert(info.end(), E.begin(), E.end());
  info.insert(info.end(), QR.begin(), QR.end());
  return info;
}

// AES-256-GCM. enc = true: ma hoa, tag la dau ra. enc = false: giai ma, tag la dau vao
static bool gcm(bool enc, const Bytes& key, const Bytes& nonce, const Bytes& aad,
                const Bytes& in, Bytes& out, Bytes& tag) {
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  NOTNULL(ctx);
  OK1(EVP_CipherInit_ex2(ctx, EVP_aes_256_gcm(), key.data(), nonce.data(), enc ? 1 : 0, nullptr));
  int len = 0;
  OK1(EVP_CipherUpdate(ctx, nullptr, &len, aad.data(), (int)aad.size())); // AAD
  out.assign(in.size() + 16, 0);
  OK1(EVP_CipherUpdate(ctx, out.data(), &len, in.data(), (int)in.size()));
  int total = len;
  if (!enc) OK1(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag.data()));
  bool ok = EVP_CipherFinal_ex(ctx, out.data() + total, &len) == 1;
  if (enc) {
    tag.assign(16, 0);
    OK1(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag.data()));
  }
  if (ok) out.resize(total + len); else { ERR_clear_error(); out.clear(); }
  EVP_CIPHER_CTX_free(ctx);
  return ok;
}

// Tao khoa moi: curve = "P-256" hoac nullptr (X25519)
static EVP_PKEY* newKey(const char* curve) {
  return curve ? EVP_EC_gen(curve) : EVP_PKEY_Q_keygen(nullptr, nullptr, "X25519");
}

static Bytes eciesSeal(EVP_PKEY* recipient, const char* curve, const Bytes& msg) {
  EVP_PKEY* eph = newKey(curve); // khoa tam thoi, moi ban tin 1 khoa moi
  NOTNULL(eph);
  Bytes Z, E = encodedPub(eph), QR = encodedPub(recipient);
  if (!evpDerive(eph, recipient, Z)) die("derive");
  EVP_PKEY_free(eph);
  Bytes K = hkdf(Z, kdfInfo(E, QR));

  Bytes nonce(12), C, T;
  OK1(RAND_bytes(nonce.data(), 12));
  Bytes h = {(unsigned char)(E.size() >> 8), (unsigned char)(E.size() & 0xff)};
  h.insert(h.end(), E.begin(), E.end());
  h.insert(h.end(), nonce.begin(), nonce.end());
  gcm(true, K, nonce, h, msg, C, T);

  OPENSSL_cleanse(Z.data(), Z.size()); OPENSSL_cleanse(K.data(), K.size());
  Bytes pkg = h;
  pkg.insert(pkg.end(), C.begin(), C.end());
  pkg.insert(pkg.end(), T.begin(), T.end());
  return pkg;
}

static bool eciesOpen(EVP_PKEY* priv, const char* curve, const Bytes& pkg, Bytes& msg, std::string& why) {
  if (pkg.size() < 2) { why = "goi tin qua ngan"; return false; }
  size_t elen = ((size_t)pkg[0] << 8) | pkg[1];
  size_t hlen = 2 + elen + 12;
  if (pkg.size() < hlen + 16) { why = "goi tin qua ngan"; return false; }
  Bytes E(pkg.begin() + 2, pkg.begin() + 2 + elen);
  Bytes nonce(pkg.begin() + 2 + elen, pkg.begin() + hlen);
  Bytes h(pkg.begin(), pkg.begin() + hlen);
  Bytes C(pkg.begin() + hlen, pkg.end() - 16), T(pkg.end() - 16, pkg.end());

  EVP_PKEY* ephPub = pubFromBytes(curve, E); // diem sai se bi tu choi o day
  if (!ephPub) { why = "khoa tam thoi khong hop le"; return false; }
  Bytes Z;
  bool ok = evpDerive(priv, ephPub, Z);
  EVP_PKEY_free(ephPub);
  if (!ok) { why = "trao doi khoa that bai"; return false; }

  Bytes K = hkdf(Z, kdfInfo(E, encodedPub(priv)));
  ok = gcm(false, K, nonce, h, C, msg, T);
  OPENSSL_cleanse(Z.data(), Z.size()); OPENSSL_cleanse(K.data(), K.size());
  why = ok ? "ok" : "giai ma that bai (tag sai)";
  return ok;
}

static void part3() {
  std::printf("== Phan 3: ECIES ==\n");
  const char* text = "The vault code is 7-3-1-9.";
  Bytes msg(text, text + std::strlen(text)), out;
  std::string why;
  struct { const char* curve; const char* name; } modes[] = {{"P-256", "P-256"}, {nullptr, "X25519"}};

  for (auto& m : modes) {
    std::string n = m.name;
    EVP_PKEY* bob = newKey(m.curve);
    NOTNULL(bob);
    Bytes pkg = eciesSeal(bob, m.curve, msg), pkg2 = eciesSeal(bob, m.curve, msg);
    std::printf(" %s: goi tin %zu byte\n", m.name, pkg.size());
    check((n + ": ma hoa roi giai ma ra dung").c_str(), eciesOpen(bob, m.curve, pkg, out, why) && out == msg);
    check((n + ": 2 lan ma hoa khac nhau (khoa tam thoi moi)").c_str(), pkg != pkg2);

    Bytes bad = pkg;
    bad[5] ^= 0x01; // doi 1 bit trong E
    bool opened = eciesOpen(bob, m.curve, bad, out, why);
    std::printf("  doi 1 bit cua E -> %s\n", why.c_str());
    check((n + ": E bi sua thi bi tu choi").c_str(), !opened);

    bad = pkg;
    bad.back() ^= 0x01; // doi 1 bit cua tag
    opened = eciesOpen(bob, m.curve, bad, out, why);
    std::printf("  doi 1 bit cua tag -> %s\n", why.c_str());
    check((n + ": tag bi sua thi bi tu choi").c_str(), !opened);

    EVP_PKEY* eve = newKey(m.curve);
    NOTNULL(eve);
    check((n + ": khoa rieng sai khong mo duoc").c_str(), !eciesOpen(eve, m.curve, pkg, out, why));
    EVP_PKEY_free(bob); EVP_PKEY_free(eve);
  }
  std::printf("\n");
}

int main() {
  part1();
  part2();
  part3();
  std::printf("%s\n", g_failures ? "SOME CHECKS FAILED" : "ALL CHECKS PASSED");
  return g_failures ? 1 : 0;
}
