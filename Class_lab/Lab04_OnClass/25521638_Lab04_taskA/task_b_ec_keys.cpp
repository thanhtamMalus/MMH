// Task B - cap khoa elliptic-curve
// Phan 1: tao khoa cho P-256, P-384, secp256k1, X25519, Ed25519, Ed448, RSA-3072
// Phan 2: nhin vao khoa P-256: kiem tra Q = d*G
// Phan 3: tao khoa tu gia tri tho (seed RFC 8032, diem Q ma hoa)
// Phan 4: ghi/doc khoa PEM va DER
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <string>
#include "helpers.h"

// Tao khoa: neu co curve thi la khoa EC, nguoc lai dung ten thuat toan
static EVP_PKEY* genKey(const char* alg, const char* curve) {
  EVP_PKEY* k = curve ? EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", curve)
                      : EVP_PKEY_Q_keygen(nullptr, nullptr, alg);
  NOTNULL(k);
  return k;
}

// Kich thuoc file khoa cong khai dang DER (SubjectPublicKeyInfo)
static int spkiSize(EVP_PKEY* key) { return i2d_PUBKEY(key, nullptr); }

// Key ID = SHA-256 cua SPKI DER
static Bytes keyId(EVP_PKEY* key) {
  unsigned char* der = nullptr;
  int len = i2d_PUBKEY(key, &der);
  if (len <= 0) die("i2d_PUBKEY");
  Bytes id(32);
  unsigned int outLen = 0;
  OK1(EVP_Digest(der, (size_t)len, id.data(), &outLen, EVP_sha256(), nullptr));
  OPENSSL_free(der);
  return id;
}

// ---------------------------------------------------------------
// Phan 1: tao khoa cho moi thuat toan
// ---------------------------------------------------------------
static void part1() {
  std::printf("== Phan 1: tao khoa ==\n");
  std::printf(" %-10s %-8s %5s %9s\n", "ten", "loai", "bits", "SPKI (B)");
  struct Row { const char* label; const char* alg; const char* curve; };
  const Row rows[] = {
    {"P-256", "EC", "P-256"}, {"P-384", "EC", "P-384"}, {"secp256k1", "EC", "secp256k1"},
    {"X25519", "X25519", nullptr}, {"Ed25519", "ED25519", nullptr}, {"Ed448", "ED448", nullptr}};
  for (const Row& r : rows) {
    EVP_PKEY* k = genKey(r.alg, r.curve);
    std::printf(" %-10s %-8s %5d %9d\n", r.label, EVP_PKEY_get0_type_name(k),
                EVP_PKEY_get_bits(k), spkiSize(k));
    EVP_PKEY_free(k);
  }
  EVP_PKEY* rsa = EVP_RSA_gen(3072); // RSA-3072 cung muc an toan voi P-256
  NOTNULL(rsa);
  std::printf(" %-10s %-8s %5d %9d\n\n", "RSA-3072", "RSA", EVP_PKEY_get_bits(rsa), spkiSize(rsa));
  EVP_PKEY_free(rsa);
}

// ---------------------------------------------------------------
// Phan 2: ben trong khoa P-256: d (khoa bi mat) va Q = d*G
// ---------------------------------------------------------------
static void part2() {
  std::printf("== Phan 2: ben trong khoa P-256 ==\n");
  EVP_PKEY* key = genKey("EC", "P-256");

  char curve[64];
  OK1(EVP_PKEY_get_utf8_string_param(key, OSSL_PKEY_PARAM_GROUP_NAME, curve, sizeof curve, nullptr));
  BIGNUM* d = nullptr;
  OK1(EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_PRIV_KEY, &d)); // khoa bi mat d
  unsigned char pub[133];
  size_t pubLen = 0;
  OK1(EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY, pub, sizeof pub, &pubLen));
  std::printf(" ten duong cong: %s\n", curve);
  printHex("Q (ma hoa)", pub, pubLen, 16);

  // Tinh lai Q = d*G va so voi khoa cong khai da luu
  BN_CTX* ctx = BN_CTX_new();
  EC_GROUP* grp = EC_GROUP_new_by_curve_name(OBJ_txt2nid(curve));
  NOTNULL(ctx); NOTNULL(grp);
  EC_POINT *Q = EC_POINT_new(grp), *Q2 = EC_POINT_new(grp);
  NOTNULL(Q); NOTNULL(Q2);
  OK1(EC_POINT_mul(grp, Q, d, nullptr, nullptr, ctx)); // Q = d*G
  OK1(EC_POINT_oct2point(grp, Q2, pub, pubLen, ctx));
  check("Q da luu == d*G", EC_POINT_cmp(grp, Q, Q2, ctx) == 0);
  check("1 <= d < n", !BN_is_zero(d) && BN_cmp(d, EC_GROUP_get0_order(grp)) < 0);

  // Dang nen cua Q
  unsigned char cmp[33];
  size_t lc = EC_POINT_point2oct(grp, Q, POINT_CONVERSION_COMPRESSED, cmp, sizeof cmp, ctx);
  printHex("Q (nen)", cmp, lc, 16);
  std::printf("\n");

  EC_POINT_free(Q); EC_POINT_free(Q2); EC_GROUP_free(grp);
  BN_CTX_free(ctx); BN_clear_free(d); EVP_PKEY_free(key);
}

// ---------------------------------------------------------------
// Phan 3: khoa tu gia tri tho
// ---------------------------------------------------------------
static void part3() {
  std::printf("== Phan 3: khoa tu gia tri tho ==\n");
  // (a) Ed25519 tu seed 32 byte (RFC 8032, test 1)
  Bytes seed = fromHex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
  Bytes expPub = fromHex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
  EVP_PKEY* ed = EVP_PKEY_new_raw_private_key_ex(nullptr, "ED25519", nullptr, seed.data(), seed.size());
  NOTNULL(ed);
  Bytes pub(32);
  size_t len = pub.size();
  OK1(EVP_PKEY_get_raw_public_key(ed, pub.data(), &len));
  printHex("Ed25519 pub", pub.data(), len, 32);
  check("khoa cong khai khop RFC 8032 test 1", pub == expPub);

  // (b) Khoa cong khai P-256 tu (ten duong cong, diem Q) - giong nhu ben nhan nhan duoc
  EVP_PKEY* full = genKey("EC", "P-256");
  unsigned char q[65];
  size_t qLen = 0;
  OK1(EVP_PKEY_get_octet_string_param(full, OSSL_PKEY_PARAM_PUB_KEY, q, sizeof q, &qLen));

  OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
  NOTNULL(bld);
  OK1(OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, "P-256", 0));
  OK1(OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, q, qLen));
  OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(bld);
  NOTNULL(params);

  EVP_PKEY_CTX* fctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
  NOTNULL(fctx);
  OKPOS(EVP_PKEY_fromdata_init(fctx));
  EVP_PKEY* pubOnly = nullptr;
  OKPOS(EVP_PKEY_fromdata(fctx, &pubOnly, EVP_PKEY_PUBLIC_KEY, params));
  check("khoa dung lai tu (curve, Q) == khoa goc", EVP_PKEY_eq(pubOnly, full) == 1);

  // Kiem tra khoa cong khai day du: Q tren duong cong, khac O, n*Q = O
  EVP_PKEY_CTX* vctx = EVP_PKEY_CTX_new_from_pkey(nullptr, pubOnly, nullptr);
  NOTNULL(vctx);
  check("EVP_PKEY_public_check chap nhan", EVP_PKEY_public_check(vctx) == 1);
  std::printf("\n");

  EVP_PKEY_CTX_free(vctx); EVP_PKEY_CTX_free(fctx);
  OSSL_PARAM_free(params); OSSL_PARAM_BLD_free(bld);
  EVP_PKEY_free(pubOnly); EVP_PKEY_free(full); EVP_PKEY_free(ed);
}

// ---------------------------------------------------------------
// Phan 4: file khoa PEM va DER
// ---------------------------------------------------------------
static void writeKeyFiles(EVP_PKEY* key, const std::string& prefix) {
  BIO* b = BIO_new_file((prefix + "_private.pem").c_str(), "wb");
  NOTNULL(b);
  OK1(PEM_write_bio_PrivateKey(b, key, nullptr, nullptr, 0, nullptr, nullptr));
  BIO_free(b);
  b = BIO_new_file((prefix + "_public.pem").c_str(), "wb");
  NOTNULL(b);
  OK1(PEM_write_bio_PUBKEY(b, key));
  BIO_free(b);
  b = BIO_new_file((prefix + "_private.der").c_str(), "wb");
  NOTNULL(b);
  OK1(i2d_PKCS8PrivateKey_bio(b, key, nullptr, nullptr, 0, nullptr, nullptr));
  BIO_free(b);
  b = BIO_new_file((prefix + "_public.der").c_str(), "wb");
  NOTNULL(b);
  OK1(i2d_PUBKEY_bio(b, key));
  BIO_free(b);
}

// Doc khoa tu file: isPrivate = khoa bi mat hay cong khai, isPem = PEM hay DER
static EVP_PKEY* loadKey(const std::string& path, bool isPrivate, bool isPem) {
  BIO* b = BIO_new_file(path.c_str(), "rb");
  NOTNULL(b);
  EVP_PKEY* k;
  if (isPrivate) k = isPem ? PEM_read_bio_PrivateKey(b, nullptr, nullptr, nullptr)
                           : d2i_PrivateKey_bio(b, nullptr);
  else           k = isPem ? PEM_read_bio_PUBKEY(b, nullptr, nullptr, nullptr)
                           : d2i_PUBKEY_bio(b, nullptr);
  BIO_free(b);
  NOTNULL(k);
  return k;
}

static void part4() {
  std::printf("== Phan 4: file PEM va DER ==\n");
  struct { const char* prefix; EVP_PKEY* key; } items[] = {
    {"ec", genKey("EC", "P-256")}, {"ed25519", genKey("ED25519", nullptr)}};
  for (auto& it : items) {
    std::string p = it.prefix;
    writeKeyFiles(it.key, p);
    EVP_PKEY* a = loadKey(p + "_private.pem", true, true);
    EVP_PKEY* b = loadKey(p + "_private.der", true, false);
    EVP_PKEY* c = loadKey(p + "_public.pem", false, true);
    EVP_PKEY* d = loadKey(p + "_public.der", false, false);
    bool ok = EVP_PKEY_eq(a, it.key) == 1 && EVP_PKEY_eq(b, it.key) == 1 &&
              EVP_PKEY_eq(c, it.key) == 1 && EVP_PKEY_eq(d, it.key) == 1;
    check((p + ": ca 4 file deu la cung 1 khoa").c_str(), ok);
    check((p + ": key ID cua PEM va DER giong nhau").c_str(), keyId(c) == keyId(d));
    Bytes id = keyId(c);
    printHex("key ID", id.data(), id.size(), 16);
    EVP_PKEY_free(a); EVP_PKEY_free(b); EVP_PKEY_free(c); EVP_PKEY_free(d);
    EVP_PKEY_free(it.key);
  }
  std::printf("\n");
}

int main() {
  part1();
  part2();
  part3();
  part4();
  std::printf("%s\n", g_failures ? "SOME CHECKS FAILED" : "ALL CHECKS PASSED");
  return g_failures ? 1 : 0;
}
