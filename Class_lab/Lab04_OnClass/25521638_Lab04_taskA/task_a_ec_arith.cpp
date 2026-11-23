// Task A - so hoc duong cong elliptic tren truong Fp, tu viet bang BIGNUM
// Duong cong: y^2 = x^3 + a*x + b (mod p)
// Phan 1: luat cong diem tren P-256 (so sanh voi OpenSSL)
// Phan 2: double-and-add tren P-256, P-384, secp256k1
// Phan 3: ma hoa diem, kiem tra diem hop le, diem tren duong cong gia (invalid-curve)
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <cstring>
#include "helpers.h"

// Tham so duong cong: p, a, b
struct Curve { BIGNUM *p, *a, *b; };
// Diem (x, y); inf = true nghia la diem vo cuc O
struct Pt { BIGNUM *x, *y; bool inf; };

static Pt newPt() {
  Pt P{BN_new(), BN_new(), true}; // moi tao la diem vo cuc
  NOTNULL(P.x); NOTNULL(P.y);
  return P;
}
static void freePt(Pt& P) { BN_free(P.x); BN_free(P.y); }
static void copyPt(Pt& R, const Pt& P) {
  NOTNULL(BN_copy(R.x, P.x)); NOTNULL(BN_copy(R.y, P.y));
  R.inf = P.inf;
}
static bool samePt(const Pt& A, const Pt& B) {
  if (A.inf || B.inf) return A.inf == B.inf;
  return BN_cmp(A.x, B.x) == 0 && BN_cmp(A.y, B.y) == 0;
}

// Kiem tra y^2 == x^3 + a*x + b (mod p)
static bool onCurve(const Curve& E, const Pt& P, BN_CTX* ctx) {
  if (P.inf) return true;
  BIGNUM *l = BN_new(), *r = BN_new(), *t = BN_new();
  NOTNULL(l); NOTNULL(r); NOTNULL(t);
  OK1(BN_mod_sqr(l, P.y, E.p, ctx)); // l = y^2
  OK1(BN_mod_sqr(r, P.x, E.p, ctx));
  OK1(BN_mod_mul(r, r, P.x, E.p, ctx)); // r = x^3
  OK1(BN_mod_mul(t, E.a, P.x, E.p, ctx));
  OK1(BN_mod_add(r, r, t, E.p, ctx)); // r = x^3 + a*x
  OK1(BN_mod_add(r, r, E.b, E.p, ctx)); // r = x^3 + a*x + b
  bool ok = BN_cmp(l, r) == 0;
  BN_free(l); BN_free(r); BN_free(t);
  return ok;
}

// Cong 2 diem: R = P + Q (quy tac day cung va tiep tuyen)
static void ecAdd(const Curve& E, Pt& R, const Pt& P, const Pt& Q, BN_CTX* ctx) {
  if (P.inf) { copyPt(R, Q); return; } // O + Q = Q
  if (Q.inf) { copyPt(R, P); return; } // P + O = P
  BIGNUM *num = BN_new(), *den = BN_new(), *lam = BN_new(), *x3 = BN_new(), *y3 = BN_new();
  NOTNULL(num); NOTNULL(den); NOTNULL(lam); NOTNULL(x3); NOTNULL(y3);
  bool toInf = false;

  if (BN_cmp(P.x, Q.x) == 0) {
    OK1(BN_mod_add(num, P.y, Q.y, E.p, ctx)); // y1 + y2
    if (BN_is_zero(num)) {
      toInf = true; // Q = -P thi tong la O
    } else {
      // Truong hop P == Q: tiep tuyen, lambda = (3*x1^2 + a) / (2*y1)
      OK1(BN_mod_sqr(num, P.x, E.p, ctx));
      OK1(BN_mul_word(num, 3));
      OK1(BN_mod_add(num, num, E.a, E.p, ctx));
      OK1(BN_mod_add(den, P.y, P.y, E.p, ctx));
    }
  } else {
    // Truong hop P != Q: day cung, lambda = (y2 - y1) / (x2 - x1)
    OK1(BN_mod_sub(num, Q.y, P.y, E.p, ctx));
    OK1(BN_mod_sub(den, Q.x, P.x, E.p, ctx));
  }

  if (toInf) {
    R.inf = true;
  } else {
    NOTNULL(BN_mod_inverse(den, den, E.p, ctx)); // chia = nhan nghich dao
    OK1(BN_mod_mul(lam, num, den, E.p, ctx));
    OK1(BN_mod_sqr(x3, lam, E.p, ctx));
    OK1(BN_mod_sub(x3, x3, P.x, E.p, ctx));
    OK1(BN_mod_sub(x3, x3, Q.x, E.p, ctx)); // x3 = lam^2 - x1 - x2
    OK1(BN_mod_sub(y3, P.x, x3, E.p, ctx));
    OK1(BN_mod_mul(y3, lam, y3, E.p, ctx));
    OK1(BN_mod_sub(y3, y3, P.y, E.p, ctx)); // y3 = lam*(x1 - x3) - y1
    NOTNULL(BN_copy(R.x, x3)); NOTNULL(BN_copy(R.y, y3));
    R.inf = false;
  }
  BN_free(num); BN_free(den); BN_free(lam); BN_free(x3); BN_free(y3);
}

// Nhan vo huong R = k*P bang double-and-add (duyet bit tu cao xuong thap)
// Chi de hoc, KHONG chay hang thoi gian (constant-time)
static void ecMul(const Curve& E, Pt& R, const BIGNUM* k, const Pt& P, BN_CTX* ctx) {
  Pt acc = newPt(); // acc = O
  for (int i = BN_num_bits(k) - 1; i >= 0; --i) {
    ecAdd(E, acc, acc, acc, ctx); // double
    if (BN_is_bit_set(k, i)) ecAdd(E, acc, acc, P, ctx); // add
  }
  copyPt(R, acc);
  freePt(acc);
}

// Doi giua Pt cua minh va EC_POINT cua OpenSSL
static void fromOpenSSL(const EC_GROUP* g, const EC_POINT* P, Pt& out, BN_CTX* ctx) {
  out.inf = EC_POINT_is_at_infinity(g, P) == 1;
  if (!out.inf) OK1(EC_POINT_get_affine_coordinates(g, P, out.x, out.y, ctx));
}
static bool sameAs(const EC_GROUP* g, const Pt& P, const EC_POINT* Q, BN_CTX* ctx) {
  Pt T = newPt();
  fromOpenSSL(g, Q, T, ctx);
  bool ok = samePt(P, T);
  freePt(T);
  return ok;
}

// Duong cong chuan do OpenSSL cung cap, cung voi G va bac n
struct NamedCurve { Curve E; EC_GROUP* g; const BIGNUM* n; Pt G; };
static NamedCurve loadCurve(int nid, BN_CTX* ctx) {
  NamedCurve C{{BN_new(), BN_new(), BN_new()}, EC_GROUP_new_by_curve_name(nid), nullptr, newPt()};
  NOTNULL(C.E.p); NOTNULL(C.E.a); NOTNULL(C.E.b); NOTNULL(C.g);
  OK1(EC_GROUP_get_curve(C.g, C.E.p, C.E.a, C.E.b, ctx)); // lay p, a, b
  C.n = EC_GROUP_get0_order(C.g); // khong can free
  fromOpenSSL(C.g, EC_GROUP_get0_generator(C.g), C.G, ctx);
  return C;
}
static void freeCurve(NamedCurve& C) {
  BN_free(C.E.p); BN_free(C.E.a); BN_free(C.E.b);
  freePt(C.G);
  EC_GROUP_free(C.g);
}

// ---------------------------------------------------------------
// Phan 1: luat cong diem tren P-256
// ---------------------------------------------------------------
static void part1(BN_CTX* ctx) {
  std::printf("== Phan 1: luat cong diem tren P-256 ==\n");
  NamedCurve C = loadCurve(NID_X9_62_prime256v1, ctx);
  printBnBits("p", C.E.p);
  printBnBits("n (bac)", C.n);
  check("G nam tren duong cong", onCurve(C.E, C.G, ctx));

  const EC_POINT* Gs = EC_GROUP_get0_generator(C.g);
  EC_POINT* R = EC_POINT_new(C.g);
  NOTNULL(R);
  Pt P2 = newPt(), P3 = newPt(), T = newPt(), O = newPt(), negG = newPt();

  // Nhan doi: G + G (tiep tuyen)
  ecAdd(C.E, P2, C.G, C.G, ctx);
  OK1(EC_POINT_dbl(C.g, R, Gs, ctx));
  check("G + G == EC_POINT_dbl(G)", sameAs(C.g, P2, R, ctx));

  // Cong 2 diem khac nhau: 2G + G (day cung)
  ecAdd(C.E, P3, P2, C.G, ctx);
  BIGNUM* k = BN_new();
  NOTNULL(k);
  OK1(BN_set_word(k, 3));
  OK1(EC_POINT_mul(C.g, R, k, nullptr, nullptr, ctx)); // R = 3G
  check("2G + G == 3G (OpenSSL)", sameAs(C.g, P3, R, ctx));

  // Phan tu don vi: G + O = G
  ecAdd(C.E, T, C.G, O, ctx);
  check("G + O == G", samePt(T, C.G));

  // Phan tu nghich dao: -G = (x, p - y)
  NOTNULL(BN_copy(negG.x, C.G.x));
  OK1(BN_sub(negG.y, C.E.p, C.G.y));
  negG.inf = false;
  ecAdd(C.E, T, C.G, negG, ctx);
  check("G + (-G) == O", T.inf);

  // (n-1)*G phai bang -G
  NOTNULL(BN_copy(k, C.n));
  OK1(BN_sub_word(k, 1));
  ecMul(C.E, T, k, C.G, ctx);
  check("(n-1)*G == -G", samePt(T, negG));

  // i*G bang cach cong lien tiep so voi EC_POINT_mul
  bool same = true;
  Pt acc = newPt();
  for (int i = 1; i <= 50; ++i) {
    ecAdd(C.E, acc, acc, C.G, ctx);
    OK1(BN_set_word(k, i));
    OK1(EC_POINT_mul(C.g, R, k, nullptr, nullptr, ctx));
    same &= sameAs(C.g, acc, R, ctx);
  }
  check("i*G cong lien tiep == EC_POINT_mul, i = 1..50", same);
  std::printf("\n");

  freePt(P2); freePt(P3); freePt(T); freePt(O); freePt(negG); freePt(acc);
  EC_POINT_free(R); BN_free(k); freeCurve(C);
}

// ---------------------------------------------------------------
// Phan 2: double-and-add tren 3 duong cong
// ---------------------------------------------------------------
static void part2(BN_CTX* ctx) {
  std::printf("== Phan 2: double-and-add so voi EC_POINT_mul ==\n");
  struct { int nid; const char* name; } curves[] = {
    {NID_X9_62_prime256v1, "P-256"}, {NID_secp384r1, "P-384"}, {NID_secp256k1, "secp256k1"}};
  for (auto& c : curves) {
    NamedCurve C = loadCurve(c.nid, ctx);
    EC_POINT* R = EC_POINT_new(C.g);
    BIGNUM* k = BN_new();
    NOTNULL(R); NOTNULL(k);
    Pt M = newPt();
    std::printf(" %s\n", c.name);

    bool same = true;
    for (int i = 0; i < 10; ++i) {
      OK1(BN_rand_range(k, C.n)); // k ngau nhien trong [0, n)
      ecMul(C.E, M, k, C.G, ctx);
      OK1(EC_POINT_mul(C.g, R, k, nullptr, nullptr, ctx));
      same &= sameAs(C.g, M, R, ctx);
    }
    check("10 so k ngau nhien: tu viet == OpenSSL", same);

    ecMul(C.E, M, C.n, C.G, ctx);
    check("n*G == O", M.inf);

    NOTNULL(BN_copy(k, C.n));
    OK1(BN_add_word(k, 1));
    ecMul(C.E, M, k, C.G, ctx);
    check("(n+1)*G == G", samePt(M, C.G));

    freePt(M); BN_free(k); EC_POINT_free(R); freeCurve(C);
  }
  std::printf("\n");
}

// ---------------------------------------------------------------
// Phan 3: ma hoa diem, kiem tra diem, tan cong invalid-curve
// ---------------------------------------------------------------
static void part3(BN_CTX* ctx) {
  std::printf("== Phan 3: ma hoa va kiem tra diem (P-256) ==\n");
  NamedCurve C = loadCurve(NID_X9_62_prime256v1, ctx);
  BIGNUM* k = BN_new();
  EC_POINT *Ps = EC_POINT_new(C.g), *Q = EC_POINT_new(C.g);
  NOTNULL(k); NOTNULL(Ps); NOTNULL(Q);
  OK1(BN_rand_range(k, C.n));
  OK1(EC_POINT_mul(C.g, Ps, k, nullptr, nullptr, ctx)); // Ps = k*G

  // Ma hoa SEC 1: khong nen (04||x||y) va nen (02/03||x)
  unsigned char unc[65], cmp[33];
  size_t lu = EC_POINT_point2oct(C.g, Ps, POINT_CONVERSION_UNCOMPRESSED, unc, sizeof unc, ctx);
  size_t lc = EC_POINT_point2oct(C.g, Ps, POINT_CONVERSION_COMPRESSED, cmp, sizeof cmp, ctx);
  if (lu != 65 || lc != 33) die("EC_POINT_point2oct");
  printHex("khong nen", unc, lu, 16);
  printHex("nen", cmp, lc, 16);
  check("prefix: 04 (khong nen), 02/03 (nen)", unc[0] == 0x04 && (cmp[0] == 0x02 || cmp[0] == 0x03));

  OK1(EC_POINT_oct2point(C.g, Q, cmp, lc, ctx)); // giai nen: tinh y bang can bac 2 mod p
  check("diem nen giai ma ra dung diem cu", EC_POINT_cmp(C.g, Q, Ps, ctx) == 0);

  // Doi 1 bit cua y -> diem khong con tren duong cong -> OpenSSL tu choi
  unsigned char bad[65];
  std::memcpy(bad, unc, 65);
  bad[64] ^= 0x01;
  check("diem sai bi EC_POINT_oct2point tu choi", EC_POINT_oct2point(C.g, Q, bad, 65, ctx) != 1);
  ERR_clear_error();

  // Tan cong invalid-curve: tim diem A tren duong cong y^2 = x^3 + a*x + (b+1)
  // Cong thuc cong diem KHONG dung b, nen code tu viet van tinh tren duong cong cua ke tan cong
  Curve E2{C.E.p, C.E.a, BN_new()};
  NOTNULL(E2.b);
  NOTNULL(BN_copy(E2.b, C.E.b));
  OK1(BN_add_word(E2.b, 1)); // b' = b + 1

  Pt A = newPt();
  BIGNUM *rhs = BN_new(), *t = BN_new();
  NOTNULL(rhs); NOTNULL(t);
  for (unsigned long x = 1;; ++x) { // thu x = 1, 2, 3... den khi ve phai la so chinh phuong
    OK1(BN_set_word(A.x, x));
    OK1(BN_mod_sqr(rhs, A.x, E2.p, ctx));
    OK1(BN_mod_mul(rhs, rhs, A.x, E2.p, ctx));
    OK1(BN_mod_mul(t, E2.a, A.x, E2.p, ctx));
    OK1(BN_mod_add(rhs, rhs, t, E2.p, ctx));
    OK1(BN_mod_add(rhs, rhs, E2.b, E2.p, ctx));
    if (BN_mod_sqrt(A.y, rhs, E2.p, ctx)) break;
    ERR_clear_error();
  }
  A.inf = false;
  check("diem A KHONG nam tren P-256", !onCurve(C.E, A, ctx));
  check("diem A nam tren duong cong b' = b + 1", onCurve(E2, A, ctx));

  // Code P-256 tu viet van nhan duoc ma khong bao loi -> nguy hiem
  Pt M = newPt();
  ecMul(C.E, M, k, A, ctx);
  check("ecMul tu viet van tinh k*A tren duong cong gia", onCurve(E2, M, ctx) && !onCurve(C.E, M, ctx));

  // OpenSSL tu choi vi oct2point co kiem tra diem tren duong cong
  unsigned char enc[65];
  enc[0] = 0x04;
  if (BN_bn2binpad(A.x, enc + 1, 32) != 32 || BN_bn2binpad(A.y, enc + 33, 32) != 32) die("encode");
  check("EC_POINT_oct2point tren P-256 tu choi diem A", EC_POINT_oct2point(C.g, Q, enc, 65, ctx) != 1);
  ERR_clear_error();
  std::printf(" -> neu khong kiem tra diem, k*A ro ri k theo cac uoc nho cua bac duong cong gia\n\n");

  freePt(A); freePt(M); BN_free(E2.b); BN_free(rhs); BN_free(t); BN_clear_free(k);
  EC_POINT_free(Ps); EC_POINT_free(Q); freeCurve(C);
}

int main() {
  BN_CTX* ctx = BN_CTX_new();
  NOTNULL(ctx);
  part1(ctx);
  part2(ctx);
  part3(ctx);
  BN_CTX_free(ctx);
  std::printf("%s\n", g_failures ? "SOME CHECKS FAILED" : "ALL CHECKS PASSED");
  return g_failures ? 1 : 0;
}
