// Lab 3, task a in class

/*
Build with task.json
 Run: ./task_agcc -> run the handout’s test vectors
    ./task_agcc <a> <b> <m> -> compute a^b mod m and a^-1 mod m
*/

// kết quả sẽ so với BN_mod_exp và BN_mod_inverse
#include <cstdio>
#include <iostream>
#include <openssl/crypto.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <iomanip>
#include "helper.h"

//decimal string into a BIGNUM
static BIGNUM* parseDec(const char* s) {
    size_t len = std::strlen(s);
    if (len == 0 || len > 10000) //ktra độ dài chữ số
        die("number must have 1..10000 digits");
    for (size_t i = 0; i < len; ++i)
    {
        if (s[i] < '0' || s[i] > '9') 
            die("not a nonnegative decimal integer"); //ktra ký tự có phải là số không âm
    }
    BIGNUM* x = nullptr; // BN_dec2bn allocates *x for us
    if (BN_dec2bn(&x, s) != static_cast<int>(len)) //check xem số lượng chữ số có đúng với độ dài của chuỗi không 
        die("BN_dec2bn");
    return x; // caller frees with BN_free
}

//2.thuật toán square-and-multiply để tính a^b mod m
/*
    r=1
    for i = k-1 downto 0 do
        r = r^2 mod m
        if bit i of b = 1 then r = r*a mod m
*/

static BIGNUM* myModExp(const BIGNUM* a, const BIGNUM* b, const BIGNUM* m, BN_CTX* ctx) {
    BIGNUM* r = BN_new();
    BIGNUM* base = BN_new();
    NOTNULL(r); NOTNULL(base);
    OK1(BN_one(r));
    OK1(BN_nnmod(base, a, m, ctx)); // reduce a into [0, m)
    for (int i = BN_num_bits(b) - 1; i >= 0; --i) {
        OK1(BN_mod_sqr(r, r, m, ctx)); // r = r^2 mod m
        if (BN_is_bit_set(b, i))
            OK1(BN_mod_mul(r, r, base, m, ctx)); // r = r*a mod m
    }
    if (BN_is_one(m)) 
        BN_zero(r); // everything is 0 mod 1
    BN_free(base);
    return r;
}

//3.thuật toán Extended Euclidean để tìm nghịch đảo a^-1(mod m) và gcd(a, m)

static BIGNUM* myModInverse(const BIGNUM* a, const BIGNUM* m, BIGNUM* gcdOut, BN_CTX* ctx) {
    BIGNUM *r0 = BN_dup(m), *r1 = BN_new(), *t0 = BN_new(), *t1 = BN_new();
    BIGNUM *q = BN_new(), *tmp = BN_new(), *prod = BN_new();
    NOTNULL(r0); NOTNULL(r1); NOTNULL(t0); NOTNULL(t1);
    NOTNULL(q); NOTNULL(tmp); NOTNULL(prod);
    OK1(BN_nnmod(r1, a, m, ctx));
    BN_zero(t0);
    OK1(BN_one(t1));


    
    while (!BN_is_zero(r1)) {
        OK1(BN_div(q, tmp, r0, r1, ctx)); // q = r0 / r1, tmp = r0 mod r1
        BN_swap(r0, r1); // (r0, r1) = (r1, r0 mod r1)
        BN_swap(r1, tmp);

        OK1(BN_mul(prod, q, t1, ctx)); // (t0, t1) = (t1, t0 - q*t1)
        OK1(BN_sub(tmp, t0, prod));
        BN_swap(t0, t1);
        BN_swap(t1, tmp);

    }
    NOTNULL(BN_copy(gcdOut, r0));
    BIGNUM* inv = nullptr;
    if (BN_is_one(r0)) {
        inv = BN_new();
        NOTNULL(inv);
        OK1(BN_nnmod(inv, t0, m, ctx)); // t0 may be negative
    }
    BN_free(r0); BN_free(r1); BN_free(t0); BN_free(t1);
    BN_free(q); BN_free(tmp); BN_free(prod);
    return inv;
}

//4.so kết quả chạy thuật toán tay với openssl
// run a test case, compare with BN_mod_exp and BN_mod_inverse
static void runCase(const char* sa, const char* sb, const char* sm, const char* expectExp, const char* expectInv) {
    BN_CTX* ctx = BN_CTX_new();
    NOTNULL(ctx);
    BIGNUM *a = parseDec(sa), *b = parseDec(sb), *m = parseDec(sm);
    if (BN_is_zero(m)) 
        die("modulus must be > 0");
    std::printf("a = %s, b = %s, m = %s\n", sa, sb, sm);

    BIGNUM* r1 = BN_new();
    NOTNULL(r1);
    OK1(BN_mod_exp(r1, a, b, m, ctx)); // library
    BIGNUM* r2 = myModExp(a, b, m, ctx); // ours
    printBn("a^b mod m", r1);

    check("square-and-multiply == BN_mod_exp", BN_cmp(r1, r2) == 0);
    if (expectExp) {
        BIGNUM* want = parseDec(expectExp);
        check("matches expected value", BN_cmp(r1, want) == 0);
        BN_free(want);
    }
    if (!BN_is_one(m)) {
            BIGNUM* g = BN_new();
            NOTNULL(g);
            BIGNUM* mine = myModInverse(a, m, g, ctx);
            BIGNUM* lib = BN_mod_inverse(nullptr, a, m, ctx); // NULL if none
            if (!lib) ERR_clear_error(); // "no inverse" is not a bug here
            if (mine) {
            printBn("a^-1 mod m", mine);
            check("extended Euclid == BN_mod_inverse", lib && BN_cmp(mine, lib) == 0);
            if (expectInv) {
                BIGNUM* want = parseDec(expectInv);
                check("matches expected inverse", BN_cmp(mine, want) == 0);
                BN_free(want);
            }
        } 
        else {
            printBn("no inverse, gcd", g);
            check("BN_mod_inverse also reports no inverse", lib == nullptr);
        }
        BN_free(g); BN_free(mine); BN_free(lib);
    }
    BN_free(a); BN_free(b); BN_free(m); BN_free(r1); BN_free(r2);
    BN_CTX_free(ctx);
    std::printf("\n");
}

//demo other operations: mod add, mod sub, mod mul, gcd
static void demoOtherOps() {
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM *a = parseDec("3"), *b = parseDec("5"), *m = parseDec("7"), *r = BN_new();
    NOTNULL(ctx); NOTNULL(r);
    OK1(BN_mod_add(r, a, b, m, ctx)); printBn("3+5 mod 7", r);
    OK1(BN_mod_sub(r, a, b, m, ctx)); printBn("3-5 mod 7", r); // 5, not -2
    OK1(BN_mod_mul(r, a, b, m, ctx)); printBn("3*5 mod 7", r);
    BIGNUM *x = parseDec("252"), *y = parseDec("105");
    OK1(BN_gcd(r, x, y, ctx)); printBn("gcd(252,105)", r);
    check("gcd(252,105) == 21", BN_is_word(r, 21));
    BN_free(a); BN_free(b); BN_free(m); BN_free(r); BN_free(x); BN_free(y);
    BN_CTX_free(ctx);
    std::printf("\n");
}




//5. main function: run the handout’s test vectors, or your own values
int main(int argc, char** argv) {
    if (argc == 4) { // your own values
        runCase(argv[1], argv[2], argv[3], nullptr, nullptr);
        return g_failures ? 1 : 0;
    }
    std::printf("== Task A: handout test vectors ==\n\n");
    demoOtherOps();
    runCase("7", "13", "33", "13", "19"); // A-T1, A-T3
    runCase("6", "2", "33", "3", nullptr); // A-T4: no inverse
    runCase("123456789012345678901234567890", "65537",
    "170141183460469231731687303715884105727", // 2^127 - 1
    "43089841487593468092862748681566865937", nullptr); // A-T7
    runCase("65537", "1", "170141183460469231731687303715884105727",
    "65537", "5192217631581220737344928932233215"); // A-T8
    std::printf("%s\n", g_failures ? "SOME CHECKS FAILED" : "ALL CHECKS PASSED");
    return g_failures ? 1 : 0;
}
// ===================== 
#include <openssl/crypto.h>

// Bài 1: vết (trace) thuật toán Euclid mở rộng
static void exA1_trace(long a, long m) {
    long r0 = m, r1 = a % m, t0 = 0, t1 = 1;
    std::printf("  %-4s %-4s %-4s %-5s %-5s\n", "q", "r0", "r1", "t0", "t1");
    std::printf("  %-4s %-4ld %-4ld %-5ld %-5ld\n", "-", r0, r1, t0, t1);
    while (r1 != 0) {
        long q = r0 / r1;
        long r2 = r0 - q * r1, t2 = t0 - q * t1;
        r0 = r1; r1 = r2; t0 = t1; t1 = t2;
        std::printf("  %-4ld %-4ld %-4ld %-5ld %-5ld\n", q, r0, r1, t0, t1);
    }
    long inv = ((t0 % m) + m) % m;
    std::printf("  gcd = r0 = %ld, inverse = t0 mod m = %ld\n", r0, inv);
    check("trace gives inverse 19", r0 == 1 && inv == 19);
}

// Bài 2: đếm số phép bình phương / nhân của square-and-multiply
static void exA2_count(const char* label, const BIGNUM* b) {
    int squarings = BN_num_bits(b), mults = 0;
    for (int i = squarings - 1; i >= 0; --i)
        if (BN_is_bit_set(b, i)) ++mults;
    std::printf("  %-16s squarings = %d, multiplications = %d, total = %d\n",
                label, squarings, mults, squarings + mults);
}

// Bài 4: mô phỏng timing side channel
static void exA4_timing_leak() {
    const unsigned long d = 0b101101; // "khóa bí mật" 45
    int top = 63;
    while (!((d >> top) & 1)) --top;
    std::vector<int> cost;// thời gian mỗi vòng lặp: 1 = chỉ S, 2 = S + M
    std::string secret;
    for (int i = top; i >= 0; --i) {
        int bit = (d >> i) & 1;
        secret += bit ? '1' : '0';
        cost.push_back(bit ? 2 : 1);
    }
    std::string recovered;
    std::printf("  secret exponent bits : %s\n  time per iteration   :", secret.c_str());
    for (int c : cost) { std::printf(" %d", c); recovered += (c == 2) ? '1' : '0'; }
    std::printf("\n  attacker recovers    : %s\n", recovered.c_str());
    check("timing trace reveals every bit of d", recovered == secret);
}

static void runExercisesA() {
    std::printf("\nTask a\n");
    std::printf("1. Extended Euclid trace, a=7, m=33\n");
    exA1_trace(7, 33);

    std::printf("2. Operation counts of square-and-multiply\n");
    BIGNUM* b1 = parseDec("65537");
    BIGNUM* b2 = BN_new(); NOTNULL(b2);
    OK1(BN_rand(b2, 2048, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY));
    exA2_count("b = 65537", b1);
    exA2_count("b = random 2048", b2);
    BN_free(b1); BN_free(b2);

    std::printf("3. Edge cases (the third one, ./task_a 1 1 0, dies by design: m = 0)\n");
    runCase("12", "0", "7", nullptr, nullptr);
    runCase("0", "5", "1", nullptr, nullptr);

    std::printf("4. Timing side channel (simulation)\n");
    exA4_timing_leak();
}
[[maybe_unused]] static const int exA_registered = [] {
    OPENSSL_init_crypto(0, nullptr);   // đăng ký cleanup của OpenSSL TRƯỚC handler của ta
    std::atexit(runExercisesA);
    return 0;
}();