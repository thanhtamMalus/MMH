// Dùng EC_GROUP thật của OpenSSL, hàm tự viết: my_new_curve_GFp, my_get_curve
// Biên dịch: gcc my_curve_ec.c -o my_curve_ec -lcrypto
#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/err.h>
struct Curve { BIGNUM *p, *a, *b; };
struct Pt { BIGNUM *x, *y; bool inf; };


// Trả 1 nếu hợp lệ, 0 nếu không
static int curve_is_valid(const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx)
{
    // p phải lẻ và đủ lớn
    if (!BN_is_odd(p) || BN_num_bits(p) < 3)
        return 0;

    // Không suy biến: 4a^3 + 27b^2 != 0 (mod p)
    BIGNUM *am = BN_new(), *bm = BN_new();
    BIGNUM *t1 = BN_new(), *t2 = BN_new();
    BN_nnmod(am, a, p, ctx);             // a mod p
    BN_nnmod(bm, b, p, ctx);             // b mod p

    BN_mod_sqr(t1, am, p, ctx);          // a^2
    BN_mod_mul(t1, t1, am, p, ctx);      // a^3
    BN_mul_word(t1, 4);                  // 4a^3
    BN_mod_sqr(t2, bm, p, ctx);          // b^2
    BN_mul_word(t2, 27);                 // 27b^2
    BN_mod_add(t1, t1, t2, p, ctx);      // tổng mod p

    int ok = !BN_is_zero(t1);
    BN_free(am); BN_free(bm); BN_free(t1); BN_free(t2);
    return ok;
}

EC_GROUP *my_new_curve_GFp(const BIGNUM *p, const BIGNUM *a,const BIGNUM *b, BN_CTX *ctx)
{
    if (curve_is_valid(p, a, b, ctx)==0)
        return NULL;             
    return EC_GROUP_new_curve_GFp(p, a, b, ctx);  
}

int my_get_curve(const EC_GROUP *group, BIGNUM *p, BIGNUM *a,
                 BIGNUM *b, BN_CTX *ctx)
{
    if (!group) return 0;
    return EC_GROUP_get_curve(group, p, a, b, ctx);
}

int main()
{
    BN_CTX *ctx = BN_CTX_new();

    // Group P-256 do OpenSSL tạo sẵn
    EC_GROUP *ossl = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);

    // Đọc p, a, b bằng hàm tự viết
    BIGNUM *p = BN_new(), *a = BN_new(), *b = BN_new();
    if (my_get_curve(ossl, p, a, b, ctx))
        printf("b (P-256) = %s\n", BN_bn2hex(b));

    // Tạo lại đường cong thật bằng hàm tự viết
    EC_GROUP *good = my_new_curve_GFp(p, a, b, ctx);
    printf("P-256 : %s\n", good ? "tao duoc" : "bi tu choi");

    // Đường cong kẻ tấn công: b + 1
    BN_add_word(b, 1);
    EC_GROUP *evil = my_new_curve_GFp(p, a, b, ctx);
    printf("Evil (b+1): %s\n", evil ? "tao duoc (khong bi chan)" : "bi tu choi");

    EC_GROUP_free(ossl);
    EC_GROUP_free(good);
    EC_GROUP_free(evil);
    BN_free(p); BN_free(a); BN_free(b);
    BN_CTX_free(ctx);
    return 0;
}