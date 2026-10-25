#ifndef COMMON_H
#define COMMON_H

// ============================================================================
// common.h - Helper dùng chung cho Lab 03 (OpenSSL BIGNUM / RSA)
// Yêu cầu: C++17 (dùng "inline" cho biến toàn cục).
// Biên dịch: g++ -std=c++17 -Wall -Wextra file.cpp -o out -lcrypto
// ============================================================================

// ---------------------------------------------------------------------------
// 0. Các header cần thiết
//    (Thiếu <iostream> chính là nguyên nhân gây lỗi 'cout/endl/cerr is not a
//    member of std' trước đây.)
// ---------------------------------------------------------------------------
#include <cstddef>     // size_t
#include <cstdlib>     // std::exit
#include <iomanip>     // std::setw, std::setfill
#include <iostream>    // std::cout, std::cerr, std::endl
#include <vector>      // std::vector (dùng cho Bytes)

#include <openssl/bn.h>      // BIGNUM, BN_*
#include <openssl/crypto.h>  // OPENSSL_free
#include <openssl/err.h>     // ERR_print_errors_fp
#include <openssl/evp.h>     // EVP_PKEY, EVP_*
#include <openssl/pem.h>     // PEM_*

// ---------------------------------------------------------------------------
// 1. Kiểu dữ liệu tiện dụng
// ---------------------------------------------------------------------------
// Mảng byte (dùng cho hash, key ID, ciphertext, ...)
using Bytes = std::vector<unsigned char>;

// ---------------------------------------------------------------------------
// 2. Biến đếm số testcase FAIL
//    "inline" (C++17) cho phép khai báo trong header mà không bị lỗi
//    multiple definition khi nhiều file .cpp cùng include.
// ---------------------------------------------------------------------------
inline int g_failures = 0;

// ---------------------------------------------------------------------------
// 3. die(): in thông báo lỗi, in hàng đợi lỗi của OpenSSL rồi thoát chương trình
//    [[noreturn]] báo cho compiler biết hàm này không bao giờ quay về.
// ---------------------------------------------------------------------------
[[noreturn]] inline void die(const char* msg) {
    std::cerr << "ERROR: " << msg << std::endl;
    ERR_print_errors_fp(stderr);  // in chi tiết lỗi OpenSSL (nếu có)
    std::exit(1);
}

// ---------------------------------------------------------------------------
// 4. Các macro kiểm tra kết quả hàm OpenSSL
//    (Mỗi macro chỉ định nghĩa MỘT lần; trước đây OK1 và NOTNULL bị định
//    nghĩa lặp hai lần gây cảnh báo redefinition.)
// ---------------------------------------------------------------------------

// NOTNULL(p): con trỏ phải khác nullptr, ngược lại die().
// Dùng cho các hàm *_new(), BN_bn2dec(), ... trả về con trỏ.
#define NOTNULL(p)                                    
    do {                                              
        if ((p) == nullptr) {                         
            die("unexpected NULL: " #p);              
        }                                             
    } while (0)

// OK1(expr): hàm phải trả về đúng 1 (quy ước thành công của đa số hàm OpenSSL).
#define OK1(expr)                                     
    do {                                              
        if ((expr) != 1) {                            
            die("OpenSSL call failed: " #expr);       
        }                                             
    } while (0)

// OKPOS(expr): hàm phải trả về giá trị > 0.
// Dùng cho các hàm EVP_PKEY_* có thể trả về 1 hoặc số dương khác,
// còn 0 / số âm nghĩa là lỗi.
#define OKPOS(expr)                                   
    do {                                              
        if ((expr) <= 0) {                            
            die("OpenSSL call failed: " #expr);       
        }                                             
    } while (0)

// ---------------------------------------------------------------------------
// 5. check(msg, cond): kiểm tra một testcase
//    - cond đúng  -> in [PASS]
//    - cond sai   -> in [FAIL] và tăng g_failures
// ---------------------------------------------------------------------------
#define check(msg, cond)                                      \
    do {                                                      \
        if (!(cond)) {                                        \
            std::cout << "[FAIL] " << msg << std::endl;       \
            g_failures++;                                     \
        } else {                                              \
            std::cout << "[PASS] " << msg << std::endl;       \
        }                                                     \
    } while (0)

// ---------------------------------------------------------------------------
// 6. printBn(): in BIGNUM ở dạng thập phân: "label = 12345..."
//    Chấp nhận bn == nullptr (in "(null)").
// ---------------------------------------------------------------------------
inline void printBn(const char* label, const BIGNUM* bn) {
    if (!bn) {
        std::cout << label << " = (null)" << std::endl;
        return;
    }
    char* str = BN_bn2dec(bn);  // OpenSSL cấp phát chuỗi
    NOTNULL(str);
    std::cout << label << " = " << str << std::endl;
    OPENSSL_free(str);          // bắt buộc giải phóng, tránh rò rỉ bộ nhớ
}

// ---------------------------------------------------------------------------
// 7. printBnBits(): in BIGNUM kèm số bit: "label [N bits] = 12345..."
// ---------------------------------------------------------------------------
inline void printBnBits(const char* label, const BIGNUM* bn) {
    if (!bn) {
        std::cout << label << " = (null)" << std::endl;
        return;
    }
    char* str = BN_bn2dec(bn);
    NOTNULL(str);
    std::cout << label << " [" << BN_num_bits(bn) << " bits] = " << str
              << std::endl;
    OPENSSL_free(str);
}

// ---------------------------------------------------------------------------
// 8. printHex(): in mảng byte ở dạng hex
//    - label    : nhãn hiển thị
//    - data,len : dữ liệu và độ dài (byte)
//    - maxBytes : nếu > 0 và len lớn hơn thì chỉ in maxBytes byte đầu rồi "..."
//                 (mặc định 0 = in toàn bộ)
// ---------------------------------------------------------------------------
inline void printHex(const char* label, const unsigned char* data, size_t len,
                     size_t maxBytes = 0) {
    size_t n = (maxBytes != 0 && len > maxBytes) ? maxBytes : len;

    std::cout << label << " = ";
    std::ios_base::fmtflags oldFlags = std::cout.flags();  // lưu định dạng cũ
    std::cout << std::hex << std::setfill('0');
    for (size_t i = 0; i < n; i++) {
        std::cout << std::setw(2) << static_cast<unsigned>(data[i]);
    }
    std::cout.flags(oldFlags);                              // khôi phục
    std::cout << std::setfill(' ');

    if (n < len) std::cout << "...";
    std::cout << " (" << len << " bytes)" << std::endl;
}

#endif // COMMON_H