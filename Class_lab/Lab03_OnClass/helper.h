// Helper blocks
#include<iostream>
using Bytes = std::vector<unsigned char>;
static int g_failures = 0;


[[noreturn]] static void die(const char* what) {
    std::fprintf(stderr, "Failed: %s\n", what);
    ERR_print_errors_fp(stderr);
    std::exit(1);
}

//OK1: trả về 1 khi success
#define OK1(call)\
do{\
    if((call)!=1)\
        die(#call);\
}while(0)

//OKPOS: EVP_PKEY_* functions returning > 0 on success
#define OKPOS(call) \
do{\
    if((call)<=0)\
        die(#call);\
}while(0)

//NOTNULL: func return a pointer
#define NOTNULL(ptr)\
do{\
    if((ptr)==nullptr)\
        die(#ptr"isNULL");\
}while(0)

[[maybe_unused]] static void printBnBits(const char* label, const BIGNUM* x){
    //long values
    char* s = BN_bn2hex(x);
    NOTNULL(s);
    std::printf(" %-16s%dbits,0x%.24s...\n",label,BN_num_bits(x),s);
    OPENSSL_free(s);
}

[[maybe_unused]]static void check(const char*name,bool ok){
    std::printf(" [%s]%s\n",ok? "PASS":"FAIL",name);
    if(!ok)++g_failures;
}

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