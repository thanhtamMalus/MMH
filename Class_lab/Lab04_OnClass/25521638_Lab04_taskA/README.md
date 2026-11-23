# Lab 4 - Task A, B, C (OpenSSL >= 4.0)

## Build
    mkdir build && cd build
    cmake ..  # cmake .. -DOPENSSL_ROOT_DIR="D:\cryptolibrary\openssl403-msvc"
    cmake --build .

## Chay
    ./task_a_ec_arith # so hoc duong cong elliptic
    ./task_b_ec_keys # cap khoa EC, X25519, Ed25519 (ghi file ec_*.pem/der trong thu muc hien tai)
    ./task_c_ecdh # ECDH, X25519 ladder, ECIES

Moi chuong trinh ket thuc bang `ALL CHECKS PASSED` neu dung.
