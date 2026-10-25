# Lab03
## Task 01

openssl bignum cli 

distinguished encoding rules(DER)

về nhà nhìn day byte và tách đc từng thành phần 1(DER-TVL)

openssl genpkey -algorithm RSA  -pkeyopt rsa_keygen_bits:3072 -out rsa_private.pem


1.2.840.113549.1.1.1 -> OID RSA, hịnh danh tên

05 00 đuôi waiter

TVL: kiểu dữ liệu-> chiều dài-> dữ lieu that

task2(b): openssl genpkey -algorithm RSA 
    -pkeyopt rsa_keygen_bits:3072 
    -out rsa_private.pem
 
openssl pkey -in rsa_private.pem 
    -outform DER 
    -out rsa_private.der
 
hexdump -v -e '16/1 "%02X " "\n"' rsa_private.der

tách các byte->hiểu rõ cách đọc
========
mọi inp đều chuyển sang binary rồi mới big number và ngược lại cho output

nhìn hình week 6 để xem lại rsa kết hợp lab 3
1 task a: đổi ra bignum, quen vs api
2 task b: tạo key rsa
3 task c: chuyển đổi file ra số r bignum
4 task d: mở rộng cái bechding, phân phối file
nguy hiểm: dùng raw 
c1=m1^e mod n
c2=m2^e mod n
-> có thể giải đc
c1c2=(m1m2)^e mod n
-> dùng m2 để motified output ->bị thay đổi

-> bechding optimal asymatric -> r mã hóa aes(?)

task e: nói về hàm hask băm key
chỉ cần 1 sheet nhỏ -> key aes -> phân phối key bên t3 làm việc