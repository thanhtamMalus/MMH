### Week 01
### Week 02
### Week 03
### Week 04
### Week 05
### Week 06
-> Tạo key đóng gói (pub) để giải (private)

### Week 07
![sơ lược bài học week 7](img/week7.png)

-> Cải tiến là key không ai handle full mà là mỗi người làm 1 phần

Tuần này học về FF, tuần sau thì học EC

VD: $3^x= 5 mod (31)$
-> x = {0,1,2....30}
-> thuật toán đảo mod

Cơ chế PHE

Security lớn hay không phụ thuộc hoàn toàn p có lớn k. Giống cái mode 2048, 3072,... trong file [ffdhe](Class/Week07/week07_codes/ffdhe_openssl_pyqt6.py) là hiểu sơ cách khoa pub ngta + pri mình -> z chung. Cơ chế này không chống được việc biết ng cầm là ai

Khó khăn
- Không biết key thật key giả
- Có thể sửa được ndung file
- ver này tính toán nặng
- Không có tính giá trị thực dụng cao

Nếu như server có public key thì làm sao dùng đc 1 round để gửi cả mess key
-> gửi public key mình, file mã hóa

- p cần đủ lớn và g cần có bậc đủ lớn ($g^m$) để tránh bị burf force
- tốt nhất bậc/số ptu g nên gần bằng q

->> Pratical DH with **OpenSSL**

## Why Openssl?
Đọc cái này [thư viện cryp](https://en.wikipedia.org/wiki/Comparison_of_cryptography_libraries), check cái verify

![](img/verify.png)
- Dùng thư viện nhưng không dùng cái **có sẵn**
- Crypto++ vẫn ok nhưng không rcm

> week 7 và 6 bộ sung cho nhau về aes, nhược điểm là tính toán lớn -> week 8 sẽ giúp update cái thuật toán này