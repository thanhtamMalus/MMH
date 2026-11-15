Cấu trúc nộp bài (cho tất cả các bài thực hành): MSV.All6labs.rar
Tệp nén duy nhất phải bao gồm:
• Mã nguồn cho tất cả các bài thực hành
• Hệ thống xây dựng (build system) CMake
• Tệp README.md (ở thư mục gốc)
• Báo cáo (một tệp PDF/DOCX duy nhất bao gồm tất cả các bài thực hành)
• Các tệp thực thi (binaries) cho Windows và Linux
• Các bài kiểm thử đơn vị (unit tests)
• Các tập lệnh xây dựng (build scripts)
• Mọi tệp tài nguyên cần thiết khác
## Thông tin
Họ và Tên: Nguyễn Hoàng Thanh Tâm
MSSV: 25521638
Lớp: NT219.R11.ANTT.2026
Giáo viên hướng dẫn: Nguyễn Ngọc Tự
## Môi Trường
### Cấu hình phần cứng

| Thông số | Windows | Linux |
|---|---|---|
| CPU | Intel Core i7-9750H, 6C/12T | AMD Ryzen 7 5800X, 8C/16T |
| RAM | 16 GB DDR4 | 32 GB DDR4 |
| Storage | SSD 512 GB | NVMe 1 TB |
| AES-NI | Có | Có |


### Môi trường phần mềm và hệ điều hành

| Thành phần | Windows | Linux |
|---|---|---|
| OS | Windows 10 Pro 21H2 | Ubuntu 22.04.3 LTS, kernel 5.15 |
| Compiler | MinGW GCC 11.2.0 | g++ 11.4.0 |
| Crypto++ | libcryptopp.a 8.9.0 | libcryptopp.so 8.9.0 |
| CMake | 3.21.3 | 3.21.3 |

## Lời cam kết học thuật
Các số liệu thực nghiệm được giữ theo nguồn; những điểm chưa có bằng chứng hoặc có mâu thuẫn được đánh dấu rõ ràng. Người thực hiện cam kết trình bày trung thực quá trình thiết kế, hiện thực, kiểm thử và benchmark; không tự tạo log, ảnh chụp, số liệu hoặc kết quả build; phân biệt kết quả quan sát với nhận định và giả thuyết; sử dụng công cụ trong phạm vi học tập, nghiên cứu được phép.

**Ngày hoàn thành báo cáo:** 
## Tóm tắt chính


# Tài liệu tham khảo

1. NIST, **FIPS PUB 197 – Advanced Encryption Standard (AES)**, 2001; cập nhật 2023.
2. NIST, **SP 800-38A – Recommendation for Block Cipher Modes of Operation: Methods and Techniques**, 2001.
3. NIST, **SP 800-38C – Recommendation for Block Cipher Modes of Operation: The CCM Mode for Authentication and Confidentiality**, 2004.
4. NIST, **SP 800-38D – Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC**, 2007.
5. NIST, **SP 800-38E – Recommendation for Block Cipher Modes of Operation: The XTS-AES Mode for Confidentiality on Storage Devices**, 2010.
6. Crypto++ Library, **Crypto++ Documentation and Source Code**, phiên bản 8.9.0.
7. IEEE, **IEEE Std 1619 – Standard for Cryptographic Protection of Data on Block-Oriented Storage Devices**.
