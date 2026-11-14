# AES Modes Lab

Một dự án C++17 minh họa AES-128/192/256 và các chế độ mã hóa theo NIST SP 800-38A, SP 800-38C (CCM) và SP 800-38D (GCM). Các ví dụ kiểm thử dùng vector công khai của NIST và RFC 3610.

> **Cảnh báo bảo mật:** Đây là mã học tập nhằm giúp hiểu thuật toán, không phải thư viện mật mã đã được kiểm toán. Cài đặt AES dạng bảng có thể rò rỉ thông tin qua timing/cache; API cũng không tự sinh nonce/IV an toàn, không bảo vệ khóa trong bộ nhớ và không cung cấp chính sách quản lý khóa. Không dùng trong ứng dụng thực tế; hãy dùng thư viện mật mã đã được kiểm toán như OpenSSL hoặc libsodium.

## Cấu trúc

```text
aes_modes_lab/
├── CMakeLists.txt
├── README.md
├── guide.md
├── include/
│   ├── aes.hpp
│   ├── common.hpp
│   ├── sp800_38a.hpp
│   ├── sp800_38c.hpp
│   └── sp800_38d.hpp
├── src/
│   ├── aes.cpp
│   ├── sp800_38a.cpp
│   ├── sp800_38c.cpp
│   └── sp800_38d.cpp
└── tests/
    └── main.cpp
```

## AES và tiện ích

`lab::AES` nhận khóa 16, 24 hoặc 32 byte tương ứng AES-128, AES-192 hoặc AES-256, và mã hóa/giải mã một khối 16 byte. Các helper cung cấp PKCS#7 (`pad`/`unpad`), XOR khối, kiểm tra IV/độ dài, nối dữ liệu và trích xuất một khối.

PKCS#7 được dùng với ECB/CBC; luôn thêm một khối padding khi plaintext đã chia hết cho 16. CFB, OFB, CTR, CCM và GCM xử lý plaintext có độ dài bất kỳ, không thêm padding.

## NIST SP 800-38A — Confidentiality Modes

Các chế độ này cung cấp **bảo mật nhưng không xác thực**. Kẻ tấn công có thể sửa ciphertext mà không bị phát hiện; nếu cần tính toàn vẹn hãy dùng AEAD như CCM hoặc GCM và luôn xác minh tag.

- **ECB (Electronic Codebook):** Mã hóa độc lập từng khối `Cᵢ = Eₖ(Pᵢ)`. Cài đặt thêm/bỏ PKCS#7. Dễ xử lý và song song, nhưng các khối plaintext giống nhau cho ra ciphertext giống nhau, làm lộ cấu trúc/mẫu hình. Không phù hợp để mã hóa dữ liệu thực tế.
- **CBC (Cipher Block Chaining):** `Cᵢ = Eₖ(Pᵢ XOR Cᵢ₋₁)`, với `C₀ = IV`; giải mã XOR kết quả AES với khối ciphertext trước (hoặc IV). Dùng PKCS#7. IV cần ngẫu nhiên, không dự đoán được và đúng 16 byte; không tái sử dụng IV dưới cùng khóa. CBC không xác thực.
- **CFB (Cipher Feedback):** Mã hóa thanh ghi phản hồi rồi XOR với từng phân đoạn; ciphertext được đưa lại vào thanh ghi. Biến AES thành mã hóa kiểu dòng và hỗ trợ phân đoạn từ 8 đến 128 bit (bội số 8 trong API). Không padding; sửa ciphertext gây lỗi dữ liệu và có thể lan truyền.
- **OFB (Output Feedback):** AES lặp trên đầu ra trước để sinh keystream độc lập với plaintext, rồi XOR keystream với dữ liệu. Không padding. Không được tái sử dụng IV/keystream dưới cùng khóa.
- **CTR (Counter Mode):** Mã hóa các giá trị bộ đếm 128-bit big-endian để sinh keystream. Có thể tính song song và xử lý độ dài tùy ý; API báo lỗi nếu tăng bộ đếm vượt quá 128 bit. Bộ đếm/nonce tuyệt đối không được lặp lại với cùng khóa.

## NIST SP 800-38C — CCM

CCM kết hợp **CBC-MAC** với **CTR**. CBC-MAC xác thực khối B0, dữ liệu AAD đã định dạng và plaintext; CTR mã hóa plaintext và che MAC để tạo tag. AAD được xác thực nhưng không mã hóa. CCM phù hợp với thiết bị/môi trường hạn chế tài nguyên.

API nhận nonce (tham số `iv`) dài 7–13 byte và tag chẵn dài 4–16 byte. Hàm mã hóa trả về cặp `{ciphertext, tag}`; giải mã chỉ trả plaintext sau khi xác thực thành công và ném `std::runtime_error` nếu tag không hợp lệ. Không tái sử dụng nonce với cùng khóa.

## NIST SP 800-38D — GCM

GCM kết hợp CTR với GHASH, hàm băm trên trường `GF(2^128)` sử dụng đa thức bất khả quy `x^128 + x^7 + x^2 + x + 1`. GCTR mã hóa plaintext; GHASH xác thực ciphertext, AAD và độ dài bit. AAD được xác thực nhưng không mã hóa. GCM có hiệu năng cao và các phép tính xác thực theo khối có thể được song song hóa.

API hỗ trợ IV không rỗng, bao gồm IV 96-bit (đường xử lý chuẩn, hiệu quả nhất), cùng tag 4, 8 hoặc 12–16 byte. Hàm mã hóa trả `{ciphertext, tag}`; giải mã xác minh tag trước khi trả plaintext và ném `std::runtime_error` khi xác thực thất bại. Không tái sử dụng IV dưới cùng khóa.

## Biên dịch và kiểm thử

Xem [guide.md](guide.md) để biết từng lệnh trên Linux, Windows và WSL. Với CMake, thư mục build tạo ra executable `aes_tests`; có thể chạy trực tiếp hoặc bằng CTest. Bộ test bao gồm AES-128/192/256, các vector SP 800-38A, một vector CCM cố định, GCM NIST, giải mã vòng lại và các trường hợp ciphertext/tag bị sửa.

## Chạy bằng Docker

[Dockerfile](Dockerfile) tạo một image nhiều giai đoạn: giai đoạn đầu cài CMake và trình biên dịch C++, biên dịch dự án rồi chạy CTest; image cuối chỉ chứa executable kiểm thử và thư viện runtime cần thiết. Cách này giúp chạy các bài kiểm thử trong môi trường Linux nhất quán mà không cần cài CMake/compiler trực tiếp trên máy. Image không cung cấp giao diện dòng lệnh để mã hóa dữ liệu tùy ý; khi chạy, chương trình thực hiện bộ kiểm thử có sẵn.

Mở terminal tại thư mục `aes_modes_lab`, sau đó build image:

```bash
docker build -t aes-modes-lab .
```

Chạy bộ kiểm thử trong container:

```bash
docker run --rm aes-modes-lab
```

Khi thành công, chương trình in `All AES mode tests passed.` Lệnh `docker build` cũng chạy CTest và sẽ thất bại nếu cấu hình, biên dịch hoặc kiểm thử lỗi.

Docker chỉ đóng gói môi trường build/chạy; đây vẫn là mã học tập chưa được kiểm toán và không nên dùng để bảo vệ dữ liệu thực tế. Xem cảnh báo bảo mật ở đầu README.

## Ghi chú sử dụng API

Các khai báo đặt trong namespace `lab`; bao gồm header tương ứng. Với ECB/CBC, `Bytes` đầu vào/đầu ra sử dụng PKCS#7. Với CFB/OFB/CTR, hai phía dùng chung hàm biến đổi (CFB có hàm riêng encrypt/decrypt). CCM/GCM trả `std::pair<Bytes, Bytes>` theo thứ tự ciphertext rồi tag. Các đối số IV/nonce là byte thô, không tự sinh ngẫu nhiên.
