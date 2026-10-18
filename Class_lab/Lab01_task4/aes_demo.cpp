#include <iostream>
#include <string>
#include <cryptopp/osrng.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>

using namespace std;
using namespace CryptoPP;

int main() {
    // 1. Tạo ngẫu nhiên Key (16 bytes) và IV (16 bytes)
    AutoSeededRandomPool prng;
    CryptoPP::byte key[AES::DEFAULT_KEYLENGTH];
    CryptoPP::byte iv[AES::BLOCKSIZE];

    prng.GenerateBlock(key, sizeof(key));
    prng.GenerateBlock(iv, sizeof(iv));

    // Chuyển Key và IV sang chuỗi Hex để in ra màn hình
    string keyHex, ivHex;
    StringSource(key, sizeof(key), true, new HexEncoder(new StringSink(keyHex)));
    StringSource(iv, sizeof(iv), true, new HexEncoder(new StringSink(ivHex)));

    cout << "Key (Hex): " << keyHex << endl;
    cout << "IV (Hex): " << ivHex << endl;

    string plaintext = "xin chào Putin";
    string ciphertext;
    string decryptedtext;

    try {
        // 2. Mã hóa AES-128-CBC với padding PKCS7
        CBC_Mode<AES>::Encryption encryptor;
        encryptor.SetKeyWithIV(key, sizeof(key), iv);

        StringSource(plaintext, true,
            new StreamTransformationFilter(encryptor,
                new StringSink(ciphertext)
            )
        );

        // Chuyển Ciphertext sang Hex để hiển thị
        string cipherHex;
        StringSource(
            reinterpret_cast<const CryptoPP::byte*>(ciphertext.data()), 
            ciphertext.size(), 
            true, 
            new HexEncoder(new StringSink(cipherHex))
        );

        // 3. Giải mã AES-128-CBC
        CBC_Mode<AES>::Decryption decryptor;
        decryptor.SetKeyWithIV(key, sizeof(key), iv);

        StringSource(
            reinterpret_cast<const CryptoPP::byte*>(ciphertext.data()), 
            ciphertext.size(), 
            true,
            new StreamTransformationFilter(decryptor,
                new StringSink(decryptedtext)
            )
        );

        // 4. In kết quả
        cout << "Ket qua Demo AES C++" << endl;
        cout << "Văn bản gốc (Plaintext) : " << plaintext << endl;
        cout << "Mã hóa (Hex Ciphertext) : " << cipherHex << endl;
        cout << "Giải mã (Decrypted Text): " << decryptedtext << endl;

    } catch (const Exception& e) {
        cerr << "Lỗi Crypto++: " << e.what() << endl;
        return 1;
    }

    return 0;
}