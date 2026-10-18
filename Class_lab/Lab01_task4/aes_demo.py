import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

key = os.urandom(16)
iv = os.urandom(16)
print(f"Key (Hex): {key.hex()}")
print(f"IV (Hex): {iv.hex()}")

plaintext = "xin chào Putin"

cipher_encrypt = AES.new(key, AES.MODE_CBC, iv)

padded_data = pad(plaintext.encode('utf-8'), AES.block_size)
ciphertext = cipher_encrypt.encrypt(padded_data)

cipher_hex = ciphertext.hex()

cipher_decrypt = AES.new(key, AES.MODE_CBC, iv)

decrypted_padded = cipher_decrypt.decrypt(ciphertext)
decrypted_text = unpad(decrypted_padded, AES.block_size).decode('utf-8')

print("Ket qua Demo AES Python")
print(f"Văn bản gốc (Plaintext) : {plaintext}")
print(f"Mã hóa (Hex Ciphertext) : {cipher_hex}")
print(f"Giải mã (Decrypted Text): {decrypted_text}")