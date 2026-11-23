# Polyalphabetic & Matrix-Based Ciphers CLI Tool – User Guide

This guide explains how to use the extended `week01_poly.py` tool for **polyalphabetic** and **matrix-based** ciphers.

```bash
D:\Pythons\Python312-uit\python.exe week01_poly.py [cipher] [options] "text"
```

Available ciphers: `vigenere`, `beaufort`, `autokey`, `playfair`, `hill`

---

## 1. Vigenère Cipher

Repeats a keyword to shift each letter.

```bash
# Encrypt
python.exe week01_poly.py vigenere --key "SECRET" "plain text"

# Decrypt
python.exe week01_poly.py vigenere --decrypt --key "SECRET" "cipher text"
```

---

## 2. Beaufort Cipher

Similar to Vigenère but uses formula: `C = K − P (mod 26)`. **Encryption and decryption use the same function.**

```bash
# Encrypt / Decrypt
python.exe week01_poly.py beaufort --key "SECRET" "plain text"
python.exe week01_poly.py beaufort --key "SECRET" "cipher text"
```

---

## 3. Autokey Cipher

Uses a keyword followed by plaintext (or recovered text) as the running key.

```bash
# Encrypt
python.exe week01_poly.py autokey --key "SECRET" "plain text"

# Decrypt
python.exe week01_poly.py autokey --decrypt --key "SECRET" "cipher text"
```

---

## 4. Playfair Cipher

Uses a 5×5 square (I/J combined). Digraph substitution rules:

* Same row → take letter to the right
* Same column → take letter below
* Rectangle → swap columns

```bash
# Encrypt
python.exe week01_poly.py playfair --playfairkey "MONARCHY" "plain text"

# Decrypt
python.exe week01_poly.py playfair --decrypt --playfairkey "MONARCHY" "cipher text"
```

Notes:

* Only letters are used (J → I).
* Double letters in a digraph are split with `X`.
* Odd-length plaintext is padded with `X`.

---

## 5. Hill Cipher (Generalized Affine – Matrix Form)

Block cipher using invertible matrix modulo 26.

* Encryption: `C = K × P (mod 26)`
* Decryption: `P = K⁻¹ × C (mod 26)`

```bash
# Encrypt with 2x2 key matrix [3 3; 2 5]
python.exe week01_poly.py hill --hillkey "3,3,2,5" "HELP"

# Decrypt
python.exe week01_poly.py hill --decrypt --hillkey "3,3,2,5" "cipher text"
```

Notes:

* Key must be `n×n` integers, comma-separated.
* Example: `3,3,2,5` → 2×2 matrix \[\[3,3],\[2,5]].
* Determinant must be invertible mod 26 (`gcd(det,26)=1`).
* Plaintext is padded with `X` if length is not multiple of `n`.

---

## General Notes

* Input is converted to **uppercase** automatically.
* Non-alphabet characters are preserved (except Playfair which strips them).
* For Hill and Playfair, only alphabetic characters are valid inputs.
