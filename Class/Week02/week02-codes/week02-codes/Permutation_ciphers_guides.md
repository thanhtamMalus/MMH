# Transposition Ciphers CLI Tool – User Guide

This guide explains how to use the `week01_trans.py` tool for **transposition / permutation ciphers**.

```bash
D:\Pythons\Python312-uit\python.exe week01_trans.py [cipher] [options] "text"
```

Available ciphers: `railfence`, `columnar`, `scytale`

---

## 1. Rail Fence Cipher

Zig-zag writing across a number of rails.

```bash
# Encrypt with 3 rails
python.exe week01_trans.py railfence --rails 3 "defend the east wall"

# Decrypt
python.exe week01_trans.py railfence --decrypt --rails 3 "DNETLEEDHESWAFATL"
```

Notes:

* Only letters are processed (spaces removed).
* Text is written diagonally across rails and read row by row.

---

## 2. Columnar Transposition

Plaintext written row-wise in a rectangle; columns are read in order defined by key.

```bash
# Encrypt with keyword ZEBRAS
python.exe week01_trans.py columnar --key "ZEBRAS" "defend the east wall"

# Decrypt with same key
python.exe week01_trans.py columnar --decrypt --key "ZEBRAS" "cipher text"
```

Notes:

* Keyword letters define column order (alphabetical).
* Plaintext is padded with `X` to fill the rectangle.
* Decryption requires the same keyword.

---

## 3. Scytale Cipher

Ancient Spartan method: wrap text around a rod (cylinder) of fixed diameter.

```bash
# Encrypt with diameter = 5
python.exe week01_trans.py scytale --diameter 5 "defend the east wall"

# Decrypt
python.exe week01_trans.py scytale --decrypt --diameter 5 "cipher text"
```

Notes:

* Text is written row by row into a rectangle of width = diameter.
* Ciphertext is read column by column.
* Plaintext padded with `X` if needed.

---

## General Notes

* Input is converted to **uppercase** automatically.
* Spaces are removed before encryption.
* Padding with `X` is added when required to fit the grid.
