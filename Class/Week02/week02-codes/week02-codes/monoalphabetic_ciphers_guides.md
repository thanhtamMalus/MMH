# Monoalphabetic Ciphers CLI Tool – User Guide

This guide explains how to use `week01_mono.py`, a Python CLI tool for various classical ciphers.

```bash
D:\Pythons\Python312-uit\python.exe week01_mono.py [cipher] [options] "text"
```

Available ciphers: `substitution`, `caesar`, `atbash`, `affine`, `keyword`, `rot`, `a1z26`, `homophonic`, `pigpen`, 

---

## 1. Substitution Cipher

Replace each letter with a unique substitution based on a 26-letter key.

**Key format:** 26 unique uppercase letters (e.g., `QWERTYUIOPASDFGHJKLZXCVBNM`)

```bash
# Encrypt
python.exe week01_mono.py substitution --subkey "QWERTYUIOPASDFGHJKLZXCVBNM" "plain text"

# Decrypt
python.exe week01_mono.py substitution --decrypt --subkey "QWERTYUIOPASDFGHJKLZXCVBNM" "cipher text"
```

---

## 2. Caesar Cipher (Shift)

Shift each letter by *n* positions in the alphabet.

```bash
# Encrypt with shift=4
python.exe week01_mono.py caesar --shift 4 "plain text"

# Decrypt with shift=4
python.exe week01_mono.py caesar --decrypt --shift 4 "cipher text"
```

---

## 3. Atbash Cipher

Fixed mapping: reverse alphabet (A→Z, B→Y, ...).

```bash
# Encrypt or Decrypt
python.exe week01_mono.py atbash "plain text"
python.exe week01_mono.py atbash --decrypt "cipher text"
```

---

## 4. Affine Cipher

Mathematical cipher:

* Encryption: `E(x) = (a*x + b) mod 26`
* Decryption: `D(y) = a⁻¹ * (y − b) mod 26`

⚠️ Condition: `gcd(a,26) = 1`

```bash
# Encrypt with a=5, b=8
python.exe week01_mono.py affine --a 5 --b 8 "plain text"

# Decrypt
python.exe week01_mono.py affine --decrypt --a 5 --b 8 "cipher text"
```

---

## 5. Keyword Cipher

Alphabet starts with a keyword, then fills with remaining letters.

```bash
# Encrypt with keyword SECRET
python.exe week01_mono.py keyword --keyword "SECRET" "plain text"

# Decrypt
python.exe week01_mono.py keyword --decrypt --keyword "SECRET" "cipher text"

# Show substitution table
python.exe week01_mono.py keyword --keyword "SECRET" --showkey "plain text"
```

---

## 6. Homophonic Substitution

Maps each letter to multiple possible symbols/numbers.

```bash
# Encrypt with custom mapping file
python.exe week01_mono.py homophonic --homofile mapping.json "plain text"

# Decrypt with same mapping
python.exe week01_mono.py homophonic --decrypt --homofile mapping.json "cipher text"
```

If `--homofile` is omitted, a built-in mapping is used.

---

## 7. Pigpen Cipher

Graphical substitution cipher using symbols.

```bash
# Encrypt with default symbols
python.exe week01_mono.py pigpen "plain text"

# Decrypt
python.exe week01_mono.py pigpen --decrypt "cipher text"

# Encrypt with custom 26-character symbol set
python.exe week01_mono.py pigpen --pigpenkey "✫◈◓◐◉∆◔◕◑◇⊟⊡◍★●□✦⊠◒✩◎✪⊞○◆✧" "plain text"
```

---

## 8. ROT-N Variants

Generalization of Caesar cipher.

```bash
# ROT13 (default)
python.exe week01_mono.py rot "plain text"

# ROT5
python.exe week01_mono.py rot --n 5 "plain text"
```

---

## 9. Numeric Cipher (A1Z26)

Maps A=1, B=2, ..., Z=26.

```bash
# Encrypt
python.exe week01_mono.py a1z26 "plain text"

# Decrypt
python.exe week01_mono.py a1z26 --decrypt "16 12 1 9 14"
```

---

## Notes

* Input is converted to **uppercase** automatically.
* Non-alphabet characters are preserved.
* For Affine, ensure `a` and 26 are coprime.
* For Homophonic, same mapping must be used for both encryption and decryption.
