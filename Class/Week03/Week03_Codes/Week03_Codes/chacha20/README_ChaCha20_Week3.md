# Week 3 — ChaCha20 Code Set (ChaCha20 only, no Poly1305)

This package follows the three-code teaching structure used for RC4, but implements the **IETF ChaCha20 variant in RFC 8439**:

- 256-bit key = 32 bytes
- 96-bit nonce = 12 bytes
- 32-bit block counter
- 64-byte keystream block
- 20 rounds = 10 column+diagonal double-rounds
- final feed-forward addition of the original state
- little-endian serialization

The package intentionally contains **no Poly1305 and no AEAD construction**.

## 1. `chacha20_warmup.py` — interactive warm-up

Goal: quickly understand the stream-cipher interface.

Features:

- select **Encrypt** or **Decrypt** interactively;
- manually enter a 32-byte key as UTF-8/hex or generate one randomly;
- manually enter a 12-byte nonce or generate one randomly;
- select the initial 32-bit counter;
- plaintext: UTF-8 or hex;
- ciphertext: hex or Base64;
- displays the generated keystream and XOR result.

Run:

```bash
python chacha20_warmup.py
```

Important classroom observation:

```text
C = P XOR Z
P = C XOR Z
```

Encryption and decryption are therefore the same operation once the same keystream is generated.

---

## 2. `chacha20_teaching.py` — detailed step-by-step algorithm

This is the main algorithm-teaching version. It explicitly shows:

1. the 4x4 initial state;
2. little-endian parsing of constants/key/counter/nonce;
3. the quarter-round ARX sequence;
4. column-round indices;
5. diagonal-round indices;
6. 10 double-rounds = 20 rounds;
7. **feed-forward addition of the original state**;
8. little-endian serialization;
9. counter progression for multiple 64-byte blocks;
10. XOR encryption/decryption.

### Algorithm overview

```bash
python chacha20_teaching.py overview
```

### RFC 8439 self-tests

```bash
python chacha20_teaching.py selftest
```

The self-test checks:

- RFC 8439 quarter-round vector;
- RFC 8439 ChaCha20 block-function vector;
- RFC 8439 full encryption vector;
- decryption/round-trip correctness.

### Trace the quarter round

```bash
python chacha20_teaching.py quarter-test --trace
```

### Trace a ChaCha20 block

```bash
python chacha20_teaching.py block \
  --key 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f \
  --nonce 000000090000004a00000000 \
  --counter 1 \
  --verbose 2 \
  --trace-double-rounds 2
```

The RFC 8439 expected block begins with:

```text
10 f1 e7 e4 d1 3b 59 15 50 0f dd 1f a3 20 71 c4 ...
```

### Encrypt

```bash
python chacha20_teaching.py encrypt \
  --key 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f \
  --nonce 000000000000004a00000000 \
  --counter 1 \
  --input "Hello ChaCha20" \
  --input-format text \
  --output-format hex
```

Use the identical key, nonce, and counter to decrypt the resulting ciphertext.

---

## 3. `chacha20_demo.py` — CLI + PyQt6 GUI

One file serves both command-line demonstrations and graphical classroom use.

### CLI self-test

```bash
python chacha20_demo.py selftest
```

### CLI encrypt

```bash
python chacha20_demo.py encrypt \
  --key 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f \
  --key-format hex \
  --nonce 000000000000004a00000000 \
  --nonce-format hex \
  --counter 1 \
  --input "Hello ChaCha20" \
  --input-format text \
  --output-format hex
```

### CLI keystream

```bash
python chacha20_demo.py keystream \
  --key 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f \
  --nonce 000000000000004a00000000 \
  --counter 1 --n 64
```

### GUI

Install PyQt6:

```bash
pip install PyQt6
```

Launch:

```bash
python chacha20_demo.py gui
```

The GUI supports:

- Encrypt / Decrypt / Keystream / Block;
- hex or text key/nonce input, with exact-size validation;
- random 32-byte key generation;
- random 12-byte nonce generation;
- initial counter selection;
- Text / Hex / Base64 input and output;
- RFC 8439 self-test.

---

## Correctness details that matter in Week 3

### 1. The IETF state layout

```text
61707865  3320646e  79622d32  6b206574
key[0]    key[1]    key[2]    key[3]
key[4]    key[5]    key[6]    key[7]
counter   nonce[0]  nonce[1]  nonce[2]
```

Key and nonce words are read as **little-endian 32-bit integers**.

### 2. Quarter-round rotations

The rotation distances must be exactly:

```text
16, 12, 8, 7
```

### 3. Exact round schedule

Column round:

```text
QR(0,4,8,12)
QR(1,5,9,13)
QR(2,6,10,14)
QR(3,7,11,15)
```

Diagonal round:

```text
QR(0,5,10,15)
QR(1,6,11,12)
QR(2,7,8,13)
QR(3,4,9,14)
```

This pair is repeated 10 times.

### 4. Feed-forward is mandatory

After 20 rounds:

```text
final[i] = working[i] + initial[i] mod 2^32
```

Omitting this step does **not** implement the ChaCha20 block function.

### 5. Stand-alone initial counter

For stand-alone ChaCha20, RFC 8439 allows the initial counter to be an explicit 32-bit value, normally 0 or 1.

Because this package does **not** implement Poly1305, block counter 0 is **not reserved** here. The programs default to `1` simply because the main RFC encryption example uses counter 1.

### 6. Nonce uniqueness

For a fixed key, the nonce must not be repeated. Repeating `(key, nonce, counter)` repeats the keystream:

```text
C1 = P1 XOR Z
C2 = P2 XOR Z
=> C1 XOR C2 = P1 XOR P2
```

This is a central Week 3 cryptanalysis lesson.

### 7. No authentication

ChaCha20 alone does not detect ciphertext modification. It is intentionally presented here as a stream cipher for algorithm study. Real protocols normally use an authenticated construction rather than raw unauthenticated ChaCha20.

## Reference

Y. Nir and A. Langley, **RFC 8439 — ChaCha20 and Poly1305 for IETF Protocols**, 2018. This code set uses only the ChaCha20 portions (Sections 2.1–2.4 and their test vectors).
