# Week 3 — ChaCha20-Poly1305 Code Set

This package follows the same three-level teaching structure used for the RC4 and ChaCha20-only examples.

> **Educational implementation.** The code directly implements the RFC 8439 construction so students can inspect the algorithm. For production software, use a vetted cryptographic library rather than this classroom code.

## 1. Warm-up code

**File:** `chacha20_poly1305_warmup.py`

Interactive program for first contact with AEAD.

Students can:

- choose **Encrypt** or **Decrypt**;
- enter a 32-byte key manually or generate one randomly;
- enter a 12-byte nonce manually or generate one randomly;
- provide optional **AAD**;
- use text, hex, or Base64 data formats;
- see ciphertext, the 16-byte authentication tag, and `ciphertext || tag`;
- observe that decryption releases plaintext **only after the tag verifies**.

Run:

```bash
python chacha20_poly1305_warmup.py
```

Core warm-up logic:

```text
Poly1305 key = ChaCha20_Block(K, counter=0, nonce)[0:32]
Ciphertext   = Plaintext XOR ChaCha20_Keystream(K, counter=1, nonce)
Tag          = Poly1305(AAD || padding || Ciphertext || padding || lengths)
```

The most important operational rule is:

```text
Never reuse the same nonce with the same ChaCha20-Poly1305 key.
```

Nonce reuse repeats both the ChaCha20 keystream and the Poly1305 one-time key.

---

## 2. Teaching code

**File:** `chacha20_poly1305_teaching.py`

This version is intended for line-by-line teaching and algorithm verification.

It exposes:

1. ChaCha20 4x4 state construction;
2. ARX quarter round;
3. column and diagonal rounds;
4. 20-round block function and feed-forward;
5. counter `0` Poly1305 one-time-key derivation;
6. counter `1+` payload encryption;
7. Poly1305 `r || s` key split;
8. `r` clamping;
9. exact AEAD MAC-input construction;
10. Poly1305 accumulation modulo `2^130 - 5`;
11. 16-byte tag generation;
12. constant-time authentication before decryption.

### Show the algorithm overview

```bash
python chacha20_poly1305_teaching.py overview
```

### Run all RFC 8439 tests

```bash
python chacha20_poly1305_teaching.py selftest
```

Expected summary:

```text
RFC 8439 Poly1305                 : PASS
RFC 8439 AEAD ciphertext          : PASS
RFC 8439 AEAD tag                 : PASS
RFC 8439 AEAD decryption          : PASS
Modified ciphertext rejected      : PASS
```

### Trace the raw Poly1305 RFC example

```bash
python chacha20_poly1305_teaching.py poly1305-test --trace-blocks 3
```

### Trace the complete RFC AEAD example

```bash
python chacha20_poly1305_teaching.py rfc-demo \
  --verbose 1 \
  --trace-poly-blocks 3
```

To also inspect the early ChaCha20 state evolution:

```bash
python chacha20_poly1305_teaching.py rfc-demo \
  --verbose 2 \
  --trace-double-rounds 1 \
  --trace-poly-blocks 2
```

### Manual encryption example

```bash
python chacha20_poly1305_teaching.py encrypt \
  --key 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f \
  --nonce 000000000000000000000002 \
  --aad "course=NT2205" --aad-format text \
  --input "Hello ChaCha20-Poly1305" --input-format text \
  --output-format hex \
  --verbose 1
```

The output gives ciphertext and tag separately, plus the combined `ciphertext || tag` encoding.

### Decryption example

```bash
python chacha20_poly1305_teaching.py decrypt \
  --key <64_hex_digits> \
  --nonce <24_hex_digits> \
  --aad "course=NT2205" --aad-format text \
  --input <ciphertext_hex> --input-format hex \
  --tag <32_hex_digits> \
  --output-format text \
  --verbose 1
```

If the key, nonce, AAD, ciphertext, or tag is modified, authentication fails and the program does not release plaintext.

---

## 3. CLI + PyQt6 GUI demo

**File:** `chacha20_poly1305_demo.py`

One program provides both command-line and GUI operation.

### CLI self-test

```bash
python chacha20_poly1305_demo.py selftest
```

### CLI encryption

```bash
python chacha20_poly1305_demo.py encrypt \
  --key 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f \
  --nonce 000000000000000000000002 \
  --aad "header" --aad-format text \
  --input "Demo message" --input-format text \
  --output-format hex
```

### CLI decryption

```bash
python chacha20_poly1305_demo.py decrypt \
  --key <key_hex> \
  --nonce <nonce_hex> \
  --aad "header" --aad-format text \
  --input <ciphertext_hex> --input-format hex \
  --tag <tag_hex> \
  --output-format text
```

### GUI

Install PyQt6:

```bash
pip install -r requirements.txt
```

Launch:

```bash
python chacha20_poly1305_demo.py gui
```

The GUI provides:

- Encrypt / Decrypt selection;
- random 256-bit key generation;
- random 96-bit nonce generation;
- Text / Hex / Base64 formats;
- AAD field;
- authentication tag field;
- RFC 8439 test-vector loader;
- built-in self-test;
- explicit authentication PASS/FAIL behavior.

---

# Algorithm relation to Week 3

The three programs intentionally distinguish **ChaCha20** from **ChaCha20-Poly1305**.

For standalone ChaCha20, the initial block counter is an explicit stream-cipher parameter. In the RFC 8439 AEAD construction, however:

```text
counter = 0  -> generate Poly1305 one-time key
counter = 1+ -> encrypt plaintext
```

Poly1305 does not encrypt data. It authenticates the AAD and ciphertext.

The authenticated message is exactly:

```text
AAD
|| pad16(AAD)
|| ciphertext
|| pad16(ciphertext)
|| little_endian_64(len(AAD))
|| little_endian_64(len(ciphertext))
```

This structure is included explicitly in the teaching code so students can inspect every byte.

---

# Suggested classroom sequence

### Warm-up

1. Encrypt a short message without AAD.
2. Copy the ciphertext/tag into decrypt mode.
3. Change one ciphertext bit and observe authentication failure.
4. Restore ciphertext, then change AAD and observe authentication failure.

### Teaching

1. Run `overview`.
2. Show the ChaCha20 block with counter 0.
3. Extract the first 32 bytes as the Poly1305 one-time key.
4. Show payload encryption beginning at counter 1.
5. Build the padded AEAD authentication input.
6. Trace several Poly1305 accumulator blocks.
7. Verify the RFC tag.
8. Demonstrate authenticate-before-decrypt.

### Demo / practical use

Use the GUI to show students that AEAD binds together:

```text
key + nonce + AAD + ciphertext + tag
```

Changing any authenticated component makes verification fail.

---

# Files

```text
Week03_ChaCha20_Poly1305_Code/
├── chacha20_poly1305_warmup.py
├── chacha20_poly1305_teaching.py
├── chacha20_poly1305_demo.py
├── README_ChaCha20_Poly1305_Week3.md
└── requirements.txt
```

## Dependency

Only the GUI requires an external package:

```text
PyQt6
```

The cryptographic teaching implementation itself uses only the Python standard library.
