# Week 3 — RC4 code set

This folder contains three progressively richer RC4 programs for the **Cryptography and Applications** master course.

> **Security note:** RC4 is obsolete, has exploitable statistical weaknesses, provides no authentication, and is prohibited in TLS by RFC 7465. These programs are for teaching and cryptanalysis experiments only.

## 1. Warm-up code — `rc4_warmup.py`

Interactive console program. No command-line arguments are required.

```bash
python rc4_warmup.py
```

Students select:
- Encrypt or decrypt.
- Manual text key, manual hex key, or generated random key.
- Text/hex plaintext or hex/Base64 ciphertext.

The program displays the keystream so students directly see:

```text
C = P XOR Z
P = C XOR Z
```

## 2. Teaching code — `rc4_teaching.py`

Detailed KSA/PRGA inspection with an algorithm overview and RFC 6229 validation.

```bash
python rc4_teaching.py overview
python rc4_teaching.py selftest
```

Example from the Week 3 slides:

```bash
python rc4_teaching.py encrypt \
  --key 736563726574 --pt 48656c6c6f --hex \
  --verbose 3 --ksa-steps 8 --dump-s-every 64
```

Inspect the PRGA and historical drop-N behavior:

```bash
python rc4_teaching.py keystream \
  --key secret --n 20 --verbose 2 \
  --prga-bytes 10 --drop-n 256
```

The `--verbose` levels are:
- `0`: final result only.
- `1`: KSA/PRGA phase overview.
- `2`: mathematical step trace.
- `3`: step trace plus state previews.

## 3. CLI/GUI code — `rc4_demo.py`

### CLI

```bash
python rc4_demo.py selftest
python rc4_demo.py encrypt --key secret --input "Hello" --output-format hex
python rc4_demo.py decrypt --key secret --input <ciphertext_hex> --input-format hex --output-format text
python rc4_demo.py keystream --key secret --n 32
```

### PyQt6 GUI

Install PyQt6:

```bash
pip install PyQt6
```

Launch:

```bash
python rc4_demo.py gui
```

The GUI supports:
- Encrypt / decrypt / keystream modes.
- Text and hex keys.
- Random key generation.
- Text, hex, and Base64 data representation.
- Optional drop-N for historical experiments.
- RFC 6229 self-test.

## Correctness check

All implementations use the RC4 definition:

### KSA

```text
S = [0,1,...,255]
j = 0
for i = 0..255:
    j = (j + S[i] + K[i mod L]) mod 256
    swap S[i], S[j]
```

### PRGA

```text
i = 0; j = 0
repeat:
    i = (i + 1) mod 256
    j = (j + S[i]) mod 256
    swap S[i], S[j]
    t = (S[i] + S[j]) mod 256
    Z = S[t]
```

RFC 6229 validation vector used in Week 3:

```text
Key:      01 02 03 04 05
Expected: b2 39 63 05 f0 3d c0 27 cc c3 52 4a 0a 11 18 a8
```

## Suggested teaching sequence

1. Run `rc4_warmup.py` to observe XOR symmetry.
2. Run `rc4_teaching.py overview` and trace the first KSA/PRGA steps.
3. Run `rc4_teaching.py selftest` before any cryptanalysis experiment.
4. Use `rc4_demo.py` for quick classroom demonstrations.
5. Next, build the cryptanalysis exercises on top of the validated implementation: output-bias measurement, distinguishers, nonce/keystream reuse, and protocol amplification examples.
