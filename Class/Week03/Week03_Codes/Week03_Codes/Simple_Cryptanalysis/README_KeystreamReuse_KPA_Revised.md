# Week 3 Cryptanalysis 01 — Revised Keystream-Reuse KPA

All three programs use only one known plaintext/ciphertext pair:

`Z = P1 XOR C1`, then `Pi = Ci XOR Z`.

No attack program accepts a secret key.

## New features
- Save recovered keystream as a raw binary file.
- Inputs can independently be `text:...`, `hex:...`, `base64:...`, or `file:path`.
- Arbitrary binary ciphertext files are supported, including images, PDFs, and ZIP files.
- Recovered plaintext can be written as raw binary files.
- Mixed input types are supported in one run.
- Partial recovery is reported if the known pair is shorter than a target.

## RC4 example
```bash
python rc4_known_plaintext_reuse_attack.py \
  --known-p file:known.png \
  --known-c file:known.png.enc \
  --target file:secret.jpg.enc \
  --target file:report.pdf.enc \
  --save-keystream rc4_keystream.bin \
  --output file \
  --output-dir recovered
```

## ChaCha20 example
```bash
python chacha20_known_plaintext_nonce_reuse_attack.py \
  --known-p file:known.bin \
  --known-c file:known.enc \
  --target file:image2.enc \
  --save-keystream chacha20_keystream.bin \
  --output file \
  --output-dir recovered
```

Attack precondition: same key + nonce + overlapping counter/byte positions.

## ChaCha20-Poly1305 example
For `ciphertext || 16-byte tag` files:
```bash
python chacha20_poly1305_known_plaintext_nonce_reuse_attack.py \
  --known-p file:known.bin \
  --known-c file:known.aead \
  --target file:image2.aead \
  --target file:report3.aead \
  --combined \
  --save-keystream aead_payload_keystream.bin \
  --output file \
  --output-dir recovered
```

The Poly1305 tag is separated and displayed but not verified. Authentication status remains `UNKNOWN`.

## Important limitation
If the known pair has `n` bytes, only the same aligned `n` keystream bytes are known. Longer targets cannot be fully recovered from that pair alone.

Educational/authorized laboratory use only.
