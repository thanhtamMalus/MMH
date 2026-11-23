# OpenSSL + PyQt6 Stream-Cipher Laboratory v3

v3 extends v2 with **ChaCha20-Poly1305 authenticated encryption (AEAD)**.

## Algorithms

| Algorithm | Secret key | State input | Authentication |
|---|---:|---:|---|
| RC4-40 | 5 bytes | none | none |
| RC4-128 | 16 bytes | none | none |
| ChaCha20 | 32 bytes | 16-byte OpenSSL IV/counter | none |
| ChaCha20-Poly1305 | 32 bytes | 12-byte nonce | 16-byte Poly1305 tag |

RC4 is obsolete and insecure and is included only for teaching/cryptanalysis.

## Four tabs

1. **Config Library** — OpenSSL executable, version, providers, cipher list, and
   ChaCha20-Poly1305 backend status.
2. **Generate Stream Key** — raw RC4/ChaCha20 keystream of exactly the same byte
   length as Text/Hex/File reference input.
3. **Encryption** — Text/Hex/File encryption.
4. **Decryption** — Text/Hex/File decryption.

## Raw stream ciphers

For RC4 and ChaCha20:

```text
KS = G(K, state, L)
|KS| = |input| = L
C = P XOR KS
P = C XOR KS
```

v3 exposes the generated keystream and verifies explicit XOR against the direct
OpenSSL transformation.

## ChaCha20-Poly1305

ChaCha20-Poly1305 is treated as AEAD:

```text
(C, TAG) = AEAD_Encrypt(K, nonce, P, AAD)
P        = AEAD_Decrypt(K, nonce, C, AAD, TAG)
```

- Secret key: 32 bytes
- Nonce: 12 bytes
- Authentication tag: 16 bytes
- AAD: optional Text or Hex
- AAD is authenticated but not encrypted.
- Decryption fails if key, nonce, AAD, tag, or ciphertext is wrong/modified.

### Why Tab 2 does not expose a ChaCha20-Poly1305 keystream

The AEAD profile is intentionally presented as an authenticated-encryption
construction rather than as a raw keystream API. Select **ChaCha20** in Tab 2
when the laboratory objective is to inspect `KS`.

## OpenSSL backend

- RC4 and raw ChaCha20 call the local `openssl` executable.
- ChaCha20-Poly1305 uses `cryptography`'s `ChaCha20Poly1305`, which is backed by
  OpenSSL in the normal cryptography distribution.

This split is necessary because `openssl enc` is not an AEAD-oriented interface
for ChaCha20-Poly1305.

## Install

```bash
python -m pip install -r requirements.txt
```

Linux also needs an OpenSSL executable, e.g.:

```bash
sudo apt update
sudo apt install openssl
```

On Windows, select `openssl.exe` in Tab 1 if it is not already on PATH.

## Run

```bash
python stream_cipher_lab_v3.py
```

## Suggested ChaCha20-Poly1305 experiment

1. Select ChaCha20-Poly1305 in Encryption.
2. Generate a random secret key and nonce.
3. Enter plaintext.
4. Enter optional AAD such as `student-id=01`.
5. Encrypt and record ciphertext and tag.
6. Copy the same key, nonce, AAD, ciphertext, and tag to Decryption.
7. Verify successful authentication and plaintext recovery.
8. Change one ciphertext byte, one AAD byte, or one tag byte.
9. Observe authentication failure.

Never reuse a ChaCha20-Poly1305 nonce with the same key.
