#!/usr/bin/env python3
"""Controlled ciphertext modification against ChaCha20-Poly1305.

Contrast with bare ChaCha20:
    C' = C XOR Delta
would predictably change plaintext bits, BUT ChaCha20-Poly1305 authenticates C.
The same controlled patch therefore fails authentication when the tag is unchanged.

This is a positive security demonstration, not a break of the AEAD construction.
"""
from __future__ import annotations
import argparse
import secrets
from chacha20_poly1305_core import aead_encrypt, aead_decrypt


def patch_ciphertext(ct: bytes, offset: int, old: bytes, new: bytes) -> bytes:
    if len(old) != len(new):
        raise ValueError("old and new must have the same byte length")
    if offset < 0 or offset + len(old) > len(ct):
        raise ValueError("patch range outside ciphertext")
    delta = bytes(a ^ b for a, b in zip(old, new))
    out = bytearray(ct)
    for i, d in enumerate(delta):
        out[offset + i] ^= d
    return bytes(out)


def demo() -> bool:
    key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)
    aad = b"record-type=account"
    plaintext = b"uid=1001;role=user;expires=2026-12-31"
    old, new = b"user", b"root"
    offset = plaintext.index(old)

    ct, tag = aead_encrypt(key, nonce, plaintext, aad)
    forged_ct = patch_ciphertext(ct, offset, old, new)

    print("Original plaintext :", plaintext.decode())
    print("Desired plaintext  :", plaintext[:offset] + new + plaintext[offset+len(old):])
    print("Original tag       :", tag.hex())
    print("Ciphertext modified: YES")

    try:
        aead_decrypt(key, nonce, forged_ct, tag, aad)
        print("ERROR: modified ciphertext was accepted")
        return False
    except ValueError:
        print("Receiver result    : AUTHENTICATION FAILED (expected)")
        print("Lesson             : AEAD prevents bare-ChaCha20 malleability when used correctly.")
        return True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--demo", action="store_true")
    args = ap.parse_args()
    ok = demo()
    raise SystemExit(0 if ok else 1)


if __name__ == "__main__":
    main()
